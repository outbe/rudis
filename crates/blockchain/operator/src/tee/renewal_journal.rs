//! Owner-only, crash-consistent journal for one manual TEE renewal intent.

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
};

use alloy_primitives::{keccak256, Address, B256};
use alloy_sol_types::SolCall as _;
use eyre::{Result, WrapErr as _};
use outbe_primitives::{
    tee_attestation_v1::{
        AttestationEvidenceV1, AttestationMode, AttestationOperationV1, RegistrationIntentV1,
    },
    tee_registry_abi_v1::ITeeRegistryV1,
};
use outbe_tee::dcap_protocol::dcap_evidence_hash_v1;
use serde::{Deserialize, Serialize};

use crate::tx::RawRelayTransactionV1;

use super::registry::RenewalBindingV1;

const DIRECTORY: &str = "tee-renewal-v1";
const JOURNAL: &str = "journal.json";
const NEXT: &str = "journal.next";
const LOCK: &str = "state.lock";
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RELAY_VARIANTS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedRenewalV1 {
    pub source: RenewalBindingV1,
    pub intent: Vec<u8>,
    pub intent_hash: B256,
    pub evidence: Vec<u8>,
    pub evidence_hash: B256,
    pub node_signature: Vec<u8>,
    pub enclave_signature: Vec<u8>,
    pub calldata: Vec<u8>,
    pub calldata_hash: B256,
    pub requested_valid_until: u64,
    pub collateral_valid_until: u64,
    pub collateral_margin: u64,
    pub relay: Address,
    pub relay_variants: Vec<RawRelayTransactionV1>,
}

impl PreparedRenewalV1 {
    fn validate(&self) -> Result<()> {
        if self.intent.is_empty()
            || self.evidence.is_empty()
            || self.calldata.is_empty()
            || self.node_signature.len() != 65
            || self.enclave_signature.len() != 64
            || self.relay_variants.is_empty()
            || self.relay_variants.len() > MAX_RELAY_VARIANTS
        {
            eyre::bail!("renewal journal contains invalid bounded material");
        }
        let intent = RegistrationIntentV1::decode_canonical(&self.intent)
            .map_err(|error| eyre::eyre!("decode renewal journal intent: {error}"))?;
        let intent_hash = intent
            .intent_hash()
            .map_err(|error| eyre::eyre!("hash renewal journal intent: {error}"))?;
        let node_signature: &[u8; 65] = self
            .node_signature
            .as_slice()
            .try_into()
            .map_err(|_| eyre::eyre!("renewal journal node signature length changed"))?;
        let enclave_signature: &[u8; 64] = self
            .enclave_signature
            .as_slice()
            .try_into()
            .map_err(|_| eyre::eyre!("renewal journal enclave signature length changed"))?;
        let next_registration_version = self
            .source
            .registration_version
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("renewal journal source registration version exhausted"))?;
        let next_renewal_nonce = self
            .source
            .renewal_nonce
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("renewal journal source nonce exhausted"))?;
        let node_id_hash = intent
            .node_id
            .node_id_hash()
            .map_err(|error| eyre::eyre!("hash renewal journal NodeHost identity: {error}"))?;
        let derived_enclave_id = intent
            .derived_enclave_id()
            .map_err(|error| eyre::eyre!("derive renewal journal enclave identity: {error}"))?;
        if intent.operation != AttestationOperationV1::RenewEnclave
            || node_id_hash != self.source.node_id_hash
            || intent.enclave_id != self.source.enclave_id
            || derived_enclave_id != intent.enclave_id
            || intent.binding_id != self.source.binding_id
            || intent.policy_hash != self.source.policy_hash
            || intent.binding_version != self.source.binding_version
            || intent.registration_version != next_registration_version
            || intent.renewal_nonce != next_renewal_nonce
            || intent.transition_nonce != self.source.transition_nonce
            || intent.requested_valid_until != self.requested_valid_until
            || B256::from(intent.recipient_x25519) != self.source.recipient_x25519
            || B256::from(intent.attestation_ed25519) != self.source.attestation_ed25519
            || B256::from(intent.noise_responder_x25519) != self.source.noise_responder_x25519
            || intent.node_host_authorization_hash != self.source.node_host_authorization_hash
            || !intent.verify_node_signature(node_signature)
            || !intent.verify_enclave_signature(enclave_signature)
        {
            eyre::bail!("renewal journal intent is not the exact next binding transition");
        }
        let evidence = AttestationEvidenceV1::decode_canonical(&self.evidence)
            .map_err(|error| eyre::eyre!("decode renewal journal evidence: {error}"))?;
        let (evidence_intent, evidence_hash) = match &evidence {
            AttestationEvidenceV1::Dcap(value) => {
                if intent.attestation_mode != AttestationMode::DcapRequired {
                    eyre::bail!("renewal journal evidence variant does not match intent mode");
                }
                (
                    &value.intent,
                    dcap_evidence_hash_v1(&self.evidence).map_err(|code| {
                        eyre::eyre!("hash renewal journal DCAP evidence: {code:?}")
                    })?,
                )
            }
            AttestationEvidenceV1::GramineDirectDev(value) => {
                if intent.attestation_mode != AttestationMode::GramineDirectDev
                    || value.dev_attestation_public != value.intent.attestation_ed25519
                    || value.dev_signature.as_slice() != self.enclave_signature.as_slice()
                    || !value.intent.verify_enclave_signature(&value.dev_signature)
                {
                    eyre::bail!("renewal journal contains invalid GramineDirectDev evidence");
                }
                (
                    &value.intent,
                    evidence
                        .evidence_hash()
                        .map_err(|error| eyre::eyre!("hash renewal journal evidence: {error}"))?,
                )
            }
        };
        if intent_hash != self.intent_hash
            || evidence_intent != &intent
            || evidence_hash != self.evidence_hash
            || keccak256(&self.calldata) != self.calldata_hash
        {
            eyre::bail!("renewal journal hash commitment mismatch");
        }
        let canonical_calldata = ITeeRegistryV1::renewEnclaveCall {
            evidence: self.evidence.clone().into(),
            nodeSignature: self.node_signature.clone().into(),
            enclaveSignature: self.enclave_signature.clone().into(),
        }
        .abi_encode();
        if self.calldata != canonical_calldata {
            eyre::bail!("renewal journal calldata is not the canonical renewal call");
        }
        let first = &self.relay_variants[0];
        if first.relay != self.relay || first.calldata_hash != self.calldata_hash {
            eyre::bail!("renewal journal relay binding mismatch");
        }
        for variant in &self.relay_variants {
            if variant.relay != self.relay
                || variant.chain_id != first.chain_id
                || variant.account_nonce != first.account_nonce
                || variant.gas_limit != first.gas_limit
                || variant.calldata_hash != self.calldata_hash
                || keccak256(&variant.raw_transaction) != variant.transaction_hash
            {
                eyre::bail!("renewal journal contains a competing relay variant");
            }
        }
        match evidence {
            AttestationEvidenceV1::Dcap(_) => {
                let ceiling = self
                    .collateral_valid_until
                    .checked_sub(self.collateral_margin)
                    .ok_or_else(|| eyre::eyre!("renewal collateral margin underflow"))?;
                if self.requested_valid_until > ceiling {
                    eyre::bail!("renewal journal lease exceeds collateral ceiling");
                }
            }
            AttestationEvidenceV1::GramineDirectDev(_) => {
                if self.collateral_valid_until != u64::MAX || self.collateral_margin != 0 {
                    eyre::bail!(
                        "renewal journal has non-canonical GramineDirectDev collateral fields"
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum RenewalJournalStateV1 {
    Prepared {
        attempt: PreparedRenewalV1,
    },
    Submitted {
        attempt: PreparedRenewalV1,
        submitted_at_finalized_height: u64,
        transaction_hashes: Vec<B256>,
    },
    Finalized {
        attempt: Box<PreparedRenewalV1>,
        finalized_binding: RenewalBindingV1,
        finalized_height: u64,
        finalized_hash: B256,
    },
    Abandoned {
        attempt: PreparedRenewalV1,
        abandoned_at_finalized_height: u64,
        reason: String,
    },
}

impl RenewalJournalStateV1 {
    pub fn attempt(&self) -> &PreparedRenewalV1 {
        match self {
            Self::Prepared { attempt }
            | Self::Submitted { attempt, .. }
            | Self::Abandoned { attempt, .. } => attempt,
            Self::Finalized { attempt, .. } => attempt.as_ref(),
        }
    }

    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Prepared { .. } => "prepared",
            Self::Submitted { .. } => "submitted",
            Self::Finalized { .. } => "finalized",
            Self::Abandoned { .. } => "abandoned",
        }
    }

    fn validate(&self) -> Result<()> {
        self.attempt().validate()?;
        if let Self::Submitted {
            attempt,
            transaction_hashes,
            ..
        } = self
        {
            if transaction_hashes.is_empty()
                || transaction_hashes.len() > attempt.relay_variants.len()
                || transaction_hashes
                    .iter()
                    .enumerate()
                    .any(|(index, hash)| attempt.relay_variants[index].transaction_hash != *hash)
            {
                eyre::bail!("submitted renewal journal transaction list is non-canonical");
            }
        }
        if let Self::Finalized {
            attempt,
            finalized_binding,
            finalized_hash,
            ..
        } = self
        {
            if finalized_hash.is_zero()
                || finalized_binding.intent_hash != attempt.intent_hash
                || finalized_binding.evidence_hash != attempt.evidence_hash
            {
                eyre::bail!("finalized renewal journal binding mismatch");
            }
        }
        if let Self::Abandoned { reason, .. } = self {
            if reason.is_empty() || reason.len() > 512 {
                eyre::bail!("abandoned renewal journal reason is invalid");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenewalJournalSnapshotV1 {
    pub version: u8,
    pub generation: u64,
    pub lifecycle: RenewalJournalStateV1,
}

impl RenewalJournalSnapshotV1 {
    pub fn new(lifecycle: RenewalJournalStateV1) -> Self {
        Self {
            version: 1,
            generation: 1,
            lifecycle,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.version != 1 || self.generation == 0 {
            eyre::bail!("unsupported renewal journal version or generation");
        }
        self.lifecycle.validate()
    }
}

pub(crate) struct RenewalJournalGuard {
    paths: JournalPaths,
    _lock: File,
}

impl RenewalJournalGuard {
    pub(crate) fn acquire(node_data_dir: &Path) -> Result<Self> {
        let paths = JournalPaths::new(node_data_dir);
        create_or_validate_directory(&paths.root)?;
        let lock = open_private_file(&paths.lock, true)?;
        if let Err(error) =
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        {
            let error = std::io::Error::from(error);
            if error.kind() == std::io::ErrorKind::WouldBlock {
                eyre::bail!("another renewal process owns the journal lock");
            }
            return Err(error).wrap_err("lock renewal journal");
        }
        reconcile_scratch(&paths)?;
        Ok(Self { paths, _lock: lock })
    }

    pub(crate) fn load(&self) -> Result<Option<RenewalJournalSnapshotV1>> {
        read_snapshot(&self.paths.journal)
    }

    pub(crate) fn store(&self, mut snapshot: RenewalJournalSnapshotV1) -> Result<()> {
        if let Some(current) = self.load()? {
            snapshot.generation = current
                .generation
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("renewal journal generation exhausted"))?;
        }
        snapshot.validate()?;
        let encoded = serde_json::to_vec(&snapshot).wrap_err("encode renewal journal")?;
        if encoded.len() as u64 > MAX_JOURNAL_BYTES {
            eyre::bail!("renewal journal exceeds its size cap");
        }
        let mut next = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&self.paths.next)
            .wrap_err("create renewal journal scratch")?;
        next.write_all(&encoded)
            .wrap_err("write renewal journal scratch")?;
        next.sync_all().wrap_err("fsync renewal journal scratch")?;
        fs::rename(&self.paths.next, &self.paths.journal).wrap_err("commit renewal journal")?;
        sync_directory(&self.paths.root)
    }
}

pub(crate) fn inspect_journal(node_data_dir: &Path) -> Result<Option<RenewalJournalSnapshotV1>> {
    let paths = JournalPaths::new(node_data_dir);
    if !paths.root.exists() {
        return Ok(None);
    }
    validate_directory(&paths.root)?;
    read_snapshot(&paths.journal)
}

#[derive(Clone)]
struct JournalPaths {
    root: PathBuf,
    journal: PathBuf,
    next: PathBuf,
    lock: PathBuf,
}

impl JournalPaths {
    fn new(node_data_dir: &Path) -> Self {
        let root = node_data_dir.join(DIRECTORY);
        Self {
            journal: root.join(JOURNAL),
            next: root.join(NEXT),
            lock: root.join(LOCK),
            root,
        }
    }
}

fn create_or_validate_directory(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(DIRECTORY_MODE);
    match builder.create(path) {
        Ok(()) => sync_directory(
            path.parent()
                .ok_or_else(|| eyre::eyre!("renewal directory has no parent"))?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => validate_directory(path),
        Err(error) => Err(error).wrap_err("create renewal journal directory"),
    }
}

fn validate_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).wrap_err("stat renewal journal directory")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != DIRECTORY_MODE
    {
        eyre::bail!("renewal journal directory is not owner-only 0700");
    }
    Ok(())
}

fn open_private_file(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .mode(FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .wrap_err_with(|| format!("open private renewal file {}", path.display()))?;
    validate_private_file(path)?;
    Ok(file)
}

fn validate_private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("stat renewal file {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != FILE_MODE
    {
        eyre::bail!("renewal journal file is not owner-only 0600");
    }
    if metadata.len() > MAX_JOURNAL_BYTES {
        eyre::bail!("renewal journal file exceeds its size cap");
    }
    Ok(())
}

fn reconcile_scratch(paths: &JournalPaths) -> Result<()> {
    if paths.next.exists() {
        validate_private_file(&paths.next)?;
        fs::remove_file(&paths.next).wrap_err("discard incomplete renewal journal scratch")?;
        sync_directory(&paths.root)?;
    }
    Ok(())
}

fn read_snapshot(path: &Path) -> Result<Option<RenewalJournalSnapshotV1>> {
    if !path.exists() {
        return Ok(None);
    }
    validate_private_file(path)?;
    let mut bytes = Vec::new();
    File::open(path)
        .wrap_err("open renewal journal")?
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .wrap_err("read renewal journal")?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        eyre::bail!("renewal journal exceeds its size cap");
    }
    let snapshot: RenewalJournalSnapshotV1 =
        serde_json::from_slice(&bytes).wrap_err("decode renewal journal")?;
    snapshot.validate()?;
    Ok(Some(snapshot))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .wrap_err_with(|| format!("open directory {} for fsync", path.display()))?
        .sync_all()
        .wrap_err_with(|| format!("fsync directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use ed25519_dalek::Signer as _;
    use k256::ecdsa::{signature::hazmat::PrehashSigner as _, SigningKey};
    use outbe_primitives::{
        addresses::TEE_REGISTRY_ADDRESS,
        tee_attestation_v1::{
            AttestationMode, AttestationOperationV1, DcapCollateralComponentV1, DcapCollateralKind,
            DcapEvidenceV1, GramineDirectEvidenceV1, NodeIdV1,
        },
    };

    use crate::tx::RelaySignerV1;

    fn binding(intent: &RegistrationIntentV1) -> RenewalBindingV1 {
        RenewalBindingV1 {
            node_id_hash: intent.node_id.node_id_hash().unwrap(),
            enclave_id: intent.enclave_id,
            binding_id: intent.binding_id,
            intent_hash: B256::repeat_byte(4),
            evidence_hash: B256::repeat_byte(5),
            policy_hash: intent.policy_hash,
            binding_version: intent.binding_version,
            registration_version: 0,
            renewal_nonce: 0,
            transition_nonce: intent.transition_nonce,
            lease_started_at: 100,
            valid_until: 200,
            collateral_valid_until: 300,
            recipient_x25519: B256::from(intent.recipient_x25519),
            attestation_ed25519: B256::from(intent.attestation_ed25519),
            noise_responder_x25519: B256::from(intent.noise_responder_x25519),
            mrenclave: B256::repeat_byte(10),
            mrsigner: B256::repeat_byte(11),
            isv_prod_id: 1,
            isv_svn: 2,
            platform_tcb_status: 0,
            verdict_hash: B256::repeat_byte(12),
            node_host_authorization_hash: intent.node_host_authorization_hash,
        }
    }

    fn sign_node_intent(signing_key: &SigningKey, intent_hash: B256) -> [u8; 65] {
        let (signature, recovery): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            signing_key.sign_prehash(intent_hash.as_slice()).unwrap();
        let mut encoded = [0_u8; 65];
        encoded[..64].copy_from_slice(signature.to_bytes().as_slice());
        encoded[64] = recovery.to_byte();
        encoded
    }

    fn relay_material(
        evidence: &[u8],
        node_signature: &[u8],
        enclave_signature: &[u8],
    ) -> (Vec<u8>, Address, Vec<RawRelayTransactionV1>) {
        let calldata = ITeeRegistryV1::renewEnclaveCall {
            evidence: evidence.to_vec().into(),
            nodeSignature: node_signature.to_vec().into(),
            enclaveSignature: enclave_signature.to_vec().into(),
        }
        .abi_encode();
        let relay = RelaySignerV1::new(&hex::encode([0x41; 32])).unwrap();
        let raw = relay
            .sign_renewal(
                1,
                2,
                U256::from(3),
                1_000_000,
                TEE_REGISTRY_ADDRESS,
                &calldata,
            )
            .unwrap();
        (calldata, relay.address(), vec![raw])
    }

    fn add_fee_bump(attempt: &mut PreparedRenewalV1) {
        let relay = RelaySignerV1::new(&hex::encode([0x41; 32])).unwrap();
        let first = &attempt.relay_variants[0];
        let replacement = relay
            .sign_renewal(
                first.chain_id,
                first.account_nonce,
                first.gas_price + U256::from(1),
                first.gas_limit,
                TEE_REGISTRY_ADDRESS,
                &attempt.calldata,
            )
            .unwrap();
        attempt.relay_variants.push(replacement);
    }

    fn attempt() -> PreparedRenewalV1 {
        let node_signer =
            SigningKey::from_bytes((&outbe_primitives::test_keys::secret(1)).into()).unwrap();
        let full_node_public: [u8; 33] = node_signer
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let enclave_signer =
            ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x21));
        let mut intent_value = RegistrationIntentV1 {
            chain_id: U256::from(1).to_be_bytes(),
            genesis_hash: B256::repeat_byte(2),
            operation: AttestationOperationV1::RenewEnclave,
            attestation_mode: AttestationMode::DcapRequired,
            policy_hash: B256::repeat_byte(6),
            node_id: NodeIdV1 {
                reth_p2p_public: full_node_public,
            },
            enclave_id: B256::repeat_byte(1),
            binding_id: B256::repeat_byte(3),
            binding_version: 1,
            registration_version: 1,
            renewal_nonce: 1,
            transition_nonce: 0,
            requested_valid_until: 250,
            recipient_x25519: [7; 32],
            attestation_ed25519: enclave_signer.verifying_key().to_bytes(),
            noise_responder_x25519: [9; 32],
            node_host_authorization_hash: B256::repeat_byte(13),
        };
        intent_value.enclave_id = intent_value.derived_enclave_id().unwrap();
        let intent = intent_value.encode_canonical().unwrap();
        let intent_hash = intent_value.intent_hash().unwrap();
        let node_signature = sign_node_intent(&node_signer, intent_hash);
        let enclave_signature = enclave_signer.sign(intent_hash.as_slice()).to_bytes();
        let evidence_value = AttestationEvidenceV1::Dcap(DcapEvidenceV1 {
            intent: intent_value.clone(),
            quote: vec![1],
            components: [
                DcapCollateralKind::PckCertificateChain,
                DcapCollateralKind::PckCrl,
                DcapCollateralKind::PckCrlIssuerChain,
                DcapCollateralKind::RootCaCrl,
                DcapCollateralKind::TcbInfo,
                DcapCollateralKind::TcbInfoIssuerChain,
                DcapCollateralKind::QeIdentity,
                DcapCollateralKind::QeIdentityIssuerChain,
            ]
            .into_iter()
            .map(|kind| DcapCollateralComponentV1 {
                kind,
                bytes: vec![kind as u8],
            })
            .collect(),
            transition_key_ready_proof: None,
        });
        let evidence = evidence_value.encode_canonical().unwrap();
        let evidence_hash = dcap_evidence_hash_v1(&evidence).unwrap();
        let (calldata, relay, relay_variants) =
            relay_material(&evidence, &node_signature, &enclave_signature);
        PreparedRenewalV1 {
            source: binding(&intent_value),
            intent_hash,
            intent,
            evidence_hash,
            evidence,
            node_signature: node_signature.to_vec(),
            enclave_signature: enclave_signature.to_vec(),
            calldata_hash: keccak256(&calldata),
            calldata,
            requested_valid_until: 250,
            collateral_valid_until: 300,
            collateral_margin: 50,
            relay,
            relay_variants,
        }
    }

    fn direct_attempt() -> PreparedRenewalV1 {
        let mut attempt = attempt();
        let signer =
            ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x31));
        let node_signer =
            SigningKey::from_bytes((&outbe_primitives::test_keys::secret(1)).into()).unwrap();
        let mut intent = RegistrationIntentV1::decode_canonical(&attempt.intent).unwrap();
        intent.attestation_mode = AttestationMode::GramineDirectDev;
        intent.attestation_ed25519 = signer.verifying_key().to_bytes();
        intent.enclave_id = intent.derived_enclave_id().unwrap();
        let intent_hash = intent.intent_hash().unwrap();
        let node_signature = sign_node_intent(&node_signer, intent_hash);
        let signature = signer.sign(intent_hash.as_slice()).to_bytes();
        let evidence_value = AttestationEvidenceV1::GramineDirectDev(GramineDirectEvidenceV1 {
            intent: intent.clone(),
            dev_attestation_public: intent.attestation_ed25519,
            dev_signature: signature,
        });
        attempt.intent = intent.encode_canonical().unwrap();
        attempt.intent_hash = intent_hash;
        attempt.source = binding(&intent);
        attempt.evidence = evidence_value.encode_canonical().unwrap();
        attempt.evidence_hash = evidence_value.evidence_hash().unwrap();
        attempt.node_signature = node_signature.to_vec();
        attempt.enclave_signature = signature.to_vec();
        let (calldata, relay, relay_variants) = relay_material(
            &attempt.evidence,
            &attempt.node_signature,
            &attempt.enclave_signature,
        );
        attempt.calldata_hash = keccak256(&calldata);
        attempt.calldata = calldata;
        attempt.relay = relay;
        attempt.relay_variants = relay_variants;
        attempt.collateral_valid_until = u64::MAX;
        attempt.collateral_margin = 0;
        attempt
    }

    #[test]
    fn owner_only_atomic_round_trip_and_generation() {
        let root = tempfile::tempdir().unwrap();
        let guard = RenewalJournalGuard::acquire(root.path()).unwrap();
        let first =
            RenewalJournalSnapshotV1::new(RenewalJournalStateV1::Prepared { attempt: attempt() });
        guard.store(first).unwrap();
        assert_eq!(guard.load().unwrap().unwrap().generation, 1);
        let second = RenewalJournalSnapshotV1::new(RenewalJournalStateV1::Abandoned {
            attempt: attempt(),
            abandoned_at_finalized_height: 5,
            reason: "stale".to_owned(),
        });
        guard.store(second).unwrap();
        assert_eq!(guard.load().unwrap().unwrap().generation, 2);
        let metadata = fs::metadata(root.path().join(DIRECTORY).join(JOURNAL)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, FILE_MODE);
    }

    #[test]
    fn duplicate_owner_is_rejected_and_read_only_inspection_does_not_mutate() {
        let root = tempfile::tempdir().unwrap();
        let guard = RenewalJournalGuard::acquire(root.path()).unwrap();
        guard
            .store(RenewalJournalSnapshotV1::new(
                RenewalJournalStateV1::Prepared { attempt: attempt() },
            ))
            .unwrap();
        assert!(RenewalJournalGuard::acquire(root.path()).is_err());
        let inspected = inspect_journal(root.path()).unwrap().unwrap();
        assert_eq!(inspected.lifecycle.label(), "prepared");
    }

    #[test]
    fn torn_scratch_is_discarded_but_corrupt_committed_state_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        {
            let guard = RenewalJournalGuard::acquire(root.path()).unwrap();
            guard
                .store(RenewalJournalSnapshotV1::new(
                    RenewalJournalStateV1::Prepared { attempt: attempt() },
                ))
                .unwrap();
        }
        let directory = root.path().join(DIRECTORY);
        fs::write(directory.join(NEXT), b"partial").unwrap();
        fs::set_permissions(directory.join(NEXT), fs::Permissions::from_mode(FILE_MODE)).unwrap();
        let guard = RenewalJournalGuard::acquire(root.path()).unwrap();
        assert!(!directory.join(NEXT).exists());
        drop(guard);
        fs::write(directory.join(JOURNAL), b"corrupt").unwrap();
        assert!(inspect_journal(root.path()).is_err());
    }

    #[test]
    fn direct_dev_journal_round_trips_and_rejects_signature_or_sentinel_drift() {
        let root = tempfile::tempdir().unwrap();
        let guard = RenewalJournalGuard::acquire(root.path()).unwrap();
        let direct = direct_attempt();
        guard
            .store(RenewalJournalSnapshotV1::new(
                RenewalJournalStateV1::Prepared {
                    attempt: direct.clone(),
                },
            ))
            .unwrap();
        assert_eq!(guard.load().unwrap().unwrap().lifecycle.attempt(), &direct);
        drop(guard);

        let mut bad_signature = direct.clone();
        bad_signature.enclave_signature[0] ^= 1;
        assert!(
            RenewalJournalSnapshotV1::new(RenewalJournalStateV1::Prepared {
                attempt: bad_signature,
            })
            .validate()
            .unwrap_err()
            .to_string()
            .contains("exact next binding transition")
        );

        let mut bad_sentinel = direct;
        bad_sentinel.collateral_margin = 1;
        assert!(
            RenewalJournalSnapshotV1::new(RenewalJournalStateV1::Prepared {
                attempt: bad_sentinel,
            })
            .validate()
            .unwrap_err()
            .to_string()
            .contains("collateral fields")
        );
    }

    #[test]
    fn journal_rejects_duplicate_deadline_or_canonical_calldata_drift() {
        let mut bad_deadline = attempt();
        bad_deadline.requested_valid_until += 1;
        assert!(
            RenewalJournalSnapshotV1::new(RenewalJournalStateV1::Prepared {
                attempt: bad_deadline,
            })
            .validate()
            .unwrap_err()
            .to_string()
            .contains("exact next binding transition")
        );

        let mut bad_calldata = direct_attempt();
        let mut substituted_node_signature = bad_calldata.node_signature.clone();
        substituted_node_signature[0] ^= 1;
        let (calldata, relay, relay_variants) = relay_material(
            &bad_calldata.evidence,
            &substituted_node_signature,
            &bad_calldata.enclave_signature,
        );
        bad_calldata.calldata_hash = keccak256(&calldata);
        bad_calldata.calldata = calldata;
        bad_calldata.relay = relay;
        bad_calldata.relay_variants = relay_variants;
        assert!(
            RenewalJournalSnapshotV1::new(RenewalJournalStateV1::Prepared {
                attempt: bad_calldata,
            })
            .validate()
            .unwrap_err()
            .to_string()
            .contains("canonical renewal call")
        );
    }

    #[test]
    fn dcap_v1_json_shape_remains_legacy_compatible() {
        let snapshot =
            RenewalJournalSnapshotV1::new(RenewalJournalStateV1::Prepared { attempt: attempt() });
        let legacy_bytes = serde_json::to_vec(&snapshot).unwrap();
        // Exact V1 DCAP journal bytes for the generated test actors. The fixture
        // hash changes with their keys; the schema and serializer stay pinned.
        assert_eq!(
            keccak256(&legacy_bytes),
            "0x3fb0991f6d62aeaaec80251ddbb3839df38d97326f34b2735ab2aa2f9ea27658"
                .parse::<B256>()
                .unwrap()
        );
        let decoded_legacy: RenewalJournalSnapshotV1 =
            serde_json::from_slice(&legacy_bytes).unwrap();
        decoded_legacy.validate().unwrap();
        assert_eq!(serde_json::to_vec(&decoded_legacy).unwrap(), legacy_bytes);

        let encoded = serde_json::to_value(snapshot).unwrap();
        let object = encoded.as_object().unwrap();
        let mut object_keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        object_keys.sort_unstable();
        assert_eq!(object_keys, ["generation", "lifecycle", "version"]);
        let lifecycle = object["lifecycle"].as_object().unwrap();
        assert_eq!(lifecycle["state"], "prepared");
        let attempt = lifecycle["attempt"].as_object().unwrap();
        let mut attempt_keys = attempt.keys().map(String::as_str).collect::<Vec<_>>();
        attempt_keys.sort_unstable();
        assert_eq!(
            attempt_keys,
            [
                "calldata",
                "calldataHash",
                "collateralMargin",
                "collateralValidUntil",
                "enclaveSignature",
                "evidence",
                "evidenceHash",
                "intent",
                "intentHash",
                "nodeSignature",
                "relay",
                "relayVariants",
                "requestedValidUntil",
                "source",
            ]
        );
        let decoded: RenewalJournalSnapshotV1 = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
    }

    #[test]
    fn submitted_journal_restarts_with_exact_fee_variants_in_both_modes() {
        for mut attempt in [attempt(), direct_attempt()] {
            add_fee_bump(&mut attempt);
            let transaction_hashes = attempt
                .relay_variants
                .iter()
                .map(|variant| variant.transaction_hash)
                .collect::<Vec<_>>();
            let state = RenewalJournalStateV1::Submitted {
                attempt,
                submitted_at_finalized_height: 120,
                transaction_hashes,
            };
            let root = tempfile::tempdir().unwrap();
            {
                RenewalJournalGuard::acquire(root.path())
                    .unwrap()
                    .store(RenewalJournalSnapshotV1::new(state.clone()))
                    .unwrap();
            }
            let loaded = RenewalJournalGuard::acquire(root.path())
                .unwrap()
                .load()
                .unwrap()
                .unwrap();
            assert_eq!(loaded.lifecycle, state);

            let RenewalJournalStateV1::Submitted {
                attempt,
                mut transaction_hashes,
                submitted_at_finalized_height,
            } = state
            else {
                unreachable!();
            };
            transaction_hashes.reverse();
            assert!(
                RenewalJournalSnapshotV1::new(RenewalJournalStateV1::Submitted {
                    attempt,
                    submitted_at_finalized_height,
                    transaction_hashes,
                })
                .validate()
                .unwrap_err()
                .to_string()
                .contains("transaction list is non-canonical")
            );
        }
    }
}
