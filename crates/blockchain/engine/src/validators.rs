//! Validator configuration read from chain state.
//!
//! `validators.json` is a tooling/genesis artifact only. Runtime validator
//! membership is read from the ValidatorSet precompile at specific block heights.

use alloy_primitives::{Address, B256, U256};
use commonware_codec::ReadExt as _;
use commonware_cryptography::bls12381;
use commonware_p2p::{Address as CommonwareAddress, Ingress as CommonwareIngress};
use commonware_utils::Hostname;
use eyre::{Result, WrapErr};
use outbe_consensus::bls::{self, KeyBackend};
use outbe_primitives::consensus_p2p::{decode_versioned, P2pAddress, P2pIngress};
use outbe_primitives::storage::{
    readonly::{ReadOnlyBlockContext, ReadOnlyStorageProvider, StorageReader},
    StorageHandle,
};
pub use outbe_primitives::validators::{ValidatorP2pAddress, ValidatorSet};
use reth_ethereum::storage::{StateProvider as _, StateProviderBox, StateProviderFactory};
use std::path::Path;
use tracing::debug;

/// Load the BLS individual signing key from a file.
///
/// Supports all key backends: plaintext hex, AES-256-GCM encrypted, and OS keychain.
/// The backend determines how the raw key bytes are read from disk.
pub fn load_signing_key(path: &Path, backend: &KeyBackend) -> Result<bls12381::PrivateKey> {
    bls::load_individual_key(path, backend)
        .wrap_err_with(|| format!("failed to load signing key: {}", path.display()))
}

// ---------------------------------------------------------------------------
// Phase 2: Dynamic reading from EVM state
// ---------------------------------------------------------------------------

/// Wrapper that implements [`StorageReader`] for Reth's `StateProvider` (boxed).
///
/// Bridges the Reth storage API (`fn storage(Address, B256) -> Option<U256>`)
/// with the outbe primitives `StorageReader` trait.
struct RethStateReader<'a> {
    state: &'a dyn RethStateAccess,
}

/// Trait object interface for Reth state storage reads.
///
/// Implemented for [`StateProviderBox`] below, bridging the Reth storage API
/// with the outbe precompile storage layer.
pub trait RethStateAccess {
    /// Read a storage slot value. Returns `None` if the slot doesn't exist.
    fn storage_read(&self, address: Address, key: B256) -> Result<Option<U256>>;
}

impl RethStateAccess for StateProviderBox {
    fn storage_read(&self, address: Address, key: B256) -> Result<Option<U256>> {
        self.storage(address, key)
            .map_err(|e| eyre::eyre!("reth storage read failed: {e}"))
    }
}

impl<'a> StorageReader for RethStateReader<'a> {
    fn read_storage(&self, address: Address, key: B256) -> outbe_primitives::error::Result<U256> {
        self.state
            .storage_read(address, key)
            .map(|opt| opt.unwrap_or(U256::ZERO))
            .map_err(|e| {
                outbe_primitives::error::PrecompileError::Storage(format!("state read failed: {e}"))
            })
    }
}

/// Read the active validator set from on-chain state.
///
/// Queries the ValidatorSet precompile at the state referenced by `state_access`,
/// returning the active validators with their BLS MinPk public keys.
///
/// This is the Phase 2 entry point - called at consensus startup and at
/// epoch boundaries to refresh the validator set.
pub fn read_validators_from_state(state_access: &dyn RethStateAccess) -> Result<ValidatorSet> {
    read_validator_set_from_state(state_access, ValidatorSetKind::ActiveValidators)
}

/// Read the current consensus participant set from on-chain state.
///
/// This includes ACTIVE and EXITING validators that still have BLS shares.
/// It is the correct set for Simplex startup/restart because EXITING validators
/// remain accountable until a finalized DKG boundary removes their share.
pub fn read_consensus_validators_from_state(
    state_access: &dyn RethStateAccess,
) -> Result<ValidatorSet> {
    read_validator_set_from_state(state_access, ValidatorSetKind::ConsensusParticipants)
}

/// Read the DKG reshare TARGET set (`status in {ACTIVE, PENDING}`) from on-chain
/// state. This is `next_players`: the committee the upcoming reshare grants shares
/// to. PENDING joiners are included (so the ceremony activates them); EXITING
/// validators are excluded (the reshare removes them). Distinct from
/// [`read_validators_from_state`] (ACTIVE-only voting set).
pub fn read_reshare_target_from_state(state_access: &dyn RethStateAccess) -> Result<ValidatorSet> {
    read_validator_set_from_state(state_access, ValidatorSetKind::ReshareTarget)
}

/// One exact freeze-height reshare target after the consensus `CycleTick` lease
/// gate, together with the legacy compatibility exclusion list.
#[derive(Clone, Debug)]
pub struct FrozenReshareTarget {
    pub validator_set: ValidatorSet,
    pub tee_expired_target_exclusions: Vec<Address>,
}

/// Exact local identity evaluated against one canonical finalized state view.
/// `expected_enclave_id` is present for the production NodeHost session and
/// binds startup to its committed manifest; development transport may omit it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalTeeRuntimeIdentityV1 {
    pub reth_p2p_public: [u8; 33],
    pub expected_enclave_id: Option<B256>,
    pub validator: Option<Address>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalTeeRuntimeRejectionV1 {
    MissingBinding,
    EnclaveIdentityMismatch,
    ValidatorBindingMismatch,
    ValidatorJailed,
    Expired { valid_until: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalTeeRuntimeAdmissionV1 {
    /// Founder registration is created later in the same fixed block-1 system
    /// zone. This never applies to a FullNode or to any later block.
    BootstrapPending,
    Ready {
        valid_until: u64,
    },
    Rejected(LocalTeeRuntimeRejectionV1),
}

/// Evaluates one local node against an exact finalized Registry + ValidatorSet
/// snapshot. The caller owns finality/header selection; this reducer never
/// consults wall clock, latest state, receipts, or a local renewal journal.
pub fn read_local_tee_runtime_admission_from_state(
    state_access: &dyn RethStateAccess,
    context: ReadOnlyBlockContext,
    identity: LocalTeeRuntimeIdentityV1,
) -> Result<LocalTeeRuntimeAdmissionV1> {
    if !context.is_complete() {
        return Err(eyre::eyre!(
            "TEE runtime admission requires a complete finalized block context"
        ));
    }
    let reader = RethStateReader {
        state: state_access,
    };
    let mut provider = ReadOnlyStorageProvider::new_with_block_context(reader, context);
    let storage = StorageHandle::new(&mut provider);
    let registry = outbe_teeregistry::TeeRegistry::new(storage.clone());
    let Some(node_binding) = registry
        .node_host_enclave_binding_v1(identity.reth_p2p_public)
        .map_err(|error| eyre::eyre!("read local NodeHost TEE binding: {error}"))?
    else {
        return Ok(
            if context.block_number
                == outbe_evm::tee_attestation_activation::TEE_ATTESTATION_V1_ACTIVATION_HEIGHT
                && identity.validator.is_some()
            {
                LocalTeeRuntimeAdmissionV1::BootstrapPending
            } else {
                LocalTeeRuntimeAdmissionV1::Rejected(LocalTeeRuntimeRejectionV1::MissingBinding)
            },
        );
    };

    if identity
        .expected_enclave_id
        .is_some_and(|expected| expected != node_binding.enclave_id)
    {
        return Ok(LocalTeeRuntimeAdmissionV1::Rejected(
            LocalTeeRuntimeRejectionV1::EnclaveIdentityMismatch,
        ));
    }

    if let Some(validator) = identity.validator {
        let Some(validator_binding) = registry
            .validator_enclave_binding_v1(validator)
            .map_err(|error| eyre::eyre!("read local validator TEE binding: {error}"))?
        else {
            return Ok(LocalTeeRuntimeAdmissionV1::Rejected(
                LocalTeeRuntimeRejectionV1::MissingBinding,
            ));
        };
        if validator_binding.node_id_hash != node_binding.node_id_hash
            || validator_binding.enclave_id != node_binding.enclave_id
            || validator_binding.binding_id != node_binding.binding_id
        {
            return Ok(LocalTeeRuntimeAdmissionV1::Rejected(
                LocalTeeRuntimeRejectionV1::ValidatorBindingMismatch,
            ));
        }
        let validator_set = outbe_validatorset::contract::ValidatorSet::new(storage);
        if validator_set
            .get_validator(validator)?
            .is_some_and(|record| record.status == outbe_validatorset::runtime::status::JAILED)
        {
            return Ok(LocalTeeRuntimeAdmissionV1::Rejected(
                LocalTeeRuntimeRejectionV1::ValidatorJailed,
            ));
        }
    }

    if node_binding.valid_until <= context.timestamp {
        return Ok(LocalTeeRuntimeAdmissionV1::Rejected(
            LocalTeeRuntimeRejectionV1::Expired {
                valid_until: node_binding.valid_until,
            },
        ));
    }
    Ok(LocalTeeRuntimeAdmissionV1::Ready {
        valid_until: node_binding.valid_until,
    })
}

/// Reads the ordinary ValidatorSet reshare target after `CycleTick` has already
/// applied any TEE deadline jail visible in this exact state. New boundary
/// artifacts retain the legacy compatibility fields but always carry an empty
/// expiry list; ValidatorSet lifecycle is the sole production membership gate.
pub fn read_reshare_target_with_empty_tee_exclusions_from_state(
    state_access: &dyn RethStateAccess,
) -> Result<FrozenReshareTarget> {
    Ok(FrozenReshareTarget {
        validator_set: read_reshare_target_from_state(state_access)?,
        tee_expired_target_exclusions: Vec::new(),
    })
}

/// Read PENDING validators (`status == PENDING`) from on-chain state - staked
/// joiners admitted to the set but not yet share-holders. Used to admit them to
/// consensus P2P as SECONDARY peers so they sync before their activating reshare.
pub fn read_pending_validators_from_state(
    state_access: &dyn RethStateAccess,
) -> Result<ValidatorSet> {
    read_validator_set_from_state(state_access, ValidatorSetKind::PendingValidators)
}

/// Read non-voting peers admitted to consensus P2P (`status in {REGISTERED, PENDING}`)
/// from on-chain state - staked PENDING joiners PLUS TEE
/// full-nodes (REGISTERED, P2P-announced, NOT staked). Used as the secondary-tier P2P
/// admission source so both sync + execute offer blocks without voting.
pub fn read_admitted_non_consensus_from_state(
    state_access: &dyn RethStateAccess,
) -> Result<ValidatorSet> {
    read_validator_set_from_state(state_access, ValidatorSetKind::AdmittedNonConsensus)
}

#[derive(Clone, Copy)]
enum ValidatorSetKind {
    ActiveValidators,
    ConsensusParticipants,
    /// DKG reshare target / `next_players`: `status in {ACTIVE, PENDING}`. PENDING
    /// joiners must be in the target so the ceremony grants them a share and they
    /// are promoted PENDING->ACTIVE.
    ReshareTarget,
    /// PENDING joiners only - admitted to consensus P2P as SECONDARY peers so they
    /// sync to head before the reshare that makes them signers.
    PendingValidators,
    /// Non-voting peers admitted to consensus P2P as SECONDARY so they sync + execute
    /// offer blocks: `status in {REGISTERED, PENDING}`. Adds TEE
    /// full-nodes (REGISTERED, P2P-announced, enclave-registered, NOT staked) to the
    /// staked PENDING joiners. Voting still needs `has_bls_share`, so this cannot
    /// affect consensus; distinct from `ReshareTarget` ({ACTIVE, PENDING}).
    AdmittedNonConsensus,
}

fn read_validator_set_from_state(
    state_access: &dyn RethStateAccess,
    kind: ValidatorSetKind,
) -> Result<ValidatorSet> {
    let reader = RethStateReader {
        state: state_access,
    };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);

    let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
    let records = match kind {
        ValidatorSetKind::ActiveValidators => vs
            .get_active_validators()
            .map_err(|e| eyre::eyre!("failed to read active validators: {e}")),
        ValidatorSetKind::ConsensusParticipants => vs
            .get_active_consensus_set()
            .map_err(|e| eyre::eyre!("failed to read active consensus set: {e}")),
        ValidatorSetKind::ReshareTarget => vs
            .get_reshare_target_set()
            .map_err(|e| eyre::eyre!("failed to read reshare target set: {e}")),
        ValidatorSetKind::PendingValidators => vs
            .get_pending_validators()
            .map_err(|e| eyre::eyre!("failed to read pending validators: {e}")),
        ValidatorSetKind::AdmittedNonConsensus => vs
            .get_admitted_non_consensus_validators()
            .map_err(|e| eyre::eyre!("failed to read admitted non-consensus validators: {e}")),
    }?;

    let mut public_keys = Vec::with_capacity(records.len());
    let mut addresses = Vec::with_capacity(records.len());
    let mut p2p_addresses = Vec::with_capacity(records.len());

    for record in &records {
        // Read full 48-byte BLS MinPk pubkey (stored across two slots by ValidatorSet).
        let pk = bls12381::PublicKey::read(&mut record.consensus_pubkey.as_slice())
            .map_err(|e| eyre::eyre!("invalid BLS pubkey for {}: {e}", record.validator_address))?;

        public_keys.push(pk);
        addresses.push(record.validator_address);
        let p2p_address = match vs.get_p2p_address(record.validator_address) {
            Ok(Some((version, encoded))) => match decode_versioned(version, &encoded) {
                Ok(decoded) => match outbe_p2p_to_commonware(decoded) {
                    Ok(addr) => ValidatorP2pAddress::Known(addr),
                    Err(err) => {
                        tracing::warn!(
                            validator = %record.validator_address,
                            version,
                            error = %err,
                            "invalid validator p2p address registry entry; excluding peer"
                        );
                        ValidatorP2pAddress::Invalid
                    }
                },
                Err(err) => {
                    tracing::warn!(
                        validator = %record.validator_address,
                        version,
                        error = %err,
                        "invalid validator p2p address registry entry; excluding peer"
                    );
                    ValidatorP2pAddress::Invalid
                }
            },
            Ok(None) => ValidatorP2pAddress::Missing,
            Err(err) => {
                tracing::warn!(
                    validator = %record.validator_address,
                    error = %err,
                    "failed to read validator p2p address registry entry; excluding peer"
                );
                ValidatorP2pAddress::Invalid
            }
        };
        p2p_addresses.push(p2p_address);
    }

    debug!(
        count = public_keys.len(),
        "read validator set from on-chain state"
    );

    Ok(ValidatorSet {
        public_keys,
        addresses,
        p2p_addresses,
    })
}

fn outbe_p2p_to_commonware(
    address: P2pAddress,
) -> std::result::Result<CommonwareAddress, eyre::Report> {
    match address {
        P2pAddress::Symmetric(socket) => Ok(CommonwareAddress::Symmetric(socket)),
        P2pAddress::Asymmetric { ingress, egress } => Ok(CommonwareAddress::Asymmetric {
            ingress: match ingress {
                P2pIngress::Socket(socket) => CommonwareIngress::Socket(socket),
                P2pIngress::Dns { host, port } => CommonwareIngress::Dns {
                    host: Hostname::new(host)
                        .map_err(|err| eyre::eyre!("invalid commonware hostname: {err}"))?,
                    port,
                },
            },
            egress,
        }),
    }
}

/// Read active validators from the EVM state at a given block hash.
///
/// Convenience wrapper that obtains a `StateProviderBox` from the factory
/// and delegates to [`read_validators_from_state`].
pub fn read_validators_at_block(
    provider: &dyn StateProviderFactory,
    block_hash: B256,
) -> Result<ValidatorSet> {
    let state = provider
        .state_by_block_hash(block_hash)
        .map_err(|e| eyre::eyre!("failed to get state at block {block_hash}: {e}"))?;
    read_validators_from_state(&state)
}

/// Read current consensus participants from the EVM state at a given block hash.
pub fn read_consensus_validators_at_block(
    provider: &dyn StateProviderFactory,
    block_hash: B256,
) -> Result<ValidatorSet> {
    let state = provider
        .state_by_block_hash(block_hash)
        .map_err(|e| eyre::eyre!("failed to get state at block {block_hash}: {e}"))?;
    read_consensus_validators_from_state(&state)
}

/// Read PENDING validators from the EVM state at a given block hash (secondary-tier
/// P2P admission candidates).
pub fn read_pending_validators_at_block(
    provider: &dyn StateProviderFactory,
    block_hash: B256,
) -> Result<ValidatorSet> {
    let state = provider
        .state_by_block_hash(block_hash)
        .map_err(|e| eyre::eyre!("failed to get state at block {block_hash}: {e}"))?;
    read_pending_validators_from_state(&state)
}

/// Read non-voting admitted peers (`status in {REGISTERED, PENDING}`) from the EVM
/// state at a given block hash - the secondary-tier P2P admission candidates,
/// including TEE full-nodes.
pub fn read_admitted_non_consensus_at_block(
    provider: &dyn StateProviderFactory,
    block_hash: B256,
) -> Result<ValidatorSet> {
    let state = provider
        .state_by_block_hash(block_hash)
        .map_err(|e| eyre::eyre!("failed to get state at block {block_hash}: {e}"))?;
    read_admitted_non_consensus_from_state(&state)
}

/// Read the active validator set from the latest committed state.
///
/// Scopes the underlying `StateProviderBox` so its MDBX read transaction
/// cannot live across await points in consensus stack startup.
pub fn read_validators_at_latest(provider: &dyn StateProviderFactory) -> Result<ValidatorSet> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    read_validators_from_state(&state)
}

/// Read the consensus participant set (ACTIVE + EXITING) from the latest
/// committed state. Same lifetime guarantees as
/// [`read_validators_at_latest`].
pub fn read_consensus_validators_at_latest(
    provider: &dyn StateProviderFactory,
) -> Result<ValidatorSet> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    read_consensus_validators_from_state(&state)
}

/// Read the exact canonical committee snapshot committed for `epoch` from one
/// state view. The resulting hash is the authority OST3 binds at block 1.
pub fn read_committee_snapshot_from_state(
    state_access: &dyn RethStateAccess,
    epoch: u64,
) -> Result<Option<outbe_validatorset::state::CommitteeSnapshot>> {
    let reader = RethStateReader {
        state: state_access,
    };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);
    outbe_validatorset::state::read_committee_snapshot_for_epoch(storage, epoch).map_err(|error| {
        eyre::eyre!("failed to read committee snapshot for epoch {epoch}: {error}")
    })
}

/// Latest-state wrapper for [`read_committee_snapshot_from_state`].
pub fn read_committee_snapshot_at_latest(
    provider: &dyn StateProviderFactory,
    epoch: u64,
) -> Result<Option<outbe_validatorset::state::CommitteeSnapshot>> {
    let state = provider
        .latest()
        .map_err(|error| eyre::eyre!("failed to get latest state: {error}"))?;
    read_committee_snapshot_from_state(&state, epoch)
}

/// Check if there's a pending validator set change in the on-chain state.
///
/// Reads the `pending_set_change` flag from the ValidatorSet contract.
/// Used by the orchestrator to detect when a DKG reshare is needed.
pub fn has_pending_set_change(state_access: &dyn RethStateAccess) -> Result<bool> {
    let reader = RethStateReader {
        state: state_access,
    };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);

    {
        let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
        vs.has_pending_set_change()
            .map_err(|e| eyre::eyre!("failed to check pending set change: {e}"))
    }
}

/// Read the on-chain registered tribute offer public key (`TeeRegistry` slot 1).
/// It is the canonical startup comparison for the permanent resident key and the
/// expected public value verified by one-time registry onboarding. Returns zero
/// only before block-1 OST3 has bootstrapped the chain.
pub fn read_tee_offer_public_from_state(state_access: &dyn RethStateAccess) -> Result<B256> {
    let reader = RethStateReader {
        state: state_access,
    };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);

    {
        let reg = outbe_teeregistry::TeeRegistry::new(storage);
        reg.offer_public_key()
            .map_err(|e| eyre::eyre!("failed to read tee offer public key: {e}"))
    }
}

/// Read the on-chain tribute offer public from the latest committed state.
pub fn read_tee_offer_public_at_latest(provider: &dyn StateProviderFactory) -> Result<B256> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    read_tee_offer_public_from_state(&state)
}

/// Read the on-chain tribute-offer epoch (`TeeRegistry` slot 4) from the latest
/// state. The current permanent genesis offer key uses epoch zero; the field is
/// decoded explicitly rather than inferred by onboarding code.
pub fn read_tee_offer_epoch_at_latest(provider: &dyn StateProviderFactory) -> Result<u64> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    let reader = RethStateReader { state: &state };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);
    let reg = outbe_teeregistry::TeeRegistry::new(storage);
    reg.tribute_offer_epoch()
        .map_err(|e| eyre::eyre!("failed to read tee offer epoch: {e}"))
}

/// Read a validator's on-chain registered `recipient_x25519` (`TeeRegistry` per-
/// validator slot). Returns zero if the validator is not registered. The one-time
/// registry artifact must target this exact attested onboarding recipient.
pub fn read_tee_recipient_x25519_from_state(
    state_access: &dyn RethStateAccess,
    validator: Address,
) -> Result<B256> {
    let reader = RethStateReader {
        state: state_access,
    };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);

    {
        let reg = outbe_teeregistry::TeeRegistry::new(storage);
        reg.validator_enclave_binding_v1(validator)
            .and_then(|binding| {
                binding
                    .map(|binding| binding.recipient_x25519)
                    .ok_or_else(|| {
                        outbe_primitives::error::PrecompileError::Revert(
                            "validator has no NodeHost enclave binding".into(),
                        )
                    })
            })
            .map_err(|e| eyre::eyre!("failed to read tee recipient_x25519: {e}"))
    }
}

/// Read a validator's on-chain registered `recipient_x25519` from the latest state.
pub fn read_tee_recipient_x25519_at_latest(
    provider: &dyn StateProviderFactory,
    validator: Address,
) -> Result<B256> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    read_tee_recipient_x25519_from_state(&state, validator)
}

/// Check if current binary version is compatible with active (or approved) proposals.
/// Also warns if there are approved versions without registered handlers.
pub fn check_binary_version_compatibility(
    provider: &dyn StateProviderFactory,
    registry: &outbe_update::handlers::UpgradeHandlerRegistry,
) -> Result<()> {
    let active_version = read_active_protocol_version_at_latest(&provider)?;
    outbe_update::startup::assert_binary_protocol_compatible(active_version)
        .map_err(eyre::Error::msg)?;
    let waiting = read_waiting_scheduled_updates_at_latest(&provider)?;
    outbe_update::startup::warn_missing_handlers_for_waiting_updates(&waiting, registry);
    Ok(())
}

/// Read the on-chain active protocol version from the latest committed state.
fn read_active_protocol_version_at_latest(
    provider: &dyn StateProviderFactory,
) -> Result<outbe_update::ProtocolVersion> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    let reader = RethStateReader { state: &state };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);
    let update = outbe_update::schema::Update::new(storage);
    Ok(update.get_active_version()?)
}

/// Read scheduled updates waiting for activation from the latest committed state.
fn read_waiting_scheduled_updates_at_latest(
    provider: &dyn StateProviderFactory,
) -> Result<Vec<outbe_update::ScheduledUpdateInfo>> {
    let state = provider
        .latest()
        .map_err(|e| eyre::eyre!("failed to get latest state: {e}"))?;
    let reader = RethStateReader { state: &state };
    let mut provider = ReadOnlyStorageProvider::new(reader);
    let storage = StorageHandle::new(&mut provider);
    let update = outbe_update::schema::Update::new(storage);
    let mut scheduled = Vec::new();
    for proposal_id in update.list_waiting_for_activation_proposal_ids()? {
        if let Some(record) = update.read_scheduled_update(proposal_id)? {
            scheduled.push(record);
        }
    }
    Ok(scheduled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Signer as _, Verifier as _};
    use commonware_math::algebra::Random;
    use outbe_primitives::consensus_p2p::{encode_v1, P2pAddress, P2P_ADDRESS_VERSION_V1};
    use outbe_primitives::storage::{
        hashmap::HashMapStorageProvider, readonly::ReadOnlyBlockContext, StorageHandle,
    };
    use outbe_primitives::tee_attestation_v1::NodeIdV1;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const OWNER: Address = Address::repeat_byte(0xA0);

    fn valid_consensus_pubkey(seed: u8) -> [u8; 48] {
        let key = bls12381::PrivateKey::from_seed(seed as u64);
        let encoded = key.public_key().encode();
        let mut out = [0u8; 48];
        out.copy_from_slice(&encoded[..48]);
        out
    }

    /// Test implementation of [`RethStateAccess`] backed by a raw storage map.
    struct TestStateAccess {
        data: HashMap<(Address, U256), U256>,
    }

    impl RethStateAccess for TestStateAccess {
        fn storage_read(&self, address: Address, key: B256) -> Result<Option<U256>> {
            let key_u256 = U256::from_be_bytes(key.0);
            Ok(self.data.get(&(address, key_u256)).copied())
        }
    }

    fn populated_p2p_state(
        p2p_writer: impl FnOnce(&mut outbe_validatorset::contract::ValidatorSet<'_>, Address),
    ) -> TestStateAccess {
        let validator = Address::with_last_byte(0x11);
        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_owner.write(OWNER).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.register_validator(OWNER, validator, &valid_consensus_pubkey(11))
                .unwrap();
            vs.activate_validator_via_boundary_for_test(validator)
                .unwrap();
            p2p_writer(&mut vs, validator);
        });
        TestStateAccess {
            data: provider.storage.clone(),
        }
    }

    fn tee_expiry_state_with_leases(valid_until: [u64; 4]) -> (TestStateAccess, Vec<Address>) {
        let validators = vec![
            Address::with_last_byte(0x21),
            Address::with_last_byte(0x22),
            Address::with_last_byte(0x23),
            Address::with_last_byte(0x24),
        ];
        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            vs.set_config_max_validators(128).unwrap();
            let registry = outbe_teeregistry::TeeRegistry::new(storage);

            for (index, (&validator, &lease_end)) in
                validators.iter().zip(valid_until.iter()).enumerate()
            {
                let consensus_pubkey = valid_consensus_pubkey((index + 1) as u8);
                vs.register_validator(OWNER, validator, &consensus_pubkey)
                    .unwrap();
                vs.activate_validator_via_boundary_for_test(validator)
                    .unwrap();

                let node_hash = NodeIdV1 {
                    reth_p2p_public: k256::ecdsa::SigningKey::from_bytes(
                        (&outbe_primitives::test_keys::secret(((index + 1) as u8) as u64)).into(),
                    )
                    .unwrap()
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                }
                .node_id_hash()
                .unwrap();
                registry
                    .validator_v1_node_hash
                    .write(&validator, node_hash)
                    .unwrap();
                registry
                    .v1_node_enclave_id
                    .write(&node_hash, B256::with_last_byte((index + 1) as u8))
                    .unwrap();
                registry
                    .v1_node_binding_id
                    .write(&node_hash, B256::with_last_byte((index + 11) as u8))
                    .unwrap();
                registry
                    .v1_node_intent_hash
                    .write(&node_hash, B256::with_last_byte((index + 21) as u8))
                    .unwrap();
                registry
                    .v1_node_valid_until
                    .write(&node_hash, lease_end)
                    .unwrap();
            }
        });
        (
            TestStateAccess {
                data: provider.storage.clone(),
            },
            validators,
        )
    }

    fn tee_expiry_state(freeze_timestamp: u64) -> (TestStateAccess, Vec<Address>) {
        tee_expiry_state_with_leases([
            freeze_timestamp.saturating_sub(1),
            freeze_timestamp,
            freeze_timestamp.saturating_add(1),
            freeze_timestamp.saturating_add(500),
        ])
    }

    #[test]
    fn frozen_target_uses_validator_lifecycle_and_emits_empty_tee_compatibility_list() {
        let freeze_timestamp = 1_800_000_000;
        let (access, validators) = tee_expiry_state(freeze_timestamp);
        let frozen = read_reshare_target_with_empty_tee_exclusions_from_state(&access).unwrap();

        assert_eq!(frozen.validator_set.addresses, validators);
        assert!(frozen.tee_expired_target_exclusions.is_empty());
    }

    fn tee_runtime_admission_state(valid_until: u64) -> (TestStateAccess, [u8; 33], Address, B256) {
        let validator = Address::with_last_byte(0x31);
        let reth_p2p_public: [u8; 33] = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0x31)).into(),
        )
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
        let node_hash = NodeIdV1 { reth_p2p_public }.node_id_hash().unwrap();
        let enclave_id = B256::repeat_byte(0x32);
        let mut provider = HashMapStorageProvider::new(1);
        provider.set_block_number(9);
        StorageHandle::enter(&mut provider, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.register_validator(OWNER, validator, &valid_consensus_pubkey(0x31))
                .unwrap();
            vs.activate_validator_via_boundary_for_test(validator)
                .unwrap();

            let registry = outbe_teeregistry::TeeRegistry::new(storage);
            registry
                .validator_v1_node_hash
                .write(&validator, node_hash)
                .unwrap();
            registry
                .v1_node_enclave_id
                .write(&node_hash, enclave_id)
                .unwrap();
            registry
                .v1_node_binding_id
                .write(&node_hash, B256::repeat_byte(0x33))
                .unwrap();
            registry
                .v1_node_intent_hash
                .write(&node_hash, B256::repeat_byte(0x34))
                .unwrap();
            registry
                .v1_node_valid_until
                .write(&node_hash, valid_until)
                .unwrap();
        });
        (
            TestStateAccess {
                data: provider.storage.clone(),
            },
            reth_p2p_public,
            validator,
            enclave_id,
        )
    }

    #[test]
    fn finalized_runtime_admission_requires_exact_live_local_binding() {
        let deadline = 1_800_001_000;
        let (access, reth_p2p_public, validator, enclave_id) =
            tee_runtime_admission_state(deadline);
        let identity = LocalTeeRuntimeIdentityV1 {
            reth_p2p_public,
            expected_enclave_id: Some(enclave_id),
            validator: Some(validator),
        };

        assert_eq!(
            read_local_tee_runtime_admission_from_state(
                &access,
                ReadOnlyBlockContext {
                    chain_id: 1,
                    genesis_hash: B256::repeat_byte(0x41),
                    block_number: 9,
                    timestamp: deadline - 1,
                },
                identity,
            )
            .unwrap(),
            LocalTeeRuntimeAdmissionV1::Ready {
                valid_until: deadline
            }
        );

        assert_eq!(
            read_local_tee_runtime_admission_from_state(
                &access,
                ReadOnlyBlockContext {
                    chain_id: 1,
                    genesis_hash: B256::repeat_byte(0x41),
                    block_number: 9,
                    timestamp: deadline,
                },
                identity,
            )
            .unwrap(),
            LocalTeeRuntimeAdmissionV1::Rejected(LocalTeeRuntimeRejectionV1::Expired {
                valid_until: deadline
            })
        );

        let wrong_enclave = LocalTeeRuntimeIdentityV1 {
            expected_enclave_id: Some(B256::repeat_byte(0xFF)),
            ..identity
        };
        assert_eq!(
            read_local_tee_runtime_admission_from_state(
                &access,
                ReadOnlyBlockContext {
                    chain_id: 1,
                    genesis_hash: B256::repeat_byte(0x41),
                    block_number: 9,
                    timestamp: deadline - 1,
                },
                wrong_enclave,
            )
            .unwrap(),
            LocalTeeRuntimeAdmissionV1::Rejected(
                LocalTeeRuntimeRejectionV1::EnclaveIdentityMismatch
            )
        );
    }

    #[test]
    fn finalized_runtime_admission_rejects_jailed_validator_with_live_lease() {
        let deadline = 1_800_001_000;
        let (mut access, reth_p2p_public, validator, enclave_id) =
            tee_runtime_admission_state(deadline);
        let mut provider = HashMapStorageProvider::new(1);
        provider.set_block_number(10);
        provider.storage = access.data;
        StorageHandle::enter(&mut provider, |storage| {
            outbe_validatorset::contract::ValidatorSet::new(storage)
                .jail_validator_for_tee_expiry(validator)
                .unwrap();
        });
        access = TestStateAccess {
            data: provider.storage.clone(),
        };

        let admission = read_local_tee_runtime_admission_from_state(
            &access,
            ReadOnlyBlockContext {
                chain_id: 1,
                genesis_hash: B256::repeat_byte(0x41),
                block_number: 10,
                timestamp: deadline - 1,
            },
            LocalTeeRuntimeIdentityV1 {
                reth_p2p_public,
                expected_enclave_id: Some(enclave_id),
                validator: Some(validator),
            },
        )
        .unwrap();
        assert_eq!(
            admission,
            LocalTeeRuntimeAdmissionV1::Rejected(LocalTeeRuntimeRejectionV1::ValidatorJailed)
        );
    }

    #[test]
    fn only_block_one_validator_may_wait_for_bootstrap_binding() {
        let access = TestStateAccess {
            data: HashMap::new(),
        };
        let validator = Address::with_last_byte(0x41);
        let identity = LocalTeeRuntimeIdentityV1 {
            reth_p2p_public: [0x02; 33],
            expected_enclave_id: None,
            validator: Some(validator),
        };
        let context = |block_number| ReadOnlyBlockContext {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x42),
            block_number,
            timestamp: 100,
        };

        assert_eq!(
            read_local_tee_runtime_admission_from_state(&access, context(1), identity).unwrap(),
            LocalTeeRuntimeAdmissionV1::BootstrapPending
        );
        assert_eq!(
            read_local_tee_runtime_admission_from_state(
                &access,
                context(1),
                LocalTeeRuntimeIdentityV1 {
                    validator: None,
                    ..identity
                },
            )
            .unwrap(),
            LocalTeeRuntimeAdmissionV1::Rejected(LocalTeeRuntimeRejectionV1::MissingBinding)
        );
        assert_eq!(
            read_local_tee_runtime_admission_from_state(&access, context(2), identity).unwrap(),
            LocalTeeRuntimeAdmissionV1::Rejected(LocalTeeRuntimeRejectionV1::MissingBinding)
        );
    }

    #[test]
    fn test_read_validators_from_state_empty() {
        let mut provider = HashMapStorageProvider::new(1);

        StorageHandle::enter(&mut provider, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_is_initialized.write(true).unwrap();
            vs.set_config_max_validators(128).unwrap();
        });

        let access = TestStateAccess {
            data: provider.storage.clone(),
        };
        let result = read_validators_from_state(&access).unwrap();
        assert!(result.public_keys.is_empty());
        assert!(result.addresses.is_empty());
    }

    #[test]
    fn test_read_consensus_validators_includes_exiting_with_share() {
        let mut provider = HashMapStorageProvider::new(1);
        provider.set_block_number(1);
        let active = Address::with_last_byte(0x01);
        let exiting = Address::with_last_byte(0x02);

        StorageHandle::enter(&mut provider, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_owner.write(OWNER).unwrap();
            vs.config_is_initialized.write(true).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.register_validator(OWNER, active, &valid_consensus_pubkey(1))
                .unwrap();
            vs.register_validator(OWNER, exiting, &valid_consensus_pubkey(2))
                .unwrap();
            vs.activate_validator_via_boundary_for_test(active).unwrap();
            vs.activate_validator_via_boundary_for_test(exiting)
                .unwrap();
            vs.deactivate_validator(OWNER, exiting).unwrap();
        });

        let access = TestStateAccess {
            data: provider.storage.clone(),
        };

        let active_only = read_validators_from_state(&access).unwrap();
        assert_eq!(active_only.addresses, vec![active]);

        let consensus = read_consensus_validators_from_state(&access).unwrap();
        assert_eq!(consensus.addresses, vec![active, exiting]);
    }

    #[test]
    fn test_read_validators_from_state_decodes_registry_p2p_address() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 30400);
        let encoded = encode_v1(&P2pAddress::Symmetric(socket));
        let access = populated_p2p_state(|vs, validator| {
            vs.set_p2p_address(validator, validator, P2P_ADDRESS_VERSION_V1, &encoded)
                .unwrap();
        });

        let validators = read_validators_from_state(&access).unwrap();
        assert_eq!(
            validators.p2p_addresses,
            vec![ValidatorP2pAddress::Known(CommonwareAddress::Symmetric(
                socket
            ))]
        );
    }

    #[test]
    fn test_read_validators_from_state_marks_invalid_registry_entry() {
        let access = populated_p2p_state(|vs, validator| {
            vs.test_corrupt_p2p_storage(validator, 99, &[0]).unwrap();
        });

        let validators = read_validators_from_state(&access).unwrap();
        assert_eq!(validators.p2p_addresses, vec![ValidatorP2pAddress::Invalid]);
    }

    #[test]
    fn test_load_signing_key_roundtrip() {
        let key = bls12381::PrivateKey::random(rand_core::OsRng);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        outbe_consensus::bls::save_individual_key(
            tmp.path(),
            &key,
            &outbe_consensus::bls::KeyBackend::Plaintext,
        )
        .unwrap();

        let loaded =
            load_signing_key(tmp.path(), &outbe_consensus::bls::KeyBackend::Plaintext).unwrap();
        assert_eq!(key, loaded);

        // Verify the loaded key works
        let sig = loaded.sign(b"test", b"msg");
        let pk = loaded.public_key();
        assert!(pk.verify(b"test", b"msg", &sig));
    }

    #[test]
    fn test_has_pending_set_change_false_by_default() {
        let mut provider = HashMapStorageProvider::new(1);

        StorageHandle::enter(&mut provider, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_is_initialized.write(true).unwrap();
            vs.set_config_max_validators(128).unwrap();
        });

        let access = TestStateAccess {
            data: provider.storage.clone(),
        };
        let result = has_pending_set_change(&access).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_has_pending_set_change_true_when_set() {
        let mut provider = HashMapStorageProvider::new(1);

        StorageHandle::enter(&mut provider, |storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            vs.config_is_initialized.write(true).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.test_set_pending_set_change(true).unwrap();
        });

        let access = TestStateAccess {
            data: provider.storage.clone(),
        };
        let result = has_pending_set_change(&access).unwrap();
        assert!(result);
    }
}
