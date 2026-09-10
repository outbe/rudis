//! OCM-FIN-001: independent finalized-intent proof vectors.
//!
//! The fixture constructs real Commonware q=3/4 finalization bytes and real
//! Ethereum account/storage MPT proofs. Verification crosses the production
//! `FinalizedIntentProofV1::verify` seam; no accepting verifier substitute is
//! used.
// OCOMP-TEST-ID: OCM-FIN-001

use std::collections::BTreeMap;

use alloy_consensus::Header;
use alloy_eips::{BlockHashOrNumber, BlockNumHash, BlockNumberOrTag};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Encodable as _;
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles, TrieAccount, KECCAK_EMPTY};
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::types::{Finalization, Proposal},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    bls12381::{
        primitives::{
            ops::{aggregate, keypair, sign_message},
            variant::{MinPk, MinSig, Variant},
        },
        PrivateKey, PublicKey,
    },
    certificate::Signers,
    sha256::Digest as Sha256Digest,
    Signer as _,
};
use commonware_utils::{ordered::Set, Participant};
use outbe_consensus::{
    block::ConsensusBlock,
    finalization::parent_cert_store::{
        CertifiedParentProofRecord, CertifiedParentProofStore, FinalizedParentCertStore, ProofKind,
    },
    hybrid::HybridScheme,
    proof::{
        constants::finalize_namespace, hybrid_seed_namespace, CommitteeEntry, CommitteeSnapshot,
        HybridCertificate, VrfProof,
    },
};
use outbe_metadosis::proof_layout::OCOMP_JOB_RECORDS_BASE_SLOT;
use outbe_node::ocomp::finality::{
    authenticate_snapshot_handoff, FinalizedIntentVerifier, RethFinalizedIntentProofBuilder,
    TrieHistoricalCommitteeAuthority,
};
use outbe_node::ocomp::retention::{
    CandidateFinalityV1, CandidatePinV1, FinalizedInputProofSource, RethFinalizedInputProofSource,
};
use outbe_ocomp_protocol::{
    codec::CodecLimits,
    common::{BoundedBytes, ProofBytes},
    control::{FinalizedIntentProofResponseV1, SnapshotHandoffV1},
    input::CheckpointIdentityV1,
    intent::{
        intent_storage_key, ActivationPreconditionsV1, AuctionEntryPriceSource,
        CertifiedParentAccountingMetadataV2, ContributorTargetPreconditionV1, DayType,
        ExpectedFinalizedIntentBindingV1, FinalizedIntentAuthorityError, FinalizedIntentProofV1,
        FinalizedIntentVerificationError, FrozenMetadosisValuesV1, JobIntentV1,
        MetadosisAttemptPreconditionV1, MetadosisExpectedStatus, NodTargetPreconditionV1,
        ParentProofKind, ReferenceEntryPriceV1, TributeInputBindingV1,
    },
    state::{OcompJobRecordV1, OcompJobStatus},
    SchemaLimits,
};
use outbe_primitives::{
    addresses::{METADOSIS_ADDRESS, VALIDATOR_SET_ADDRESS},
    header::OutbeHeader,
    storage::types::StorageKey as _,
    OutbeBlock, OutbeReceipt,
};
use rand::{rngs::StdRng, SeedableRng as _};
use reth_chainspec::ChainInfo;
use reth_primitives_traits::{Account, Bytecode, SealedBlock};
use reth_storage_api::{
    errors::provider::ProviderResult, AccountReader, BlockHashReader, BlockIdReader,
    BlockNumReader, BytecodeReader, HashedPostStateProvider, HeaderProvider, ReceiptProvider,
    StateProofProvider, StateProvider, StateProviderBox, StateProviderFactory, StateRootProvider,
    StorageRootProvider,
};
use reth_trie::updates::TrieUpdates;
use reth_trie::{
    AccountProof, HashedPostState, HashedStorage, KeccakKeyHasher, MultiProof, MultiProofTargets,
    StorageMultiProof, StorageProof, TrieInput,
};
use std::ops::{RangeBounds, RangeInclusive};

const LIMITS: SchemaLimits = SchemaLimits {
    codec: CodecLimits::new(1_048_576, 4_096, 2_097_152),
    max_bounded_bytes: 262_144,
    max_proof_bytes: 262_144,
    max_opening_bytes: 262_144,
    max_collection_items: 4_096,
    max_action_items: 4_096,
    max_chunk_items: 4_096,
    max_unit_inputs: 64,
    max_result_chunk_bytes: 524_288,
    max_control_body_bytes: 262_144,
};
const FINALIZED_BLOCK_NUMBER: u64 = 1;
const FINALIZED_EPOCH: u64 = 2;
const FINALIZED_VIEW: u64 = 3;
const PARENT_VIEW: u64 = 2;
const VRF_MATERIAL_VERSION: u64 = 5;

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn intent() -> JobIntentV1 {
    JobIntentV1 {
        chain_id: 42,
        genesis_hash: hash(1),
        fork_id: hash(2),
        wwd: 7,
        pending_nonce: 0,
        attempt: 0,
        protocol_bundle_hash: hash(3),
        ce_sealed_root: hash(4),
        sealed_tribute_collection_key: hash(5),
        sealed_tribute_collection_root: hash(6),
        authenticated_day_count: 0,
        authenticated_day_nominal: U256::ZERO,
        pre_admission_envelope_hash: hash(7),
        source_availability_policy_id: hash(8),
        frozen_metadosis_values: FrozenMetadosisValuesV1 {
            day_type: DayType::Green,
            day_limit: U256::from(1_000),
            previous_vwap: U256::from(90),
            current_vwap: U256::from(100),
            gratis_demand: U256::from(25),
            gratis_supply: U256::from(20),
            lysis_budget: U256::from(300),
            auction_base: U256::from(700),
            auction_entry_prices: vec![ReferenceEntryPriceV1 {
                reference_currency: 840,
                entry_price_minor: U256::from(95),
                source: AuctionEntryPriceSource::LastClosedDayVwap,
                source_day: 6,
            }],
            request_budget_split_receipt_hash: hash(9),
        },
        logical_evaluation_height: FINALIZED_BLOCK_NUMBER,
        logical_evaluation_time: 1_000,
        activation_preconditions: ActivationPreconditionsV1 {
            tribute: TributeInputBindingV1 {
                wwd: 7,
                source_generation: 1,
                collection_key: hash(5),
                sealed_collection_root: hash(6),
                exact_count: 0,
                exact_nominal_total: U256::ZERO,
            },
            nod: NodTargetPreconditionV1 {
                wwd: 7,
                target_generation: 1,
                namespace_root_before: hash(10),
                max_nod_count: 0,
            },
            contributors: ContributorTargetPreconditionV1 {
                worldwide_day: 7,
                expected_series_version: 1,
                max_contributor_count: 0,
                max_eligible_nominal_total: U256::ZERO,
            },
            metadosis: MetadosisAttemptPreconditionV1 {
                wwd: 7,
                pending_nonce: 0,
                expected_status: MetadosisExpectedStatus::OffchainPending,
                state_version: 1,
            },
        },
        result_validator_set_epoch: 1,
        result_committee_set_hash: hash(11),
        result_ocomp_binding_hash: hash(12),
        result_member_count: 4,
        result_quorum_threshold: 3,
        custody_committee_epoch_hash: None,
    }
}

struct Dkg {
    keys: Vec<PrivateKey>,
    vrf_group_public_key: <MinSig as Variant>::Public,
    vrf_threshold_private: commonware_cryptography::bls12381::primitives::group::Private,
}

fn build_dkg() -> Dkg {
    let keys = (1..=4).map(PrivateKey::from_seed).collect();
    let mut rng = StdRng::seed_from_u64(13);
    let (vrf_threshold_private, vrf_group_public_key) = keypair::<_, MinSig>(&mut rng);
    Dkg {
        keys,
        vrf_group_public_key,
        vrf_threshold_private,
    }
}

fn build_snapshot(dkg: &Dkg) -> CommitteeSnapshot {
    let committee = dkg
        .keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let encoded = key.public_key().encode();
            let mut consensus_pubkey = [0_u8; 48];
            consensus_pubkey.copy_from_slice(encoded.as_ref());
            CommitteeEntry {
                address: Address::with_last_byte((index + 1) as u8),
                consensus_pubkey,
            }
        })
        .collect();
    CommitteeSnapshot {
        committee,
        vrf_material_version: VRF_MATERIAL_VERSION,
        vrf_group_public_key_bytes: dkg.vrf_group_public_key.encode().to_vec(),
        vrf_public_polynomial_hash: B256::ZERO,
    }
}

fn proposal(header_hash: B256) -> Proposal<Sha256Digest> {
    Proposal::new(
        Round::new(Epoch::new(FINALIZED_EPOCH), View::new(FINALIZED_VIEW)),
        View::new(PARENT_VIEW),
        Sha256Digest(header_hash.0),
    )
}

fn finalization_bytes(dkg: &Dkg, signer_indices: &[u32], header_hash: B256) -> Vec<u8> {
    let proposal = proposal(header_hash);
    let committee = Set::<PublicKey>::from_iter_dedup(dkg.keys.iter().map(PrivateKey::public_key));
    let namespace = finalize_namespace(&committee);
    let vote_message = proposal.encode().to_vec();
    let signatures = signer_indices
        .iter()
        .map(|index| dkg.keys[*index as usize].sign(&namespace, &vote_message))
        .collect::<Vec<_>>();
    let bls_aggregated_vote =
        aggregate::combine_signatures::<MinPk, _>(signatures.iter().map(AsRef::as_ref));
    let seed_message = proposal.round.encode().to_vec();
    let threshold_signature = sign_message::<MinSig>(
        &dkg.vrf_threshold_private,
        &hybrid_seed_namespace(),
        &seed_message,
    );
    let certificate = HybridCertificate::<MinSig> {
        signers: Signers::from(
            dkg.keys.len(),
            signer_indices.iter().copied().map(Participant::new),
        ),
        bls_aggregated_vote,
        vrf_proof: VrfProof {
            material_version: VRF_MATERIAL_VERSION,
            threshold_signature,
        },
    };
    Finalization::<HybridScheme<MinSig>, Sha256Digest> {
        proposal,
        certificate,
    }
    .encode()
    .to_vec()
}

fn signer_bitmap(signer_indices: &[u32]) -> Vec<u8> {
    let mut bitmap = vec![0_u8; 4];
    for index in signer_indices {
        bitmap[*index as usize] = 1;
    }
    bitmap
}

fn independent_storage_slots(logical_key: B256, encoded_record: &[u8]) -> Vec<(U256, U256)> {
    let base = logical_key.mapping_slot(U256::from(OCOMP_JOB_RECORDS_BASE_SLOT));
    if encoded_record.len() <= 31 {
        let mut inline = [0_u8; 32];
        inline[..encoded_record.len()].copy_from_slice(encoded_record);
        inline[31] = (encoded_record.len() * 2) as u8;
        return vec![(base, U256::from_be_bytes(inline))];
    }

    let mut slots = Vec::with_capacity(1 + encoded_record.len().div_ceil(32));
    slots.push((base, U256::from(encoded_record.len() * 2 + 1)));
    let data_base = U256::from_be_bytes(keccak256(base.to_be_bytes::<32>()).0);
    for (index, chunk) in encoded_record.chunks(32).enumerate() {
        let mut word = [0_u8; 32];
        word[..chunk.len()].copy_from_slice(chunk);
        slots.push((data_base + U256::from(index), U256::from_be_bytes(word)));
    }
    slots
}

fn storage_trie(slots: &[(U256, U256)]) -> (B256, Vec<Vec<Bytes>>) {
    let targets = slots
        .iter()
        .map(|(slot, _)| Nibbles::unpack(keccak256(slot.to_be_bytes::<32>())))
        .collect::<Vec<_>>();
    let mut leaves = BTreeMap::new();
    for ((_, word), target) in slots.iter().zip(&targets) {
        if !word.is_zero() {
            leaves.insert(*target, alloy_rlp::encode_fixed_size(word).to_vec());
        }
    }

    let mut builder =
        HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(targets.clone()));
    for (path, value) in leaves {
        builder.add_leaf(path, &value);
    }
    let root = builder.root();
    let retained = builder.take_proof_nodes();
    let proofs = targets
        .iter()
        .map(|target| {
            retained
                .matching_nodes_sorted(target)
                .into_iter()
                .map(|(_, node)| node)
                .collect()
        })
        .collect();
    (root, proofs)
}

fn account_trie(accounts: &[(Address, TrieAccount)]) -> (B256, BTreeMap<Address, Vec<Bytes>>) {
    let targets = accounts
        .iter()
        .map(|(address, _)| (*address, Nibbles::unpack(keccak256(address))))
        .collect::<BTreeMap<_, _>>();
    let retainer = ProofRetainer::from_iter(targets.values().copied());
    let mut builder = HashBuilder::default().with_proof_retainer(retainer);
    let mut leaves = accounts
        .iter()
        .map(|(address, account)| (targets[address], alloy_rlp::encode(*account)))
        .collect::<Vec<_>>();
    leaves.sort_by_key(|(path, _)| *path);
    for (path, value) in leaves {
        builder.add_leaf(path, &value);
    }
    let root = builder.root();
    let retained = builder.take_proof_nodes();
    let proofs = targets
        .into_iter()
        .map(|(address, target)| {
            let proof = retained
                .matching_nodes_sorted(&target)
                .into_iter()
                .map(|(_, node)| node)
                .collect();
            (address, proof)
        })
        .collect();
    (root, proofs)
}

fn push_nodes(encoded: &mut Vec<u8>, nodes: &[Bytes]) {
    encoded.extend_from_slice(
        &u32::try_from(nodes.len())
            .expect("vector node count fits u32")
            .to_be_bytes(),
    );
    for node in nodes {
        encoded.extend_from_slice(
            &u32::try_from(node.len())
                .expect("vector node length fits u32")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(node);
    }
}

fn account_witness(account: TrieAccount, nodes: &[Bytes]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"OAPI");
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(&account.nonce.to_be_bytes());
    encoded.extend_from_slice(&account.balance.to_be_bytes::<32>());
    encoded.extend_from_slice(account.storage_root.as_slice());
    encoded.extend_from_slice(account.code_hash.as_slice());
    push_nodes(&mut encoded, nodes);
    encoded
}

fn storage_witness(proofs: &[Vec<Bytes>]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"OSPI");
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(proofs.len())
            .expect("vector proof count fits u32")
            .to_be_bytes(),
    );
    for proof in proofs {
        push_nodes(&mut encoded, proof);
    }
    encoded
}

fn independent_snapshot_key(epoch: u64, committee_set_hash: B256) -> B256 {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"OUTBE_COMMITTEE_SNAPSHOT_KEY_V2");
    preimage.extend_from_slice(&epoch.to_be_bytes());
    preimage.extend_from_slice(committee_set_hash.as_slice());
    keccak256(preimage)
}

fn committee_storage_slots(
    snapshot: &CommitteeSnapshot,
    epoch: u64,
    committee_set_hash: B256,
) -> Vec<(U256, U256)> {
    let key = independent_snapshot_key(epoch, committee_set_hash);
    let mapped = |slot: u64| key.mapping_slot(U256::from(slot));
    let nested = |slot: u64, index: u64| index.mapping_slot(mapped(slot));
    let mut slots = vec![
        (mapped(31), U256::from(1)),
        (mapped(32), U256::from(snapshot.committee.len())),
    ];
    for (index, entry) in snapshot.committee.iter().enumerate() {
        let index = index as u64;
        let mut high = [0_u8; 32];
        high[..16].copy_from_slice(&entry.consensus_pubkey[32..]);
        slots.extend([
            (
                nested(33, index),
                U256::from_be_slice(entry.address.as_slice()),
            ),
            (
                nested(34, index),
                U256::from_be_bytes::<32>(entry.consensus_pubkey[..32].try_into().unwrap()),
            ),
            (nested(35, index), U256::from_be_bytes(high)),
        ]);
    }
    slots.extend([
        (mapped(36), U256::from(snapshot.vrf_material_version)),
        (
            mapped(37),
            U256::from_be_bytes(keccak256(&snapshot.vrf_group_public_key_bytes).0),
        ),
        (
            mapped(38),
            U256::from(snapshot.vrf_group_public_key_bytes.len()),
        ),
    ]);
    for (index, chunk) in snapshot.vrf_group_public_key_bytes.chunks(32).enumerate() {
        let mut word = [0_u8; 32];
        word[..chunk.len()].copy_from_slice(chunk);
        slots.push((nested(39, index as u64), U256::from_be_bytes(word)));
    }
    slots.push((
        mapped(47),
        U256::from_be_bytes(snapshot.vrf_public_polynomial_hash.0),
    ));
    slots
}

fn historical_committee_witness(
    snapshot: &CommitteeSnapshot,
    validator_account: TrieAccount,
    account_nodes: &[Bytes],
    storage_proofs: &[Vec<Bytes>],
) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"OCHI");
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(snapshot.committee.len())
            .expect("committee length fits u32")
            .to_be_bytes(),
    );
    for entry in &snapshot.committee {
        encoded.extend_from_slice(entry.address.as_slice());
        encoded.extend_from_slice(&entry.consensus_pubkey);
    }
    encoded.extend_from_slice(&snapshot.vrf_material_version.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(snapshot.vrf_group_public_key_bytes.len())
            .expect("VRF key length fits u32")
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&snapshot.vrf_group_public_key_bytes);
    encoded.extend_from_slice(snapshot.vrf_public_polynomial_hash.as_slice());

    let account = account_witness(validator_account, account_nodes);
    encoded.extend_from_slice(
        &u32::try_from(account.len())
            .expect("account witness length fits u32")
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&account);
    let storage = storage_witness(storage_proofs);
    encoded.extend_from_slice(
        &u32::try_from(storage.len())
            .expect("storage witness length fits u32")
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&storage);
    encoded
}

#[derive(Clone)]
struct FixtureStateProvider {
    state_root: B256,
    block_number: u64,
    block_hash: B256,
    accounts: BTreeMap<Address, Account>,
    storage: BTreeMap<(Address, B256), U256>,
    proofs: BTreeMap<Address, AccountProof>,
}

impl AccountReader for FixtureStateProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        Ok(self.accounts.get(address).copied())
    }
}

impl BlockHashReader for FixtureStateProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        Ok((number == self.block_number).then_some(self.block_hash))
    }

    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        Ok((start..end)
            .filter_map(|number| (number == self.block_number).then_some(self.block_hash))
            .collect())
    }
}

impl BytecodeReader for FixtureStateProvider {
    fn bytecode_by_hash(&self, _code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        Ok(None)
    }
}

impl StateRootProvider for FixtureStateProvider {
    fn state_root(&self, _hashed_state: HashedPostState) -> ProviderResult<B256> {
        Ok(self.state_root)
    }

    fn state_root_from_nodes(&self, _input: TrieInput) -> ProviderResult<B256> {
        Ok(self.state_root)
    }

    fn state_root_with_updates(
        &self,
        _hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Ok((self.state_root, TrieUpdates::default()))
    }

    fn state_root_from_nodes_with_updates(
        &self,
        _input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Ok((self.state_root, TrieUpdates::default()))
    }
}

impl StorageRootProvider for FixtureStateProvider {
    fn storage_root(
        &self,
        address: Address,
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        Ok(self
            .proofs
            .get(&address)
            .map_or(B256::ZERO, |proof| proof.storage_root))
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        let proof = self
            .proofs
            .get(&address)
            .and_then(|proof| proof.storage_proofs.iter().find(|proof| proof.key == slot))
            .cloned()
            .unwrap_or_else(|| StorageProof::new(slot));
        Ok(proof)
    }

    fn storage_multiproof(
        &self,
        _address: Address,
        _slots: &[B256],
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        Ok(StorageMultiProof::empty())
    }
}

impl StateProofProvider for FixtureStateProvider {
    fn proof(
        &self,
        _input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        let mut proof = self
            .proofs
            .get(&address)
            .cloned()
            .unwrap_or_else(|| AccountProof::new(address));
        proof.storage_proofs = slots
            .iter()
            .map(|slot| {
                proof
                    .storage_proofs
                    .iter()
                    .find(|storage| storage.key == *slot)
                    .cloned()
                    .unwrap_or_else(|| StorageProof::new(*slot))
            })
            .collect();
        Ok(proof)
    }

    fn multiproof(
        &self,
        _input: TrieInput,
        _targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        Ok(MultiProof::default())
    }

    fn witness(
        &self,
        _input: TrieInput,
        _target: HashedPostState,
        _mode: reth_trie::ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        Ok(Vec::new())
    }
}

impl HashedPostStateProvider for FixtureStateProvider {
    fn hashed_post_state(&self, bundle_state: &revm::database::BundleState) -> HashedPostState {
        HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle_state.state())
    }
}

impl StateProvider for FixtureStateProvider {
    fn storage(&self, account: Address, storage_key: B256) -> ProviderResult<Option<U256>> {
        Ok(self.storage.get(&(account, storage_key)).copied())
    }
}

#[derive(Clone)]
struct FixtureProvider {
    state: FixtureStateProvider,
    header: OutbeHeader,
}

impl BlockHashReader for FixtureProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.state.block_hash(number)
    }

    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        self.state.canonical_hashes_range(start, end)
    }
}

impl BlockNumReader for FixtureProvider {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        Ok(ChainInfo {
            best_hash: self.state.block_hash,
            best_number: self.state.block_number,
        })
    }

    fn best_block_number(&self) -> ProviderResult<u64> {
        Ok(self.state.block_number)
    }

    fn last_block_number(&self) -> ProviderResult<u64> {
        Ok(self.state.block_number)
    }

    fn block_number(&self, hash: B256) -> ProviderResult<Option<u64>> {
        Ok((hash == self.state.block_hash).then_some(self.state.block_number))
    }
}

impl BlockIdReader for FixtureProvider {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(self.chain_info()?.into()))
    }

    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(self.chain_info()?.into()))
    }

    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(self.chain_info()?.into()))
    }
}

impl HeaderProvider for FixtureProvider {
    type Header = OutbeHeader;

    fn header(&self, block_hash: B256) -> ProviderResult<Option<Self::Header>> {
        Ok((block_hash == self.state.block_hash).then(|| self.header.clone()))
    }

    fn header_by_number(&self, number: u64) -> ProviderResult<Option<Self::Header>> {
        Ok((number == self.state.block_number).then(|| self.header.clone()))
    }

    fn headers_range(&self, range: impl RangeBounds<u64>) -> ProviderResult<Vec<Self::Header>> {
        let contains = match (range.start_bound(), range.end_bound()) {
            (std::ops::Bound::Included(start), std::ops::Bound::Included(end)) => {
                *start <= self.state.block_number && self.state.block_number <= *end
            }
            (std::ops::Bound::Included(start), std::ops::Bound::Excluded(end)) => {
                *start <= self.state.block_number && self.state.block_number < *end
            }
            (std::ops::Bound::Excluded(start), std::ops::Bound::Included(end)) => {
                *start < self.state.block_number && self.state.block_number <= *end
            }
            (std::ops::Bound::Excluded(start), std::ops::Bound::Excluded(end)) => {
                *start < self.state.block_number && self.state.block_number < *end
            }
            (std::ops::Bound::Unbounded, std::ops::Bound::Included(end)) => {
                self.state.block_number <= *end
            }
            (std::ops::Bound::Unbounded, std::ops::Bound::Excluded(end)) => {
                self.state.block_number < *end
            }
            (std::ops::Bound::Included(start), std::ops::Bound::Unbounded) => {
                *start <= self.state.block_number
            }
            (std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded) => {
                *start < self.state.block_number
            }
            (std::ops::Bound::Unbounded, std::ops::Bound::Unbounded) => true,
        };
        Ok(contains.then(|| self.header.clone()).into_iter().collect())
    }

    fn sealed_header(
        &self,
        number: u64,
    ) -> ProviderResult<Option<reth_primitives_traits::SealedHeader<Self::Header>>> {
        Ok((number == self.state.block_number).then(|| {
            reth_primitives_traits::SealedHeader::new(self.header.clone(), self.state.block_hash)
        }))
    }

    fn sealed_headers_while(
        &self,
        range: impl RangeBounds<u64>,
        mut predicate: impl FnMut(&reth_primitives_traits::SealedHeader<Self::Header>) -> bool,
    ) -> ProviderResult<Vec<reth_primitives_traits::SealedHeader<Self::Header>>> {
        let headers = self.headers_range(range)?;
        let mut sealed = Vec::new();
        for header in headers {
            let header = reth_primitives_traits::SealedHeader::new(header, self.state.block_hash);
            if !predicate(&header) {
                break;
            }
            sealed.push(header);
        }
        Ok(sealed)
    }
}

impl ReceiptProvider for FixtureProvider {
    type Receipt = OutbeReceipt;

    fn receipt(&self, _id: u64) -> ProviderResult<Option<Self::Receipt>> {
        Ok(None)
    }

    fn receipt_by_hash(&self, _hash: B256) -> ProviderResult<Option<Self::Receipt>> {
        Ok(None)
    }

    fn receipts_by_block(
        &self,
        block: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<Self::Receipt>>> {
        let known = match block {
            BlockHashOrNumber::Hash(hash) => hash == self.state.block_hash,
            BlockHashOrNumber::Number(number) => number == self.state.block_number,
        };
        Ok(known.then(Vec::new))
    }

    fn receipts_by_tx_range(
        &self,
        _range: impl RangeBounds<u64>,
    ) -> ProviderResult<Vec<Self::Receipt>> {
        Ok(Vec::new())
    }

    fn receipts_by_block_range(
        &self,
        _block_range: RangeInclusive<u64>,
    ) -> ProviderResult<Vec<Vec<Self::Receipt>>> {
        Ok(Vec::new())
    }
}

impl StateProviderFactory for FixtureProvider {
    fn latest(&self) -> ProviderResult<StateProviderBox> {
        Ok(Box::new(self.state.clone()))
    }

    fn state_by_block_number_or_tag(
        &self,
        _number_or_tag: BlockNumberOrTag,
    ) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn history_by_block_number(&self, _block: u64) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn history_by_block_hash(&self, _block: B256) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn state_by_block_hash(&self, _block: B256) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn pending(&self) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn pending_state_by_hash(&self, _block_hash: B256) -> ProviderResult<Option<StateProviderBox>> {
        self.latest().map(Some)
    }

    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> {
        self.latest().map(Some)
    }
}

struct Fixture {
    intent: JobIntentV1,
    intent_id: B256,
    expected: ExpectedFinalizedIntentBindingV1,
    proof: FinalizedIntentProofV1,
    state_root: B256,
    header_hash: B256,
    block: ConsensusBlock,
    provider: FixtureProvider,
    finalization_record: CertifiedParentProofRecord,
}

impl Fixture {
    fn verify(
        &self,
        proof: &FinalizedIntentProofV1,
    ) -> Result<
        outbe_ocomp_protocol::intent::VerifiedFinalizedIntentV1,
        FinalizedIntentVerificationError,
    > {
        proof.verify(
            self.expected,
            &FinalizedIntentVerifier::new(TrieHistoricalCommitteeAuthority),
            &LIMITS,
        )
    }
}

fn fixture(signer_indices: &[u32]) -> Fixture {
    fixture_with_intent(signer_indices, intent())
}

fn fixture_with_intent(signer_indices: &[u32], intent: JobIntentV1) -> Fixture {
    let canonical_job_intent = intent.encode_canonical(&LIMITS).unwrap();
    let intent_id = intent.intent_id(&LIMITS).unwrap();
    let logical_key = intent_storage_key(intent_id).unwrap();
    let record = OcompJobRecordV1 {
        intent: intent.clone(),
        intent_height: intent.logical_evaluation_height,
        status: OcompJobStatus::AwaitingFinality,
        finalized: None,
        terminal: None,
    };
    let slots = independent_storage_slots(logical_key, &record.encode_canonical(&LIMITS).unwrap());
    let (intent_storage_root, intent_storage_proofs) = storage_trie(&slots);
    let intent_account = TrieAccount {
        nonce: 0,
        balance: U256::ZERO,
        storage_root: intent_storage_root,
        code_hash: KECCAK_EMPTY,
    };

    let dkg = build_dkg();
    let snapshot = build_snapshot(&dkg);
    let committee_set_hash = snapshot.committee_set_hash_v2(FINALIZED_EPOCH);
    let committee_slots = committee_storage_slots(&snapshot, FINALIZED_EPOCH, committee_set_hash);
    let (validator_storage_root, validator_storage_proofs) = storage_trie(&committee_slots);
    let validator_account = TrieAccount {
        nonce: 0,
        balance: U256::ZERO,
        storage_root: validator_storage_root,
        code_hash: KECCAK_EMPTY,
    };
    let (state_root, account_proofs) = account_trie(&[
        (METADOSIS_ADDRESS, intent_account),
        (VALIDATOR_SET_ADDRESS, validator_account),
    ]);
    let header = OutbeHeader::new(Header {
        number: FINALIZED_BLOCK_NUMBER,
        state_root,
        ..Header::default()
    });
    let mut canonical_header = Vec::new();
    header.encode(&mut canonical_header);
    let header_hash = keccak256(&canonical_header);
    let block = ConsensusBlock::from_sealed(SealedBlock::seal_slow(OutbeBlock {
        header: header.clone(),
        body: Default::default(),
    }));
    assert_eq!(block.block_hash(), header_hash);

    let finalization = finalization_bytes(&dkg, signer_indices, header_hash);
    let bitmap = signer_bitmap(signer_indices);
    let ordered_committee = snapshot
        .committee
        .iter()
        .map(|entry| entry.address)
        .collect::<Vec<_>>();
    let vrf_group_public_key_hash = keccak256(&snapshot.vrf_group_public_key_bytes);
    let finalization_record = CertifiedParentProofRecord {
        kind: ProofKind::Finalization {
            finalized_block_number: FINALIZED_BLOCK_NUMBER,
        },
        finalized_epoch: FINALIZED_EPOCH,
        finalized_view: FINALIZED_VIEW,
        parent_view: PARENT_VIEW,
        finalized_block_hash: header_hash,
        committee_set_hash,
        vrf_material_version: VRF_MATERIAL_VERSION,
        vrf_group_public_key_hash,
        ordered_committee: ordered_committee.clone(),
        signer_bitmap: bitmap.clone(),
        encoded_proof: Bytes::from(finalization.clone()),
        stored_at_height: FINALIZED_BLOCK_NUMBER,
        ..CertifiedParentProofRecord::default()
    };
    let parent_accounting = CertifiedParentAccountingMetadataV2 {
        finalized_block_number: FINALIZED_BLOCK_NUMBER,
        finalized_block_hash: header_hash,
        finalized_epoch: FINALIZED_EPOCH,
        finalized_view: FINALIZED_VIEW,
        parent_view: PARENT_VIEW,
        ordered_committee: ordered_committee
            .iter()
            .map(|address| BoundedBytes(address.as_slice().to_vec()))
            .collect(),
        signer_bitmap: BoundedBytes(bitmap),
        canonical_commonware_finalization_proof: ProofBytes(finalization),
        committee_set_hash,
        vrf_material_version: VRF_MATERIAL_VERSION as u16,
        vrf_group_public_key_hash,
        proof_kind: ParentProofKind::Finalization,
        missed_proposers: Vec::new(),
    };
    let proof = FinalizedIntentProofV1 {
        chain_id: intent.chain_id,
        genesis_hash: intent.genesis_hash,
        fork_id: intent.fork_id,
        protocol_bundle_hash: intent.protocol_bundle_hash,
        canonical_request_header_rlp: ProofBytes(canonical_header),
        parent_accounting,
        historical_committee_membership_proof: ProofBytes(historical_committee_witness(
            &snapshot,
            validator_account,
            &account_proofs[&VALIDATOR_SET_ADDRESS],
            &validator_storage_proofs,
        )),
        canonical_job_intent: BoundedBytes(canonical_job_intent),
        intent_account_proof: ProofBytes(account_witness(
            intent_account,
            &account_proofs[&METADOSIS_ADDRESS],
        )),
        intent_storage_proof: ProofBytes(storage_witness(&intent_storage_proofs)),
    };
    let account = |trie: TrieAccount| Account {
        nonce: trie.nonce,
        balance: trie.balance,
        // Reth represents an account with empty code as `None`; the production
        // proof builder must derive KECCAK_EMPTY through `Account::get_bytecode_hash`.
        bytecode_hash: None,
    };
    let storage_proofs = |slots: &[(U256, U256)], proofs: &[Vec<Bytes>]| {
        slots
            .iter()
            .zip(proofs)
            .map(|((slot, value), nodes)| {
                let key = B256::new(slot.to_be_bytes::<32>());
                StorageProof {
                    key,
                    value: *value,
                    ..StorageProof::new(key)
                }
                .with_proof(nodes.clone())
            })
            .collect::<Vec<_>>()
    };
    let mut accounts = BTreeMap::new();
    accounts.insert(METADOSIS_ADDRESS, account(intent_account));
    accounts.insert(VALIDATOR_SET_ADDRESS, account(validator_account));
    let mut storage = BTreeMap::new();
    storage.extend(slots.iter().map(|(slot, value)| {
        (
            (METADOSIS_ADDRESS, B256::new(slot.to_be_bytes::<32>())),
            *value,
        )
    }));
    storage.extend(committee_slots.iter().map(|(slot, value)| {
        (
            (VALIDATOR_SET_ADDRESS, B256::new(slot.to_be_bytes::<32>())),
            *value,
        )
    }));
    let mut proofs = BTreeMap::new();
    proofs.insert(
        METADOSIS_ADDRESS,
        AccountProof {
            address: METADOSIS_ADDRESS,
            info: Some(account(intent_account)),
            proof: account_proofs[&METADOSIS_ADDRESS].clone(),
            storage_root: intent_account.storage_root,
            storage_proofs: storage_proofs(&slots, &intent_storage_proofs),
        },
    );
    proofs.insert(
        VALIDATOR_SET_ADDRESS,
        AccountProof {
            address: VALIDATOR_SET_ADDRESS,
            info: Some(account(validator_account)),
            proof: account_proofs[&VALIDATOR_SET_ADDRESS].clone(),
            storage_root: validator_account.storage_root,
            storage_proofs: storage_proofs(&committee_slots, &validator_storage_proofs),
        },
    );
    let provider = FixtureProvider {
        state: FixtureStateProvider {
            state_root,
            block_number: FINALIZED_BLOCK_NUMBER,
            block_hash: header_hash,
            accounts,
            storage,
            proofs,
        },
        header,
    };
    Fixture {
        expected: ExpectedFinalizedIntentBindingV1 {
            chain_id: intent.chain_id,
            genesis_hash: intent.genesis_hash,
            fork_id: intent.fork_id,
            protocol_bundle_hash: intent.protocol_bundle_hash,
        },
        intent,
        intent_id,
        proof,
        state_root,
        header_hash,
        block,
        provider,
        finalization_record,
    }
}

fn flip_first_account_trie_node(witness: &mut [u8]) {
    let node_count = u32::from_be_bytes(witness[110..114].try_into().unwrap());
    assert!(node_count > 0, "account vector must contain a trie node");
    let node_len = u32::from_be_bytes(witness[114..118].try_into().unwrap()) as usize;
    assert!(node_len > 0, "account trie node must be non-empty");
    witness[118] ^= 1;
}

fn flip_first_storage_trie_node(witness: &mut [u8]) {
    let proof_count = u32::from_be_bytes(witness[6..10].try_into().unwrap());
    assert!(proof_count > 0, "storage vector must contain a proof");
    let node_count = u32::from_be_bytes(witness[10..14].try_into().unwrap());
    assert!(
        node_count > 0,
        "first storage proof must contain a trie node"
    );
    let node_len = u32::from_be_bytes(witness[14..18].try_into().unwrap()) as usize;
    assert!(node_len > 0, "storage trie node must be non-empty");
    witness[18] ^= 1;
}

fn historical_account_witness_range(witness: &[u8]) -> std::ops::Range<usize> {
    assert_eq!(&witness[..4], b"OCHI");
    let committee_len = u32::from_be_bytes(witness[6..10].try_into().unwrap()) as usize;
    let mut offset = 10 + committee_len * (20 + 48) + 8;
    let vrf_key_len = u32::from_be_bytes(witness[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4 + vrf_key_len + 32;
    let account_len = u32::from_be_bytes(witness[offset..offset + 4].try_into().unwrap()) as usize;
    let start = offset + 4;
    start..start + account_len
}

fn historical_storage_witness_range(witness: &[u8]) -> std::ops::Range<usize> {
    let account = historical_account_witness_range(witness);
    let offset = account.end;
    let storage_len = u32::from_be_bytes(witness[offset..offset + 4].try_into().unwrap()) as usize;
    let start = offset + 4;
    start..start + storage_len
}

#[test]
fn ocm_fin_001_four_validators_derive_same_job_from_real_q3_finality_and_mpt() {
    let fixture = fixture(&[0, 1, 2]);
    assert_eq!(
        fixture.proof.parent_accounting.signer_bitmap.0,
        [1, 1, 1, 0],
        "the happy vector must prove the PoC's exact q=3/4 quorum"
    );

    let mut job_ids = Vec::new();
    for _validator_domain in 0..4 {
        let verified = fixture
            .verify(&fixture.proof)
            .expect("real finalized header, q=3 certificate, and MPT proofs must verify");
        assert_eq!(verified.intent, fixture.intent);
        assert_eq!(verified.request.block_hash, fixture.header_hash);
        assert_eq!(verified.request.state_root, fixture.state_root);
        assert_eq!(
            verified.job_id,
            fixture
                .intent
                .job_id(fixture.header_hash, fixture.state_root, &LIMITS)
                .unwrap()
        );
        job_ids.push(verified.job_id);
    }
    assert!(job_ids.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn ocm_fin_001_exporter_derives_job_inputs_only_from_verified_handoff_proof() {
    let baseline = fixture(&[0, 1, 2]);
    let verified = baseline
        .verify(&baseline.proof)
        .expect("baseline finality proof");
    let response = FinalizedIntentProofResponseV1 {
        job_id: verified.job_id,
        canonical_proof: BoundedBytes(
            baseline
                .proof
                .encode_canonical(&LIMITS)
                .expect("canonical finalized proof"),
        ),
    };
    let handoff = SnapshotHandoffV1 {
        job_id: verified.job_id,
        input_lease_id: verified.intent.input_lease_id().expect("input lease id"),
        pin_generation: 1,
        lease_generation: 2,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: verified.request.block_number,
            finalized_block_hash: verified.request.block_hash,
            finalized_state_root: verified.request.state_root,
            finalized_ce_root: verified.intent.ce_sealed_root,
            ce_schema_version: 1,
        },
        canonical_lease_offer: BoundedBytes(vec![1]),
    };

    let authenticated =
        authenticate_snapshot_handoff(&handoff, &response, baseline.expected, &LIMITS)
            .expect("production exporter verifier closes every handoff binding");
    assert_eq!(authenticated, verified);

    let mut wrong_ce = handoff;
    wrong_ce.checkpoint.finalized_ce_root = hash(0xee);
    assert!(
        authenticate_snapshot_handoff(&wrong_ce, &response, baseline.expected, &LIMITS).is_err()
    );
}

#[test]
fn ocm_fin_001_production_builder_reconstructs_and_verifies_the_independent_vector() {
    let fixture = fixture(&[0, 1, 2]);
    let finalizations = FinalizedParentCertStore::new();
    finalizations
        .put_finalization(fixture.finalization_record.clone())
        .expect("persist exact Commonware finalization fixture");
    let builder =
        RethFinalizedIntentProofBuilder::new(fixture.provider.clone(), finalizations, LIMITS);

    let (built, verified) = builder
        .build_and_verify(&fixture.block, fixture.intent_id)
        .expect("production builder opens state, constructs MPT witnesses and self-verifies");

    assert_eq!(built, fixture.proof);
    assert_eq!(verified.intent_id, fixture.intent_id);
    assert_eq!(
        verified.job_id,
        fixture
            .intent
            .job_id(fixture.header_hash, fixture.state_root, &LIMITS)
            .expect("expected JobId")
    );
}

#[test]
fn ocm_fin_001_production_source_resolves_exact_finality_and_refuses_ambiguity() {
    let fixture = fixture(&[0, 1, 2]);
    let candidate = CandidatePinV1 {
        block_number: FINALIZED_BLOCK_NUMBER,
        block_hash: fixture.header_hash,
        state_root: fixture.state_root,
        intent_id: fixture.intent_id,
        wwd: fixture.intent.wwd,
        ce_sealed_root: fixture.intent.ce_sealed_root,
        protocol_bundle_hash: fixture.intent.protocol_bundle_hash,
        input_lease_id: fixture.intent.input_lease_id().expect("input lease id"),
    };
    let expected_job_id = fixture
        .intent
        .job_id(fixture.header_hash, fixture.state_root, &LIMITS)
        .expect("expected JobId");

    let exact_store = FinalizedParentCertStore::new();
    exact_store
        .put_finalization(fixture.finalization_record.clone())
        .expect("persist exact finalization");
    let exact_source =
        RethFinalizedInputProofSource::new(fixture.provider.clone(), exact_store, || Ok(None), 64);
    assert_eq!(
        exact_source
            .resolve_finality(candidate)
            .expect("exact persisted finality resolves"),
        CandidateFinalityV1::Finalized(outbe_node::ocomp::retention::FinalizedJobPinV1 {
            candidate,
            job_id: expected_job_id,
            finality_recorded_height: FINALIZED_BLOCK_NUMBER,
            open_height: FINALIZED_BLOCK_NUMBER + 4,
            deadline_height: FINALIZED_BLOCK_NUMBER + 4 + 64,
        })
    );

    let competing_store = FinalizedParentCertStore::new();
    let mut competing = fixture.finalization_record.clone();
    competing.finalized_block_hash = hash(0x99);
    competing_store
        .put_finalization(competing)
        .expect("persist competing finalization identity");
    let competing_source = RethFinalizedInputProofSource::new(
        fixture.provider.clone(),
        competing_store,
        || Ok(None),
        64,
    );
    assert_eq!(
        competing_source
            .resolve_finality(candidate)
            .expect("one exact competing finalization proves orphaning"),
        CandidateFinalityV1::Orphaned
    );

    let ambiguous_store = FinalizedParentCertStore::new();
    ambiguous_store
        .put_finalization(fixture.finalization_record.clone())
        .expect("persist first exact finalization");
    let mut duplicate = fixture.finalization_record.clone();
    duplicate.finalized_view += 1;
    ambiguous_store
        .put_finalization(duplicate)
        .expect("persist second exact-key variant");
    let ambiguous_source = RethFinalizedInputProofSource::new(
        fixture.provider.clone(),
        ambiguous_store,
        || Ok(None),
        64,
    );
    assert!(ambiguous_source.resolve_finality(candidate).is_err());
}

#[test]
fn ocm_fin_001_rejects_invented_historical_committee_values_and_paths() {
    let baseline = fixture(&[0, 1, 2]);

    let mut invented_member_key = baseline.proof.clone();
    invented_member_key.historical_committee_membership_proof.0[30] ^= 1;
    assert_eq!(
        baseline.verify(&invented_member_key),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::HistoricalCommittee,
        ))
    );

    let mut corrupt_validator_account = baseline.proof.clone();
    let account = historical_account_witness_range(
        &corrupt_validator_account
            .historical_committee_membership_proof
            .0,
    );
    flip_first_account_trie_node(
        &mut corrupt_validator_account
            .historical_committee_membership_proof
            .0[account],
    );
    assert_eq!(
        baseline.verify(&corrupt_validator_account),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::HistoricalCommittee,
        ))
    );

    let mut corrupt_validator_storage = baseline.proof.clone();
    let storage = historical_storage_witness_range(
        &corrupt_validator_storage
            .historical_committee_membership_proof
            .0,
    );
    flip_first_storage_trie_node(
        &mut corrupt_validator_storage
            .historical_committee_membership_proof
            .0[storage],
    );
    assert_eq!(
        baseline.verify(&corrupt_validator_storage),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::HistoricalCommittee,
        ))
    );
}

#[test]
fn ocm_fin_001_rejects_finality_committee_and_mpt_rebinding() {
    let baseline = fixture(&[0, 1, 2]);

    let mut wrong_request_state_root = baseline.proof.clone();
    let mut header = baseline.provider.header.clone();
    header.inner.state_root = hash(0x30);
    let mut canonical_header = Vec::new();
    header.encode(&mut canonical_header);
    wrong_request_state_root.canonical_request_header_rlp = ProofBytes(canonical_header);
    assert_eq!(
        baseline.verify(&wrong_request_state_root),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::CanonicalHeader,
        ))
    );

    let mut wrong_header_hash = baseline.proof.clone();
    wrong_header_hash.parent_accounting.finalized_block_hash = hash(0x31);
    assert_eq!(
        baseline.verify(&wrong_header_hash),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::CanonicalHeader,
        ))
    );

    let mut wrong_finalized_height = baseline.proof.clone();
    wrong_finalized_height
        .parent_accounting
        .finalized_block_number += 1;
    assert_eq!(
        baseline.verify(&wrong_finalized_height),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::CanonicalHeader,
        ))
    );

    let mut corrupt_finalization_certificate = baseline.proof.clone();
    let certificate = &mut corrupt_finalization_certificate
        .parent_accounting
        .canonical_commonware_finalization_proof
        .0;
    let last = certificate
        .last_mut()
        .expect("real finalization certificate is non-empty");
    *last ^= 1;
    assert_eq!(
        baseline.verify(&corrupt_finalization_certificate),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::ConsensusFinality,
        ))
    );

    let mut invented_committee = baseline.proof.clone();
    invented_committee.parent_accounting.ordered_committee[0] =
        BoundedBytes(Address::with_last_byte(0xfe).as_slice().to_vec());
    assert_eq!(
        baseline.verify(&invented_committee),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::ConsensusFinality,
        ))
    );

    let mut wrong_bitmap = baseline.proof.clone();
    wrong_bitmap.parent_accounting.signer_bitmap = BoundedBytes(vec![1, 1, 1, 1]);
    assert_eq!(
        baseline.verify(&wrong_bitmap),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::ConsensusFinality,
        ))
    );

    let below_quorum = fixture(&[0, 1]);
    assert_eq!(
        below_quorum.verify(&below_quorum.proof),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::ConsensusFinality,
        ))
    );

    let mut wrong_historical_opening = baseline.proof.clone();
    wrong_historical_opening
        .historical_committee_membership_proof
        .0[0] ^= 1;
    assert_eq!(
        baseline.verify(&wrong_historical_opening),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::HistoricalCommittee,
        ))
    );

    let mut corrupt_account_proof = baseline.proof.clone();
    flip_first_account_trie_node(&mut corrupt_account_proof.intent_account_proof.0);
    assert_eq!(
        baseline.verify(&corrupt_account_proof),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::IntentAccountProof,
        ))
    );

    let mut malformed_account_witness = baseline.proof.clone();
    malformed_account_witness.intent_account_proof.0[0] ^= 1;
    assert_eq!(
        baseline.verify(&malformed_account_witness),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::IntentAccountProof,
        ))
    );

    let mut corrupt_storage_proof = baseline.proof.clone();
    flip_first_storage_trie_node(&mut corrupt_storage_proof.intent_storage_proof.0);
    assert_eq!(
        baseline.verify(&corrupt_storage_proof),
        Err(FinalizedIntentVerificationError::Authority(
            FinalizedIntentAuthorityError::IntentStorageProof,
        ))
    );

    let mut wrong_chain = baseline.proof.clone();
    wrong_chain.chain_id += 1;
    assert_eq!(
        baseline.verify(&wrong_chain),
        Err(FinalizedIntentVerificationError::WrongChain)
    );

    let mut missed_proposer = baseline.proof.clone();
    missed_proposer
        .parent_accounting
        .missed_proposers
        .push(hash(0xaa));
    assert_eq!(
        baseline.verify(&missed_proposer),
        Err(FinalizedIntentVerificationError::NonEmptyMissedProposers)
    );
}
