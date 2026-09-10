use alloy_primitives::{Address, B256, U256};
use outbe_macros::contract;
use outbe_primitives::addresses::VALIDATOR_SET_ADDRESS;
use outbe_primitives::storage::types::{Mapping, Slot, StorageBytes};

/// EVM storage layout for the ValidatorSet precompile.
///
/// Storage slots:
///   0:  config_owner            - Address
///   1:  config_max_validators   - u32
///   2:  config_epoch_length_blocks - u32
///   3:  config_min_stake        - U256  [deprecated; Staking is the source of truth]
///   4:  config_is_initialized   - bool
///   5:  val_consensus_pubkey_lo - mapping(address => bytes32)  [BLS MinPk pubkey bytes 0..32]
///   6:  val_consensus_pubkey_hi - mapping(address => bytes32)  [BLS MinPk pubkey bytes 32..48, right-padded]
///   7:  val_stake               - mapping(address => uint256)
///   8:  val_status              - mapping(address => uint8)
///   9:  val_slash_count         - mapping(address => uint64)
///   10: val_missed_blocks       - mapping(address => uint64)
///   11: val_missed_votes        - mapping(address => uint64)
///   12: val_blocks_proposed     - mapping(address => uint64)
///   13: val_joined_at_height    - mapping(address => uint64)
///   14: val_deactivated_at_height - mapping(address => uint64)
///   15: val_unbonding_end       - mapping(address => uint64)
///   16: address_to_index        - mapping(address => uint64)  [1-indexed]
///   17: index_to_address        - mapping(uint64 => address)
///   18: consensus_pubkey_hash_to_address - mapping(bytes32 => address)  [keccak256(48-byte pubkey)]
///   19: _reserved_slot_19       - mapping(bytes32 => address)  [unused, was bls_pubkey_to_address]
///   20: validator_count         - u32
///   21: epoch_number            - U256
///   22: epoch_start_timestamp   - u64
///   23: epoch_start_block       - u64
///   24: val_has_bls_share       - mapping(address => bool)
///   25: pending_set_change      - bool
///   26: active_consensus_set_hash - B256
///   27: config_reregistration_cooldown - u32
///   28: val_p2p_address_version - mapping(address => uint8)
///   29: val_p2p_address_payload - mapping(address => bytes)
///   30: finalized_participation_recorded - mapping(B256 => bool),
///       idempotency guard for `record_finalized_participation` - keyed by
///       the finalized block hash, set on first successful record so
///       replays of the same metadata-tx are no-ops.
///   31: committee_snapshot_exists                  - mapping(B256 => bool)
///       gates every snapshot read on a fully-written record. Keyed by the
///       canonical `snapshot_key`.
///   32: committee_snapshot_len                     - mapping(B256 => u64)
///       length of the ordered committee at `snapshot_key`.
///   33: committee_snapshot_address_at              - mapping(B256 => mapping(u64 => Address))
///       i-th validator address in canonical Commonware public-key order.
///   34: committee_snapshot_pubkey_lo_at            - mapping(B256 => mapping(u64 => B256))
///       i-th BLS MinPk consensus pubkey bytes 0..32.
///   35: committee_snapshot_pubkey_hi_at            - mapping(B256 => mapping(u64 => B256))
///       i-th BLS MinPk consensus pubkey bytes 32..48 right-padded with zeros.
///   36: committee_snapshot_vrf_material_version    - mapping(B256 => u64)
///       VRF material version active when this snapshot was committed.
///   37: committee_snapshot_vrf_group_public_key_hash - mapping(B256 => B256)
///       `keccak256(commonware_codec::Encode(polynomial.public()))` of the
///       VRF group public key, matching the metadata `vrf_group_public_key_hash`.
///   38: committee_snapshot_vrf_group_public_key_len  - mapping(B256 => u64)
///       length in bytes of the encoded VRF group public key (so the reader
///       can trim the last 32-byte chunk).
///   39: committee_snapshot_vrf_group_public_key_chunk_at - mapping(B256 => mapping(u64 => B256))
///       32-byte chunks of `commonware_codec::Encode(polynomial.public())`.
///       Last chunk is right-padded with zeros;.
///   40: _reserved_committee_snapshot_slot_40       - Slot<B256>
///       reserved for future snapshot pruning metadata; must remain zero in
///       genesis V2.
///   41: val_join_confirmed       - mapping(address => bool)
///       stale-join activation guard; set by `confirmValidatorReady()` once a
///       PENDING joiner's node has caught up to head, gating its inclusion in
///       the DKG reshare target.
///   42: config_unjail_cooldown_blocks - u64 (default 0)
///       blocks a JAILED validator must wait before `unjailValidator()`.
///   43: val_jailed_at_height     - mapping(address => uint64)
///       block height the validator was JAILED; drives the unjail cooldown.
///   44: committee_snapshot_key_ring - mapping(u64 => bytes32)
///       prune ring bounding the committee-snapshot store (slots 31..40).
///   45: finalized_participation_ring - mapping(u64 => bytes32)
///       prune ring bounding the participation guard (slot 30).
///   46: finalized_participation_ring_seq - u64
///       monotonic index counter for slot 45.
///   47: committee_snapshot_vrf_public_polynomial_hash - mapping(B256 => B256)
///   48: delegate_by_validator_role - mapping(address => mapping(uint8 => address))
///       explicit operational key selected by a validator for one protocol role.
///   49: validator_by_role_delegate - mapping(uint8 => mapping(address => address))
///       reverse role-scoped lookup used by protocol consumers and ZeroFee.
///   50: val_ocomp_registration - mapping(address => bytes)
///       canonical `OcompKeyRegistrationV1` accepted by `confirmValidatorReady`.
///   51: ocomp_key_hash_to_validator - mapping(bytes32 => address)
///       reverse reservation keyed by `keccak256(compressed SEC1 OCOMP public key)`.
///   52: committee_snapshot_ocomp_epoch - mapping(bytes32 => uint64)
///   53: committee_snapshot_ocomp_consensus_hash - mapping(bytes32 => bytes32)
///   54: committee_snapshot_ocomp_binding_hash - mapping(bytes32 => bytes32)
///   55: committee_snapshot_ocomp_member_count - mapping(bytes32 => uint64)
///   56: committee_snapshot_ocomp_key_lo_at - mapping(bytes32 => mapping(uint64 => bytes32))
///   57: committee_snapshot_ocomp_key_hi_at - mapping(bytes32 => mapping(uint64 => bytes32))
///   58: committee_snapshot_ocomp_key_epoch_at - mapping(bytes32 => mapping(uint64 => uint64))
///   59: val_radicle_node_id - mapping(address => bytes32)
///       immutable Radicle transport identity bound during validator registration.
///   60: radicle_node_id_to_validator - mapping(bytes32 => address)
///       reverse uniqueness reservation for Radicle transport identities.
///   61: val_ocomp_miss_count - mapping(address => uint64)
///       cumulative number of missed OCOMP result votes.
///   62: val_ocomp_recovery_deadline - mapping(address => uint64)
///       fixed recovery deadline opened by the first miss; zero means closed.
#[contract(addr = VALIDATOR_SET_ADDRESS)]
pub struct ValidatorSet {
    // Config (slots 0-4)
    pub config_owner: Slot<Address>,
    pub config_max_validators: Slot<u32>,
    pub config_epoch_length_blocks: Slot<u32>,
    pub config_min_stake: Slot<U256>,
    pub config_is_initialized: Slot<bool>,

    // Per-validator fields keyed by Address (slots 5-15)
    /// BLS MinPk consensus public key - low 32 bytes (bytes[0..32]).
    pub(crate) val_consensus_pubkey_lo: Mapping<Address, B256>,
    /// BLS MinPk consensus public key - high 16 bytes (bytes[32..48]), right-padded with zeros.
    pub(crate) val_consensus_pubkey_hi: Mapping<Address, B256>,
    pub(crate) val_stake: Mapping<Address, U256>,
    pub(crate) val_status: Mapping<Address, u8>,
    pub(crate) val_slash_count: Mapping<Address, u64>,
    pub(crate) val_missed_blocks: Mapping<Address, u64>,
    pub(crate) val_missed_votes: Mapping<Address, u64>,
    pub(crate) val_blocks_proposed: Mapping<Address, u64>,
    pub(crate) val_joined_at_height: Mapping<Address, u64>,
    pub(crate) val_deactivated_at_height: Mapping<Address, u64>,
    pub(crate) val_unbonding_end: Mapping<Address, u64>,

    // Validator list - 1-indexed array pattern (slots 16-17)
    pub(crate) address_to_index: Mapping<Address, u64>,
    pub(crate) index_to_address: Mapping<u64, Address>,

    // Pubkey reverse lookup (slot 18) - keyed by keccak256(48-byte BLS MinPk pubkey)
    pub(crate) consensus_pubkey_hash_to_address: Mapping<B256, Address>,
    // Reserved (slot 19) - previously bls_pubkey_to_address
    pub _reserved_slot_19: Mapping<B256, Address>,

    // Counters + epoch (slots 20-23)
    pub(crate) validator_count: Slot<u32>,
    pub(crate) epoch_number: Slot<U256>,
    pub(crate) epoch_start_timestamp: Slot<u64>,
    pub(crate) epoch_start_block: Slot<u64>,

    // Consensus set tracking (slots 24-26)
    pub(crate) val_has_bls_share: Mapping<Address, bool>,
    pub(crate) pending_set_change: Slot<bool>,
    pub(crate) active_consensus_set_hash: Slot<B256>,

    // Re-registration cooldown (slot 27)
    // Number of blocks a validator must wait after deactivation before re-registering.
    // 0 = no cooldown.
    pub config_reregistration_cooldown: Slot<u32>,

    // Versioned Commonware P2P address registry (slots 28-29)
    pub(crate) val_p2p_address_version: Mapping<Address, u8>,
    pub(crate) val_p2p_address_payload: Mapping<Address, StorageBytes>,

    // Per-finalized-block idempotency guard for `record_finalized_participation`
    // (slot 30). Keyed by `metadata.finalized_block_hash`; set on first
    // successful record so replays do not double-increment `val_missed_votes`.
    pub finalized_participation_recorded: Mapping<B256, bool>,

    // V2 `CommitteeSnapshotStore` (slots 31..40).
    // Keyed by the canonical `snapshot_key =
    //   keccak256("OUTBE_COMMITTEE_SNAPSHOT_KEY_V2" || epoch_be_u64 || committee_set_hash)`.
    // Writes are field-by-field; `committee_snapshot_exists` is written LAST so
    // checkpoint-rolled-back transactions never leave a half-snapshot reachable.
    /// Slot 31 - existence flag, gates every read path on a fully-written record.
    pub committee_snapshot_exists: Mapping<B256, bool>,
    /// Slot 32 - length of the ordered committee.
    pub committee_snapshot_len: Mapping<B256, u64>,
    /// Slot 33 - `i`-th validator address in Commonware public-key order.
    pub committee_snapshot_address_at: Mapping<B256, Mapping<u64, Address>>,
    /// Slot 34 - BLS MinPk pubkey bytes 0..32 for entry `i`.
    pub committee_snapshot_pubkey_lo_at: Mapping<B256, Mapping<u64, B256>>,
    /// Slot 35 - BLS MinPk pubkey bytes 32..48, right-padded with zeros.
    pub committee_snapshot_pubkey_hi_at: Mapping<B256, Mapping<u64, B256>>,
    /// Slot 36 - `vrf_material_version` active when the snapshot was committed.
    pub committee_snapshot_vrf_material_version: Mapping<B256, u64>,
    /// Slot 37 - `keccak256(commonware_codec::Encode(polynomial.public()))`.
    pub committee_snapshot_vrf_group_public_key_hash: Mapping<B256, B256>,
    /// Slot 38 - length in bytes of the encoded VRF group public key.
    pub committee_snapshot_vrf_group_public_key_len: Mapping<B256, u64>,
    /// Slot 39 - 32-byte chunks of `commonware_codec::Encode(polynomial.public())`.
    /// Last chunk is right-padded with zeros; readers trim using slot-38 length.
    pub committee_snapshot_vrf_group_public_key_chunk_at: Mapping<B256, Mapping<u64, B256>>,
    /// Slot 40 - reserved for future snapshot pruning metadata. Genesis V2
    /// requires this to remain zero.
    pub _reserved_committee_snapshot_slot_40: Slot<B256>,

    /// Slot 41 - stale-join activation guard. A PENDING joiner is included in
    /// the DKG reshare target (and thus activated) only once it has confirmed,
    /// on-chain, that its node has caught up to head - set by
    /// `confirmValidatorReady()` (caller = the validator itself). Cleared when
    /// the validator leaves PENDING. Without this flag a behind/stale joiner
    /// would be frozen into the ceremony and flipped ACTIVE before it can vote.
    pub(crate) val_join_confirmed: Mapping<Address, bool>,

    /// Slot 42 - unjail cooldown in blocks. A JAILED validator may call
    /// `unjailValidator()` only once `block_number >= val_jailed_at_height +
    /// config_unjail_cooldown_blocks`. Default 0 (read via
    /// `unjail_cooldown_blocks()`): immediate unjail allowed, but the mechanism
    /// exists so a non-zero cooldown can be configured at genesis.
    pub config_unjail_cooldown_blocks: Slot<u64>,

    /// Slot 43 - block height at which a validator was JAILED (set by
    /// `jail_validator`). Drives the unjail cooldown check; meaningless unless
    /// the validator is currently JAILED.
    pub(crate) val_jailed_at_height: Mapping<Address, u64>,

    /// Slot 44 - committee-snapshot prune ring (`epoch % COMMITTEE_SNAPSHOT_RETAIN_EPOCHS
    /// -> snapshot_key`). `write_committee_snapshot` pushes each new key here and
    /// clears the snapshot it evicts, bounding the V2 `CommitteeSnapshotStore`
    /// (slots 31..40) to the last `COMMITTEE_SNAPSHOT_RETAIN_EPOCHS` epochs instead
    /// of growing one full committee per epoch forever. Safe because every reader
    /// only touches the current finalized epoch (+/- the K-block late-finalize
    /// window); see `state::write_committee_snapshot`.
    pub committee_snapshot_key_ring: Mapping<u64, B256>,

    /// Slot 45 - finalized-participation guard prune ring (`seq %
    /// FINALIZED_PARTICIPATION_RETAIN -> fb_hash`). Bounds slot 30
    /// (`finalized_participation_recorded`, one entry per finalized block) to the
    /// last `FINALIZED_PARTICIPATION_RETAIN` finalized blocks: recording a new
    /// block evicts the guard flag of the block `RETAIN` records ago. Safe because
    /// a finalized block older than the K-block late-finalize window can never be
    /// replayed.
    pub finalized_participation_ring: Mapping<u64, B256>,

    /// Slot 46 - monotonic counter for the slot-45 ring index (incremented once
    /// per distinct finalized block recorded).
    pub finalized_participation_ring_seq: Slot<u64>,

    /// Slot 47 - `keccak256(Encode(full public polynomial))` per committee
    /// snapshot, keyed by `snapshot_key` (same key as slots 31..40). Written by
    /// `write_committee_snapshot` and zeroed by `clear_committee_snapshot` so it
    /// is pruned in lockstep with the snapshot it belongs to. Lets SlashIndicator
    /// derive any signer's threshold pubkey to verify an invalid-seed-partial
    /// slash offense. `B256::ZERO` means no full polynomial was available.
    pub committee_snapshot_vrf_public_polynomial_hash: Mapping<B256, B256>,

    /// Slot 48 - validator-owned operational-key assignment, keyed first by the
    /// validator identity and then by a stable protocol role id.
    pub delegate_by_validator_role: Mapping<Address, Mapping<u8, Address>>,

    /// Slot 49 - reverse role-scoped operational-key lookup. The same delegate
    /// may serve different roles, but a `(role, delegate)` pair resolves to at
    /// most one validator.
    pub validator_by_role_delegate: Mapping<u8, Mapping<Address, Address>>,

    /// Slot 50 - canonical OCOMP key registration per validator. Registration
    /// validity is checked before the bytes become reachable or readiness is set.
    pub val_ocomp_registration: Mapping<Address, StorageBytes>,

    /// Slot 51 - unique ownership of a compressed SEC1 OCOMP key.
    pub ocomp_key_hash_to_validator: Mapping<B256, Address>,

    /// Slots 52..58 - OCOMP extension keyed by the unchanged consensus
    /// `committee_snapshot_key`. It is deliberately separate from
    /// `CommitteeEntry` and therefore cannot change `committee_set_hash_v2`.
    pub committee_snapshot_ocomp_epoch: Mapping<B256, u64>,
    pub committee_snapshot_ocomp_consensus_hash: Mapping<B256, B256>,
    pub committee_snapshot_ocomp_binding_hash: Mapping<B256, B256>,
    pub committee_snapshot_ocomp_member_count: Mapping<B256, u64>,
    pub committee_snapshot_ocomp_key_lo_at: Mapping<B256, Mapping<u64, B256>>,
    pub committee_snapshot_ocomp_key_hi_at: Mapping<B256, Mapping<u64, B256>>,
    pub committee_snapshot_ocomp_key_epoch_at: Mapping<B256, Mapping<u64, u64>>,

    /// Slot 59 - Radicle Ed25519 NodeId bound atomically during registration.
    pub val_radicle_node_id: Mapping<Address, B256>,

    /// Slot 60 - unique validator owner of a non-zero Radicle NodeId.
    pub radicle_node_id_to_validator: Mapping<B256, Address>,

    /// Slot 61 - cumulative OCOMP result-vote misses per validator.
    pub val_ocomp_miss_count: Mapping<Address, u64>,

    /// Slot 62 - fixed OCOMP recovery deadline. Zero means no open window.
    pub val_ocomp_recovery_deadline: Mapping<Address, u64>,
}
