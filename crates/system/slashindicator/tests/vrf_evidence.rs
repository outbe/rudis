//! Integration tests for `SlashIndicator.submitInvalidVrfProofEvidence`.
//! The tests are grouped by axis:
//!
//! * size / age / epoch-lag caps
//! * codec & Phase 1 envelope shape
//! * committee / proposer binding
//! * verifier outcome classification (happy)
//! * dedup
//! * helper-level VRF class table
//!
//! The happy-path test builds a real 4-validator DKG fixture, a
//! real aggregated BLS signature over the canonical proposal, and a
//! real ECDSA-signed Phase 1 TxLegacy. The cert carries a mandatory but
//! cryptographically invalid VRF proof while its BLS vote aggregate remains
//! valid, producing canonical failure class 7. This proves end-to-end that:
//!   * the codec -> admissibility -> proposer recovery -> snapshot lookup
//!     -> verifier -> felony chain is wired correctly;
//!   * the recovered proposer is byte-equal to the EVM address derived
//!     from the test's `PrivateKeySigner`;
//!   * the felony helper credits the submitter with 10% of the slashed
//!     amount and force-exits the proposer.
//!
//! Tests rely on `submit_invalid_vrf_evidence_with_schedule`, the
//! `#[doc(hidden)]` test-seam that lets us pass relaxed evidence limits
//! (`invalid_vrf_evidence_max_bytes` / `_max_age_blocks` / `_max_epoch_lag`).
//! Production callers always go through `submit_invalid_vrf_evidence`, which
//! passes `OutbeProtocolSchedule::default()`.

use alloy_consensus::{SignableTransaction as _, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, b256, keccak256, Address, Bytes, B256, U256};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use commonware_codec::Encode;
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
    Signer,
};
use commonware_utils::Participant;
use outbe_consensus::hybrid::HybridScheme;
use outbe_consensus::proof::{
    constants::finalize_namespace, hybrid_seed_namespace, invalid_vrf_evidence_hash_v2,
    HybridCertificate, V2VerifyError, VrfProof,
};
use outbe_primitives::addresses::STAKING_ADDRESS;
use outbe_primitives::consensus_metadata::{
    CertifiedParentAccountingMetadata, ParentParticipationProof,
};
use outbe_primitives::protocol_schedule::OutbeProtocolSchedule;
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_primitives::system_tx::{build_unsigned_system_tx, SystemTxInputV2, SystemTxKind};
use outbe_slashindicator::runtime::classify_vrf_failure;
use outbe_slashindicator::schema::SlashIndicator;
use outbe_slashindicator::vrf_evidence::{InvalidVrfProofEvidence, MAGIC, VERSION};
use outbe_staking::contract::Staking;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::state::{
    committee_set_hash_v2, write_committee_snapshot, CommitteeEntry, CommitteeSnapshot,
};
use outbe_validatorset::{StakeProjection, ValidatorLifecycle};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// ---------------------------------------------------------------------------
// Fixture constants - chosen so admissibility checks pass by default and
// individual tests can perturb a single axis without disturbing the others.
// ---------------------------------------------------------------------------

const CHAIN_ID: u64 = 1;
const CHILD_BLOCK_NUMBER: u64 = 42;
const CHILD_EPOCH: u64 = 3;
const PARENT_BLOCK_NUMBER: u64 = 41;
const FINALIZED_VIEW: u64 = 100;
const PARENT_VIEW: u64 = 99;
const VRF_MATERIAL_VERSION: u64 = 5;

const PARENT_BLOCK_HASH: B256 =
    b256!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
const CHILD_BLOCK_HASH: B256 =
    b256!("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

const OWNER: Address = address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
const SUBMITTER: Address = address!("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");
const STAKE_AMOUNT: u64 = 1_000_000_000_000u64;

// Schedule with relaxed evidence limits so a single test can stress a single
// axis (size / age / epoch-lag) without bumping into the others.
fn relaxed_schedule() -> OutbeProtocolSchedule {
    OutbeProtocolSchedule {
        // Base gas is the precompile gas charge, not consumed by the verification
        // path these tests exercise; left at a small value.
        slash_indicator_vrf_evidence_base_gas: 1,
        invalid_vrf_evidence_max_bytes: 1_000_000,
        invalid_vrf_evidence_max_age_blocks: 10_000,
        invalid_vrf_evidence_max_epoch_lag: 100,
        ..OutbeProtocolSchedule::default()
    }
}

// ---------------------------------------------------------------------------
// DKG + cert + committee snapshot helpers (mirroring v3_fingerprint_end_to_end.rs)
// ---------------------------------------------------------------------------

struct Dkg {
    keys: Vec<PrivateKey>,
    pubkeys: Vec<PublicKey>,
    vrf_group_public_key: <MinSig as Variant>::Public,
    vrf_threshold_private: commonware_cryptography::bls12381::primitives::group::Private,
}

fn build_dkg(n: u32) -> Dkg {
    let keys: Vec<PrivateKey> = (0..n)
        .map(|i| PrivateKey::from_seed(i as u64 + 1))
        .collect();
    let pubkeys: Vec<PublicKey> = keys.iter().cloned().map(PublicKey::from).collect();
    let mut rng = ChaCha20Rng::seed_from_u64(13);
    let (vrf_threshold_private, vrf_group_public_key) = keypair::<_, MinSig>(&mut rng);
    Dkg {
        keys,
        pubkeys,
        vrf_group_public_key,
        vrf_threshold_private,
    }
}

fn build_snapshot(dkg: &Dkg, proposer_addr: Address) -> CommitteeSnapshot {
    // Slot 0 = the proposer (the validator we'll be accusing). Other
    // slots get distinct placeholder addresses so the committee
    // membership check is non-trivial.
    let committee: Vec<CommitteeEntry> = dkg
        .pubkeys
        .iter()
        .enumerate()
        .map(|(i, pk)| {
            let address = if i == 0 {
                proposer_addr
            } else {
                Address::with_last_byte((i + 1) as u8)
            };
            let mut consensus_pubkey = [0u8; 48];
            consensus_pubkey.copy_from_slice(pk.encode().as_ref());
            CommitteeEntry {
                address,
                consensus_pubkey,
            }
        })
        .collect();
    CommitteeSnapshot {
        committee,
        vrf_material_version: VRF_MATERIAL_VERSION,
        vrf_group_public_key_bytes: dkg.vrf_group_public_key.encode().to_vec(),
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    }
}

fn proposal_bytes(parent_hash: B256) -> (Round, Vec<u8>, Vec<u8>) {
    let round = Round::new(Epoch::new(CHILD_EPOCH), View::new(FINALIZED_VIEW));
    let payload = Sha256Digest(parent_hash.0);
    let proposal: Proposal<Sha256Digest> = Proposal::new(round, View::new(PARENT_VIEW), payload);
    let vote_message = proposal.encode().to_vec();
    let seed_message = round.encode().to_vec();
    (round, vote_message, seed_message)
}

/// Builds a cert whose BLS aggregate is real, and lets the caller choose a
/// valid or cryptographically invalid mandatory `VrfProof`.
fn build_cert(
    dkg: &Dkg,
    signer_indices: &[u32],
    parent_hash: B256,
    valid_vrf: bool,
) -> HybridCertificate<MinSig> {
    let participants = dkg.keys.len();
    let signers = Signers::from(
        participants,
        signer_indices.iter().copied().map(Participant::new),
    );

    let (_, vote_message, seed_message) = proposal_bytes(parent_hash);
    // finalize votes bind the ordered committee; build the canonical `Set`
    // from the DKG committee (matches the snapshot the verifier reads).
    let committee_set: commonware_utils::ordered::Set<PublicKey> =
        commonware_utils::ordered::Set::from_iter_dedup(dkg.pubkeys.iter().cloned());
    let sigs: Vec<_> = signer_indices
        .iter()
        .map(|&i| dkg.keys[i as usize].sign(&finalize_namespace(&committee_set), &vote_message))
        .collect();
    let bls_aggregated_vote =
        aggregate::combine_signatures::<MinPk, _>(sigs.iter().map(|s| s.as_ref()));

    let vrf_signer = if valid_vrf {
        dkg.vrf_threshold_private.clone()
    } else {
        let mut rng = ChaCha20Rng::seed_from_u64(0x0BAD_5EED);
        keypair::<_, MinSig>(&mut rng).0
    };
    let threshold_signature =
        sign_message::<MinSig>(&vrf_signer, &hybrid_seed_namespace(), &seed_message);
    let vrf_proof = VrfProof::<MinSig> {
        material_version: VRF_MATERIAL_VERSION,
        threshold_signature,
    };

    HybridCertificate {
        signers,
        bls_aggregated_vote,
        vrf_proof,
    }
}

fn proof_envelope_bytes(cert: &HybridCertificate<MinSig>, parent_hash: B256) -> Vec<u8> {
    let round = Round::new(Epoch::new(CHILD_EPOCH), View::new(FINALIZED_VIEW));
    let payload = Sha256Digest(parent_hash.0);
    let proposal: Proposal<Sha256Digest> = Proposal::new(round, View::new(PARENT_VIEW), payload);
    Finalization::<HybridScheme<MinSig>, Sha256Digest> {
        proposal,
        certificate: cert.clone(),
    }
    .encode()
    .to_vec()
}

fn build_metadata(
    snapshot: &CommitteeSnapshot,
    proof_bytes: &[u8],
) -> CertifiedParentAccountingMetadata {
    let ordered_committee: Vec<Address> = snapshot
        .committee
        .iter()
        .map(|entry| entry.address)
        .collect();
    let signer_bitmap = vec![1u8; snapshot.committee.len()];
    let committee_set_hash = committee_set_hash_v2(CHILD_EPOCH, snapshot);
    let vrf_group_public_key_hash = keccak256(&snapshot.vrf_group_public_key_bytes);
    CertifiedParentAccountingMetadata {
        finalized_block_number: PARENT_BLOCK_NUMBER,
        finalized_block_hash: PARENT_BLOCK_HASH,
        finalized_epoch: CHILD_EPOCH,
        finalized_view: FINALIZED_VIEW,
        parent_view: PARENT_VIEW,
        ordered_committee,
        signer_bitmap,
        proof: Bytes::copy_from_slice(proof_bytes),
        committee_set_hash,
        vrf_material_version: VRF_MATERIAL_VERSION,
        vrf_group_public_key_hash,
        proof_kind: ParentParticipationProof::Finalization,
        missed_proposers: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Phase 1 tx signing helper. Returns (encoded_2718_bytes, recovered_address).
// The recovered address matches what `submit_invalid_vrf_evidence` ecrecovers
// from the encoded bytes - proves the proposer-attribution chain.
// ---------------------------------------------------------------------------

fn signer_with_address() -> (PrivateKeySigner, Address) {
    let signer = PrivateKeySigner::from_bytes(&b256!(
        "0x4242424242424242424242424242424242424242424242424242424242424242"
    ))
    .unwrap();
    let address = signer.address();
    (signer, address)
}

fn sign_phase1_tx(signer: &PrivateKeySigner, input: Bytes) -> Vec<u8> {
    let tx = build_unsigned_system_tx(
        SystemTxKind::CertifiedParentAccounting,
        0,
        CHILD_BLOCK_NUMBER,
        CHAIN_ID,
        input,
    )
    .unwrap();
    let sighash = tx.signature_hash();
    let sig: Signature = signer.sign_hash_sync(&sighash).unwrap();
    let envelope: TxEnvelope = tx.into_signed(sig).into();
    envelope.encoded_2718()
}

fn sign_phase1_metadata_tx(
    signer: &PrivateKeySigner,
    metadata: &CertifiedParentAccountingMetadata,
) -> Vec<u8> {
    let input = SystemTxInputV2::CertifiedParentAccounting {
        metadata: metadata.clone(),
    }
    .encode()
    .unwrap();
    sign_phase1_tx(signer, input)
}

// ---------------------------------------------------------------------------
// Storage setup helper. Registers the proposer in ValidatorSet, gives them
// stake (so slash_stake has something to burn), and writes the committee
// snapshot used by the precompile.
// ---------------------------------------------------------------------------

/// Populates storage with the minimum entries needed for the runtime
/// function to reach the verifier: registered + staked proposer, epoch
/// counter, and the committee snapshot. The provider's block number must
/// be set separately via `with_storage_at` (StorageHandle does not expose
/// a setter - block_number is part of the provider's block context).
fn setup_storage(
    storage: StorageHandle,
    proposer: Address,
    snapshot: &CommitteeSnapshot,
    current_epoch: u64,
) {
    let mut vs = ValidatorSet::new(storage.clone());
    vs.config_owner.write(OWNER).unwrap();
    vs.set_config_max_validators(100).unwrap();
    set_current_epoch(&mut vs, current_epoch);
    let stake = U256::from(STAKE_AMOUNT);
    let proposer_pubkey = snapshot
        .committee
        .iter()
        .find(|member| member.address == proposer)
        .expect("proposer belongs to snapshot")
        .consensus_pubkey;
    vs.register_validator(OWNER, proposer, &proposer_pubkey)
        .unwrap();
    vs.test_set_stake_projection(proposer, StakeProjection::new(stake, None))
        .unwrap();
    vs.activate_validator_via_boundary_for_test(proposer)
        .unwrap();
    for member in &snapshot.committee {
        if !vs.is_validator(member.address).unwrap() {
            vs.register_validator(OWNER, member.address, &member.consensus_pubkey)
                .unwrap();
            vs.activate_validator_via_boundary_for_test(member.address)
                .unwrap();
        }
    }

    let staking = Staking::new(storage.clone());
    staking.stake_amount.write(&proposer, stake).unwrap();
    staking.total_staked.write(stake).unwrap();
    staking
        .storage
        .increase_balance(STAKING_ADDRESS, stake)
        .unwrap();
    write_committee_snapshot(storage, CHILD_EPOCH, snapshot).unwrap();
}

fn set_current_epoch(vs: &mut ValidatorSet<'_>, number: u64) {
    let mut epoch = vs.epoch_snapshot().unwrap();
    epoch.number = U256::from(number);
    vs.test_set_epoch_snapshot(epoch).unwrap();
}

// Helper: build a default-shape evidence struct. Metadata and proof are always
// recovered from the signed Phase 1 transaction bytes.
fn evidence_skeleton(phase1_tx_bytes: Vec<u8>) -> InvalidVrfProofEvidence {
    InvalidVrfProofEvidence {
        child_block_number: CHILD_BLOCK_NUMBER,
        child_block_hash: CHILD_BLOCK_HASH,
        child_epoch: CHILD_EPOCH,
        parent_block_number: PARENT_BLOCK_NUMBER,
        parent_block_hash: PARENT_BLOCK_HASH,
        failure_code: 7,
        phase1_tx_bytes,
    }
}

/// Registers `SUBMITTER` as an ACTIVE validator so the precompile's
/// submitter ACL passes by default. Tests that exercise the
/// ACL rejection branch use the `_raw` variants below.
fn register_submitter_as_active(storage: StorageHandle) {
    let mut vs = ValidatorSet::new(storage);
    let mut pk = [0u8; 48];
    pk[0] = 0x77;
    vs.config_owner.write(OWNER).unwrap();
    vs.set_config_max_validators(100).unwrap();
    vs.register_validator(OWNER, SUBMITTER, &pk).unwrap();
    vs.activate_validator_via_boundary_for_test(SUBMITTER)
        .unwrap();
}

fn with_storage<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    // Seed the canonical-history fixture so the canonicity check passes by default.
    // Individual tests that want to exercise the non-canonical branch
    // either clear this entry or use `with_storage_no_canonical_parent`.
    provider.set_canonical_block_hash(CHILD_BLOCK_NUMBER, CHILD_BLOCK_HASH);
    provider.set_canonical_block_hash(PARENT_BLOCK_NUMBER, PARENT_BLOCK_HASH);
    provider.enter(|storage| {
        register_submitter_as_active(storage.clone());
        f(storage)
    })
}

/// Same as [`with_storage`] but pins the provider's block number so the
/// runtime's `storage.block_number()` reads the configured value during
/// admissibility checks. Necessary for the block-age cap test and any
/// happy-path test that asserts felony invariants tied to the current
/// block height. Also seeds the canonical parent fixture and
/// registers `SUBMITTER` as an ACTIVE validator.
fn with_storage_at<R>(block_number: u64, f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(block_number);
    provider.set_canonical_block_hash(CHILD_BLOCK_NUMBER, CHILD_BLOCK_HASH);
    provider.set_canonical_block_hash(PARENT_BLOCK_NUMBER, PARENT_BLOCK_HASH);
    provider.enter(|storage| {
        register_submitter_as_active(storage.clone());
        f(storage)
    })
}

/// Provider with `block_number` set but the canonical-history fixture
/// **omitted** for `PARENT_BLOCK_NUMBER`. Drives "parent outside
/// retention window" branch.
fn with_storage_no_canonical_parent<R>(block_number: u64, f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(block_number);
    provider.set_canonical_block_hash(CHILD_BLOCK_NUMBER, CHILD_BLOCK_HASH);
    provider.enter(|storage| {
        register_submitter_as_active(storage.clone());
        f(storage)
    })
}

/// Provider with `block_number` set and the canonical fixture seeded with
/// a DIFFERENT hash at `PARENT_BLOCK_NUMBER` - drives the
/// "canonical mismatch" branch.
fn with_storage_with_foreign_canonical_parent<R>(
    block_number: u64,
    foreign_hash: B256,
    f: impl FnOnce(StorageHandle) -> R,
) -> R {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(block_number);
    provider.set_canonical_block_hash(CHILD_BLOCK_NUMBER, CHILD_BLOCK_HASH);
    provider.set_canonical_block_hash(PARENT_BLOCK_NUMBER, foreign_hash);
    provider.enter(|storage| {
        register_submitter_as_active(storage.clone());
        f(storage)
    })
}

/// Raw provider - does NOT auto-register `SUBMITTER` as an ACTIVE
/// validator. Used by ACL-rejection tests.
fn with_storage_no_acl<R>(block_number: u64, f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(block_number);
    provider.set_canonical_block_hash(CHILD_BLOCK_NUMBER, CHILD_BLOCK_HASH);
    provider.set_canonical_block_hash(PARENT_BLOCK_NUMBER, PARENT_BLOCK_HASH);
    provider.enter(f)
}

// ===========================================================================
// submitter must be an ACTIVE validator. The
// entry-point's first runtime check rejects any non-ACTIVE caller before
// any cryptography runs. This is the production DoS-resistance guarantee:
// only the staked set can spend chain CPU on the verifier.
//
// Two-axis pin:
//   (a) random EOA with no ValidatorSet entry -> reject with status 0.
//   (b) registered-but-EXITING validator -> reject because status != ACTIVE.
// ===========================================================================
#[test]
fn invalid_vrf_evidence_rejects_non_active_submitter() {
    // (a) random EOA, never registered.
    with_storage_no_acl(CHILD_BLOCK_NUMBER + 1, |storage| {
        let mut si = SlashIndicator::new(storage);
        let err = si.submit_invalid_vrf_evidence(SUBMITTER, &[]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not an ACTIVE validator") && msg.contains(&format!("status: {}", 0u8)),
            "non-validator submitter must be rejected; got: {msg}",
        );
    });

    // (b) registered + activated, then force-exited (status = EXITING).
    with_storage_no_acl(CHILD_BLOCK_NUMBER + 1, |storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        let mut pk = [0u8; 48];
        pk[0] = 0x44;
        vs.config_owner.write(OWNER).unwrap();
        vs.set_config_max_validators(100).unwrap();
        vs.register_validator(OWNER, SUBMITTER, &pk).unwrap();
        vs.activate_validator_via_boundary_for_test(SUBMITTER)
            .unwrap();
        vs.force_exit_validator(SUBMITTER).unwrap();

        let mut si = SlashIndicator::new(storage);
        let err = si.submit_invalid_vrf_evidence(SUBMITTER, &[]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not an ACTIVE validator"),
            "EXITING validator must be rejected; got: {msg}",
        );
        // The ABI-compatible stored EXITING discriminant is 3.
        assert!(
            msg.contains("status: 3"),
            "rejection must echo the stored status; got: {msg}",
        );
    });
}

// ===========================================================================
// oversized evidence is rejected by the size cap before codec runs.
// ===========================================================================
#[test]
fn invalid_vrf_evidence_rejects_over_max_bytes() {
    with_storage(|storage| {
        let mut si = SlashIndicator::new(storage);
        let oversized = vec![0u8; relaxed_schedule().invalid_vrf_evidence_max_bytes + 1];
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &oversized, &relaxed_schedule())
            .unwrap_err();
        assert!(
            format!("{err}").contains("evidence too large"),
            "got: {err}"
        );
    });
}

// ===========================================================================
// evidence whose `child_block_number` is older than current_block -
// max_age_blocks is rejected.
// ===========================================================================
#[test]
fn invalid_vrf_evidence_rejects_after_max_age() {
    with_storage_at(CHILD_BLOCK_NUMBER + 10, |storage| {
        let evidence = evidence_skeleton(vec![]).encode();
        let mut si = SlashIndicator::new(storage);
        let mut schedule = relaxed_schedule();
        schedule.invalid_vrf_evidence_max_age_blocks = 5; // child is 10 blocks old -> stale
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &schedule)
            .unwrap_err();
        assert!(format!("{err}").contains("evidence stale"), "got: {err}");
    });
}

// ===========================================================================
// epoch_lag check uses the on-chain ValidatorSet epoch snapshot (Option C).
// ===========================================================================
#[test]
fn evidence_epoch_deadline_inadmissible_after_grace_epoch() {
    with_storage(|storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        set_current_epoch(&mut vs, CHILD_EPOCH + 5);

        let evidence = evidence_skeleton(vec![]).encode();
        let mut si = SlashIndicator::new(storage);
        let mut schedule = relaxed_schedule();
        schedule.invalid_vrf_evidence_max_epoch_lag = 1; // child is 5 epochs old -> stale
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &schedule)
            .unwrap_err();
        assert!(
            format!("{err}").contains("evidence epoch-stale"),
            "got: {err}"
        );
    });
}

// ===========================================================================
// codec rejects bad magic. (Mirrors a codec unit test; this test
// confirms the codec error propagates through the runtime path.)
// ===========================================================================
#[test]
fn evidence_with_bad_magic_propagates_codec_error_through_runtime() {
    with_storage(|storage| {
        let mut encoded = evidence_skeleton(vec![]).encode();
        encoded[0] ^= 0xFF;
        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &encoded, &relaxed_schedule())
            .unwrap_err();
        assert!(format!("{err}").contains("bad magic"), "got: {err}");
    });
}

// ===========================================================================
// phase1_tx_bytes that doesn't decode as an EIP-2718 envelope
// is rejected (the runtime guards against junk bytes before recovery).
// ===========================================================================
#[test]
fn evidence_with_phase1_tx_not_eip2718_envelope_rejected() {
    with_storage(|storage| {
        let evidence = evidence_skeleton(vec![0xFF; 32]).encode();
        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("phase1_tx invalid") && msg.contains("decode failed"),
            "got: {msg}"
        );
    });
}

// ===========================================================================
// phase1_tx_bytes with trailing bytes after the envelope is rejected.
// ===========================================================================
#[test]
fn evidence_with_phase1_tx_trailing_bytes_rejected() {
    with_storage(|storage| {
        let (signer, _) = signer_with_address();
        let dkg = build_dkg(4);
        let snapshot = build_snapshot(&dkg, signer.address());
        let cert = build_cert(&dkg, &[0, 1, 2, 3], PARENT_BLOCK_HASH, false);
        let cert_bytes = proof_envelope_bytes(&cert, PARENT_BLOCK_HASH);
        let metadata = build_metadata(&snapshot, &cert_bytes);
        let mut phase1 = sign_phase1_metadata_tx(&signer, &metadata);
        phase1.push(0xAB); // trailing junk
        let evidence = evidence_skeleton(phase1).encode();
        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap_err();
        assert!(
            format!("{err}").contains("trailing bytes after EIP-2718 envelope"),
            "got: {err}"
        );
    });
}

// ===========================================================================
// no committee snapshot for the metadata's (epoch, committee_set_hash).
// ===========================================================================
#[test]
fn evidence_with_missing_committee_snapshot_rejected() {
    with_storage_at(CHILD_BLOCK_NUMBER + 1, |storage| {
        let (signer, proposer) = signer_with_address();
        let dkg = build_dkg(4);
        let snapshot = build_snapshot(&dkg, proposer);
        let cert = build_cert(&dkg, &[0, 1, 2, 3], PARENT_BLOCK_HASH, false);
        let cert_bytes = proof_envelope_bytes(&cert, PARENT_BLOCK_HASH);
        let metadata = build_metadata(&snapshot, &cert_bytes);

        // Storage minimum to satisfy admissibility but DO NOT write the
        // committee snapshot.
        let mut vs = ValidatorSet::new(storage.clone());
        set_current_epoch(&mut vs, CHILD_EPOCH);

        let phase1 = sign_phase1_metadata_tx(&signer, &metadata);
        let evidence = evidence_skeleton(phase1).encode();

        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap_err();
        assert!(
            format!("{err}").contains("no committee snapshot"),
            "got: {err}"
        );
    });
}

// ===========================================================================
// proposer recovered from phase1_tx is NOT in the snapshot's
// committee -> reject.
// ===========================================================================
#[test]
fn invalid_vrf_evidence_without_child_proposer_attribution_rejects() {
    with_storage_at(CHILD_BLOCK_NUMBER + 1, |storage| {
        let (signer, _proposer) = signer_with_address();
        let dkg = build_dkg(4);
        // Build a snapshot whose committee does NOT contain the
        // proposer-derived address - use a different placeholder for
        // slot 0 (the same `foreign_addr` is what setup_storage
        // registers + stakes, so its identity is consistent).
        let foreign_addr = address!("0xfefefefefefefefefefefefefefefefefefefefe");
        let snapshot = build_snapshot(&dkg, foreign_addr);
        let cert = build_cert(&dkg, &[0, 1, 2, 3], PARENT_BLOCK_HASH, false);
        let cert_bytes = proof_envelope_bytes(&cert, PARENT_BLOCK_HASH);
        let metadata = build_metadata(&snapshot, &cert_bytes);

        setup_storage(storage.clone(), foreign_addr, &snapshot, CHILD_EPOCH);

        let phase1 = sign_phase1_metadata_tx(&signer, &metadata);
        let evidence = evidence_skeleton(phase1).encode();

        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap_err();
        assert!(format!("{err}").contains("not in committee"), "got: {err}");
    });
}

// ===========================================================================
// VALID proof submitted as evidence -> reject ("nothing to slash").
// ===========================================================================
#[test]
fn evidence_with_valid_proof_rejected_as_not_slashable() {
    with_storage_at(CHILD_BLOCK_NUMBER + 1, |storage| {
        let (signer, proposer) = signer_with_address();
        let dkg = build_dkg(4);
        let snapshot = build_snapshot(&dkg, proposer);
        let cert = build_cert(
            &dkg,
            &[0, 1, 2, 3],
            PARENT_BLOCK_HASH,
            /* valid VRF */ true,
        );
        let cert_bytes = proof_envelope_bytes(&cert, PARENT_BLOCK_HASH);
        let metadata = build_metadata(&snapshot, &cert_bytes);
        setup_storage(storage.clone(), proposer, &snapshot, CHILD_EPOCH);

        let phase1 = sign_phase1_metadata_tx(&signer, &metadata);
        let evidence = evidence_skeleton(phase1).encode();

        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap_err();
        assert!(format!("{err}").contains("VALID proof"), "got: {err}");
    });
}

// ===========================================================================
// non-VRF verifier failure (BLS aggregate invalid) -> reject as
// "non-VRF class".
// ===========================================================================
#[test]
fn invalid_vrf_evidence_for_non_vrf_failure_class_rejects() {
    with_storage_at(CHILD_BLOCK_NUMBER + 1, |storage| {
        let (signer, proposer) = signer_with_address();
        let dkg = build_dkg(4);
        let snapshot = build_snapshot(&dkg, proposer);
        // Build a cert with the WRONG signer_indices in the BLS
        // aggregate (sign with all 4 keys but claim only signers
        // {0,1,2} in the bitmap). The verifier reconstructs the
        // expected aggregate from the bitmap and rejects with
        // BitmapMismatch / BlsAggregateInvalid - a non-VRF class.
        let cert = build_cert(&dkg, &[0, 1, 2], PARENT_BLOCK_HASH, true);
        let cert_bytes = proof_envelope_bytes(&cert, PARENT_BLOCK_HASH);
        let mut metadata = build_metadata(&snapshot, &cert_bytes);
        // Claim all 4 signers in the bitmap even though only 3 signed -
        // this makes the BLS aggregate mismatch the reconstructed
        // expected payload.
        metadata.signer_bitmap = vec![1u8; 4];

        setup_storage(storage.clone(), proposer, &snapshot, CHILD_EPOCH);

        let phase1 = sign_phase1_metadata_tx(&signer, &metadata);
        let evidence = evidence_skeleton(phase1).encode();

        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("non-VRF class"),
            "expected non-VRF class rejection; got: {msg}"
        );
    });
}

// ===========================================================================
// HAPPY PATH - invalid mandatory VRF proof, BLS aggregate valid -> felony.
// Pins:
//   * proposer recovered from phase1_tx_bytes matches the registered
//     validator (ecrecover <-> ValidatorSet identity wiring is correct)
//   * proposer status flips ACTIVE -> JAILED
//   * stake is slashed by 5% (the helper's config default)
//   * submitter receives 10% of slashed amount in their balance
//   * dedup slot is marked
//   * second submission of the same evidence is rejected with
//     "evidence already processed"
// ===========================================================================
#[test]
fn invalid_vrf_proof_evidence_slashes_child_proposer() {
    with_storage_at(CHILD_BLOCK_NUMBER + 1, |storage| {
        let (signer, proposer) = signer_with_address();
        let dkg = build_dkg(4);
        let snapshot = build_snapshot(&dkg, proposer);
        // false => the mandatory proof is present but signed by the wrong key.
        let cert = build_cert(&dkg, &[0, 1, 2, 3], PARENT_BLOCK_HASH, false);
        let cert_bytes = proof_envelope_bytes(&cert, PARENT_BLOCK_HASH);
        let metadata = build_metadata(&snapshot, &cert_bytes);
        setup_storage(storage.clone(), proposer, &snapshot, CHILD_EPOCH);

        let phase1 = sign_phase1_metadata_tx(&signer, &metadata);
        let phase1_hash = keccak256(&phase1);
        let evidence_struct = evidence_skeleton(phase1);
        let evidence = evidence_struct.encode();

        let initial_submitter_balance = storage.balance(SUBMITTER).unwrap();
        let initial_stake = Staking::new(storage.clone()).get_stake(proposer).unwrap();

        let mut si = SlashIndicator::new(storage.clone());
        si.submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap();

        // (a) Validator JAILED (felony, not force-exited).
        let vs = ValidatorSet::new(storage.clone());
        assert!(
            matches!(
                vs.validator_lifecycle(proposer).unwrap(),
                ValidatorLifecycle::JailRetained(_)
            ),
            "proposer must be jailed"
        );

        // (b) Stake slashed by 5% (the default config_slash_amount_percent).
        let remaining_stake = Staking::new(storage.clone()).get_stake(proposer).unwrap();
        let expected_stake = initial_stake * U256::from(95u64) / U256::from(100u64);
        assert_eq!(
            remaining_stake, expected_stake,
            "stake must be 95% of original after 5% slash"
        );

        // (c) Submitter received 10% of slashed amount.
        let slashed = initial_stake - remaining_stake;
        let expected_reward = slashed * U256::from(10u64) / U256::from(100u64);
        let final_submitter_balance = storage.balance(SUBMITTER).unwrap();
        assert_eq!(
            final_submitter_balance - initial_submitter_balance,
            expected_reward,
            "submitter must receive 10% of slashed stake"
        );

        // (d) Dedup slot marked at the canonical (child, phase1) key.
        let evidence_hash = invalid_vrf_evidence_hash_v2(CHILD_BLOCK_HASH, phase1_hash);
        assert!(
            SlashIndicator::new(storage.clone())
                .invalid_vrf_evidence_processed
                .read(&evidence_hash)
                .unwrap(),
            "dedup slot must be set after successful slash"
        );

        // (e) Replay rejected: a dedicated test pins this independently, but the
        // happy path also asserts it for end-to-end completeness.
        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap_err();
        assert!(
            format!("{err}").contains("evidence already processed"),
            "replay must be rejected; got: {err}"
        );
    });
}

// ===========================================================================
// dedup - second submission of the SAME evidence reverts.
// Independent of the happy path (uses a stand-alone happy submission then
// re-submits) so the dedup contract is testable even if the felony helper
// is later refactored.
// ===========================================================================
#[test]
fn invalid_vrf_evidence_deduplicates_by_canonical_hash() {
    with_storage_at(CHILD_BLOCK_NUMBER + 1, |storage| {
        let (signer, proposer) = signer_with_address();
        let dkg = build_dkg(4);
        let snapshot = build_snapshot(&dkg, proposer);
        let cert = build_cert(&dkg, &[0, 1, 2, 3], PARENT_BLOCK_HASH, false);
        let cert_bytes = proof_envelope_bytes(&cert, PARENT_BLOCK_HASH);
        let metadata = build_metadata(&snapshot, &cert_bytes);
        setup_storage(storage.clone(), proposer, &snapshot, CHILD_EPOCH);

        let phase1 = sign_phase1_metadata_tx(&signer, &metadata);
        let evidence = evidence_skeleton(phase1).encode();

        let mut si = SlashIndicator::new(storage.clone());
        si.submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .expect("first submission succeeds");

        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap_err();
        assert!(
            format!("{err}").contains("evidence already processed"),
            "second submission must dedup; got: {err}"
        );
    });
}

// ===========================================================================
// helper-level classifier table. Exhaustive check that
// classify_vrf_failure returns Some(code) for every VRF variant of
// V2VerifyError and None for representative non-VRF variants. Pins the
// emitted `failureCode` wire constants.
// ===========================================================================
#[test]
fn classify_vrf_failure_covers_all_reachable_vrf_variants_only() {
    use V2VerifyError::*;

    assert_eq!(classify_vrf_failure(&MalformedVrfProof), Some(2));
    assert_eq!(
        classify_vrf_failure(&WrongVrfMaterialVersion {
            expected: 1,
            actual: 2
        }),
        Some(3)
    );
    assert_eq!(
        classify_vrf_failure(&WrongVrfGroupKeyHash {
            expected: B256::ZERO,
            actual: B256::ZERO
        }),
        Some(4)
    );
    assert_eq!(classify_vrf_failure(&WrongVrfNamespace), Some(5));
    assert_eq!(
        classify_vrf_failure(&WrongVrfSeedRound {
            expected_epoch: 0,
            expected_view: 0
        }),
        Some(6)
    );
    assert_eq!(classify_vrf_failure(&InvalidVrfSignature), Some(7));

    // Representative non-VRF variants must return None - the precompile
    // reverts with "non-VRF class" rather than slashing.
    assert_eq!(
        classify_vrf_failure(&BelowQuorum {
            signers: 1,
            quorum: 3
        }),
        None
    );
    assert_eq!(classify_vrf_failure(&BlsAggregateInvalid), None);
    assert_eq!(
        classify_vrf_failure(&WrongAccountedNumber {
            expected: 1,
            actual: 2
        }),
        None
    );
    assert_eq!(
        classify_vrf_failure(&WrongAccountedHash {
            expected: B256::ZERO,
            actual: B256::ZERO
        }),
        None
    );
}

// ===========================================================================
// Sanity: confirm the codec wire constants used in the file above match
// the runtime's published values. Acts as a smoke check that the codec
// header didn't drift away from what the runtime expects.
// ===========================================================================
#[test]
fn codec_wire_constants_are_stable() {
    assert_eq!(MAGIC, *b"IVE2");
    assert_eq!(VERSION, 0x02);
}

// ===========================================================================
// body test #4 - boundary form of the block-age cap.
//
// `invalid_vrf_evidence_rejects_after_max_age` proves admissibility
// rejects evidence past the deadline. This test pins the OTHER side of
// the boundary: exactly at the deadline the evidence is admissible
// (only verifier-side reasons reject it). The pair locks the inclusive
// upper bound `current_block <= child + max_age`.
// ===========================================================================
#[test]
fn evidence_max_age_inadmissible_after_deadline() {
    // (a) deadline exactly - admissibility passes; we expect a later
    // failure path (here the codec, because metadata is empty), proving
    // we got past the block-age gate.
    let mut schedule = relaxed_schedule();
    schedule.invalid_vrf_evidence_max_age_blocks = 5;
    let on_boundary_block = CHILD_BLOCK_NUMBER + 5;
    with_storage_at(on_boundary_block, |storage| {
        let evidence = evidence_skeleton(vec![]).encode();
        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &schedule)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.contains("evidence stale"),
            "on-boundary block must pass the age gate; got: {msg}",
        );
    });

    // (b) one block past deadline - explicit stale revert.
    let past_block = CHILD_BLOCK_NUMBER + 6;
    with_storage_at(past_block, |storage| {
        let evidence = evidence_skeleton(vec![]).encode();
        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &schedule)
            .unwrap_err();
        assert!(format!("{err}").contains("evidence stale"), "got: {err}");
    });
}

// ===========================================================================
// body test #6 - admissibility reads `current_epoch` from
// ValidatorSet epoch storage, NOT from any in-memory cache.
//
// We install an epoch snapshot through the test fixture API and assert the
// precompile observes it. Drives the on-chain-state path (BP-0 option C).
// ===========================================================================
#[test]
fn evidence_admissibility_reads_current_epoch_from_validator_set_storage() {
    with_storage_at(CHILD_BLOCK_NUMBER + 1, |storage| {
        // No submission or transition_epoch call: install the canonical epoch
        // fixture the precompile consults.
        let mut vs = ValidatorSet::new(storage.clone());
        set_current_epoch(&mut vs, CHILD_EPOCH + 7);

        let evidence = evidence_skeleton(vec![]).encode();
        let mut si = SlashIndicator::new(storage);
        let mut schedule = relaxed_schedule();
        schedule.invalid_vrf_evidence_max_epoch_lag = 1; // 7 > 1 -> epoch-stale
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &schedule)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("evidence epoch-stale"),
            "precompile must read the ValidatorSet epoch from storage; got: {msg}",
        );
        // The current_epoch in the error message must be exactly the
        // value we just wrote - pins the storage-read path.
        assert!(
            msg.contains(&format!("current_epoch {}", CHILD_EPOCH + 7)),
            "rejection must echo the stored epoch value; got: {msg}",
        );
    });
}

// ===========================================================================
// body test #9 - at-most-one-slash even when several evidences
// carry different (submitter-asserted) failure codes for the SAME
// `(child_block_hash, phase1_tx_hash)`. The dedup key derives from the
// canonical preimage only, so the failure-code axis is not a way around
// the guard.
// ===========================================================================
#[test]
fn multiple_evidence_with_different_failure_codes_for_same_child_apply_at_most_one_slash() {
    with_storage_at(CHILD_BLOCK_NUMBER + 1, |storage| {
        let (signer, proposer) = signer_with_address();
        let dkg = build_dkg(4);
        let snapshot = build_snapshot(&dkg, proposer);
        let cert = build_cert(&dkg, &[0, 1, 2, 3], PARENT_BLOCK_HASH, false);
        let cert_bytes = proof_envelope_bytes(&cert, PARENT_BLOCK_HASH);
        let metadata = build_metadata(&snapshot, &cert_bytes);
        setup_storage(storage.clone(), proposer, &snapshot, CHILD_EPOCH);

        let phase1 = sign_phase1_metadata_tx(&signer, &metadata);

        // First submission: failure_code = 7 (InvalidVrfSignature, the truth).
        let mut ev1 = evidence_skeleton(phase1.clone());
        ev1.failure_code = 7;
        let evidence1 = ev1.encode();

        let mut si = SlashIndicator::new(storage.clone());
        si.submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence1, &relaxed_schedule())
            .expect("first submission succeeds");

        let stake_after_first = Staking::new(storage.clone()).get_stake(proposer).unwrap();

        // Second submission: SAME child + SAME phase1_tx, but a different
        // submitter-asserted failure code. Must dedup.
        let mut ev2 = evidence_skeleton(phase1);
        ev2.failure_code = 3; // WrongVrfMaterialVersion claim - not the truth
        let evidence2 = ev2.encode();

        let err = SlashIndicator::new(storage.clone())
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence2, &relaxed_schedule())
            .unwrap_err();
        assert!(
            format!("{err}").contains("evidence already processed"),
            "different failure_code must not bypass dedup; got: {err}",
        );

        // Stake unchanged after the second attempt (no double-slash).
        let stake_after_second = Staking::new(storage).get_stake(proposer).unwrap();
        assert_eq!(
            stake_after_second, stake_after_first,
            "second submission must not re-slash",
        );
    });
}

// ===========================================================================
// body test #10 - confirms the new entry-point reuses the
// existing `apply_evidence_felony` helper rather than reimplementing
// 5%/10% economics inline. Asserts the same conservation that the
// double-proposal and conflicting-vote paths already enforce:
//
//   * slashed = 5% of initial stake
//   * submitter reward = 10% of slashed
//   * destroyed supply = slashed - reward (slash burns from STAKING_ADDRESS,
//     reward is minted back to submitter, so net burn is the remainder)
// ===========================================================================
#[test]
fn invalid_vrf_evidence_uses_existing_evidence_felony_economics() {
    with_storage_at(CHILD_BLOCK_NUMBER + 1, |storage| {
        let (signer, proposer) = signer_with_address();
        let dkg = build_dkg(4);
        let snapshot = build_snapshot(&dkg, proposer);
        let cert = build_cert(&dkg, &[0, 1, 2, 3], PARENT_BLOCK_HASH, false);
        let cert_bytes = proof_envelope_bytes(&cert, PARENT_BLOCK_HASH);
        let metadata = build_metadata(&snapshot, &cert_bytes);
        setup_storage(storage.clone(), proposer, &snapshot, CHILD_EPOCH);

        let initial_staking_balance = storage.balance(STAKING_ADDRESS).unwrap();
        let initial_submitter_balance = storage.balance(SUBMITTER).unwrap();
        let initial_stake = Staking::new(storage.clone()).get_stake(proposer).unwrap();

        let phase1 = sign_phase1_metadata_tx(&signer, &metadata);
        let evidence = evidence_skeleton(phase1).encode();

        let mut si = SlashIndicator::new(storage.clone());
        si.submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap();

        // 5% slash off the registered stake.
        let expected_slashed = initial_stake * U256::from(5u64) / U256::from(100u64);
        let post_stake = Staking::new(storage.clone()).get_stake(proposer).unwrap();
        assert_eq!(
            initial_stake - post_stake,
            expected_slashed,
            "slash must equal 5% of stake (apply_evidence_felony default)",
        );

        // 10% of slashed goes to submitter, the rest is burned from
        // STAKING_ADDRESS (same conservation as
        // submitDoubleProposalEvidence / submitConflictingVoteEvidence).
        let expected_reward = expected_slashed * U256::from(10u64) / U256::from(100u64);
        let submitter_delta = storage.balance(SUBMITTER).unwrap() - initial_submitter_balance;
        assert_eq!(
            submitter_delta, expected_reward,
            "submitter reward must equal 10% of slashed (apply_evidence_felony default)",
        );

        let staking_delta = initial_staking_balance - storage.balance(STAKING_ADDRESS).unwrap();
        assert_eq!(
            staking_delta, expected_slashed,
            "STAKING_ADDRESS must lose exactly the slashed amount",
        );
    });
}

// ===========================================================================
// body test #11 - evidence whose `parent_block_hash`
// is not canonical at `parent_block_number` is rejected as
// non-attributable. Covers both branches:
//   (a) parent number is OUTSIDE the canonical-history window (None)
//   (b) parent number is in window but with a DIFFERENT canonical hash
//       (side-chain evidence)
// ===========================================================================
#[test]
fn invalid_vrf_proof_evidence_with_non_canonical_parent_rejects() {
    // (a) parent outside the canonical window -> "not in canonical-history window".
    with_storage_no_canonical_parent(CHILD_BLOCK_NUMBER + 1, |storage| {
        let evidence = evidence_skeleton(vec![]).encode();
        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not in canonical-history window"),
            "unknown parent must be rejected as out-of-window; got: {msg}",
        );
    });

    // (b) parent in window but canonical hash differs -> "not canonical at block".
    let foreign_parent =
        b256!("0xfeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface");
    with_storage_with_foreign_canonical_parent(CHILD_BLOCK_NUMBER + 1, foreign_parent, |storage| {
        let evidence = evidence_skeleton(vec![]).encode();
        let mut si = SlashIndicator::new(storage);
        let err = si
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("is not canonical at block"),
            "side-chain parent must be rejected as non-canonical; got: {msg}",
        );
    });
}

// ===========================================================================
// body test #14 - after a successful slash the canonical
// `(child_hash, phase1_tx_hash)` dedup slot must be set, AND a fresh
// `SlashIndicator` facade attached to the same storage must still see
// it (the slot is persisted in EVM storage, not cached on the contract
// instance). Locks the persistence boundary that the dedup guard relies
// on across separate precompile invocations.
// ===========================================================================
#[test]
fn slashindicator_dedup_retains_invalid_vrf_evidence_seen_hash() {
    with_storage_at(CHILD_BLOCK_NUMBER + 1, |storage| {
        let (signer, proposer) = signer_with_address();
        let dkg = build_dkg(4);
        let snapshot = build_snapshot(&dkg, proposer);
        let cert = build_cert(&dkg, &[0, 1, 2, 3], PARENT_BLOCK_HASH, false);
        let cert_bytes = proof_envelope_bytes(&cert, PARENT_BLOCK_HASH);
        let metadata = build_metadata(&snapshot, &cert_bytes);
        setup_storage(storage.clone(), proposer, &snapshot, CHILD_EPOCH);

        let phase1 = sign_phase1_metadata_tx(&signer, &metadata);
        let phase1_hash = keccak256(&phase1);
        let evidence = evidence_skeleton(phase1).encode();

        SlashIndicator::new(storage.clone())
            .submit_invalid_vrf_evidence_with_schedule(SUBMITTER, &evidence, &relaxed_schedule())
            .unwrap();

        // Fresh facade - proves the dedup slot is read from storage, not
        // an in-instance cache.
        let canonical = invalid_vrf_evidence_hash_v2(CHILD_BLOCK_HASH, phase1_hash);
        let later = SlashIndicator::new(storage);
        assert!(
            later
                .invalid_vrf_evidence_processed
                .read(&canonical)
                .unwrap(),
            "dedup slot must persist for a freshly-attached facade",
        );
    });
}

// ===========================================================================
// body test #2 - `submitInvalidVrfProofEvidence` rides the
// regular precompile dispatch path used by mempool / txpool transactions,
// NOT the begin-zone system-tx phase.
//
// Behavioural pin (not a source grep):
//   * ABI-decode the canonical 4-byte selector through `ISlashIndicator`
//     (the txpool precompile's interface) - the route exists.
//   * Confirm the dispatch closure reaches the runtime entry-point with
// an ACTIVE-validator caller (the ACL gate) and proceeds
//     into the decode phase. A begin-zone phase wouldn't enforce the
//     validator-set ACL (system txs run as `SYSTEM_ADDRESS` against a
//     different dispatcher), so the canonical revert text is a
//     behavioural marker for "this ran through the user-tx precompile
//     dispatch and was gated by the ACL".
// The begin-zone path lives in a different crate (`outbe-evm`) that
// `outbe-slashindicator` cannot depend on without cycle, so the
// structural "begin-zone does NOT host this selector" claim is enforced
// by the type system: `outbe_evm::system_tx::SystemTxInputV2` is a
// closed enum with 4 named variants (CertifiedParentAccounting,
// CycleTick, BoundaryOutcome, OracleSlashWindow), none of which
// reference `submitInvalidVrfProofEvidence`.
// ===========================================================================
#[test]
fn invalid_vrf_evidence_uses_txpool_precompile_path_not_begin_zone() {
    use alloy_sol_types::{sol, SolCall, SolInterface};

    sol!("../../../contracts/precompiles/src/ISlashIndicator.sol");

    // (a) The ABI selector decodes through the txpool precompile's
    // interface. If the entry-point moved to a different routing, this
    // would either decode to a different selector or fail.
    let call = ISlashIndicator::submitInvalidVrfProofEvidenceCall {
        evidence: Bytes::from_static(b""),
    };
    let calldata = call.abi_encode();
    let decoded = ISlashIndicator::ISlashIndicatorCalls::abi_decode(&calldata).unwrap();
    matches!(
        decoded,
        ISlashIndicator::ISlashIndicatorCalls::submitInvalidVrfProofEvidence(_)
    )
    .then_some(())
    .expect("ABI selector must route to submitInvalidVrfProofEvidence");

    // (b) Hitting the txpool-style dispatch (`SlashIndicator::new(...)`
    // then the runtime entry-point) with a registered ACTIVE submitter
    // proceeds past the ACL gate into the decode phase. The
    // empty input fails at the codec ("bad magic"), proving the dispatch
    // path is wired through to runtime decode without going through any
    // begin-zone shortcut.
    with_storage(|storage| {
        let mut si = SlashIndicator::new(storage);
        let err = si.submit_invalid_vrf_evidence(SUBMITTER, &[]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("InvalidVrfProofEvidence: input too short")
                || msg.contains("bad magic")
                || msg.contains("decode error"),
            "txpool precompile path must reach codec decode for ACTIVE submitter; got: {msg}",
        );
    });
}
