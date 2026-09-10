//! V2 Phase 1 metadata invariants.
//!
//! INV4: `CertifiedParentAccountingMetadata` carries no money
//! fields and no raw consensus public keys; only fingerprint hashes survive.

use alloy_primitives::{address, B256};
use outbe_primitives::consensus_metadata::{
    CertifiedParentAccountingMetadata, MissedProposerEvent, ParentParticipationProof,
};

fn sample_v2_metadata() -> CertifiedParentAccountingMetadata {
    CertifiedParentAccountingMetadata {
        finalized_block_number: 42,
        finalized_block_hash: B256::repeat_byte(0xAB),
        finalized_epoch: 7,
        finalized_view: 42,
        parent_view: 41,
        ordered_committee: vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
        ],
        signer_bitmap: vec![1, 0, 1],
        proof: alloy_primitives::Bytes::from_static(b"hybrid-certificate-v2"),
        committee_set_hash: B256::repeat_byte(0xCC),
        vrf_material_version: 5,
        vrf_group_public_key_hash: B256::repeat_byte(0xDD),
        proof_kind: ParentParticipationProof::Finalization,
        missed_proposers: Vec::new(),
    }
}

#[test]
fn certified_parent_accounting_metadata_roundtrip() {
    let m = sample_v2_metadata();
    let encoded = m.encode().expect("encode");
    let decoded = CertifiedParentAccountingMetadata::decode(encoded.as_ref()).expect("decode");
    assert_eq!(decoded, m);

    let re_encoded = decoded.encode().expect("re-encode");
    assert_eq!(
        re_encoded.as_ref(),
        encoded.as_ref(),
        "wire codec not byte-stable"
    );
}

#[test]
fn certified_parent_accounting_metadata_rlp_roundtrip() {
    let m = sample_v2_metadata();
    let encoded = m.encode_rlp().expect("rlp encode");
    let decoded =
        CertifiedParentAccountingMetadata::decode_rlp(encoded.as_ref()).expect("rlp decode");
    assert_eq!(decoded, m);
}

#[test]
fn certified_notarization_proof_kind_roundtrips() {
    let mut m = sample_v2_metadata();
    m.proof_kind = ParentParticipationProof::CertifiedNotarization;
    let encoded = m.encode().expect("encode");
    let decoded = CertifiedParentAccountingMetadata::decode(encoded.as_ref()).expect("decode");
    assert_eq!(
        decoded.proof_kind,
        ParentParticipationProof::CertifiedNotarization
    );
}

#[test]
fn certified_parent_accounting_metadata_rejects_trailing_bytes() {
    let m = sample_v2_metadata();
    let mut bytes = m.encode().expect("encode").to_vec();
    bytes.push(0xFF);
    let err = CertifiedParentAccountingMetadata::decode(&bytes)
        .expect_err("trailing bytes must be rejected");
    assert!(format!("{err}").contains("trailing bytes"), "{err}");
}

#[test]
fn certified_parent_accounting_metadata_rejects_v1_magic() {
    // V1 magic "OMTX" is structurally distinct from OAV3 so a V1 envelope
    // cannot be decoded as V2 even if its body length happens to match.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"OMTX");
    bytes.push(3);
    bytes.resize(200, 0);
    let err = CertifiedParentAccountingMetadata::decode(&bytes)
        .expect_err("V1 envelope must be rejected by V2 decoder");
    assert!(format!("{err}").contains("magic"), "{err}");
}

#[test]
fn missed_proposer_event_codec_supports_non_empty_list_for_future_forks() {
    let mut m = sample_v2_metadata();
    m.missed_proposers = vec![
        MissedProposerEvent {
            view: 100,
            validator: m.ordered_committee[0],
        },
        MissedProposerEvent {
            view: 101,
            validator: m.ordered_committee[1],
        },
    ];
    let encoded = m.encode().expect("encode");
    let decoded = CertifiedParentAccountingMetadata::decode(encoded.as_ref()).expect("decode");
    assert_eq!(decoded.missed_proposers, m.missed_proposers);
}
