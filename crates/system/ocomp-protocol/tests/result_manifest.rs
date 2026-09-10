use alloy_primitives::B256;
use outbe_ocomp_protocol::{
    local_control::poc_schema_limits, result::OutputManifestEntryV1, CasObjectRefV1, ObjectKind,
    ProtocolError,
};

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn manifest_entry() -> OutputManifestEntryV1 {
    OutputManifestEntryV1 {
        chunk_ordinal: 7,
        result_chunk_hash: hash(0x31),
        result_chunk_ref: CasObjectRefV1 {
            transport_digest: hash(0x32),
            encoded_bytes: 128,
            expected_ocb1_kind: Some(ObjectKind::ResultChunkV1.tag()),
        },
    }
}

#[test]
fn output_manifest_entry_has_one_strict_canonical_record() {
    let limits = poc_schema_limits();
    let entry = manifest_entry();

    let encoded = entry.encode_canonical_record(&limits).unwrap();
    assert_eq!(
        OutputManifestEntryV1::decode_canonical_record(&encoded, &limits).unwrap(),
        entry
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert!(matches!(
        OutputManifestEntryV1::decode_canonical_record(&trailing, &limits),
        Err(ProtocolError::TrailingBytes { .. })
    ));
}

#[test]
fn output_manifest_entry_rejects_non_retrievable_or_untyped_chunks() {
    let limits = poc_schema_limits();
    let mut exact_cap = manifest_entry();
    exact_cap.result_chunk_ref.encoded_bytes = limits.max_result_chunk_bytes;
    assert!(exact_cap.encode_canonical_record(&limits).is_ok());

    let mutations = [
        {
            let mut value = manifest_entry();
            value.result_chunk_hash = B256::ZERO;
            value
        },
        {
            let mut value = manifest_entry();
            value.result_chunk_ref.transport_digest = B256::ZERO;
            value
        },
        {
            let mut value = manifest_entry();
            value.result_chunk_ref.encoded_bytes = 0;
            value
        },
        {
            let mut value = manifest_entry();
            value.result_chunk_ref.encoded_bytes = limits.max_result_chunk_bytes + 1;
            value
        },
        {
            let mut value = manifest_entry();
            value.result_chunk_ref.expected_ocb1_kind = None;
            value
        },
        {
            let mut value = manifest_entry();
            value.result_chunk_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
            value
        },
    ];

    for mutation in mutations {
        assert!(mutation.encode_canonical_record(&limits).is_err());
    }
}
