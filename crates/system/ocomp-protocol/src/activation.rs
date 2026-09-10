use alloy_primitives::B256;

use crate::{
    committee::POC_KEY_EPOCH,
    error::ProtocolError,
    hash::hash_framed,
    registry::HashDomain,
    schema::{impl_top_level_codec, require, wire_enum_u8, wire_struct, SchemaLimits},
    vote::ResultVoteSigningSubjectV1,
};

wire_enum_u8! {
    pub enum SignOncePurpose {
        ResultSignature = 1,
    }
}

wire_struct! {
    pub struct SignOnceRecordV1 {
        pub chain_id: u64,
        pub genesis_hash: B256,
        pub fork_id: B256,
        pub purpose: SignOncePurpose,
        pub job_id: B256,
        pub attempt: u32,
        pub protocol_bundle_hash: B256,
        pub result_validator_set_epoch: u64,
        pub result_committee_set_hash: B256,
        pub result_ocomp_binding_hash: B256,
        pub ocomp_key_hash: B256,
        pub key_epoch: u64,
        pub result_digest: B256,
        pub signature_rs: [u8; 64],
    }
}
impl_top_level_codec!(SignOnceRecordV1, SignOnceRecordV1);

wire_struct! {
    pub struct ActivationCallCoreV1 {
        pub intent_id: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub protocol_bundle_hash: B256,
        pub result_digest: B256,
        pub activation_preconditions_hash: B256,
        pub terminal_pending_nonce: u64,
    }
}
impl_top_level_codec!(ActivationCallCoreV1, ActivationCallCoreV1);

impl SignOnceRecordV1 {
    pub fn slot_id(&self) -> Result<B256, ProtocolError> {
        require(self.key_epoch == POC_KEY_EPOCH, "sign-once key epoch")?;
        let mut payload = Vec::with_capacity(45);
        payload.extend_from_slice(&self.chain_id.to_be_bytes());
        payload.push(self.purpose as u8);
        payload.extend_from_slice(self.job_id.as_slice());
        payload.extend_from_slice(&self.attempt.to_be_bytes());
        hash_framed(HashDomain::SignOnceSlot, &payload)
    }

    pub fn signing_digest(&self) -> Result<B256, ProtocolError> {
        ResultVoteSigningSubjectV1 {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            fork_id: self.fork_id,
            protocol_bundle_hash: self.protocol_bundle_hash,
            job_id: self.job_id,
            attempt: self.attempt,
            result_validator_set_epoch: self.result_validator_set_epoch,
            result_committee_set_hash: self.result_committee_set_hash,
            result_ocomp_binding_hash: self.result_ocomp_binding_hash,
            ocomp_key_hash: self.ocomp_key_hash,
            key_epoch: self.key_epoch,
            purpose: self.purpose as u8,
            result_digest: self.result_digest,
        }
        .signing_digest()
    }
}

impl ActivationCallCoreV1 {
    pub fn activation_call_id(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        hash_framed(HashDomain::ActivationCall, &self.encode_canonical(limits)?)
    }
}
