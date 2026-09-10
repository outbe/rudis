//! Reachable development-network fixtures for cross-crate tests.
//!
//! This module is available only behind `test-utils`. It constructs real
//! `GramineDirectDev` signatures and never fabricates a DCAP verdict, so callers
//! cannot mistake it for hardware or QVL evidence.

use std::collections::BTreeMap;

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use k256::ecdsa::signature::hazmat::PrehashSigner as _;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::Value;

use crate::{
    signer::OutbeEvmSigner,
    tee_attestation_v1::{
        AttestationEvidenceV1, AttestationMode, AttestationOperationV1, GramineDirectEvidenceV1,
        NodeIdV1, PlatformTcbStatusSetV1, QvlTcbStatusV1, RegistrationIntentV1, ResourceScheduleV1,
        TeeMeasurementRuleV1, TeePolicyV1, ValidatorNodeBindingV1,
    },
    tee_bootstrap_v2::{
        TeeBootstrapAuthorityV2, TeeBootstrapParticipantSubmissionV2, TeeBootstrapV2,
    },
    tee_genesis_v1::tee_attestation_v1_genesis_field,
};

const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

#[derive(Clone, Copy, Debug)]
pub struct DevValidatorV1 {
    pub evm_secret: [u8; 32],
    pub bls_minpk_public: [u8; 48],
}

pub fn gramine_direct_policy_v1(chain_id: u64, genesis_hash: B256) -> Result<TeePolicyV1, String> {
    let resource_schedule_hash = ResourceScheduleV1::normative()
        .and_then(|schedule| schedule.schedule_hash())
        .map_err(|error| format!("derive normative resource schedule: {error}"))?;
    let policy = TeePolicyV1 {
        policy_version: 1,
        chain_id: U256::from(chain_id).to_be_bytes(),
        genesis_hash,
        activation_height: 1,
        predecessor_policy_hash: B256::ZERO,
        attestation_mode: AttestationMode::GramineDirectDev,
        intel_root_der_hash: B256::repeat_byte(0x72),
        quote_version: 3,
        tee_type: 0,
        attestation_key_type: 2,
        qe_vendor_id: INTEL_QE_VENDOR_ID,
        certification_data_type: 5,
        tcb_info_schema_version: 3,
        qe_identity_schema_version: 2,
        minimum_tcb_evaluation_data_number: 1,
        accepted_platform_tcb_statuses: PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        accepted_qe_tcb_status: QvlTcbStatusV1::UpToDate,
        minimum_lease: 3_600,
        maximum_lease: 604_800,
        collateral_margin: 3_600,
        resource_schedule_hash,
        measurement_rules: vec![TeeMeasurementRuleV1 {
            mrenclave: B256::repeat_byte(0x81),
            mrsigner: B256::repeat_byte(0x82),
            isv_prod_id: 1,
            minimum_isv_svn: 2,
            admit_from_height: 1,
            admit_until_height_exclusive: u64::MAX,
        }],
    };
    policy
        .encode_canonical()
        .map_err(|error| format!("encode GramineDirectDev test policy: {error}"))?;
    Ok(policy)
}

pub fn tee_attestation_v1_extra_field(policy: &TeePolicyV1) -> Result<Value, String> {
    tee_attestation_v1_genesis_field(policy)
}

pub fn gramine_direct_bootstrap_v2(
    policy: TeePolicyV1,
    committee_snapshot_hash: B256,
    committee_snapshot_block: u64,
    requested_valid_until: u64,
    validators: &[DevValidatorV1],
) -> Result<TeeBootstrapV2, String> {
    if validators.is_empty() {
        return Err("GramineDirectDev test committee is empty".into());
    }

    let policy_hash = policy
        .policy_hash()
        .map_err(|error| format!("hash GramineDirectDev test policy: {error}"))?;
    let mut signers = BTreeMap::<Address, OutbeEvmSigner>::new();
    let mut submissions = Vec::with_capacity(validators.len());
    for (index, validator) in validators.iter().enumerate() {
        let signer = OutbeEvmSigner::from_secret_bytes(validator.evm_secret)
            .map_err(|error| format!("construct test validator signer: {error}"))?;
        let address = signer.address();
        if signers.insert(address, signer.clone()).is_some() {
            return Err("GramineDirectDev test committee contains a duplicate validator".into());
        }

        let ordinal = u64::try_from(index)
            .map_err(|_| "GramineDirectDev test validator index exceeds u64")?;
        let attestation_seed = deterministic_key(
            b"outbe/test/gramine-direct/attestation",
            &validator.evm_secret,
            ordinal,
        );
        let attestation = Ed25519KeyPair::from_seed_unchecked(&attestation_seed)
            .map_err(|_| "construct GramineDirectDev test attestation key")?;
        let attestation_public: [u8; 32] = attestation
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| "GramineDirectDev test attestation key is not Ed25519-32")?;
        let recipient_x25519 = deterministic_key(
            b"outbe/test/gramine-direct/recipient",
            &validator.evm_secret,
            ordinal,
        );
        let noise_responder_x25519 = deterministic_key(
            b"outbe/test/gramine-direct/noise",
            &validator.evm_secret,
            ordinal,
        );
        let binding_id = B256::from(deterministic_key(
            b"outbe/test/gramine-direct/binding",
            &validator.evm_secret,
            ordinal,
        ));
        let node_host_authorization_hash = B256::from(deterministic_key(
            b"outbe/test/gramine-direct/node-host",
            &validator.evm_secret,
            ordinal,
        ));
        let node_secret = deterministic_key(
            b"outbe/test/gramine-direct/node-host-p2p",
            &validator.evm_secret,
            ordinal,
        );
        let node_signer = k256::ecdsa::SigningKey::from_bytes((&node_secret).into())
            .map_err(|_| "construct GramineDirectDev test NodeHost signer")?;
        let reth_p2p_public = node_signer
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| "GramineDirectDev test NodeHost key is not SEC1-33")?;
        let mut intent = RegistrationIntentV1 {
            chain_id: policy.chain_id,
            genesis_hash: policy.genesis_hash,
            operation: AttestationOperationV1::RegisterEnclave,
            attestation_mode: AttestationMode::GramineDirectDev,
            policy_hash,
            node_id: NodeIdV1 { reth_p2p_public },
            enclave_id: B256::repeat_byte(1),
            binding_id,
            binding_version: 1,
            registration_version: 0,
            renewal_nonce: 0,
            transition_nonce: 0,
            requested_valid_until,
            recipient_x25519,
            attestation_ed25519: attestation_public,
            noise_responder_x25519,
            node_host_authorization_hash,
        };
        intent.enclave_id = intent
            .derived_enclave_id()
            .map_err(|error| format!("derive GramineDirectDev test enclave ID: {error}"))?;
        let intent_hash = intent
            .intent_hash()
            .map_err(|error| format!("hash GramineDirectDev test intent: {error}"))?;
        let (node_signature_body, node_recovery) = node_signer
            .sign_prehash(intent_hash.as_slice())
            .map_err(|_| "sign GramineDirectDev test intent as NodeHost")?;
        let mut node_signature = [0_u8; 65];
        node_signature[..64].copy_from_slice(node_signature_body.to_bytes().as_slice());
        node_signature[64] = node_recovery.to_byte();
        let validator_binding = ValidatorNodeBindingV1 {
            chain_id: policy.chain_id,
            genesis_hash: policy.genesis_hash,
            validator: address.into_array(),
            node_id_hash: intent
                .node_id
                .node_id_hash()
                .map_err(|error| format!("hash GramineDirectDev test NodeHost: {error}"))?,
        };
        let binding_hash = validator_binding
            .binding_hash()
            .map_err(|error| format!("hash GramineDirectDev validator binding: {error}"))?;
        let validator_signature = signer
            .sign_hash(&binding_hash)
            .map_err(|error| format!("sign GramineDirectDev validator binding: {error}"))?;
        let (node_binding_body, node_binding_recovery) = node_signer
            .sign_prehash(binding_hash.as_slice())
            .map_err(|_| "sign GramineDirectDev NodeHost binding")?;
        let mut node_binding_signature = [0_u8; 65];
        node_binding_signature[..64].copy_from_slice(node_binding_body.to_bytes().as_slice());
        node_binding_signature[64] = node_binding_recovery.to_byte();
        let enclave_signature: [u8; 64] = attestation
            .sign(intent_hash.as_slice())
            .as_ref()
            .try_into()
            .map_err(|_| "GramineDirectDev test signature is not Ed25519-64")?;
        submissions.push(TeeBootstrapParticipantSubmissionV2 {
            evidence: AttestationEvidenceV1::GramineDirectDev(GramineDirectEvidenceV1 {
                intent,
                dev_attestation_public: attestation_public,
                dev_signature: enclave_signature,
            }),
            validator_binding,
            validator_signature,
            node_binding_signature,
            node_signature,
            enclave_signature,
        });
    }

    let authority = TeeBootstrapAuthorityV2 {
        policy,
        committee_snapshot_hash,
        committee_snapshot_block,
        key_epoch: 0,
        tribute_offer_epoch: 0,
        dkg_transcript_hash: B256::ZERO,
        tribute_offer_public_key: B256::repeat_byte(0x23),
        tribute_offer_group_public_key: Bytes::from(vec![0x24; 96]),
    };
    let mut payload = TeeBootstrapV2::assemble_unsigned(authority, submissions)
        .map_err(|error| format!("assemble GramineDirectDev OST3 test payload: {error}"))?;
    let signing_hash = payload
        .signing_hash()
        .map_err(|error| format!("hash GramineDirectDev OST3 test payload: {error}"))?;
    for signature in &mut payload.committee_signatures {
        let signer = signers
            .get(&signature.validator)
            .ok_or_else(|| "assembled OST3 signer is absent from test committee".to_owned())?;
        signature.signature = signer
            .sign_hash(&signing_hash)
            .map_err(|error| format!("sign GramineDirectDev OST3 test payload: {error}"))?;
    }
    payload
        .encode_canonical()
        .map_err(|error| format!("validate GramineDirectDev OST3 test payload: {error}"))?;
    Ok(payload)
}

fn deterministic_key(domain: &[u8], secret: &[u8; 32], ordinal: u64) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(domain.len() + secret.len() + 8);
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(secret);
    preimage.extend_from_slice(&ordinal.to_be_bytes());
    let hash = keccak256(preimage);
    let mut key = [0_u8; 32];
    key.copy_from_slice(hash.as_slice());
    key
}
