//! Canonical block-1 TEE policy and ChainSpec-manifest construction.
//!
//! The development profile is selected explicitly in genesis, never as a
//! fallback for an unavailable DCAP verifier. It is admitted on the devnet and
//! testnet identities so the same fresh testnet topology can run without SGX.
//! `DcapRequired` construction still requires the exact signed-enclave
//! measurement tuple; no placeholder DCAP policy can be emitted through this
//! API.

use alloy_primitives::{keccak256, B256, U256};
use serde_json::{json, Value};

use crate::{
    chain::{DEVNET_CHAIN_ID, MAINNET_CHAIN_ID, TESTNET_CHAIN_ID},
    tee_attestation_v1::{
        AttestationMode, PlatformTcbStatusSetV1, QvlTcbStatusV1, ResourceScheduleV1,
        TeeMeasurementRuleV1, TeePolicyScheduleEntryV1, TeePolicyScheduleV1, TeePolicyV1,
    },
};

/// Primary chain ID for the runnable Gramine Direct devnet.
pub const GRAMINE_DIRECT_DEV_CHAIN_ID: u64 = DEVNET_CHAIN_ID;

/// Returns whether an explicitly configured development policy may use this
/// fresh-network identity. Testnet keeps requiring an explicit genesis
/// `GramineDirectDev` policy; this is not a runtime fallback from DCAP.
pub const fn is_gramine_direct_dev_chain_id(chain_id: u64) -> bool {
    chain_id == DEVNET_CHAIN_ID || chain_id == TESTNET_CHAIN_ID
}

/// Returns whether the chain has a production DCAP identity.
pub const fn is_dcap_required_chain_id(chain_id: u64) -> bool {
    chain_id == DEVNET_CHAIN_ID || chain_id == TESTNET_CHAIN_ID || chain_id == MAINNET_CHAIN_ID
}

/// Returns whether a product network may select this explicit attestation
/// mode at genesis. The selected mode is subsequently fixed for the life of
/// the chain by TeeRegistry successor-policy validation.
pub const fn is_attestation_mode_allowed_for_chain_id(
    chain_id: u64,
    mode: AttestationMode,
) -> bool {
    match mode {
        AttestationMode::DcapRequired => is_dcap_required_chain_id(chain_id),
        AttestationMode::GramineDirectDev => is_gramine_direct_dev_chain_id(chain_id),
    }
}

/// SHA-256 of Intel's pinned SGX Root CA DER certificate.
pub const INTEL_SGX_ROOT_CA_DER_SHA256: [u8; 32] = [
    0x44, 0xa0, 0x19, 0x6b, 0x2b, 0x99, 0xf8, 0x89, 0xb8, 0xe1, 0x49, 0xe9, 0x5b, 0x80, 0x7a, 0x35,
    0x0e, 0x74, 0x24, 0x96, 0x43, 0x99, 0xe8, 0x85, 0xa7, 0xcb, 0xb8, 0xcc, 0xfa, 0xb6, 0x74, 0xd3,
];

const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

/// Canonical production enclave lease period: fourteen consensus days.
pub const PRODUCTION_TEE_LEASE_SECONDS_V1: u64 = 14 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionSgxMeasurementV1 {
    pub mrenclave: B256,
    pub mrsigner: B256,
    pub isv_prod_id: u16,
    pub minimum_isv_svn: u16,
    pub minimum_tcb_evaluation_data_number: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialTeeProfileV1 {
    DcapRequired(ProductionSgxMeasurementV1),
    GramineDirectDev,
}

impl InitialTeeProfileV1 {
    pub const fn attestation_mode(self) -> AttestationMode {
        match self {
            Self::DcapRequired(_) => AttestationMode::DcapRequired,
            Self::GramineDirectDev => AttestationMode::GramineDirectDev,
        }
    }
}

/// Build the only policy shape permitted at block 1.
///
/// NodeHost admission is role-neutral because every role executes the same
/// pinned enclave binary.
pub fn initial_tee_policy_v1(
    profile: InitialTeeProfileV1,
    chain_id: u64,
    genesis_hash: B256,
) -> Result<TeePolicyV1, String> {
    if genesis_hash.is_zero() {
        return Err("TEE genesis policy requires a non-zero genesis hash".into());
    }
    match profile.attestation_mode() {
        AttestationMode::DcapRequired
            if !is_attestation_mode_allowed_for_chain_id(
                chain_id,
                AttestationMode::DcapRequired,
            ) =>
        {
            return Err(format!(
                "DcapRequired requires devnet, testnet, or mainnet chain ID ({DEVNET_CHAIN_ID}, {TESTNET_CHAIN_ID}, or {MAINNET_CHAIN_ID})"
            ));
        }
        AttestationMode::GramineDirectDev
            if !is_attestation_mode_allowed_for_chain_id(
                chain_id,
                AttestationMode::GramineDirectDev,
            ) =>
        {
            return Err(format!(
                "GramineDirectDev requires devnet or testnet chain ID ({DEVNET_CHAIN_ID} or {TESTNET_CHAIN_ID})"
            ));
        }
        _ => {}
    }

    let resource_schedule_hash = ResourceScheduleV1::normative()
        .and_then(|schedule| schedule.schedule_hash())
        .map_err(|error| format!("derive normative resource schedule: {error}"))?;
    let (minimum_tcb_evaluation_data_number, measurement_rule) = match profile {
        InitialTeeProfileV1::DcapRequired(measurement) => {
            if measurement.mrenclave.is_zero() || measurement.mrsigner.is_zero() {
                return Err("DcapRequired measurements must be non-zero".into());
            }
            if measurement.minimum_tcb_evaluation_data_number == 0 {
                return Err(
                    "DcapRequired minimum TCB evaluation data number must be non-zero".into(),
                );
            }
            let rule = TeeMeasurementRuleV1 {
                mrenclave: measurement.mrenclave,
                mrsigner: measurement.mrsigner,
                isv_prod_id: measurement.isv_prod_id,
                minimum_isv_svn: measurement.minimum_isv_svn,
                admit_from_height: 1,
                admit_until_height_exclusive: u64::MAX,
            };
            (measurement.minimum_tcb_evaluation_data_number, rule)
        }
        InitialTeeProfileV1::GramineDirectDev => {
            // These are domain-separated non-hardware projections used only by
            // the explicitly separate development policy. They are not SGX
            // measurements and cannot be selected by DcapRequired construction.
            let rule = TeeMeasurementRuleV1 {
                mrenclave: keccak256(b"outbe/tee/gramine-direct-dev/mrenclave/v1"),
                mrsigner: keccak256(b"outbe/tee/gramine-direct-dev/mrsigner/v1"),
                isv_prod_id: 1,
                minimum_isv_svn: 1,
                admit_from_height: 1,
                admit_until_height_exclusive: u64::MAX,
            };
            (1, rule)
        }
    };

    let policy = TeePolicyV1 {
        policy_version: 1,
        chain_id: U256::from(chain_id).to_be_bytes(),
        genesis_hash,
        activation_height: 1,
        predecessor_policy_hash: B256::ZERO,
        attestation_mode: profile.attestation_mode(),
        intel_root_der_hash: B256::from(INTEL_SGX_ROOT_CA_DER_SHA256),
        quote_version: 3,
        tee_type: 0,
        attestation_key_type: 2,
        qe_vendor_id: INTEL_QE_VENDOR_ID,
        certification_data_type: 5,
        tcb_info_schema_version: 3,
        qe_identity_schema_version: 2,
        minimum_tcb_evaluation_data_number,
        accepted_platform_tcb_statuses: PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        accepted_qe_tcb_status: QvlTcbStatusV1::UpToDate,
        minimum_lease: 3_600,
        maximum_lease: PRODUCTION_TEE_LEASE_SECONDS_V1,
        collateral_margin: 3_600,
        resource_schedule_hash,
        measurement_rules: vec![measurement_rule],
    };
    policy
        .encode_canonical()
        .map_err(|error| format!("encode initial TEE policy: {error}"))?;
    Ok(policy)
}

/// Encode the canonical one-entry policy schedule into the genesis config
/// field consumed by every testnet node.
pub fn tee_attestation_v1_genesis_field(policy: &TeePolicyV1) -> Result<Value, String> {
    let schedule = TeePolicyScheduleV1 {
        chain_id: policy.chain_id,
        genesis_hash: policy.genesis_hash,
        entries: vec![TeePolicyScheduleEntryV1 {
            activation_height: policy.activation_height,
            policy: policy.clone(),
        }],
    };
    let encoded = schedule
        .encode_canonical()
        .map_err(|error| format!("encode initial TEE policy schedule: {error}"))?;
    let policy_schedule_hash = schedule
        .schedule_hash()
        .map_err(|error| format!("hash initial TEE policy schedule: {error}"))?;
    Ok(json!({
        "activationHeight": 1,
        "policySchedule": format!("0x{}", hex::encode(encoded)),
        "policyScheduleHash": policy_schedule_hash,
        "resourceScheduleHash": policy.resource_schedule_hash,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{DEVNET_CHAIN_ID, MAINNET_CHAIN_ID, TESTNET_CHAIN_ID};

    fn dcap_measurement() -> ProductionSgxMeasurementV1 {
        ProductionSgxMeasurementV1 {
            mrenclave: B256::repeat_byte(0x11),
            mrsigner: B256::repeat_byte(0x22),
            isv_prod_id: 7,
            minimum_isv_svn: 3,
            minimum_tcb_evaluation_data_number: 17,
        }
    }

    #[test]
    fn devnet_and_testnet_accept_both_modes_while_mainnet_requires_dcap() {
        let genesis_hash = B256::repeat_byte(0x33);
        assert_eq!(GRAMINE_DIRECT_DEV_CHAIN_ID, DEVNET_CHAIN_ID);
        assert_ne!(GRAMINE_DIRECT_DEV_CHAIN_ID, TESTNET_CHAIN_ID);
        assert!(initial_tee_policy_v1(
            InitialTeeProfileV1::DcapRequired(dcap_measurement()),
            TESTNET_CHAIN_ID,
            genesis_hash,
        )
        .is_ok());
        assert!(initial_tee_policy_v1(
            InitialTeeProfileV1::DcapRequired(dcap_measurement()),
            MAINNET_CHAIN_ID,
            genesis_hash,
        )
        .is_ok());
        assert!(initial_tee_policy_v1(
            InitialTeeProfileV1::DcapRequired(dcap_measurement()),
            DEVNET_CHAIN_ID,
            genesis_hash,
        )
        .is_ok());
        assert!(initial_tee_policy_v1(
            InitialTeeProfileV1::DcapRequired(dcap_measurement()),
            DEVNET_CHAIN_ID + 1,
            genesis_hash,
        )
        .unwrap_err()
        .contains("devnet, testnet, or mainnet"));
        assert!(initial_tee_policy_v1(
            InitialTeeProfileV1::GramineDirectDev,
            TESTNET_CHAIN_ID,
            genesis_hash,
        )
        .is_ok());
        assert!(initial_tee_policy_v1(
            InitialTeeProfileV1::GramineDirectDev,
            DEVNET_CHAIN_ID,
            genesis_hash,
        )
        .is_ok());
        assert!(initial_tee_policy_v1(
            InitialTeeProfileV1::GramineDirectDev,
            MAINNET_CHAIN_ID,
            genesis_hash,
        )
        .is_err());
        assert!(initial_tee_policy_v1(
            InitialTeeProfileV1::GramineDirectDev,
            TESTNET_CHAIN_ID + 1,
            genesis_hash,
        )
        .unwrap_err()
        .contains("devnet or testnet chain ID"));
    }

    #[test]
    fn dcap_policy_pins_one_role_neutral_release_measurement() {
        let measurement = dcap_measurement();
        let policy = initial_tee_policy_v1(
            InitialTeeProfileV1::DcapRequired(measurement),
            TESTNET_CHAIN_ID,
            B256::repeat_byte(0x33),
        )
        .unwrap();
        assert_eq!(policy.attestation_mode, AttestationMode::DcapRequired);
        assert_eq!(policy.measurement_rules.len(), 1);
        for rule in &policy.measurement_rules {
            assert_eq!(rule.mrenclave, measurement.mrenclave);
            assert_eq!(rule.mrsigner, measurement.mrsigner);
            assert_eq!(rule.isv_prod_id, measurement.isv_prod_id);
            assert_eq!(rule.minimum_isv_svn, measurement.minimum_isv_svn);
        }
        assert_eq!(
            policy.accepted_platform_tcb_statuses,
            PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded
        );
        assert_eq!(policy.accepted_qe_tcb_status, QvlTcbStatusV1::UpToDate);
        assert_eq!(policy.minimum_lease, 3_600);
        assert_eq!(policy.maximum_lease, 14 * 24 * 60 * 60);
    }

    #[test]
    fn dcap_policy_rejects_zero_release_measurements() {
        let genesis_hash = B256::repeat_byte(0x33);
        for measurement in [
            ProductionSgxMeasurementV1 {
                mrenclave: B256::ZERO,
                ..dcap_measurement()
            },
            ProductionSgxMeasurementV1 {
                mrsigner: B256::ZERO,
                ..dcap_measurement()
            },
            ProductionSgxMeasurementV1 {
                minimum_tcb_evaluation_data_number: 0,
                ..dcap_measurement()
            },
        ] {
            assert!(initial_tee_policy_v1(
                InitialTeeProfileV1::DcapRequired(measurement),
                TESTNET_CHAIN_ID,
                genesis_hash,
            )
            .is_err());
        }
    }

    #[test]
    fn development_field_is_canonical_but_not_hardware_evidence() {
        let policy = initial_tee_policy_v1(
            InitialTeeProfileV1::GramineDirectDev,
            GRAMINE_DIRECT_DEV_CHAIN_ID,
            B256::repeat_byte(0x44),
        )
        .unwrap();
        let field = tee_attestation_v1_genesis_field(&policy).unwrap();
        let encoded = field["policySchedule"]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap();
        let schedule =
            TeePolicyScheduleV1::decode_canonical(&hex::decode(encoded).unwrap()).unwrap();
        assert_eq!(
            schedule.active_policy(1).unwrap().attestation_mode,
            AttestationMode::GramineDirectDev
        );
        assert_eq!(schedule.active_policy(1).unwrap(), &policy);
        assert_eq!(
            field["policyScheduleHash"],
            json!(schedule.schedule_hash().unwrap())
        );
        assert_eq!(policy.measurement_rules.len(), 1);
        let rule = &policy.measurement_rules[0];
        assert_eq!(
            rule.mrenclave,
            keccak256(b"outbe/tee/gramine-direct-dev/mrenclave/v1")
        );
        assert_eq!(
            rule.mrsigner,
            keccak256(b"outbe/tee/gramine-direct-dev/mrsigner/v1")
        );
        assert_ne!(rule.mrenclave, rule.mrsigner);
    }
}
