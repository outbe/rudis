//! Vote payload encoding for scheduled updates.
//!
//! JSON schema:
//! ```json
//! {"version":"1.2", "activationHeight":12345, "info":"notes", "teePolicy":"<canonical TeePolicyV1 lowercase hex>"}
//! ```
//!
//! `version` is a `"major.minor"` string (no `v` prefix). Raw numeric JSON
//! values and undotted version strings are rejected. `teePolicy` is optional;
//! unknown fields and non-canonical encodings are rejected.

use outbe_ocompregistry::{poc_schema_limits, OcompSuccessorV1};
use outbe_primitives::tee_attestation_v1::{TeePolicyV1, MAX_TEE_POLICY_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::constants::min_activation_buffer;
use crate::errors::UpdateError;
use crate::version::{
    protocol_version_major, protocol_version_minor, try_parse_protocol_version, ProtocolVersion,
};

/// JSON payload for scheduling a protocol update via vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScheduleUpdatePayload {
    pub version: String,
    pub activation_height: u64,
    #[serde(default)]
    pub info: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocomp_successor: Option<String>,
}

impl ScheduleUpdatePayload {
    pub fn new(version: ProtocolVersion, activation_height: u64, info: impl Into<String>) -> Self {
        Self {
            version: Self::format_version(version),
            activation_height,
            info: info.into(),
            tee_policy: None,
            ocomp_successor: None,
        }
    }

    /// Builds an Update payload carrying one exact canonical successor TEE
    /// policy. The JSON uses bounded lowercase hex because Vote payloads are
    /// UTF-8 strings; callers never provide a policy hash without its rules.
    pub fn with_tee_policy(
        version: ProtocolVersion,
        activation_height: u64,
        info: impl Into<String>,
        policy: &TeePolicyV1,
    ) -> std::result::Result<Self, UpdateError> {
        let canonical = policy
            .encode_canonical()
            .map_err(|_| UpdateError::InvalidTeePolicy)?;
        Ok(Self {
            version: Self::format_version(version),
            activation_height,
            info: info.into(),
            tee_policy: Some(hex::encode(canonical)),
            ocomp_successor: None,
        })
    }

    /// Adds one exact predecessor-bound OCOMP successor to this Update.
    pub fn with_ocomp_successor(
        mut self,
        successor: &OcompSuccessorV1,
    ) -> std::result::Result<Self, UpdateError> {
        let canonical = successor
            .encode_canonical(&poc_schema_limits())
            .map_err(|_| UpdateError::InvalidOcompSuccessor)?;
        self.ocomp_successor = Some(hex::encode(canonical));
        Ok(self)
    }

    pub fn from_value(payload: &Value) -> std::result::Result<Self, UpdateError> {
        serde_json::from_value(payload.clone()).map_err(|_| UpdateError::InvalidPayload)
    }

    pub fn protocol_version(&self) -> std::result::Result<ProtocolVersion, UpdateError> {
        Self::parse_version(&self.version)
    }

    /// Decodes the optional canonical successor policy after enforcing the
    /// encoded cap before allocation.
    pub fn tee_policy(&self) -> std::result::Result<Option<TeePolicyV1>, UpdateError> {
        let Some(encoded) = self.tee_policy.as_deref() else {
            return Ok(None);
        };
        let maximum_hex_len = MAX_TEE_POLICY_BYTES
            .checked_mul(2)
            .ok_or(UpdateError::InvalidTeePolicy)?;
        if encoded.is_empty()
            || encoded.len() > maximum_hex_len
            || encoded.len() % 2 != 0
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(UpdateError::InvalidTeePolicy);
        }
        let canonical = hex::decode(encoded).map_err(|_| UpdateError::InvalidTeePolicy)?;
        TeePolicyV1::decode_canonical(&canonical)
            .map(Some)
            .map_err(|_| UpdateError::InvalidTeePolicy)
    }

    pub fn ocomp_successor(&self) -> std::result::Result<Option<OcompSuccessorV1>, UpdateError> {
        let Some(encoded) = self.ocomp_successor.as_deref() else {
            return Ok(None);
        };
        let maximum_hex_len = poc_schema_limits()
            .codec
            .max_allocation_bytes
            .checked_mul(2)
            .ok_or(UpdateError::InvalidOcompSuccessor)?;
        if encoded.is_empty()
            || encoded.len() > maximum_hex_len
            || encoded.len() % 2 != 0
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(UpdateError::InvalidOcompSuccessor);
        }
        let canonical = hex::decode(encoded).map_err(|_| UpdateError::InvalidOcompSuccessor)?;
        OcompSuccessorV1::decode_canonical(&canonical, &poc_schema_limits())
            .map(Some)
            .map_err(|_| UpdateError::InvalidOcompSuccessor)
    }

    pub fn validate(
        &self,
        current_height: u64,
        chain_id: u64,
    ) -> std::result::Result<(), UpdateError> {
        let version = self.protocol_version()?;
        if version.is_zero() {
            return Err(UpdateError::InvalidVersion);
        }
        let min_activation = current_height.saturating_add(min_activation_buffer(chain_id));
        if self.activation_height < min_activation {
            return Err(UpdateError::HeightInPast);
        }
        if let Some(policy) = self.tee_policy()? {
            let mut expected_chain_id = [0u8; 32];
            expected_chain_id[24..].copy_from_slice(&chain_id.to_be_bytes());
            if policy.chain_id != expected_chain_id {
                return Err(UpdateError::TeePolicyChainIdentityMismatch);
            }
            if policy.activation_height != self.activation_height {
                return Err(UpdateError::TeePolicyActivationMismatch);
            }
        }
        if let Some(successor) = self.ocomp_successor()? {
            if successor.authority.request_profile.chain_id != chain_id {
                return Err(UpdateError::OcompSuccessorChainIdentityMismatch);
            }
            if successor.activation_height != self.activation_height {
                return Err(UpdateError::OcompSuccessorActivationMismatch);
            }
        }
        Ok(())
    }

    /// Formats a protocol version as the vote-payload string `"major.minor"`.
    fn format_version(version: ProtocolVersion) -> String {
        format!(
            "{}.{}",
            protocol_version_major(version),
            protocol_version_minor(version)
        )
    }

    /// Parses a vote-payload `"major.minor"` version string.
    fn parse_version(version: &str) -> std::result::Result<ProtocolVersion, UpdateError> {
        // Require dotted major.minor form; reject raw numeric strings like "65538".
        if !version.contains('.') {
            return Err(UpdateError::InvalidPayload);
        }
        try_parse_protocol_version(version).map_err(|_| UpdateError::InvalidVersion)
    }
}

/// Encodes update fields into a vote JSON payload string.
pub fn encode_schedule_update_json(
    version: ProtocolVersion,
    activation_height: u64,
    info: &str,
) -> String {
    serde_json::to_string(&ScheduleUpdatePayload::new(
        version,
        activation_height,
        info,
    ))
    .expect("schedule update payload JSON should serialize")
}

/// Decodes a vote JSON payload into update fields.
pub fn decode_schedule_update_json(
    payload: &Value,
) -> std::result::Result<(ProtocolVersion, u64, String), UpdateError> {
    let decoded = ScheduleUpdatePayload::from_value(payload)?;
    Ok((
        decoded.protocol_version()?,
        decoded.activation_height,
        decoded.info,
    ))
}

/// Validates structural update JSON fields and activation-height buffer.
pub fn validate_schedule_update_json(
    payload: &Value,
    current_height: u64,
    chain_id: u64,
) -> std::result::Result<(), UpdateError> {
    ScheduleUpdatePayload::from_value(payload)?.validate(current_height, chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MIN_ACTIVATION_BUFFER;
    use crate::encode_protocol_version;
    use alloy_primitives::B256;
    use outbe_primitives::tee_attestation_v1::{
        AttestationMode, PlatformTcbStatusSetV1, QvlTcbStatusV1, TeeMeasurementRuleV1, TeePolicyV1,
    };

    const LOCALNET_CHAIN_ID: u64 = 70_860_602;
    const OTHER_CHAIN_ID: u64 = 1;

    fn payload(activation_height: u64) -> ScheduleUpdatePayload {
        ScheduleUpdatePayload::new(ProtocolVersion::from(2), activation_height, "notes")
    }

    fn successor_policy(chain_id: u64, activation_height: u64) -> TeePolicyV1 {
        let mut chain_id_word = [0u8; 32];
        chain_id_word[24..].copy_from_slice(&chain_id.to_be_bytes());
        TeePolicyV1 {
            policy_version: 2,
            chain_id: chain_id_word,
            genesis_hash: B256::repeat_byte(0x11),
            activation_height,
            predecessor_policy_hash: B256::repeat_byte(0x22),
            attestation_mode: AttestationMode::DcapRequired,
            intel_root_der_hash: B256::repeat_byte(0x33),
            quote_version: 3,
            tee_type: 0,
            attestation_key_type: 2,
            qe_vendor_id: [
                0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f,
                0x06, 0x07,
            ],
            certification_data_type: 5,
            tcb_info_schema_version: 3,
            qe_identity_schema_version: 2,
            minimum_tcb_evaluation_data_number: 1,
            accepted_platform_tcb_statuses: PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
            accepted_qe_tcb_status: QvlTcbStatusV1::UpToDate,
            minimum_lease: 3_600,
            maximum_lease: 604_800,
            collateral_margin: 3_600,
            resource_schedule_hash: B256::repeat_byte(0x44),
            measurement_rules: vec![TeeMeasurementRuleV1 {
                mrenclave: B256::repeat_byte(0x55),
                mrsigner: B256::repeat_byte(0x66),
                isv_prod_id: 7,
                minimum_isv_svn: 2,
                admit_from_height: activation_height,
                admit_until_height_exclusive: u64::MAX,
            }],
        }
    }

    #[test]
    fn update_payload_roundtrips_exact_successor_tee_policy() {
        let version = encode_protocol_version(1, 2);
        let activation_height = 12_345;
        let policy = successor_policy(OTHER_CHAIN_ID, activation_height);
        let payload = ScheduleUpdatePayload::with_tee_policy(
            version,
            activation_height,
            "release notes",
            &policy,
        )
        .unwrap();

        payload.validate(100, OTHER_CHAIN_ID).unwrap();
        assert_eq!(payload.tee_policy().unwrap(), Some(policy));

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: ScheduleUpdatePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(decoded.tee_policy().unwrap(), payload.tee_policy().unwrap());
    }

    #[test]
    fn update_payload_rejects_unknown_policy_authority_fields() {
        let value: Value = serde_json::from_str(
            r#"{"version":"1.2","activationHeight":1000,"info":"","policyHash":"0x01"}"#,
        )
        .unwrap();
        assert_eq!(
            ScheduleUpdatePayload::from_value(&value).unwrap_err(),
            UpdateError::InvalidPayload
        );
    }

    #[test]
    fn tee_policy_hex_is_bounded_and_lowercase() {
        let activation_height = 12_345;
        let policy = successor_policy(OTHER_CHAIN_ID, activation_height);
        let mut payload = ScheduleUpdatePayload::with_tee_policy(
            encode_protocol_version(1, 2),
            activation_height,
            "release",
            &policy,
        )
        .unwrap();

        payload.tee_policy = Some("AA".into());
        assert_eq!(
            payload.tee_policy().unwrap_err(),
            UpdateError::InvalidTeePolicy
        );

        payload.tee_policy = Some("a".repeat(MAX_TEE_POLICY_BYTES * 2 + 2));
        assert_eq!(
            payload.tee_policy().unwrap_err(),
            UpdateError::InvalidTeePolicy
        );
    }

    #[test]
    fn update_payload_binds_tee_policy_to_chain_and_activation_height() {
        let version = encode_protocol_version(1, 2);
        let activation_height = 12_345;
        let wrong_chain = successor_policy(LOCALNET_CHAIN_ID, activation_height);
        let payload = ScheduleUpdatePayload::with_tee_policy(
            version,
            activation_height,
            "release",
            &wrong_chain,
        )
        .unwrap();
        assert_eq!(
            payload.validate(100, OTHER_CHAIN_ID).unwrap_err(),
            UpdateError::TeePolicyChainIdentityMismatch
        );

        let wrong_height = successor_policy(OTHER_CHAIN_ID, activation_height + 1);
        let payload = ScheduleUpdatePayload::with_tee_policy(
            version,
            activation_height,
            "release",
            &wrong_height,
        )
        .unwrap();
        assert_eq!(
            payload.validate(100, OTHER_CHAIN_ID).unwrap_err(),
            UpdateError::TeePolicyActivationMismatch
        );
    }

    #[test]
    fn localnet_allows_immediate_activation() {
        // buffer is 0 on localnet: activation at the current height is accepted.
        assert!(payload(100).validate(100, LOCALNET_CHAIN_ID).is_ok());
    }

    #[test]
    fn other_chains_still_require_the_buffer() {
        let current = 100;
        let just_under = current + MIN_ACTIVATION_BUFFER - 1;
        assert!(matches!(
            payload(just_under).validate(current, OTHER_CHAIN_ID),
            Err(UpdateError::HeightInPast)
        ));
        assert!(payload(current + MIN_ACTIVATION_BUFFER)
            .validate(current, OTHER_CHAIN_ID)
            .is_ok());
    }

    #[test]
    fn encode_decode_roundtrip_major_minor_string() {
        let version = encode_protocol_version(1, 2);
        let json = encode_schedule_update_json(version, 12345, "notes");
        assert!(json.contains(r#""version":"1.2""#), "json={json}");

        let value: Value = serde_json::from_str(&json).unwrap();
        let (decoded, height, info) = decode_schedule_update_json(&value).unwrap();
        assert_eq!(decoded, version);
        assert_eq!(height, 12345);
        assert_eq!(info, "notes");
    }

    #[test]
    fn rejects_numeric_version_json() {
        let value: Value =
            serde_json::from_str(r#"{"version":65538,"activationHeight":1000,"info":""}"#).unwrap();
        assert_eq!(
            decode_schedule_update_json(&value).unwrap_err(),
            UpdateError::InvalidPayload
        );
    }

    #[test]
    fn rejects_undotted_version_string() {
        let value: Value =
            serde_json::from_str(r#"{"version":"65538","activationHeight":1000,"info":""}"#)
                .unwrap();
        assert_eq!(
            decode_schedule_update_json(&value).unwrap_err(),
            UpdateError::InvalidPayload
        );
    }

    #[test]
    fn rejects_zero_major_minor_version() {
        let value: Value =
            serde_json::from_str(r#"{"version":"0.0","activationHeight":1000,"info":""}"#).unwrap();
        assert_eq!(
            validate_schedule_update_json(&value, 0, LOCALNET_CHAIN_ID).unwrap_err(),
            UpdateError::InvalidVersion
        );
    }
}
