//! Immutable protocol parameters shared by every runtime module.

use serde::{Deserialize, Serialize};
#[cfg(feature = "test-protocol-overrides")]
use std::sync::OnceLock;
use thiserror::Error;

pub const GENESIS_CONFIG_KEY: &str = "outbeProtocol";
pub const PROTOCOL_CONSTANTS_SCHEMA_VERSION: u16 = 1;

pub const DEFAULT_METADOSIS_FORMING_PERIOD_SECONDS: u64 = 50 * 60 * 60;
pub const DEFAULT_METADOSIS_LOOKBACK_DELAY_SECONDS: u64 = 502 * 60 * 60;
pub const DEFAULT_METADOSIS_OFFERING_PERIOD_SECONDS: u64 = 50 * 60 * 60;
pub const DEFAULT_METADOSIS_WAITING_PERIOD_SECONDS: u64 = 12 * 60 * 60;
pub const DEFAULT_METADOSIS_BOOTSTRAP_DURATION_SECONDS: u64 = 504 * 60 * 60;
pub const DEFAULT_METADOSIS_ADVANCE_INTERVAL_SECONDS: u64 = 60 * 60;
pub const DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS: u64 = 1_800;
pub const DEFAULT_GOVERNANCE_VOTING_WINDOW_BLOCKS: u64 = 86_400;
pub const DEFAULT_NOD_MATERIALIZATION_BATCH_SUBTREE_HEIGHT: u8 = 3;
pub const DEFAULT_NOD_MATERIALIZATION_RETRY_INTERVAL_BLOCKS: u64 = 30;
pub const DEFAULT_NOD_MATERIALIZATION_MAX_ATTEMPTS_PER_BLOCK: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisProtocolParametersV1 {
    pub governance_voting_window_blocks: u64,
    pub metadosis_forming_period_seconds: u64,
    pub metadosis_lookback_delay_seconds: u64,
    pub metadosis_offering_period_seconds: u64,
    pub metadosis_waiting_period_seconds: u64,
    pub metadosis_bootstrap_duration_seconds: u64,
    pub metadosis_advance_interval_seconds: u64,
    pub ocomp_compute_vote_window_blocks: u64,
    pub nod_materialization_batch_subtree_height: u8,
    pub nod_materialization_retry_interval_blocks: u64,
    pub nod_materialization_max_attempts_per_block: u16,
}

const DEFAULTS: GenesisProtocolParametersV1 = GenesisProtocolParametersV1 {
    governance_voting_window_blocks: DEFAULT_GOVERNANCE_VOTING_WINDOW_BLOCKS,
    metadosis_forming_period_seconds: DEFAULT_METADOSIS_FORMING_PERIOD_SECONDS,
    metadosis_lookback_delay_seconds: DEFAULT_METADOSIS_LOOKBACK_DELAY_SECONDS,
    metadosis_offering_period_seconds: DEFAULT_METADOSIS_OFFERING_PERIOD_SECONDS,
    metadosis_waiting_period_seconds: DEFAULT_METADOSIS_WAITING_PERIOD_SECONDS,
    metadosis_bootstrap_duration_seconds: DEFAULT_METADOSIS_BOOTSTRAP_DURATION_SECONDS,
    metadosis_advance_interval_seconds: DEFAULT_METADOSIS_ADVANCE_INTERVAL_SECONDS,
    ocomp_compute_vote_window_blocks: DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS,
    nod_materialization_batch_subtree_height: DEFAULT_NOD_MATERIALIZATION_BATCH_SUBTREE_HEIGHT,
    nod_materialization_retry_interval_blocks: DEFAULT_NOD_MATERIALIZATION_RETRY_INTERVAL_BLOCKS,
    nod_materialization_max_attempts_per_block: DEFAULT_NOD_MATERIALIZATION_MAX_ATTEMPTS_PER_BLOCK,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodMaterializationProfileV1 {
    pub batch_subtree_height: u8,
    pub retry_interval_blocks: u64,
    pub max_attempts_per_block: u16,
}

impl Default for NodMaterializationProfileV1 {
    fn default() -> Self {
        Self {
            batch_subtree_height: DEFAULT_NOD_MATERIALIZATION_BATCH_SUBTREE_HEIGHT,
            retry_interval_blocks: DEFAULT_NOD_MATERIALIZATION_RETRY_INTERVAL_BLOCKS,
            max_attempts_per_block: DEFAULT_NOD_MATERIALIZATION_MAX_ATTEMPTS_PER_BLOCK,
        }
    }
}

impl NodMaterializationProfileV1 {
    pub fn batch_capacity(self) -> Result<usize, ProtocolConstantsError> {
        1_usize
            .checked_shl(u32::from(self.batch_subtree_height))
            .ok_or(ProtocolConstantsError::InvalidValue {
                field: "nodMaterialization.batchSubtreeHeight",
                requirement: "produce a capacity in 1..=256",
                actual: u64::from(self.batch_subtree_height),
            })
    }

    fn validate(self) -> Result<(), ProtocolConstantsError> {
        let capacity = self.batch_capacity()?;
        if capacity == 0 || capacity > 256 {
            return Err(ProtocolConstantsError::InvalidValue {
                field: "nodMaterialization.batchSubtreeHeight",
                requirement: "produce a capacity in 1..=256",
                actual: u64::from(self.batch_subtree_height),
            });
        }
        if self.retry_interval_blocks == 0 {
            return Err(ProtocolConstantsError::InvalidValue {
                field: "nodMaterialization.retryIntervalBlocks",
                requirement: "be non-zero",
                actual: 0,
            });
        }
        if self.max_attempts_per_block == 0 {
            return Err(ProtocolConstantsError::InvalidValue {
                field: "nodMaterialization.maxAttemptsPerBlock",
                requirement: "be non-zero",
                actual: 0,
            });
        }
        Ok(())
    }
}

impl Default for GenesisProtocolParametersV1 {
    fn default() -> Self {
        DEFAULTS
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenesisProtocolOverridesV1 {
    #[serde(default)]
    governance: GovernanceOverridesV1,
    #[serde(default)]
    schema_version: Option<u16>,
    #[serde(default)]
    metadosis: MetadosisOverridesV1,
    #[serde(default)]
    ocomp: OcompOverridesV1,
    #[serde(default)]
    nod_materialization: NodMaterializationOverridesV1,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NodMaterializationOverridesV1 {
    batch_subtree_height: Option<u8>,
    retry_interval_blocks: Option<u64>,
    max_attempts_per_block: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MetadosisOverridesV1 {
    forming_period_seconds: Option<u64>,
    lookback_delay_seconds: Option<u64>,
    offering_period_seconds: Option<u64>,
    waiting_period_seconds: Option<u64>,
    bootstrap_duration_seconds: Option<u64>,
    advance_interval_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OcompOverridesV1 {
    compute_vote_window_blocks: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GovernanceOverridesV1 {
    voting_window_blocks: Option<u64>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolConstantsError {
    #[error("invalid genesis {GENESIS_CONFIG_KEY}: {0}")]
    InvalidJson(String),
    #[error("unsupported protocol constants schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("protocol constant {field} must be {requirement}, got {actual}")]
    InvalidValue {
        field: &'static str,
        requirement: &'static str,
        actual: u64,
    },
    #[error("config.{GENESIS_CONFIG_KEY} is supported only by test-protocol-overrides builds")]
    UnsupportedInProduction,
    #[error("protocol constants were already initialized")]
    AlreadyInitialized,
}

impl GenesisProtocolParametersV1 {
    pub fn resolve(value: Option<&serde_json::Value>) -> Result<Self, ProtocolConstantsError> {
        let overrides = match value {
            Some(value) => serde_json::from_value::<GenesisProtocolOverridesV1>(value.clone())
                .map_err(|error| ProtocolConstantsError::InvalidJson(error.to_string()))?,
            None => GenesisProtocolOverridesV1::default(),
        };
        if let Some(version) = overrides.schema_version {
            if version != PROTOCOL_CONSTANTS_SCHEMA_VERSION {
                return Err(ProtocolConstantsError::UnsupportedSchemaVersion(version));
            }
        }
        let defaults = Self::default();
        let resolved = Self {
            governance_voting_window_blocks: overrides
                .governance
                .voting_window_blocks
                .unwrap_or(defaults.governance_voting_window_blocks),
            metadosis_forming_period_seconds: overrides
                .metadosis
                .forming_period_seconds
                .unwrap_or(defaults.metadosis_forming_period_seconds),
            metadosis_lookback_delay_seconds: overrides
                .metadosis
                .lookback_delay_seconds
                .unwrap_or(defaults.metadosis_lookback_delay_seconds),
            metadosis_offering_period_seconds: overrides
                .metadosis
                .offering_period_seconds
                .unwrap_or(defaults.metadosis_offering_period_seconds),
            metadosis_waiting_period_seconds: overrides
                .metadosis
                .waiting_period_seconds
                .unwrap_or(defaults.metadosis_waiting_period_seconds),
            metadosis_bootstrap_duration_seconds: overrides
                .metadosis
                .bootstrap_duration_seconds
                .unwrap_or(defaults.metadosis_bootstrap_duration_seconds),
            metadosis_advance_interval_seconds: overrides
                .metadosis
                .advance_interval_seconds
                .unwrap_or(defaults.metadosis_advance_interval_seconds),
            ocomp_compute_vote_window_blocks: overrides
                .ocomp
                .compute_vote_window_blocks
                .unwrap_or(defaults.ocomp_compute_vote_window_blocks),
            nod_materialization_batch_subtree_height: overrides
                .nod_materialization
                .batch_subtree_height
                .unwrap_or(defaults.nod_materialization_batch_subtree_height),
            nod_materialization_retry_interval_blocks: overrides
                .nod_materialization
                .retry_interval_blocks
                .unwrap_or(defaults.nod_materialization_retry_interval_blocks),
            nod_materialization_max_attempts_per_block: overrides
                .nod_materialization
                .max_attempts_per_block
                .unwrap_or(defaults.nod_materialization_max_attempts_per_block),
        };
        resolved.validate()?;
        Ok(resolved)
    }

    pub fn validate(self) -> Result<(), ProtocolConstantsError> {
        validate_nonzero_at_most(
            "governance.votingWindowBlocks",
            self.governance_voting_window_blocks,
            DEFAULT_GOVERNANCE_VOTING_WINDOW_BLOCKS,
        )?;
        validate_nonzero_at_most(
            "metadosis.formingPeriodSeconds",
            self.metadosis_forming_period_seconds,
            DEFAULT_METADOSIS_FORMING_PERIOD_SECONDS,
        )?;
        NodMaterializationProfileV1 {
            batch_subtree_height: self.nod_materialization_batch_subtree_height,
            retry_interval_blocks: self.nod_materialization_retry_interval_blocks,
            max_attempts_per_block: self.nod_materialization_max_attempts_per_block,
        }
        .validate()?;
        validate_at_most(
            "metadosis.lookbackDelaySeconds",
            self.metadosis_lookback_delay_seconds,
            DEFAULT_METADOSIS_LOOKBACK_DELAY_SECONDS,
        )?;
        validate_nonzero_at_most(
            "metadosis.offeringPeriodSeconds",
            self.metadosis_offering_period_seconds,
            DEFAULT_METADOSIS_OFFERING_PERIOD_SECONDS,
        )?;
        validate_nonzero_at_most(
            "metadosis.waitingPeriodSeconds",
            self.metadosis_waiting_period_seconds,
            DEFAULT_METADOSIS_WAITING_PERIOD_SECONDS,
        )?;
        validate_nonzero_at_most(
            "metadosis.bootstrapDurationSeconds",
            self.metadosis_bootstrap_duration_seconds,
            DEFAULT_METADOSIS_BOOTSTRAP_DURATION_SECONDS,
        )?;
        validate_nonzero_at_most(
            "metadosis.advanceIntervalSeconds",
            self.metadosis_advance_interval_seconds,
            DEFAULT_METADOSIS_ADVANCE_INTERVAL_SECONDS,
        )?;
        validate_nonzero_at_most(
            "ocomp.computeVoteWindowBlocks",
            self.ocomp_compute_vote_window_blocks,
            DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS,
        )?;

        self.metadosis_forming_period_seconds
            .checked_add(self.metadosis_lookback_delay_seconds)
            .and_then(|value| value.checked_add(self.metadosis_offering_period_seconds))
            .and_then(|value| value.checked_add(self.metadosis_waiting_period_seconds))
            .ok_or(ProtocolConstantsError::InvalidValue {
                field: "metadosis pipeline",
                requirement: "fit u64 seconds",
                actual: u64::MAX,
            })?;
        Ok(())
    }

    /// Resolve protocol parameters directly from `config.outbeProtocol` in a
    /// genesis JSON document. The `alloc` section is deliberately irrelevant.
    pub fn from_genesis(genesis: &serde_json::Value) -> Result<Self, ProtocolConstantsError> {
        let config = genesis
            .get("config")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                ProtocolConstantsError::InvalidJson(
                    "genesis config must be a JSON object".to_owned(),
                )
            })?;
        Self::resolve(config.get(GENESIS_CONFIG_KEY))
    }

    /// Apply the build policy to a parsed `config.outbeProtocol` value.
    pub fn select_for_build(
        value: Option<&serde_json::Value>,
    ) -> Result<Self, ProtocolConstantsError> {
        #[cfg(feature = "test-protocol-overrides")]
        {
            Self::resolve(value)
        }

        #[cfg(not(feature = "test-protocol-overrides"))]
        {
            if value.is_some() {
                return Err(ProtocolConstantsError::UnsupportedInProduction);
            }
            Ok(DEFAULTS)
        }
    }
}

#[cfg(feature = "test-protocol-overrides")]
static PARAMETERS: OnceLock<GenesisProtocolParametersV1> = OnceLock::new();

/// Enforce the build policy and initialize test-only overrides when enabled.
pub fn initialize(value: Option<&serde_json::Value>) -> Result<(), ProtocolConstantsError> {
    let parameters = GenesisProtocolParametersV1::select_for_build(value)?;

    #[cfg(feature = "test-protocol-overrides")]
    {
        PARAMETERS
            .set(parameters)
            .map_err(|_| ProtocolConstantsError::AlreadyInitialized)
    }

    #[cfg(not(feature = "test-protocol-overrides"))]
    {
        let _ = parameters;
        Ok(())
    }
}

#[cfg(not(feature = "test-protocol-overrides"))]
fn parameters() -> &'static GenesisProtocolParametersV1 {
    &DEFAULTS
}

#[cfg(feature = "test-protocol-overrides")]
fn parameters() -> &'static GenesisProtocolParametersV1 {
    PARAMETERS
        .get()
        .expect("protocol constants must be initialized before runtime access")
}

pub fn get_metadosis_forming_period_seconds() -> u64 {
    parameters().metadosis_forming_period_seconds
}

pub fn get_metadosis_lookback_delay_seconds() -> u64 {
    parameters().metadosis_lookback_delay_seconds
}

pub fn get_metadosis_offering_period_seconds() -> u64 {
    parameters().metadosis_offering_period_seconds
}

pub fn get_metadosis_waiting_period_seconds() -> u64 {
    parameters().metadosis_waiting_period_seconds
}

pub fn get_metadosis_bootstrap_duration_seconds() -> u64 {
    parameters().metadosis_bootstrap_duration_seconds
}

pub fn get_metadosis_advance_interval_seconds() -> u64 {
    parameters().metadosis_advance_interval_seconds
}

pub fn get_ocomp_compute_vote_window_blocks() -> u64 {
    parameters().ocomp_compute_vote_window_blocks
}

pub fn get_governance_voting_window_blocks() -> u64 {
    parameters().governance_voting_window_blocks
}

pub fn get_nod_materialization_batch_subtree_height() -> u8 {
    parameters().nod_materialization_batch_subtree_height
}

pub fn get_nod_materialization_retry_interval_blocks() -> u64 {
    parameters().nod_materialization_retry_interval_blocks
}

pub fn get_nod_materialization_max_attempts_per_block() -> u16 {
    parameters().nod_materialization_max_attempts_per_block
}

fn validate_nonzero_at_most(
    field: &'static str,
    value: u64,
    maximum: u64,
) -> Result<(), ProtocolConstantsError> {
    if value == 0 || value > maximum {
        return Err(ProtocolConstantsError::InvalidValue {
            field,
            requirement: "non-zero and no greater than the production default",
            actual: value,
        });
    }
    Ok(())
}

fn validate_at_most(
    field: &'static str,
    value: u64,
    maximum: u64,
) -> Result<(), ProtocolConstantsError> {
    if value > maximum {
        return Err(ProtocolConstantsError::InvalidValue {
            field,
            requirement: "no greater than the production default",
            actual: value,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn governance_window_is_independent_and_strictly_bounded() {
        for blocks in [1, 6, 20, 86_400] {
            let resolved = GenesisProtocolParametersV1::resolve(Some(&json!({
                "governance": { "votingWindowBlocks": blocks },
                "ocomp": { "computeVoteWindowBlocks": 120 }
            })))
            .unwrap();
            assert_eq!(resolved.governance_voting_window_blocks, blocks);
            assert_eq!(resolved.ocomp_compute_vote_window_blocks, 120);
        }
        for blocks in [
            json!(0),
            json!(86_401),
            json!(u64::MAX),
            json!(-1),
            json!("6"),
        ] {
            assert!(GenesisProtocolParametersV1::resolve(Some(&json!({
                "governance": { "votingWindowBlocks": blocks }
            })))
            .is_err());
        }
        assert!(GenesisProtocolParametersV1::resolve(Some(&json!({
            "governance": { "votingWindowBlock": 6 }
        })))
        .is_err());
        assert_eq!(
            GenesisProtocolParametersV1::resolve(Some(&json!({
                "governance": {}
            })))
            .unwrap()
            .governance_voting_window_blocks,
            86_400
        );
    }

    #[test]
    fn absent_fields_resolve_once_to_canonical_defaults() {
        assert_eq!(
            GenesisProtocolParametersV1::resolve(None).unwrap(),
            GenesisProtocolParametersV1::default()
        );
        assert_eq!(
            GenesisProtocolParametersV1::resolve(Some(&json!({}))).unwrap(),
            GenesisProtocolParametersV1::default()
        );
    }

    #[test]
    fn explicit_fields_override_independently_without_exposing_origin() {
        let resolved = GenesisProtocolParametersV1::resolve(Some(&json!({
            "schemaVersion": 1,
            "metadosis": {
                "formingPeriodSeconds": 60,
                "lookbackDelaySeconds": 0,
                "offeringPeriodSeconds": 120,
                "waitingPeriodSeconds": 30,
                "bootstrapDurationSeconds": 300,
                "advanceIntervalSeconds": 10
            },
            "ocomp": { "computeVoteWindowBlocks": 120 }
        })))
        .unwrap();

        assert_eq!(resolved.metadosis_forming_period_seconds, 60);
        assert_eq!(resolved.metadosis_lookback_delay_seconds, 0);
        assert_eq!(resolved.metadosis_offering_period_seconds, 120);
        assert_eq!(resolved.metadosis_waiting_period_seconds, 30);
        assert_eq!(resolved.metadosis_bootstrap_duration_seconds, 300);
        assert_eq!(resolved.metadosis_advance_interval_seconds, 10);
        assert_eq!(resolved.ocomp_compute_vote_window_blocks, 120);
    }

    #[test]
    fn malformed_unknown_and_unsafe_values_are_rejected() {
        assert!(GenesisProtocolParametersV1::resolve(Some(&json!({
            "unknown": 1
        })))
        .is_err());
        assert!(GenesisProtocolParametersV1::resolve(Some(&json!({
            "metadosis": { "formingPeriodSeconds": 0 }
        })))
        .is_err());
        assert!(GenesisProtocolParametersV1::resolve(Some(&json!({
            "ocomp": { "computeVoteWindowBlocks": 1801 }
        })))
        .is_err());
    }

    #[test]
    fn genesis_reader_resolves_config_without_alloc_state() {
        let expected = GenesisProtocolParametersV1::resolve(Some(&json!({
            "metadosis": { "formingPeriodSeconds": 60 },
            "ocomp": { "computeVoteWindowBlocks": 120 }
        })))
        .unwrap();
        let genesis = json!({
            "config": {
                "outbeProtocol": {
                    "metadosis": { "formingPeriodSeconds": 60 },
                    "ocomp": { "computeVoteWindowBlocks": 120 }
                }
            }
        });
        assert_eq!(
            GenesisProtocolParametersV1::from_genesis(&genesis).unwrap(),
            expected
        );
    }
}
