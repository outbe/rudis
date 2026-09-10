//! Outbe RPC API trait definition.

use alloy_primitives::{Address, Bytes, B256, U256};
use jsonrpsee::proc_macros::rpc;
use outbe_primitives::consensus::RandomnessStatus;
use outbe_primitives::tee_operator_v1::TeeRenewalScheduleV1;

/// Response type for validator information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorInfo {
    pub address: Address,
    pub consensus_pubkey: String,
    pub status: u8,
    pub stake: U256,
}

/// Response type for epoch information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochInfo {
    pub epoch_number: U256,
    pub epoch_start_timestamp: u64,
    pub epoch_start_block: u64,
    pub epoch_length_blocks: u32,
    pub active_validator_count: u32,
    pub total_staked: U256,
}

/// Response type for slash information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlashInfo {
    pub proposer_miss_count: u64,
    pub voter_miss_count: u64,
    pub felony_count: u64,
}

/// Response type for consensus status.
///
/// **Note:** This is a finalized snapshot, not real-time consensus state.
/// Fields are updated by the reporter on each finalization event.
/// - `current_view`: last *finalized* Simplex view (not the live voting view)
/// - `connected_peers`: number of signers in the last certificate bitmap
///   (not the actual number of P2P connections)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusStatusInfo {
    /// Last finalized Simplex view (updated on finalization, not real-time).
    pub current_view: u64,
    /// Number of signers in the last finalized certificate (not live P2P peers).
    pub connected_peers: u32,
    pub is_active: bool,
    pub has_threshold_shares: bool,
    pub last_finalized_block: u64,
    pub last_vrf_seed: Option<B256>,
    pub randomness_status: RandomnessStatus,
    pub vrf_material_version: u64,
    pub last_dkg_activation_height: u64,
    pub next_planned_activation_height: u64,
    pub vrf_expiry_height: u64,
    pub is_validator: bool,
    /// Phase-1 finalized-parent certificate verification policy for this node.
    pub phase1_verification_mode: Phase1VerificationMode,
    /// Local Mongo materialization and business-readiness state.
    pub projection: ProjectionStatusInfo,
    /// Canary-observed local TEE-enclave health. Local health, not consensus
    /// data; `disabled` when the canary worker is off.
    pub enclave: EnclaveHealthInfo,
}

/// Operator-visible local TEE-enclave health, fed by the node's periodic
/// canary decrypt (`--tee-canary.*`). Mirrors [`ProjectionStatusInfo`]'s role:
/// local observability only, never a consensus input.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveHealthInfo {
    pub state: EnclaveHealth,
    /// True when the last canary decrypt succeeded.
    pub ready: bool,
    pub offer_key_ready: bool,
    pub last_ok_ago_millis: Option<u64>,
    pub last_canary_latency_ms: Option<u64>,
    pub consecutive_failures: u64,
    pub last_failure_class: Option<String>,
    /// Self-reported enclave uptime (from `EnclaveRequest::Health`).
    pub uptime_s: Option<u64>,
    pub heap_current_bytes: Option<u64>,
    pub heap_peak_bytes: Option<u64>,
    /// `null` until feature detection ran; `false` = enclave binary predates
    /// the Health probe (canary-decrypt-only mode).
    pub health_probe_supported: Option<bool>,
}

/// Stable JSON enclave-health vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EnclaveHealth {
    Disabled,
    Starting,
    Ready,
    Degraded,
    Unavailable,
}

impl Default for EnclaveHealthInfo {
    fn default() -> Self {
        Self {
            state: EnclaveHealth::Disabled,
            ready: false,
            offer_key_ready: false,
            last_ok_ago_millis: None,
            last_canary_latency_ms: None,
            consecutive_failures: 0,
            last_failure_class: None,
            uptime_s: None,
            heap_current_bytes: None,
            heap_peak_bytes: None,
            health_probe_supported: None,
        }
    }
}

/// Operator-visible local projection state. This is local health, not consensus data.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionStatusInfo {
    pub state: ProjectionHealth,
    pub checkpoint_number: Option<u64>,
    pub checkpoint_hash: Option<B256>,
    pub reth_finalized_number: Option<u64>,
    pub reth_finalized_hash: Option<B256>,
    pub lag_blocks: Option<u64>,
    pub ready: bool,
    pub unavailable_for_millis: Option<u64>,
    pub last_failure_class: Option<String>,
}

/// Stable JSON projection-health vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProjectionHealth {
    Starting,
    CatchingUp,
    Ready,
    MongoUnavailable,
    Fatal,
}

/// Operator-visible Phase-1 finalized-parent verification boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase1VerificationMode {
    /// Validator-mode node: consensus layer validates the exact parent
    /// certificate before it is accepted into payload attributes / proposals.
    ValidatorEnforced,
    /// Full-node mode: no consensus bridge or private BLS material is loaded;
    /// the node imports already-finalized EL blocks under trusted-finality semantics.
    TrustedFinality,
}

/// Response type for reward emission parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmissionInfo {
    pub validator_reward_percent: u64,
    pub fee_escrow_address: Address,
}

/// Response type for slashing configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlashConfig {
    pub proposer_misdemeanor_threshold: u64,
    pub proposer_felony_threshold: u64,
    pub voter_misdemeanor_threshold: u64,
    pub voter_felony_threshold: u64,
    pub slash_amount_percent: u64,
    pub evidence_reward_percent: u64,
}

/// Detailed validator information returned by `getValidator`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorDetailInfo {
    pub address: Address,
    pub consensus_pubkey: String,
    pub status: u8,
    pub stake: U256,
    pub slash_count: u64,
    pub missed_blocks: u64,
    pub missed_votes: u64,
    pub blocks_proposed: u64,
    pub joined_at_height: u64,
    pub deactivated_at_height: u64,
    pub unbonding_end: u64,
    pub has_bls_share: bool,
}

/// Response type for validator participation statistics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParticipationInfo {
    pub address: Address,
    pub blocks_proposed: u64,
    pub missed_blocks: u64,
    pub missed_votes: u64,
}

/// Response type for node sync status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusInfo {
    pub is_syncing: bool,
    pub current_block: u64,
    pub highest_block: u64,
    pub consensus_active: bool,
    pub connected_peers: u32,
}

/// Response type for `getFinalization`: the finalized certificate + block for a
/// height, as hex of their commonware-codec encodings. A follower's resolver
/// reconstructs the marshal delivery as the decoded `finalizationHex` followed
/// by the decoded `blockHex`, then verifies the certificate against the epoch
/// committee. Hex (0x-prefixed) keeps the wire JSON-friendly; the bytes are NOT
/// trusted by the caller - verification happens against the committee, not this
/// RPC.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizationProof {
    /// Hex of the `commonware_codec::Encode` finalization certificate.
    pub finalization_hex: String,
    /// Hex of the `commonware_codec::Encode` finalized `ConsensusBlock`.
    pub block_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RadiclePhaseInfo {
    Disabled,
    JoiningUnbound,
    Ready,
    RuntimeDegraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RadiclePhaseErrorInfo {
    SidecarUnavailable,
    LocalNodeIdUnavailable,
    BindingMismatch,
    ActiveBindingMissing,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RadicleStatusInfo {
    pub phase: RadiclePhaseInfo,
    pub phase_error: Option<RadiclePhaseErrorInfo>,
    pub local_node_id: Option<B256>,
    pub last_seen_finalized_number: Option<u64>,
    pub last_seen_finalized_hash: Option<B256>,
    pub last_converged_finalized_number: Option<u64>,
    pub last_converged_finalized_hash: Option<B256>,
    pub desired_repository_count: u64,
    pub available_repository_count: u64,
    pub pending_repository_count: u64,
    pub resolved_peer_count: u64,
    pub unresolved_peer_count: u64,
    pub connected_peer_count: u64,
    pub finality_regressions: u64,
    pub finality_conflicts: u64,
    pub provider_failures: u64,
    pub endpoint_failures: u64,
    pub uds_failures: u64,
    pub tcp_status_failures: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RadiclePeerInfo {
    pub validator: Address,
    pub sender_bls_public_key: Bytes,
    pub request_id: B256,
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub node_id: B256,
    pub addresses: Vec<String>,
    pub anchor_number: u64,
    pub anchor_hash: B256,
    pub valid_until_height: u64,
    pub signature: Bytes,
    pub encoded_frame: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RadicleRepositoryStateInfo {
    Available,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RadicleRepositoryInfo {
    pub repo_id: String,
    pub state: RadicleRepositoryStateInfo,
}
/// Outbe custom RPC namespace.
///
/// Provides read-only access to validator infrastructure state.
/// Enable with `--http.api rudis`.
/// Sealed Gratis view + modify keys returned by `rudis_deriveGratisKeys`.
///
/// The enclave derives the account's keys and seals them to the requester's
/// ephemeral X25519 key: `sealed = AEAD(ECDHE(enclaveEphemeral, requesterEphemeral),
/// view_key || modify_key)`. The client recovers `view_key || modify_key` with its
/// ephemeral secret + `enclaveEphemeralPubkey`. Opaque to the node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GratisKeysSealed {
    pub sealed: alloy_primitives::Bytes,
    pub nonce: alloy_primitives::Bytes,
    pub enclave_ephemeral_pubkey: B256,
}

#[rpc(server, namespace = "rudis")]
pub trait OutbeApi {
    /// Returns one independently verifiable latest-finalized compressed-entity
    /// point package. V1 deliberately has no caller-selected block.
    #[method(name = "getCompressedEntity")]
    async fn get_compressed_entity(
        &self,
        request: outbe_compressed_entities::PointReadRequestV1,
    ) -> jsonrpsee::core::RpcResult<outbe_compressed_entities::PointReadResultV1>;

    /// Builds the exact Fidelity/Oracle openings for one finalized OCOMP
    /// `JobIntent`. The event supplies only `intent_id`; the node resolves the
    /// authoritative finalized record and exact request state locally.
    #[method(name = "getOcompLysisOpeningsV1")]
    async fn get_ocomp_lysis_openings_v1(
        &self,
        intent_id: B256,
        canonical_request: Bytes,
    ) -> jsonrpsee::core::RpcResult<Bytes>;

    /// Returns information about all active validators.
    #[method(name = "getValidators")]
    async fn get_validators(&self) -> jsonrpsee::core::RpcResult<Vec<ValidatorInfo>>;

    /// Derive the account's confidential view + modify keys for `ledger` (`Gratis`
    /// or `Promis`) inside the enclave and return them sealed to `ephemeralPubkey`
    /// (a client X25519 public key). Off-chain key delivery - it never touches
    /// consensus state.
    ///
    /// The caller MUST prove control of `account`: `signature` is an EIP-191
    /// `personal_sign` over `"outbe/<ledger>/derive-keys/v1" || account ||
    /// ephemeralPubkey`, and the recovered signer must equal `account`. Without a
    /// matching signature the enclave is never asked - otherwise anyone could obtain
    /// any account's modify key.
    #[method(name = "deriveKeys")]
    async fn derive_keys(
        &self,
        ledger: outbe_tee::protocol::Ledger,
        account: Address,
        ephemeral_pubkey: B256,
        signature: alloy_primitives::Bytes,
    ) -> jsonrpsee::core::RpcResult<GratisKeysSealed>;

    /// Deprecated alias for `deriveKeys(Gratis, ...)`, kept for existing Gratis
    /// clients.
    #[method(name = "deriveGratisKeys")]
    async fn derive_gratis_keys(
        &self,
        account: Address,
        ephemeral_pubkey: B256,
        signature: alloy_primitives::Bytes,
    ) -> jsonrpsee::core::RpcResult<GratisKeysSealed>;

    /// Returns detailed information about a single validator by address.
    #[method(name = "getValidator")]
    async fn get_validator(
        &self,
        address: Address,
    ) -> jsonrpsee::core::RpcResult<Option<ValidatorDetailInfo>>;

    /// Returns current epoch information.
    #[method(name = "getEpochInfo")]
    async fn get_epoch_info(&self) -> jsonrpsee::core::RpcResult<EpochInfo>;

    /// Exact finalized epoch/freeze schedule for host-side TEE renewal alerts.
    #[method(name = "teeRenewalScheduleV1")]
    async fn tee_renewal_schedule_v1(&self) -> jsonrpsee::core::RpcResult<TeeRenewalScheduleV1>;

    /// Returns the stake amount for a validator address.
    #[method(name = "getStake")]
    async fn get_stake(&self, address: Address) -> jsonrpsee::core::RpcResult<U256>;

    /// Returns slash counters for a validator.
    #[method(name = "getSlashInfo")]
    async fn get_slash_info(&self, address: Address) -> jsonrpsee::core::RpcResult<SlashInfo>;

    /// Returns finalized consensus snapshot (view, certificate signers, shares, is_validator).
    #[method(name = "consensusStatus")]
    async fn consensus_status(&self) -> jsonrpsee::core::RpcResult<ConsensusStatusInfo>;

    /// Returns the committed VRF seed (block header `mixHash` / prev_randao) for
    /// the given block number, or for the latest canonical block when omitted
    /// (which, under Outbe's fast finality, is the latest finalized block).
    /// Reads the authoritative committed header via the provider, so the answer
    /// is identical on validators and full nodes. `None` if the block does not
    /// exist or carries no `mixHash`.
    #[method(name = "getVrfSeed")]
    async fn get_vrf_seed(
        &self,
        block_number: Option<u64>,
    ) -> jsonrpsee::core::RpcResult<Option<B256>>;

    /// Returns current reward emission parameters.
    #[method(name = "getEmissionInfo")]
    async fn get_emission_info(&self) -> jsonrpsee::core::RpcResult<EmissionInfo>;

    /// Returns slashing configuration parameters.
    #[method(name = "getSlashConfig")]
    async fn get_slash_config(&self) -> jsonrpsee::core::RpcResult<SlashConfig>;

    /// Returns participation statistics for a validator address.
    #[method(name = "getParticipation")]
    async fn get_participation(
        &self,
        address: Address,
    ) -> jsonrpsee::core::RpcResult<ParticipationInfo>;

    /// Returns the node's sync status.
    #[method(name = "syncStatus")]
    async fn sync_status(&self) -> jsonrpsee::core::RpcResult<SyncStatusInfo>;

    /// Immutable local Radicle integration health snapshot.
    #[method(name = "radicleStatus")]
    async fn radicle_status(&self) -> jsonrpsee::core::RpcResult<RadicleStatusInfo>;

    /// Canonical signed endpoint evidence for verified active peers.
    #[method(name = "radiclePeers")]
    async fn radicle_peers(&self) -> jsonrpsee::core::RpcResult<Vec<RadiclePeerInfo>>;

    /// Desired public repositories and their local availability state.
    #[method(name = "radicleRepositories")]
    async fn radicle_repositories(&self) -> jsonrpsee::core::RpcResult<Vec<RadicleRepositoryInfo>>;

    /// Returns the finalized certificate + block at `height` (hex-encoded), for
    /// `--upstream` followers to backfill and verify. Served only by nodes
    /// running consensus (validators) or a follower that has itself synced the
    /// height; otherwise errors. The caller verifies the certificate against the
    /// epoch committee - this RPC is a bytes transport, not a trust root.
    #[method(name = "getFinalization")]
    async fn get_finalization(&self, height: u64) -> jsonrpsee::core::RpcResult<FinalizationProof>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radicle_rpc_types_are_canonical() {
        let status = RadicleStatusInfo {
            phase: RadiclePhaseInfo::Ready,
            phase_error: None,
            local_node_id: Some(B256::repeat_byte(0x11)),
            last_seen_finalized_number: Some(7),
            last_seen_finalized_hash: Some(B256::repeat_byte(0x22)),
            last_converged_finalized_number: Some(7),
            last_converged_finalized_hash: Some(B256::repeat_byte(0x22)),
            desired_repository_count: 2,
            available_repository_count: 1,
            pending_repository_count: 1,
            resolved_peer_count: 3,
            unresolved_peer_count: 1,
            connected_peer_count: 2,
            finality_regressions: 0,
            finality_conflicts: 0,
            provider_failures: 0,
            endpoint_failures: 0,
            uds_failures: 0,
            tcp_status_failures: 0,
        };
        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json["phase"], "ready");
        assert_eq!(
            json["localNodeId"],
            format!("{:#x}", B256::repeat_byte(0x11))
        );

        let repository = RadicleRepositoryInfo {
            repo_id: "11".repeat(20),
            state: RadicleRepositoryStateInfo::Pending,
        };
        let json = serde_json::to_value(repository).unwrap();
        assert_eq!(json["repoId"].as_str().unwrap().len(), 40);
        assert_eq!(json["state"], "pending");
    }

    fn ready_projection() -> ProjectionStatusInfo {
        ProjectionStatusInfo {
            state: ProjectionHealth::Ready,
            checkpoint_number: Some(41),
            checkpoint_hash: Some(B256::repeat_byte(0x41)),
            reth_finalized_number: Some(41),
            reth_finalized_hash: Some(B256::repeat_byte(0x41)),
            lag_blocks: Some(0),
            ready: true,
            unavailable_for_millis: None,
            last_failure_class: None,
        }
    }

    #[test]
    fn test_consensus_status_info_serialization_camel_case() {
        let info = ConsensusStatusInfo {
            current_view: 42,
            connected_peers: 3,
            is_active: true,
            has_threshold_shares: true,
            last_finalized_block: 41,
            last_vrf_seed: Some(B256::ZERO),
            randomness_status: RandomnessStatus::Healthy,
            vrf_material_version: 2,
            last_dkg_activation_height: 21,
            next_planned_activation_height: 21021,
            vrf_expiry_height: 21621,
            is_validator: true,
            phase1_verification_mode: Phase1VerificationMode::ValidatorEnforced,
            projection: ready_projection(),
            enclave: EnclaveHealthInfo::default(),
        };

        let json = serde_json::to_string(&info).unwrap();

        // Verify camelCase field names (not snake_case).
        assert!(
            json.contains("\"currentView\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"connectedPeers\""),
            "must use camelCase: {json}"
        );
        assert!(json.contains("\"isActive\""), "must use camelCase: {json}");
        assert!(
            json.contains("\"hasThresholdShares\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"lastFinalizedBlock\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"lastVrfSeed\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"randomnessStatus\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"vrfMaterialVersion\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"lastDkgActivationHeight\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"nextPlannedActivationHeight\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"vrfExpiryHeight\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"isValidator\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"phase1VerificationMode\""),
            "must use camelCase: {json}"
        );
        assert!(
            json.contains("\"validatorEnforced\""),
            "validator-mode status must expose enforced Phase-1 verification: {json}"
        );

        // Must NOT contain snake_case.
        assert!(!json.contains("current_view"), "must not use snake_case");
        assert!(!json.contains("connected_peers"), "must not use snake_case");
    }

    #[test]
    fn test_consensus_status_info_roundtrip() {
        let info = ConsensusStatusInfo {
            current_view: 100,
            connected_peers: 5,
            is_active: false,
            has_threshold_shares: false,
            last_finalized_block: 99,
            last_vrf_seed: None,
            randomness_status: RandomnessStatus::Expired,
            vrf_material_version: 5,
            last_dkg_activation_height: 100,
            next_planned_activation_height: 21100,
            vrf_expiry_height: 21700,
            is_validator: false,
            phase1_verification_mode: Phase1VerificationMode::TrustedFinality,
            projection: ready_projection(),
            enclave: EnclaveHealthInfo::default(),
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ConsensusStatusInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.current_view, 100);
        assert_eq!(deserialized.connected_peers, 5);
        assert!(!deserialized.is_active);
        assert!(!deserialized.has_threshold_shares);
        assert_eq!(deserialized.last_finalized_block, 99);
        assert!(deserialized.last_vrf_seed.is_none());
        assert_eq!(deserialized.randomness_status, RandomnessStatus::Expired);
        assert_eq!(deserialized.vrf_material_version, 5);
        assert_eq!(deserialized.last_dkg_activation_height, 100);
        assert_eq!(deserialized.next_planned_activation_height, 21100);
        assert_eq!(deserialized.vrf_expiry_height, 21700);
        assert!(!deserialized.is_validator);
        assert_eq!(
            deserialized.phase1_verification_mode,
            Phase1VerificationMode::TrustedFinality
        );
        assert!(deserialized.projection.ready);
        assert_eq!(deserialized.projection.checkpoint_number, Some(41));
    }

    #[test]
    fn test_sync_status_info_full_node_semantics() {
        // Full node: is_syncing may be true, consensus_active = false.
        let info = SyncStatusInfo {
            is_syncing: true,
            current_block: 50,
            highest_block: 100,
            consensus_active: false,
            connected_peers: 3,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: SyncStatusInfo = serde_json::from_str(&json).unwrap();

        assert!(!deserialized.consensus_active);
        assert!(deserialized.is_syncing);
    }
}
