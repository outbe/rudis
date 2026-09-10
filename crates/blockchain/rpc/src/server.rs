//! Outbe RPC server implementation.
//!
//! TODO(future): Full nodes could verify finality proofs from block headers
//! (BLS threshold signature in extra_data) without running full consensus.
//! This would provide light-client-grade trust: verify that 2/3+1 validators
//! signed each block using the group public key from the ValidatorSet contract.

use alloy_primitives::{Address, Bytes, B256, U256};
use jsonrpsee::core::RpcResult;
use outbe_compressed_entities::{
    CeDomain, CompressedTreeService, PointReadRequestV1, PointReadResultV1, SelectedHeaderV1,
};
use outbe_offchain_data::RuntimeBodyReaders;
use outbe_primitives::header::OutbeHeader;
use outbe_primitives::tee_operator_v1::TeeRenewalScheduleV1;
use outbe_primitives::{
    consensus::ConsensusExecutionBridge,
    projection::{ProjectionReadinessHandle, ProjectionStatus},
    storage::{
        readonly::{ReadOnlyStorageProvider, StorageReader},
        StorageHandle,
    },
};
use reth_ethereum::primitives::AlloyBlockHeader as _;
use reth_ethereum::storage::{
    BlockNumReader, HeaderProvider, StateProvider as _, StateProviderBox, StateProviderFactory,
};
use reth_provider::BlockIdReader;
use std::sync::Arc;

use crate::api::{
    ConsensusStatusInfo, EmissionInfo, EpochInfo, FinalizationProof, GratisKeysSealed,
    OutbeApiServer, ParticipationInfo, Phase1VerificationMode, ProjectionHealth,
    ProjectionStatusInfo, RadiclePeerInfo, RadiclePhaseErrorInfo, RadiclePhaseInfo,
    RadicleRepositoryInfo, RadicleRepositoryStateInfo, RadicleStatusInfo, SlashConfig, SlashInfo,
    SyncStatusInfo, ValidatorDetailInfo, ValidatorInfo,
};
use outbe_radicle::integration::{
    RadicleRepositoryState, RadicleStatusHandle, RadicleStatusSnapshot, RadicleVotingGate,
    RadicleVotingGateError,
};

fn read_effective_slash_config(
    storage: StorageHandle<'_>,
) -> Result<SlashConfig, outbe_primitives::error::PrecompileError> {
    let si = outbe_slashindicator::contract::SlashIndicator::new(storage);
    Ok(SlashConfig {
        proposer_misdemeanor_threshold: si.proposer_misdemeanor_threshold()?,
        proposer_felony_threshold: si.proposer_felony_threshold()?,
        voter_misdemeanor_threshold: si.voter_misdemeanor_threshold()?,
        voter_felony_threshold: si.voter_felony_threshold()?,
        slash_amount_percent: si.slash_amount_percent()?,
        evidence_reward_percent: si.evidence_reward_percent()?,
    })
}

/// Bridge from Reth's `StateProvider` to outbe's `StorageReader` trait.
struct RethStateReader<'a> {
    state: &'a StateProviderBox,
}

impl StorageReader for RethStateReader<'_> {
    fn read_storage(&self, address: Address, key: B256) -> outbe_primitives::error::Result<U256> {
        self.state
            .storage(address, key)
            .map(|opt| opt.unwrap_or(U256::ZERO))
            .map_err(|e| {
                outbe_primitives::error::PrecompileError::Storage(format!("state read failed: {e}"))
            })
    }
}

/// RPC handler for the `rudis_*` namespace.
#[derive(Clone)]
pub struct OutbeApiHandler<P> {
    provider: Arc<P>,
    bridge: Option<ConsensusExecutionBridge>,
    /// Whether this node runs consensus as a VALIDATOR. A `--upstream` follower
    /// also holds a bridge (to serve `rudis_getFinalization` to downstream
    /// followers) but must report itself as a non-validator / TrustedFinality
    /// node. This flag, NOT `bridge.is_some()`, drives validator-status fields.
    is_validator: bool,
    projection_readiness: ProjectionReadinessHandle,
    point_reads: Option<PointReadRuntime>,
    tee_renewal_schedule: Option<TeeRenewalScheduleConfigV1>,
    ocomp_lysis_openings: Option<OcompLysisOpeningsRuntimeV1>,
    radicle_status: RadicleStatusHandle,
    tee_enclave_health: outbe_tee::TeeEnclaveHealthChannel,
}

type OcompLysisOpeningsBuilderV1 =
    dyn Fn(B256, Bytes) -> Result<Bytes, String> + Send + Sync + 'static;

#[derive(Clone)]
pub struct OcompLysisOpeningsRuntimeV1(Arc<OcompLysisOpeningsBuilderV1>);

impl OcompLysisOpeningsRuntimeV1 {
    #[must_use]
    pub fn new(
        builder: impl Fn(B256, Bytes) -> Result<Bytes, String> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(builder))
    }

    fn build(&self, intent_id: B256, subjects: Bytes) -> Result<Bytes, String> {
        (self.0)(intent_id, subjects)
    }
}

#[derive(Clone, Copy, Debug)]
struct TeeRenewalScheduleConfigV1 {
    dkg_prepare_window_blocks: u64,
    minimum_block_time_millis: u64,
}

#[derive(Clone)]
struct PointReadRuntime {
    tree: Arc<CompressedTreeService>,
    bodies: RuntimeBodyReaders,
    chain_id: u64,
}

impl std::fmt::Debug for PointReadRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PointReadRuntime")
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl<P> std::fmt::Debug for OutbeApiHandler<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OutbeApiHandler")
            .field("is_validator", &self.is_validator)
            .field("point_reads", &self.point_reads)
            .finish_non_exhaustive()
    }
}

impl<P> OutbeApiHandler<P> {
    /// Create a new handler backed by the given state provider factory (no
    /// bridge; plain EL full node).
    pub fn new(provider: Arc<P>, projection_readiness: ProjectionReadinessHandle) -> Self {
        Self {
            provider,
            bridge: None,
            is_validator: false,
            projection_readiness,
            point_reads: None,
            tee_renewal_schedule: None,
            ocomp_lysis_openings: None,
            radicle_status: outbe_radicle::integration::RadicleStatusChannel::disabled(),
            tee_enclave_health: outbe_tee::TeeEnclaveHealthChannel::disabled(),
        }
    }

    /// Create a validator handler with full access to the consensus bridge.
    pub fn with_bridge(
        provider: Arc<P>,
        bridge: ConsensusExecutionBridge,
        projection_readiness: ProjectionReadinessHandle,
    ) -> Self {
        Self {
            provider,
            bridge: Some(bridge),
            is_validator: true,
            projection_readiness,
            point_reads: None,
            tee_renewal_schedule: None,
            ocomp_lysis_openings: None,
            radicle_status: outbe_radicle::integration::RadicleStatusChannel::disabled(),
            tee_enclave_health: outbe_tee::TeeEnclaveHealthChannel::disabled(),
        }
    }

    /// Create a `--upstream` follower handler: it holds the bridge so it can
    /// serve `rudis_getFinalization` (chaining followers), but reports itself as
    /// a non-validator (TrustedFinality) node, not a validator.
    pub fn with_follower_bridge(
        provider: Arc<P>,
        bridge: ConsensusExecutionBridge,
        projection_readiness: ProjectionReadinessHandle,
    ) -> Self {
        Self {
            provider,
            bridge: Some(bridge),
            is_validator: false,
            projection_readiness,
            point_reads: None,
            tee_renewal_schedule: None,
            ocomp_lysis_openings: None,
            radicle_status: outbe_radicle::integration::RadicleStatusChannel::disabled(),
            tee_enclave_health: outbe_tee::TeeEnclaveHealthChannel::disabled(),
        }
    }

    #[must_use]
    pub fn with_point_reads(
        mut self,
        tree: Arc<CompressedTreeService>,
        bodies: RuntimeBodyReaders,
        chain_id: u64,
    ) -> Self {
        self.point_reads = Some(PointReadRuntime {
            tree,
            bodies,
            chain_id,
        });
        self
    }

    #[must_use]
    pub fn with_tee_renewal_schedule(
        mut self,
        dkg_prepare_window_blocks: u64,
        minimum_block_time_millis: u64,
    ) -> Self {
        self.tee_renewal_schedule = Some(TeeRenewalScheduleConfigV1 {
            dkg_prepare_window_blocks,
            minimum_block_time_millis,
        });
        self
    }

    #[must_use]
    pub fn with_ocomp_lysis_openings(mut self, runtime: OcompLysisOpeningsRuntimeV1) -> Self {
        self.ocomp_lysis_openings = Some(runtime);
        self
    }

    #[must_use]
    pub fn with_radicle_status(mut self, status: RadicleStatusHandle) -> Self {
        self.radicle_status = status;
        self
    }

    #[must_use]
    pub fn with_tee_enclave_health(mut self, channel: outbe_tee::TeeEnclaveHealthChannel) -> Self {
        self.tee_enclave_health = channel;
        self
    }
}

/// Map the canary snapshot into the RPC shape. Pure so it is unit-testable;
/// `now_unix_ms` is passed in to keep assertions wall-clock-free.
pub(crate) fn enclave_health_info(
    snapshot: &outbe_tee::TeeEnclaveHealthSnapshot,
    now_unix_ms: u64,
) -> crate::api::EnclaveHealthInfo {
    use crate::api::EnclaveHealth;
    use outbe_tee::TeeEnclaveHealthState;
    let state = match snapshot.state {
        TeeEnclaveHealthState::Disabled => EnclaveHealth::Disabled,
        TeeEnclaveHealthState::Starting => EnclaveHealth::Starting,
        TeeEnclaveHealthState::Ready => EnclaveHealth::Ready,
        TeeEnclaveHealthState::Degraded => EnclaveHealth::Degraded,
        TeeEnclaveHealthState::Unavailable => EnclaveHealth::Unavailable,
    };
    crate::api::EnclaveHealthInfo {
        state,
        ready: matches!(state, EnclaveHealth::Ready),
        offer_key_ready: snapshot.offer_key_ready,
        last_ok_ago_millis: snapshot
            .last_ok_unix_ms
            .map(|ok_ms| now_unix_ms.saturating_sub(ok_ms)),
        last_canary_latency_ms: snapshot.last_canary_latency_ms,
        consecutive_failures: snapshot.consecutive_failures,
        last_failure_class: snapshot.last_failure.clone(),
        uptime_s: snapshot.enclave.as_ref().map(|status| status.uptime_s),
        heap_current_bytes: snapshot
            .enclave
            .as_ref()
            .map(|status| status.heap_current_bytes),
        heap_peak_bytes: snapshot
            .enclave
            .as_ref()
            .map(|status| status.heap_peak_bytes),
        health_probe_supported: snapshot.health_probe_supported,
    }
}

pub(crate) fn radicle_status_info(
    snapshot: &RadicleStatusSnapshot,
) -> Result<RadicleStatusInfo, String> {
    let manager = &snapshot.manager;
    let phase = match manager.phase {
        outbe_radicle::manager::ManagerPhase::Disabled => RadiclePhaseInfo::Disabled,
        outbe_radicle::manager::ManagerPhase::JoiningUnbound => RadiclePhaseInfo::JoiningUnbound,
        outbe_radicle::manager::ManagerPhase::Ready => RadiclePhaseInfo::Ready,
        outbe_radicle::manager::ManagerPhase::RuntimeDegraded => RadiclePhaseInfo::RuntimeDegraded,
    };
    let phase_error = match snapshot.voting_gate {
        RadicleVotingGate::Fatal(error) => Some(match error {
            RadicleVotingGateError::SidecarUnavailable => RadiclePhaseErrorInfo::SidecarUnavailable,
            RadicleVotingGateError::LocalNodeIdUnavailable => {
                RadiclePhaseErrorInfo::LocalNodeIdUnavailable
            }
            RadicleVotingGateError::BindingMismatch => RadiclePhaseErrorInfo::BindingMismatch,
            RadicleVotingGateError::ActiveBindingMissing => {
                RadiclePhaseErrorInfo::ActiveBindingMissing
            }
        }),
        _ => manager.phase_error.map(|error| match error {
            outbe_radicle::manager::PhaseError::SidecarUnavailable => {
                RadiclePhaseErrorInfo::SidecarUnavailable
            }
            outbe_radicle::manager::PhaseError::LocalNodeIdUnavailable => {
                RadiclePhaseErrorInfo::LocalNodeIdUnavailable
            }
            outbe_radicle::manager::PhaseError::BindingMismatch => {
                RadiclePhaseErrorInfo::BindingMismatch
            }
        }),
    };
    let count = |value: usize| {
        u64::try_from(value).map_err(|_| "Radicle status counter exceeds u64".to_owned())
    };
    Ok(RadicleStatusInfo {
        phase,
        phase_error,
        local_node_id: snapshot.local_node_id.map(B256::from),
        last_seen_finalized_number: manager.last_seen_finalized.map(|block| block.number),
        last_seen_finalized_hash: manager.last_seen_finalized.map(|block| block.hash),
        last_converged_finalized_number: manager.last_converged_finalized.map(|block| block.number),
        last_converged_finalized_hash: manager.last_converged_finalized.map(|block| block.hash),
        desired_repository_count: count(manager.desired_repository_count)?,
        available_repository_count: count(manager.available_repository_count)?,
        pending_repository_count: count(manager.pending_repository_count)?,
        resolved_peer_count: count(manager.resolved_peer_count)?,
        unresolved_peer_count: count(manager.unresolved_peer_count)?,
        connected_peer_count: count(manager.connected_peer_count)?,
        finality_regressions: manager.finality_regressions,
        finality_conflicts: manager.finality_conflicts,
        provider_failures: manager.provider_failures,
        endpoint_failures: manager.endpoint_failures,
        uds_failures: manager.uds_failures,
        tcp_status_failures: manager.tcp_status_failures,
    })
}

fn radicle_peer_info(
    proof: &outbe_radicle::integration::SignedEndpointEvidence,
) -> RadiclePeerInfo {
    let body = proof.response.body();
    RadiclePeerInfo {
        validator: body.validator,
        sender_bls_public_key: proof.peer.as_bytes().to_vec().into(),
        request_id: B256::from(body.request_id),
        chain_id: body.chain_id,
        genesis_hash: body.genesis_hash,
        node_id: B256::from(body.node_id),
        addresses: body.addresses.iter().map(canonical_endpoint).collect(),
        anchor_number: body.anchor_number,
        anchor_hash: body.anchor_hash,
        valid_until_height: body.valid_until,
        signature: proof.response.signature().to_vec().into(),
        encoded_frame: proof.encoded_frame.clone().into(),
    }
}

fn canonical_endpoint(address: &outbe_radicle::endpoint::EndpointAddress) -> String {
    let encoded = address.encode();
    match encoded[0] {
        0 => format!(
            "{}:{}",
            std::net::Ipv4Addr::new(encoded[1], encoded[2], encoded[3], encoded[4]),
            u16::from_be_bytes([encoded[5], encoded[6]])
        ),
        1 => {
            let octets: [u8; 16] = encoded[1..17].try_into().expect("canonical IPv6 endpoint");
            format!(
                "[{}]:{}",
                std::net::Ipv6Addr::from(octets),
                u16::from_be_bytes([encoded[17], encoded[18]])
            )
        }
        2 => {
            let length = usize::from(encoded[1]);
            let host = std::str::from_utf8(&encoded[2..2 + length])
                .expect("canonical DNS endpoint is ASCII");
            let offset = 2 + length;
            format!(
                "{}:{}",
                host,
                u16::from_be_bytes([encoded[offset], encoded[offset + 1]])
            )
        }
        _ => unreachable!("EndpointAddress has a canonical tag"),
    }
}

impl<P> OutbeApiHandler<P>
where
    P: StateProviderFactory + HeaderProvider<Header = OutbeHeader> + Send + Sync + 'static,
{
    async fn serve_compressed_entity(
        &self,
        request: PointReadRequestV1,
    ) -> RpcResult<PointReadResultV1> {
        let Some(runtime) = self.point_reads.clone() else {
            return Ok(PointReadResultV1::Unavailable);
        };
        let provider = Arc::clone(&self.provider);
        tokio::task::spawn_blocking(move || {
            runtime.tree.serve_point_read_v1(
                runtime.chain_id,
                request,
                |height, expected_hash| {
                    let finalized = provider.finalized_block_num_hash().ok().flatten()?;
                    if finalized.number < height {
                        return None;
                    }
                    provider
                        .sealed_header(height)
                        .ok()
                        .flatten()
                        .filter(|header| header.hash() == expected_hash)
                        .map(|header| SelectedHeaderV1 {
                            block_number: height,
                            block_hash: expected_hash,
                            extra_data: header.header().inner.extra_data.to_vec(),
                        })
                },
                |domain, raw_id| match domain {
                    CeDomain::Tribute => match runtime.bodies.tribute().get_stored_body(raw_id) {
                        Ok(Some(body)) => Some(body.encode()),
                        Ok(None) | Err(_) => {
                            runtime.bodies.report_unavailable();
                            None
                        }
                    },
                    CeDomain::NodItem => match runtime.bodies.nod().get_stored_item(raw_id) {
                        Ok(Some(body)) => Some(body.encode()),
                        Ok(None) | Err(_) => {
                            runtime.bodies.report_unavailable();
                            None
                        }
                    },
                    CeDomain::NodBucket => match runtime.bodies.nod().get_stored_bucket(raw_id) {
                        Ok(Some(body)) => Some(body.encode()),
                        Ok(None) | Err(_) => {
                            runtime.bodies.report_unavailable();
                            None
                        }
                    },
                },
            )
        })
        .await
        .map_err(|error| internal_err(format!("point-read worker failed: {error}")))?
        .map_err(|error| invalid_params(error.to_string()))
    }

    /// Read precompile state at the latest block using a closure.
    fn with_latest_state<R>(
        &self,
        f: impl FnOnce(StorageHandle) -> Result<R, outbe_primitives::error::PrecompileError>,
    ) -> RpcResult<R> {
        let state = self
            .provider
            .latest()
            .map_err(|e| internal_err(format!("failed to get latest state: {e}")))?;

        let reader = RethStateReader { state: &state };
        let mut provider = ReadOnlyStorageProvider::new(reader);
        let storage = StorageHandle::new(&mut provider);

        f(storage).map_err(|e| internal_err(format!("precompile error: {e}")))
    }
}

#[jsonrpsee::core::async_trait]
impl<P> OutbeApiServer for OutbeApiHandler<P>
where
    P: StateProviderFactory
        + HeaderProvider<Header = OutbeHeader>
        + BlockNumReader
        + BlockIdReader
        + Send
        + Sync
        + 'static,
{
    async fn get_compressed_entity(
        &self,
        request: PointReadRequestV1,
    ) -> RpcResult<PointReadResultV1> {
        self.serve_compressed_entity(request).await
    }

    async fn get_ocomp_lysis_openings_v1(
        &self,
        intent_id: B256,
        canonical_request: Bytes,
    ) -> RpcResult<Bytes> {
        let runtime = self
            .ocomp_lysis_openings
            .clone()
            .ok_or_else(|| internal_err("OCOMP Lysis openings are not configured".to_owned()))?;
        tokio::task::spawn_blocking(move || runtime.build(intent_id, canonical_request))
            .await
            .map_err(|error| internal_err(format!("OCOMP openings worker failed: {error}")))?
            .map_err(internal_err)
    }

    async fn derive_keys(
        &self,
        ledger: outbe_tee::protocol::Ledger,
        account: Address,
        ephemeral_pubkey: B256,
        signature: alloy_primitives::Bytes,
    ) -> RpcResult<GratisKeysSealed> {
        use outbe_tee::protocol::{EnclaveRequest, EnclaveResponse};

        // Prove the caller controls `account` before the enclave derives its
        // (secret) modify key: recover the EIP-191 personal_sign signer over
        // `"outbe/<ledger>/derive-keys/v1" || account || ephemeralPubkey` and require
        // it to equal `account`.
        let sig65: [u8; 65] = signature.as_ref().try_into().map_err(|_| {
            invalid_params_err(format!(
                "signature must be 65 bytes (r||s||v), got {}",
                signature.len()
            ))
        })?;
        // Fast reject: recover the signer here so an unauthorized request is dropped
        // before the enclave round-trip. This is defense-in-depth only - the enclave
        // re-verifies the same signature, because a compromised host could bypass this
        // check and reach the enclave transport directly (see DeriveAccountKeys arm).
        let prehash = outbe_tee::protocol::eip191_hash(
            &outbe_tee::protocol::derive_account_keys_message(ledger, account, ephemeral_pubkey),
        );
        let recovered = outbe_primitives::tee_signatures::recover_signer(&prehash, &sig65)
            .map_err(|e| invalid_params_err(format!("signature recovery failed: {e}")))?;
        if recovered != account {
            return Err(invalid_params_err(format!(
                "signature signer {recovered} does not control account {account}"
            )));
        }

        // Off-chain key delivery via the process-global enclave client (no state).
        // Thread `owner_sig` through so the enclave enforces ownership in its own
        // trust domain, not ours.
        let response = outbe_tee::try_with_enclave(|client| {
            client.request(&EnclaveRequest::DeriveAccountKeys {
                ledger,
                account,
                requester_ephemeral_pubkey: ephemeral_pubkey.0,
                owner_sig: sig65.to_vec(),
            })
        })
        .ok_or_else(|| internal_err("tee enclave not configured".to_string()))?
        .map_err(|e| internal_err(format!("enclave DeriveAccountKeys failed: {e}")))?;
        match response {
            EnclaveResponse::AccountKeysSealed {
                sealed,
                nonce,
                enclave_ephemeral_pubkey,
                ..
            } => Ok(GratisKeysSealed {
                sealed: sealed.into(),
                nonce: nonce.to_vec().into(),
                enclave_ephemeral_pubkey: B256::from(enclave_ephemeral_pubkey),
            }),
            EnclaveResponse::Error { message } => {
                Err(internal_err(format!("enclave error: {message}")))
            }
            other => Err(internal_err(format!(
                "unexpected enclave response: {other:?}"
            ))),
        }
    }

    async fn derive_gratis_keys(
        &self,
        account: Address,
        ephemeral_pubkey: B256,
        signature: alloy_primitives::Bytes,
    ) -> RpcResult<GratisKeysSealed> {
        // Deprecated alias - the Gratis ledger of the unified `deriveKeys`.
        self.derive_keys(
            outbe_tee::protocol::Ledger::Gratis,
            account,
            ephemeral_pubkey,
            signature,
        )
        .await
    }

    async fn get_validators(&self) -> RpcResult<Vec<ValidatorInfo>> {
        self.with_latest_state(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let records = vs.get_active_validators()?;

            let staking = outbe_staking::contract::Staking::new(storage);

            let mut result = Vec::with_capacity(records.len());
            for r in &records {
                let stake = staking.get_stake(r.validator_address).unwrap_or(U256::ZERO);
                result.push(ValidatorInfo {
                    address: r.validator_address,
                    consensus_pubkey: hex::encode(r.consensus_pubkey),
                    status: r.status,
                    stake,
                });
            }
            Ok(result)
        })
    }

    async fn get_validator(&self, address: Address) -> RpcResult<Option<ValidatorDetailInfo>> {
        self.with_latest_state(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let state = vs.validator_state(address)?;
            if !state.is_registered() {
                return Ok(None);
            }
            let consensus_pubkey = state.consensus_pubkey().ok_or_else(|| {
                outbe_primitives::error::PrecompileError::Fatal(
                    "registered validator is missing consensus pubkey".into(),
                )
            })?;
            let history = state.history().ok_or_else(|| {
                outbe_primitives::error::PrecompileError::Fatal(
                    "registered validator is missing history".into(),
                )
            })?;
            Ok(Some(ValidatorDetailInfo {
                address,
                consensus_pubkey: hex::encode(consensus_pubkey),
                status: state.lifecycle().stored_status().ok_or_else(|| {
                    outbe_primitives::error::PrecompileError::Fatal(
                        "registered validator has no persisted status".into(),
                    )
                })?,
                stake: state.bonded_stake(),
                slash_count: history.slash_count(),
                missed_blocks: history.missed_blocks(),
                missed_votes: history.missed_votes(),
                blocks_proposed: history.blocks_proposed(),
                joined_at_height: history.joined_at_height(),
                deactivated_at_height: history.last_deactivated_at_height().unwrap_or(0),
                unbonding_end: state.unbonding_end_hint().unwrap_or(0),
                has_bls_share: state.has_bls_share(),
            }))
        })
    }

    async fn get_epoch_info(&self) -> RpcResult<EpochInfo> {
        self.with_latest_state(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            let epoch = vs.epoch_snapshot()?;
            let active_count = vs.active_validator_count()?;

            let staking = outbe_staking::contract::Staking::new(storage);
            let total_staked = staking.get_total_staked()?;

            Ok(EpochInfo {
                epoch_number: epoch.number,
                epoch_start_timestamp: epoch.start_timestamp,
                epoch_start_block: epoch.start_block,
                epoch_length_blocks: epoch.length_blocks,
                active_validator_count: active_count,
                total_staked,
            })
        })
    }

    async fn tee_renewal_schedule_v1(&self) -> RpcResult<TeeRenewalScheduleV1> {
        let config = self
            .tee_renewal_schedule
            .ok_or_else(|| internal_err("TEE renewal schedule is not configured".to_owned()))?;
        if config.minimum_block_time_millis == 0 {
            return Err(internal_err(
                "TEE renewal schedule has zero minimum block time".to_owned(),
            ));
        }
        let finalized = self
            .provider
            .finalized_block_num_hash()
            .map_err(|error| internal_err(format!("failed to read finalized block: {error}")))?
            .ok_or_else(|| internal_err("finalized block is unavailable".to_owned()))?;
        let header = self
            .provider
            .sealed_header(finalized.number)
            .map_err(|error| {
                internal_err(format!(
                    "failed to read finalized header {}: {error}",
                    finalized.number
                ))
            })?
            .ok_or_else(|| internal_err("finalized header is unavailable".to_owned()))?;
        if header.hash() != finalized.hash {
            return Err(internal_err(
                "finalized block marker and canonical header disagree".to_owned(),
            ));
        }
        let state = self
            .provider
            .state_by_block_hash(finalized.hash)
            .map_err(|error| internal_err(format!("failed to read finalized state: {error}")))?;
        let reader = RethStateReader { state: &state };
        let mut provider = ReadOnlyStorageProvider::new(reader);
        let storage = StorageHandle::new(&mut provider);
        let validators = outbe_validatorset::contract::ValidatorSet::new(storage);
        let epoch = validators
            .epoch_snapshot()
            .map_err(|error| internal_err(error.to_string()))?;
        let epoch_number = epoch.number;
        if epoch_number > U256::from(u64::MAX) {
            return Err(internal_err(
                "finalized epoch number exceeds u64".to_owned(),
            ));
        }
        let epoch_start_height = epoch.start_block;
        let epoch_length_blocks = epoch.length_blocks;
        if epoch_length_blocks == 0 {
            return Err(internal_err("finalized epoch length is zero".to_owned()));
        }
        let planned_activation_height = epoch_start_height
            .checked_add(u64::from(epoch_length_blocks))
            .ok_or_else(|| internal_err("planned activation height overflow".to_owned()))?;
        let prepare = config
            .dkg_prepare_window_blocks
            .min(u64::from(epoch_length_blocks));
        TeeRenewalScheduleV1 {
            finalized_height: finalized.number,
            finalized_hash: finalized.hash,
            finalized_timestamp: header.timestamp(),
            epoch_number: epoch_number.to::<u64>(),
            epoch_start_height,
            epoch_length_blocks,
            next_freeze_height: planned_activation_height.saturating_sub(prepare),
            planned_activation_height,
            dkg_prepare_window_blocks: prepare,
            minimum_block_time_millis: config.minimum_block_time_millis,
        }
        .validate()
        .map_err(|error| internal_err(error.to_owned()))
    }

    async fn get_stake(&self, address: Address) -> RpcResult<U256> {
        self.with_latest_state(|storage| {
            let staking = outbe_staking::contract::Staking::new(storage);
            staking.get_stake(address)
        })
    }

    async fn get_slash_info(&self, address: Address) -> RpcResult<SlashInfo> {
        self.with_latest_state(|storage| {
            let si = outbe_slashindicator::contract::SlashIndicator::new(storage);
            Ok(SlashInfo {
                proposer_miss_count: si.proposer_miss_count.read(&address)?,
                voter_miss_count: si.voter_miss_count.read(&address)?,
                felony_count: si.felony_count.read(&address)?,
            })
        })
    }

    async fn consensus_status(&self) -> RpcResult<ConsensusStatusInfo> {
        let is_validator = self.is_validator;
        let (status, has_threshold_shares) = self
            .bridge
            .as_ref()
            .map(ConsensusExecutionBridge::consensus_status_with_threshold_shares)
            .unwrap_or_default();
        let projection = projection_status_info(
            self.projection_readiness.current(),
            self.provider
                .finalized_block_num_hash()
                .ok()
                .flatten()
                .map(|block| (block.number, block.hash)),
        );

        Ok(ConsensusStatusInfo {
            current_view: status.current_view,
            connected_peers: status.connected_peers,
            is_active: status.is_active(),
            has_threshold_shares,
            last_finalized_block: status.last_finalized_block,
            last_vrf_seed: status.last_vrf_seed,
            randomness_status: status.randomness_status,
            vrf_material_version: status.vrf_material_version,
            last_dkg_activation_height: status.last_dkg_activation_height,
            next_planned_activation_height: status.next_planned_activation_height,
            vrf_expiry_height: status.vrf_expiry_height,
            is_validator,
            phase1_verification_mode: if is_validator {
                Phase1VerificationMode::ValidatorEnforced
            } else {
                Phase1VerificationMode::TrustedFinality
            },
            projection,
            enclave: enclave_health_info(
                &self.tee_enclave_health.snapshot(),
                std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
                    .unwrap_or(0),
            ),
        })
    }

    async fn get_vrf_seed(&self, block_number: Option<u64>) -> RpcResult<Option<B256>> {
        // read the committed VRF seed from the target block header's
        // `mixHash` (prev_randao) via the provider, honoring `block_number`.
        // This is the authoritative, per-node-consistent committed value - not
        // the process-local in-memory consensus seed (which a full node never
        // has and which can diverge between nodes). `None` resolves to the
        // latest canonical block, which under Outbe's fast finality is the
        // latest finalized block.
        let target = match block_number {
            Some(n) => n,
            None => self
                .provider
                .best_block_number()
                .map_err(|e| internal_err(format!("failed to read latest block number: {e}")))?,
        };
        let header = self
            .provider
            .header_by_number(target)
            .map_err(|e| internal_err(format!("failed to read header for block {target}: {e}")))?;
        // `mix_hash()` is itself `Option<B256>`; a missing block also yields None.
        Ok(header.and_then(|h| h.mix_hash()))
    }

    async fn get_emission_info(&self) -> RpcResult<EmissionInfo> {
        Ok(EmissionInfo {
            validator_reward_percent: outbe_rewards::logic::VALIDATOR_REWARD_PERCENT,
            fee_escrow_address: outbe_primitives::addresses::REWARDS_ADDRESS,
        })
    }

    async fn get_slash_config(&self) -> RpcResult<SlashConfig> {
        self.with_latest_state(read_effective_slash_config)
    }

    async fn get_participation(&self, address: Address) -> RpcResult<ParticipationInfo> {
        self.with_latest_state(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            let participation = vs.participation(address)?;
            Ok(ParticipationInfo {
                address,
                blocks_proposed: participation.blocks_proposed,
                missed_blocks: participation.missed_blocks,
                missed_votes: participation.missed_votes,
            })
        })
    }

    async fn sync_status(&self) -> RpcResult<SyncStatusInfo> {
        match &self.bridge {
            Some(b) => {
                let consensus = b.consensus_status();
                Ok(SyncStatusInfo {
                    is_syncing: !consensus.is_active(),
                    current_block: consensus.last_finalized_block,
                    highest_block: consensus.last_finalized_block,
                    consensus_active: consensus.is_active(),
                    connected_peers: consensus.connected_peers,
                })
            }
            None => {
                // Full-node mode: sync is handled by DevP2P (eth_syncing).
                // Report not syncing since we have no consensus bridge.
                Ok(SyncStatusInfo {
                    is_syncing: false,
                    current_block: 0,
                    highest_block: 0,
                    consensus_active: false,
                    connected_peers: 0,
                })
            }
        }
    }

    async fn radicle_status(&self) -> RpcResult<RadicleStatusInfo> {
        radicle_status_info(&self.radicle_status.snapshot()).map_err(internal_err)
    }

    async fn radicle_peers(&self) -> RpcResult<Vec<RadiclePeerInfo>> {
        Ok(self
            .radicle_status
            .snapshot()
            .signed_peers
            .iter()
            .map(radicle_peer_info)
            .collect())
    }

    async fn radicle_repositories(&self) -> RpcResult<Vec<RadicleRepositoryInfo>> {
        Ok(self
            .radicle_status
            .snapshot()
            .repositories
            .iter()
            .map(|repository| RadicleRepositoryInfo {
                repo_id: hex::encode(repository.repo_id),
                state: match repository.state {
                    RadicleRepositoryState::Available => RadicleRepositoryStateInfo::Available,
                    RadicleRepositoryState::Pending => RadicleRepositoryStateInfo::Pending,
                },
            })
            .collect())
    }

    async fn get_finalization(&self, height: u64) -> RpcResult<FinalizationProof> {
        // Only nodes running consensus (or a follower that has itself synced the
        // height) can serve this - both install a finalization fetcher on the
        // bridge at marshal-start. A node without a bridge (pure EL full node)
        // has no marshal and cannot answer.
        let bridge = self.bridge.as_ref().ok_or_else(|| {
            internal_err("node is not serving consensus finalizations".to_string())
        })?;
        let proof = bridge.request_finalization(height).await.ok_or_else(|| {
            internal_err(format!(
                "no finalization available for height {height} (not finalized locally or pruned)"
            ))
        })?;
        Ok(FinalizationProof {
            finalization_hex: format!("0x{}", hex::encode(&proof.finalization)),
            block_hex: format!("0x{}", hex::encode(&proof.block)),
        })
    }
}

fn projection_status_info(
    status: ProjectionStatus,
    reth_finalized: Option<(u64, B256)>,
) -> ProjectionStatusInfo {
    let (state, checkpoint, ready, unavailable_for_millis, last_failure_class) = match status {
        ProjectionStatus::Starting => (ProjectionHealth::Starting, None, false, None, None),
        ProjectionStatus::CatchingUp { checkpoint } => {
            (ProjectionHealth::CatchingUp, checkpoint, false, None, None)
        }
        ProjectionStatus::Ready { checkpoint } => {
            (ProjectionHealth::Ready, Some(checkpoint), true, None, None)
        }
        ProjectionStatus::MongoUnavailable { checkpoint, since } => (
            ProjectionHealth::MongoUnavailable,
            checkpoint,
            false,
            Some(u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)),
            Some("Unavailable".to_owned()),
        ),
        ProjectionStatus::Fatal { checkpoint, error } => (
            ProjectionHealth::Fatal,
            checkpoint,
            false,
            None,
            Some(format!("{:?}", error.class)),
        ),
    };
    let checkpoint_number = checkpoint.map(|value| value.block_number);
    let checkpoint_hash = checkpoint.map(|value| value.block_hash);
    let reth_finalized_number = reth_finalized.map(|value| value.0);
    let reth_finalized_hash = reth_finalized.map(|value| value.1);
    let lag_blocks = checkpoint_number.zip(reth_finalized_number).map(
        |(checkpoint_number, reth_finalized_number)| {
            reth_finalized_number.saturating_sub(checkpoint_number)
        },
    );
    ProjectionStatusInfo {
        state,
        checkpoint_number,
        checkpoint_hash,
        reth_finalized_number,
        reth_finalized_hash,
        lag_blocks,
        ready,
        unavailable_for_millis,
        last_failure_class,
    }
}

/// Create an internal JSON-RPC error.
fn internal_err(msg: String) -> jsonrpsee::types::ErrorObject<'static> {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INTERNAL_ERROR_CODE,
        msg,
        None::<()>,
    )
}

fn invalid_params(msg: String) -> jsonrpsee::types::ErrorObject<'static> {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        msg,
        None::<()>,
    )
}

fn invalid_params_err(msg: String) -> jsonrpsee::types::ErrorObject<'static> {
    invalid_params(msg)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Bytes, B256};
    use commonware_cryptography::{bls12381, Signer as _};
    use outbe_radicle::{
        endpoint::{sign_response, EndpointAddress, EndpointFrame, EndpointResponseBody, PeerId},
        integration::{RadicleStatusChannel, SignedEndpointEvidence},
    };

    use super::{
        radicle_peer_info, radicle_status_info, read_effective_slash_config,
        OcompLysisOpeningsRuntimeV1,
    };
    use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};

    #[tokio::test]
    async fn rudis_namespace_dispatches_and_rejects_old_wire_names() {
        use crate::api::OutbeApiServer;
        use outbe_primitives::projection::{
            projection_readiness, ProjectionCheckpoint, ProjectionStatus,
        };
        use reth_provider::test_utils::MockEthProvider;

        let baseline = ProjectionCheckpoint {
            block_number: 0,
            block_hash: B256::ZERO,
        };
        let (_publisher, readiness) = projection_readiness(
            baseline,
            ProjectionStatus::Ready {
                checkpoint: baseline,
            },
        );
        let handler = super::OutbeApiHandler::new(
            std::sync::Arc::new(MockEthProvider::<outbe_primitives::OutbePrimitives>::new()),
            readiness,
        );
        let module = handler.into_rpc();
        assert!(module.method_names().all(|name| name.starts_with("rudis_")));
        let (response, _) = module
            .raw_json_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"rudis_radicleStatus","params":[]}"#,
                1,
            )
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_str(response.get()).unwrap();
        assert_eq!(response["result"]["phase"], "disabled");
        assert!(response.get("error").is_none());
        let (response, _) = module
            .raw_json_request(
                r#"{"jsonrpc":"2.0","id":2,"method":"outbe_radicleStatus","params":[]}"#,
                1,
            )
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_str(response.get()).unwrap();
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn slash_config_rpc_reports_runtime_defaults_for_zero_storage() {
        let mut provider = HashMapStorageProvider::new(1);
        let config = StorageHandle::enter(&mut provider, |storage| {
            read_effective_slash_config(storage).expect("read effective slash config")
        });

        assert_eq!(config.proposer_misdemeanor_threshold, 50);
        assert_eq!(config.proposer_felony_threshold, 150);
        assert_eq!(config.voter_misdemeanor_threshold, 150);
        assert_eq!(config.voter_felony_threshold, 500);
        assert_eq!(config.slash_amount_percent, 5);
        assert_eq!(config.evidence_reward_percent, 10);
    }

    #[test]
    fn radicle_rpc_reads_immutable_status() {
        let status = radicle_status_info(&RadicleStatusChannel::disabled().snapshot()).unwrap();
        assert_eq!(status.phase, crate::api::RadiclePhaseInfo::Disabled);
        assert!(status.local_node_id.is_none());
        assert_eq!(status.desired_repository_count, 0);
    }

    #[test]
    fn enclave_health_defaults_to_disabled() {
        let info = super::enclave_health_info(
            &outbe_tee::TeeEnclaveHealthChannel::disabled().snapshot(),
            1_000_000,
        );
        assert_eq!(info.state, crate::api::EnclaveHealth::Disabled);
        assert!(!info.ready);
        assert!(info.last_ok_ago_millis.is_none());
        assert!(info.health_probe_supported.is_none());
    }

    #[test]
    fn enclave_health_maps_ready_snapshot() {
        let channel = outbe_tee::TeeEnclaveHealthChannel::disabled();
        channel.publish(outbe_tee::TeeEnclaveHealthSnapshot {
            state: outbe_tee::TeeEnclaveHealthState::Ready,
            last_ok_unix_ms: Some(900_000),
            last_canary_latency_ms: Some(4),
            consecutive_failures: 0,
            last_failure: None,
            offer_key_ready: true,
            health_probe_supported: Some(true),
            enclave: Some(outbe_tee::protocol::EnclaveHealthStatusV1 {
                uptime_s: 77,
                offer_key_ready: true,
                heap_current_bytes: 1024,
                heap_peak_bytes: 4096,
                requests_total: 10,
                requests_errored: 0,
                requests_denied: 0,
                class_initialized: 2,
                class_founding_keyless: 0,
                class_keyless_onboarding: 0,
                class_ready: 8,
                class_dev_source_seal: 0,
                class_dev_recipient_ingest: 0,
            }),
        });
        let info = super::enclave_health_info(&channel.snapshot(), 1_000_000);
        assert_eq!(info.state, crate::api::EnclaveHealth::Ready);
        assert!(info.ready);
        assert_eq!(info.last_ok_ago_millis, Some(100_000));
        assert_eq!(info.last_canary_latency_ms, Some(4));
        assert_eq!(info.uptime_s, Some(77));
        assert_eq!(info.heap_peak_bytes, Some(4096));
        // Stable JSON vocabulary (camelCase, lowercase state labels).
        let json = serde_json::to_string(&info).expect("serialize");
        assert!(json.contains("\"state\":\"ready\""), "json: {json}");
        assert!(json.contains("\"offerKeyReady\":true"), "json: {json}");
        assert!(
            json.contains("\"healthProbeSupported\":true"),
            "json: {json}"
        );
    }

    #[test]
    fn radicle_rpc_evidence() {
        let signer = bls12381::PrivateKey::from_seed(7);
        let body = EndpointResponseBody {
            request_id: [8_u8; 32],
            chain_id: 70_860_602,
            genesis_hash: B256::repeat_byte(0xaa),
            validator: alloy_primitives::Address::repeat_byte(0x11),
            node_id: [9_u8; 32],
            addresses: vec![EndpointAddress::dns("peer.example.com", 8776).unwrap()],
            anchor_number: 40,
            anchor_hash: B256::repeat_byte(0x40),
            valid_until: 80,
        };
        let response = sign_response(body, &signer).unwrap();
        let evidence = SignedEndpointEvidence {
            peer: PeerId::from_public_key(&signer.public_key()),
            encoded_frame: EndpointFrame::Response(Box::new(response.clone())).encode(),
            response,
        };
        let info = radicle_peer_info(&evidence);
        assert_eq!(info.sender_bls_public_key.len(), 48);
        assert_eq!(info.signature.len(), 96);
        assert_eq!(info.encoded_frame.as_ref(), evidence.encoded_frame);
        assert_eq!(info.addresses, ["peer.example.com:8776"]);
        assert_eq!(info.valid_until_height, 80);
    }

    #[test]
    fn ocomp_openings_runtime_forwards_exact_intent_and_canonical_request() {
        let expected_intent = B256::repeat_byte(0x41);
        let expected_request = Bytes::from_static(b"canonical-request");
        let runtime = OcompLysisOpeningsRuntimeV1::new({
            let expected_request = expected_request.clone();
            move |intent_id, request| {
                assert_eq!(intent_id, expected_intent);
                assert_eq!(request, expected_request);
                Ok(Bytes::from_static(b"canonical-openings"))
            }
        });

        assert_eq!(
            runtime
                .build(expected_intent, expected_request)
                .expect("purpose-bound openings"),
            Bytes::from_static(b"canonical-openings")
        );
    }
}
