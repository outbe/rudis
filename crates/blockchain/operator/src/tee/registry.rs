//! Canonical Registry selectors and exact onboarding expectations.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolCall;
use eyre::{Result, WrapErr as _};
use outbe_primitives::{
    addresses::TEE_REGISTRY_ADDRESS,
    tee_attestation_v1::{AttestationMode, TeePolicyV1},
    tee_operator_v1::TeeRenewalScheduleV1,
    tee_registry_abi_v1::{ITeeRegistryV1, NodeEnclaveBindingV1View},
};
use outbe_tee::FinalizedRegistryViewV1;
use serde::{Deserialize, Serialize};

use crate::rpc::RenewalRpc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeBindingSelectorV1 {
    NodeHost([u8; 33]),
    Validator(Address),
}

impl NodeBindingSelectorV1 {
    pub fn binding_call(&self) -> Vec<u8> {
        match self {
            Self::NodeHost(public) => ITeeRegistryV1::nodeHostEnclaveBindingCall {
                rethP2pPrefix: public[0],
                rethP2pX: B256::from_slice(&public[1..]),
            }
            .abi_encode(),
            Self::Validator(validator) => ITeeRegistryV1::validatorEnclaveBindingCall {
                validator: *validator,
            }
            .abi_encode(),
        }
    }

    pub fn decode_binding(
        &self,
        encoded: &[u8],
    ) -> alloy_sol_types::Result<NodeEnclaveBindingV1View> {
        match self {
            Self::NodeHost(_) => {
                ITeeRegistryV1::nodeHostEnclaveBindingCall::abi_decode_returns(encoded)
            }
            Self::Validator(_) => {
                ITeeRegistryV1::validatorEnclaveBindingCall::abi_decode_returns(encoded)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenewalBindingV1 {
    pub node_id_hash: B256,
    pub enclave_id: B256,
    pub binding_id: B256,
    pub intent_hash: B256,
    pub evidence_hash: B256,
    pub policy_hash: B256,
    pub binding_version: u64,
    pub registration_version: u64,
    pub renewal_nonce: u64,
    pub transition_nonce: u64,
    pub lease_started_at: u64,
    pub valid_until: u64,
    pub collateral_valid_until: u64,
    pub recipient_x25519: B256,
    pub attestation_ed25519: B256,
    pub noise_responder_x25519: B256,
    pub mrenclave: B256,
    pub mrsigner: B256,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub platform_tcb_status: u8,
    pub verdict_hash: B256,
    pub node_host_authorization_hash: B256,
}

impl TryFrom<NodeEnclaveBindingV1View> for RenewalBindingV1 {
    type Error = eyre::Report;

    fn try_from(value: NodeEnclaveBindingV1View) -> Result<Self> {
        if !value.exists {
            eyre::bail!("finalized Registry has no enclave binding for this node");
        }
        Ok(Self {
            node_id_hash: value.nodeIdHash,
            enclave_id: value.enclaveId,
            binding_id: value.bindingId,
            intent_hash: value.intentHash,
            evidence_hash: value.evidenceHash,
            policy_hash: value.policyHash,
            binding_version: value.bindingVersion,
            registration_version: value.registrationVersion,
            renewal_nonce: value.renewalNonce,
            transition_nonce: value.transitionNonce,
            lease_started_at: value.leaseStartedAt,
            valid_until: value.validUntil,
            collateral_valid_until: value.collateralValidUntil,
            recipient_x25519: value.recipientX25519,
            attestation_ed25519: value.attestationEd25519,
            noise_responder_x25519: value.noiseResponderX25519,
            mrenclave: value.mrenclave,
            mrsigner: value.mrsigner,
            isv_prod_id: value.isvProdId,
            isv_svn: value.isvSvn,
            platform_tcb_status: value.platformTcbStatus,
            verdict_hash: value.verdictHash,
            node_host_authorization_hash: value.nodeHostAuthorizationHash,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedRenewalChainViewV1 {
    pub schedule: TeeRenewalScheduleV1,
    pub policy: TeePolicyV1,
    pub binding: RenewalBindingV1,
    pub tribute_offer_public: B256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedRegistryChainViewV1 {
    pub schedule: TeeRenewalScheduleV1,
    pub view: FinalizedRegistryViewV1,
    pub policy: TeePolicyV1,
    pub binding: Option<RenewalBindingV1>,
    pub tribute_offer_public: B256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedStagedSuccessorPolicyV1 {
    pub finalized_height: u64,
    pub finalized_hash: B256,
    pub proposal_id: U256,
    pub policy: TeePolicyV1,
}

/// Read the staged successor only at the RPC node's exact finalized block.
/// Latest/pending state is deliberately never used for an upgrade decision.
pub async fn read_finalized_staged_successor_policy_v1(
    rpc: &(impl RenewalRpc + Sync),
) -> Result<Option<FinalizedStagedSuccessorPolicyV1>> {
    let finalized = rpc
        .finalized_block()
        .await
        .wrap_err("read finalized block for staged TEE policy")?;
    let finalized_height = json_hex_u64(&finalized, "number")?;
    let finalized_hash = finalized
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("finalized block has no hash"))?
        .parse::<B256>()
        .wrap_err("parse finalized block hash")?;
    let tag = format!("0x{finalized_height:x}");
    let encoded = rpc
        .call_at(
            TEE_REGISTRY_ADDRESS,
            &ITeeRegistryV1::stagedSuccessorPolicyV1Call {}.abi_encode(),
            &tag,
        )
        .await
        .wrap_err("read finalized staged successor TEE policy")?;
    let view = ITeeRegistryV1::stagedSuccessorPolicyV1Call::abi_decode_returns(&encoded)
        .wrap_err("decode finalized staged successor TEE policy")?;
    if !view.exists {
        if !view.proposalId.is_zero() || !view.policy.is_empty() {
            eyre::bail!("empty finalized staged policy view has non-empty anchors");
        }
        return Ok(None);
    }
    if view.proposalId.is_zero() || view.policy.is_empty() {
        eyre::bail!("finalized staged policy view is incomplete");
    }
    let policy = TeePolicyV1::decode_canonical(&view.policy)
        .map_err(|error| eyre::eyre!("finalized staged TEE policy is non-canonical: {error}"))?;
    let rpc_chain_id = rpc.chain_id().await.wrap_err("read eth_chainId")?;
    if policy.chain_id != U256::from(rpc_chain_id).to_be_bytes() {
        eyre::bail!("finalized staged TEE policy chain id does not match eth_chainId");
    }
    Ok(Some(FinalizedStagedSuccessorPolicyV1 {
        finalized_height,
        finalized_hash,
        proposal_id: view.proposalId,
        policy,
    }))
}

pub async fn read_finalized_renewal_view_v1(
    rpc: &(impl RenewalRpc + Sync),
    selector: &NodeBindingSelectorV1,
) -> Result<FinalizedRenewalChainViewV1> {
    let view = read_finalized_registry_view_v1(rpc, selector).await?;
    require_dcap_renewal_mode_v1(view.policy.attestation_mode)?;
    require_bound_renewal_view_v1(view)
}

/// Read the exact finalized policy and required binding for the shared manual
/// renewal lifecycle, independent of the genesis-selected evidence mode.
pub async fn read_finalized_bound_renewal_view_v1(
    rpc: &(impl RenewalRpc + Sync),
    selector: &NodeBindingSelectorV1,
) -> Result<FinalizedRenewalChainViewV1> {
    let view = read_finalized_registry_view_v1(rpc, selector).await?;
    require_bound_renewal_view_v1(view)
}

fn require_bound_renewal_view_v1(
    view: FinalizedRegistryChainViewV1,
) -> Result<FinalizedRenewalChainViewV1> {
    let binding = view
        .binding
        .ok_or_else(|| eyre::eyre!("finalized Registry has no enclave binding for this node"))?;
    Ok(FinalizedRenewalChainViewV1 {
        schedule: view.schedule,
        policy: view.policy,
        binding,
        tribute_offer_public: view.tribute_offer_public,
    })
}

fn require_dcap_renewal_mode_v1(mode: AttestationMode) -> Result<()> {
    if mode != AttestationMode::DcapRequired {
        eyre::bail!("DCAP renewal is disabled for non-DcapRequired networks");
    }
    Ok(())
}

/// Read the exact finalized policy and optional node binding used by initial
/// join, live-lease rejection, and expired rejoin recovery.
pub async fn read_finalized_registry_view_v1(
    rpc: &(impl RenewalRpc + Sync),
    selector: &NodeBindingSelectorV1,
) -> Result<FinalizedRegistryChainViewV1> {
    let schedule = rpc
        .tee_renewal_schedule_v1()
        .await
        .wrap_err("read exact finalized TEE renewal schedule")?
        .validate()
        .map_err(eyre::Report::msg)?;
    let finalized = rpc
        .finalized_block()
        .await
        .wrap_err("read finalized block")?;
    let number = json_hex_u64(&finalized, "number")?;
    let timestamp = json_hex_u64(&finalized, "timestamp")?;
    let hash = finalized
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("finalized block has no hash"))?
        .parse::<B256>()
        .wrap_err("parse finalized block hash")?;
    let state_root = finalized
        .get("stateRoot")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("finalized block has no stateRoot"))?
        .parse::<B256>()
        .wrap_err("parse finalized block stateRoot")?;
    if number != schedule.finalized_height
        || timestamp != schedule.finalized_timestamp
        || hash != schedule.finalized_hash
    {
        eyre::bail!("finalized schedule and eth finalized block disagree");
    }
    let tag = format!("0x{number:x}");
    let policy_bytes = rpc
        .call_at(
            TEE_REGISTRY_ADDRESS,
            &ITeeRegistryV1::activePolicyV1Call {}.abi_encode(),
            &tag,
        )
        .await
        .wrap_err("read finalized active TEE policy")?;
    let canonical = ITeeRegistryV1::activePolicyV1Call::abi_decode_returns(&policy_bytes)
        .wrap_err("decode finalized active TEE policy")?;
    let policy = TeePolicyV1::decode_canonical(&canonical)
        .map_err(|error| eyre::eyre!("finalized TEE policy is non-canonical: {error}"))?;
    let rpc_chain_id = rpc.chain_id().await.wrap_err("read eth_chainId")?;
    if policy.chain_id != U256::from(rpc_chain_id).to_be_bytes() {
        eyre::bail!("finalized TEE policy chain id does not match eth_chainId");
    }
    let binding_bytes = rpc
        .call_at(TEE_REGISTRY_ADDRESS, &selector.binding_call(), &tag)
        .await
        .wrap_err("read finalized enclave binding")?;
    let binding_view = selector
        .decode_binding(&binding_bytes)
        .wrap_err("decode finalized enclave binding")?;
    let binding = binding_view
        .exists
        .then(|| RenewalBindingV1::try_from(binding_view))
        .transpose()?;
    let offer_bytes = rpc
        .call_at(
            TEE_REGISTRY_ADDRESS,
            &ITeeRegistryV1::tributeOfferPublicKeyCall {}.abi_encode(),
            &tag,
        )
        .await
        .wrap_err("read finalized tribute offer public key")?;
    let offer = ITeeRegistryV1::tributeOfferPublicKeyCall::abi_decode_returns(&offer_bytes)
        .wrap_err("decode finalized tribute offer public key")?;
    let tribute_offer_public = B256::from(offer.to_be_bytes::<32>());
    if tribute_offer_public.is_zero() {
        eyre::bail!("finalized Registry tribute offer public key is zero");
    }
    Ok(FinalizedRegistryChainViewV1 {
        schedule,
        view: FinalizedRegistryViewV1 {
            chain_id: policy.chain_id,
            genesis_hash: policy.genesis_hash,
            block_number: number,
            block_hash: hash,
            state_root,
            consensus_timestamp: timestamp,
        },
        policy,
        binding,
        tribute_offer_public,
    })
}

fn json_hex_u64(value: &serde_json::Value, field: &str) -> Result<u64> {
    let encoded = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("finalized block has no {field}"))?;
    u64::from_str_radix(encoded.strip_prefix("0x").unwrap_or(encoded), 16)
        .wrap_err_with(|| format!("parse finalized block {field}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedOnboardingBindingV1 {
    pub selector: NodeBindingSelectorV1,
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub node_id_hash: B256,
    pub enclave_id: B256,
    pub intent_hash: B256,
    pub recipient_x25519: [u8; 32],
    pub tribute_offer_public: [u8; 32],
    pub key_epoch: u64,
    pub tribute_offer_epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::FinalityRpc;
    use alloy_primitives::Bytes;
    use outbe_primitives::{
        chain::DEVNET_CHAIN_ID,
        tee_genesis_v1::{initial_tee_policy_v1, InitialTeeProfileV1, ProductionSgxMeasurementV1},
        tee_operator_v1::TeeRenewalScheduleV1,
    };

    #[derive(Clone)]
    struct RegistryRpc {
        policy: TeePolicyV1,
        binding: NodeEnclaveBindingV1View,
        schedule: TeeRenewalScheduleV1,
    }

    impl FinalityRpc for RegistryRpc {
        async fn transaction_receipt(
            &self,
            _transaction_hash: &str,
        ) -> Result<Option<serde_json::Value>> {
            eyre::bail!("unused transaction_receipt");
        }

        async fn logs(
            &self,
            _address: Address,
            _topics: &[Option<String>],
            _from_block: &str,
            _to_block: &str,
        ) -> Result<Vec<serde_json::Value>> {
            eyre::bail!("unused logs");
        }

        async fn block_by_number(&self, _block: u64) -> Result<serde_json::Value> {
            eyre::bail!("unused block_by_number");
        }

        async fn finalized_block(&self) -> Result<serde_json::Value> {
            Ok(serde_json::json!({
                "number": format!("0x{:x}", self.schedule.finalized_height),
                "timestamp": format!("0x{:x}", self.schedule.finalized_timestamp),
                "hash": format!("{:#x}", self.schedule.finalized_hash),
                "stateRoot": format!("{:#x}", B256::repeat_byte(0x71)),
            }))
        }

        async fn call_at(&self, _to: Address, data: &[u8], _block_tag: &str) -> Result<Vec<u8>> {
            if data.starts_with(&ITeeRegistryV1::activePolicyV1Call::SELECTOR) {
                let policy = Bytes::from(self.policy.encode_canonical().unwrap());
                return Ok(ITeeRegistryV1::activePolicyV1Call::abi_encode_returns(
                    &policy,
                ));
            }
            if data.starts_with(&ITeeRegistryV1::nodeHostEnclaveBindingCall::SELECTOR) {
                return Ok(
                    ITeeRegistryV1::nodeHostEnclaveBindingCall::abi_encode_returns(&self.binding),
                );
            }
            if data.starts_with(&ITeeRegistryV1::tributeOfferPublicKeyCall::SELECTOR) {
                return Ok(
                    ITeeRegistryV1::tributeOfferPublicKeyCall::abi_encode_returns(&U256::from(7)),
                );
            }
            eyre::bail!("unexpected Registry call");
        }
    }

    impl RenewalRpc for RegistryRpc {
        async fn chain_id(&self) -> Result<u64> {
            Ok(DEVNET_CHAIN_ID)
        }

        async fn gas_price(&self) -> Result<U256> {
            eyre::bail!("unused gas_price");
        }

        async fn transaction_count(&self, _address: Address) -> Result<u64> {
            eyre::bail!("unused transaction_count");
        }

        async fn balance(&self, _address: Address) -> Result<U256> {
            eyre::bail!("unused balance");
        }

        async fn send_raw_transaction(&self, _raw_transaction: &[u8]) -> Result<String> {
            eyre::bail!("unused send_raw_transaction");
        }

        async fn tee_renewal_schedule_v1(&self) -> Result<TeeRenewalScheduleV1> {
            Ok(self.schedule)
        }
    }

    fn registry_rpc(binding_exists: bool, mode: AttestationMode) -> RegistryRpc {
        let finalized_hash = B256::repeat_byte(0x70);
        let profile = match mode {
            AttestationMode::DcapRequired => {
                InitialTeeProfileV1::DcapRequired(ProductionSgxMeasurementV1 {
                    mrenclave: B256::repeat_byte(0x61),
                    mrsigner: B256::repeat_byte(0x62),
                    isv_prod_id: 1,
                    minimum_isv_svn: 1,
                    minimum_tcb_evaluation_data_number: 1,
                })
            }
            AttestationMode::GramineDirectDev => InitialTeeProfileV1::GramineDirectDev,
        };
        RegistryRpc {
            policy: initial_tee_policy_v1(profile, DEVNET_CHAIN_ID, B256::repeat_byte(0x72))
                .unwrap(),
            binding: NodeEnclaveBindingV1View {
                exists: binding_exists,
                nodeIdHash: B256::repeat_byte(0x73),
                enclaveId: B256::repeat_byte(0x74),
                bindingId: B256::repeat_byte(0x75),
                intentHash: B256::repeat_byte(0x76),
                evidenceHash: B256::repeat_byte(0x77),
                policyHash: B256::repeat_byte(0x78),
                bindingVersion: 1,
                registrationVersion: 1,
                renewalNonce: 1,
                transitionNonce: 0,
                leaseStartedAt: 100,
                validUntil: 200,
                collateralValidUntil: u64::MAX,
                recipientX25519: B256::repeat_byte(0x79),
                attestationEd25519: B256::repeat_byte(0x7a),
                noiseResponderX25519: B256::repeat_byte(0x7b),
                mrenclave: B256::ZERO,
                mrsigner: B256::ZERO,
                isvProdId: 0,
                isvSvn: 0,
                platformTcbStatus: 0,
                verdictHash: B256::ZERO,
                nodeHostAuthorizationHash: B256::repeat_byte(0x7c),
            },
            schedule: TeeRenewalScheduleV1 {
                finalized_height: 120,
                finalized_hash,
                finalized_timestamp: 1_000,
                epoch_number: 2,
                epoch_start_height: 100,
                epoch_length_blocks: 100,
                next_freeze_height: 180,
                planned_activation_height: 200,
                dkg_prepare_window_blocks: 20,
                minimum_block_time_millis: 2_000,
            },
        }
    }

    #[test]
    fn finalized_join_selectors_cover_node_host_and_evm_association() {
        let node = NodeBindingSelectorV1::NodeHost([2; 33]).binding_call();
        let validator = NodeBindingSelectorV1::Validator(Address::repeat_byte(3)).binding_call();
        assert_eq!(
            &node[..4],
            ITeeRegistryV1::nodeHostEnclaveBindingCall::SELECTOR
        );
        assert_eq!(
            &validator[..4],
            ITeeRegistryV1::validatorEnclaveBindingCall::SELECTOR
        );
        assert_ne!(node, validator);
    }

    #[test]
    fn legacy_dcap_reader_gate_stays_dcap_only() {
        assert!(require_dcap_renewal_mode_v1(AttestationMode::DcapRequired).is_ok());
        assert!(
            require_dcap_renewal_mode_v1(AttestationMode::GramineDirectDev)
                .unwrap_err()
                .to_string()
                .contains("DCAP renewal is disabled")
        );
    }

    #[tokio::test]
    async fn public_readers_keep_mode_neutral_binding_and_legacy_dcap_error_order() {
        let selector = NodeBindingSelectorV1::NodeHost([2; 33]);
        let bound = read_finalized_bound_renewal_view_v1(
            &registry_rpc(true, AttestationMode::GramineDirectDev),
            &selector,
        )
        .await
        .unwrap();
        assert_eq!(
            bound.policy.attestation_mode,
            AttestationMode::GramineDirectDev
        );
        assert_eq!(bound.binding.binding_id, B256::repeat_byte(0x75));

        let legacy_error = read_finalized_renewal_view_v1(
            &registry_rpc(false, AttestationMode::GramineDirectDev),
            &selector,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(legacy_error.contains("DCAP renewal is disabled"));

        let neutral_error = read_finalized_bound_renewal_view_v1(
            &registry_rpc(false, AttestationMode::GramineDirectDev),
            &selector,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(neutral_error.contains("no enclave binding"));

        let dcap_rpc = registry_rpc(true, AttestationMode::DcapRequired);
        assert_eq!(
            read_finalized_bound_renewal_view_v1(&dcap_rpc, &selector)
                .await
                .unwrap()
                .policy
                .attestation_mode,
            AttestationMode::DcapRequired
        );
        assert_eq!(
            read_finalized_renewal_view_v1(&dcap_rpc, &selector)
                .await
                .unwrap()
                .policy
                .attestation_mode,
            AttestationMode::DcapRequired
        );
    }
}
