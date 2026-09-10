//! Finality-gated retrieval of one exact Registry onboarding artifact.

use std::time::Duration;

use alloy_primitives::{B256, U256};
use alloy_sol_types::SolEvent;
use eyre::{Result, WrapErr as _};
use outbe_primitives::{addresses::TEE_REGISTRY_ADDRESS, tee_registry_abi_v1::ITeeRegistryV1};
use outbe_tee::dcap_protocol::DcapOnboardingArtifactV1;

use crate::rpc::FinalityRpc;

use super::registry::ExpectedOnboardingBindingV1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedOnboardingV1 {
    pub artifact: DcapOnboardingArtifactV1,
    pub receipt_block_number: u64,
    pub receipt_block_hash: B256,
    pub finalized_height: u64,
}

pub async fn await_finalized_onboarding_v1(
    rpc: &(impl FinalityRpc + Sync),
    transaction_hash: &str,
    expected: &ExpectedOnboardingBindingV1,
    timeout: Duration,
) -> Result<FinalizedOnboardingV1> {
    let started = tokio::time::Instant::now();
    loop {
        if started.elapsed() >= timeout {
            eyre::bail!(
                "timed out after {}s waiting for exact finalized TeeRegistry onboarding",
                timeout.as_secs()
            );
        }
        let Some(receipt) = rpc
            .transaction_receipt(transaction_hash)
            .await
            .wrap_err("read onboarding transaction receipt")?
        else {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        };
        let receipt_facts = receipt_facts(&receipt, transaction_hash)?;
        if !receipt_facts.success {
            eyre::bail!(
                "registerEnclave transaction {transaction_hash} reverted in block {}",
                receipt_facts.block_number
            );
        }

        let finalized = rpc
            .finalized_block()
            .await
            .wrap_err("read finalized head")?;
        let finalized_height = hex_field_u64(&finalized, "number", "finalized block")?;
        if finalized_height < receipt_facts.block_number {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }

        let canonical = rpc
            .block_by_number(receipt_facts.block_number)
            .await
            .wrap_err("read canonical receipt-height block")?;
        let canonical_hash = b256_field(&canonical, "hash", "canonical block")?;
        if canonical_hash != receipt_facts.block_hash {
            eyre::bail!(
                "registerEnclave receipt was reorged before finality; key possession is possible but canonical join is not claimed"
            );
        }

        let block_tag = format!("0x{:x}", receipt_facts.block_number);
        let topic0 = format!(
            "0x{}",
            hex::encode(ITeeRegistryV1::OfferKeySealedForRegistryV1::SIGNATURE_HASH)
        );
        let topic1 = format!("0x{}", hex::encode(expected.node_id_hash));
        let logs = rpc
            .logs(
                TEE_REGISTRY_ADDRESS,
                &[Some(topic0.clone()), Some(topic1.clone())],
                &block_tag,
                &block_tag,
            )
            .await
            .wrap_err("read finalized onboarding event")?;
        let artifact = exact_artifact(&logs, &topic0, &topic1, transaction_hash, expected)?;

        let binding_bytes = rpc
            .call_at(
                TEE_REGISTRY_ADDRESS,
                &expected.selector.binding_call(),
                &block_tag,
            )
            .await
            .wrap_err("read enclave binding at the finalized receipt block")?;
        let binding = expected
            .selector
            .decode_binding(&binding_bytes)
            .wrap_err("decode finalized enclave binding")?;
        if !binding.exists
            || binding.nodeIdHash != expected.node_id_hash
            || binding.enclaveId != expected.enclave_id
            || binding.intentHash != expected.intent_hash
            || binding.recipientX25519 != B256::from(expected.recipient_x25519)
        {
            eyre::bail!("finalized Registry binding does not match the submitted registration");
        }
        return Ok(FinalizedOnboardingV1 {
            artifact,
            receipt_block_number: receipt_facts.block_number,
            receipt_block_hash: receipt_facts.block_hash,
            finalized_height,
        });
    }
}

struct ReceiptFactsV1 {
    success: bool,
    block_number: u64,
    block_hash: B256,
}

fn receipt_facts(receipt: &serde_json::Value, transaction_hash: &str) -> Result<ReceiptFactsV1> {
    let actual_hash = receipt
        .get("transactionHash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("registration receipt has no transactionHash"))?;
    if !actual_hash.eq_ignore_ascii_case(transaction_hash) {
        eyre::bail!("registration receipt transaction hash mismatch");
    }
    let status = hex_field_u64(receipt, "status", "registration receipt")?;
    if status > 1 {
        eyre::bail!("registration receipt has non-canonical status {status}");
    }
    Ok(ReceiptFactsV1 {
        success: status == 1,
        block_number: hex_field_u64(receipt, "blockNumber", "registration receipt")?,
        block_hash: b256_field(receipt, "blockHash", "registration receipt")?,
    })
}

fn exact_artifact(
    logs: &[serde_json::Value],
    topic0: &str,
    topic1: &str,
    transaction_hash: &str,
    expected: &ExpectedOnboardingBindingV1,
) -> Result<DcapOnboardingArtifactV1> {
    let mut exact = None;
    for log in logs {
        let Some(actual_tx) = log
            .get("transactionHash")
            .and_then(serde_json::Value::as_str)
        else {
            eyre::bail!("onboarding log has no transactionHash");
        };
        if !actual_tx.eq_ignore_ascii_case(transaction_hash) {
            continue;
        }
        let topics = log
            .get("topics")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| eyre::eyre!("onboarding log has no topics"))?;
        if topics.len() != 2
            || topics[0]
                .as_str()
                .is_none_or(|value| !value.eq_ignore_ascii_case(topic0))
            || topics[1]
                .as_str()
                .is_none_or(|value| !value.eq_ignore_ascii_case(topic1))
        {
            eyre::bail!("onboarding event topics are non-canonical");
        }
        let data = log
            .get("data")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| eyre::eyre!("onboarding log has no data"))?;
        let encoded = hex::decode(data.strip_prefix("0x").unwrap_or(data))
            .wrap_err("decode onboarding event data")?;
        let bytes = decode_single_dynamic_bytes(&encoded)?;
        let artifact = DcapOnboardingArtifactV1::decode_canonical(&bytes)
            .map_err(|code| eyre::eyre!("invalid onboarding artifact: {:#06x}", code.code()))?;
        let context = artifact.context;
        if context.chain_id != expected.chain_id
            || context.genesis_hash != expected.genesis_hash
            || context.intent_hash != expected.intent_hash
            || context.node_id_hash != expected.node_id_hash
            || context.enclave_id != expected.enclave_id
            || context.recipient_x25519 != expected.recipient_x25519
            || context.tribute_offer_public != expected.tribute_offer_public
            || context.key_epoch != expected.key_epoch
            || context.tribute_offer_epoch != expected.tribute_offer_epoch
        {
            eyre::bail!("onboarding artifact context does not match the exact registration");
        }
        if exact.replace(artifact).is_some() {
            eyre::bail!("transaction emitted more than one exact onboarding artifact");
        }
    }
    exact.ok_or_else(|| eyre::eyre!("finalized transaction has no exact onboarding artifact"))
}

fn decode_single_dynamic_bytes(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 64 || U256::from_be_slice(&data[..32]) != U256::from(32) {
        eyre::bail!("onboarding event has non-canonical bytes offset");
    }
    let len_word = U256::from_be_slice(&data[32..64]);
    if len_word > U256::from(outbe_tee::dcap_protocol::MAX_DCAP_ONBOARDING_ARTIFACT_BYTES) {
        eyre::bail!("onboarding artifact exceeds its protocol cap");
    }
    let len = len_word.to::<usize>();
    let padded = len
        .checked_add(31)
        .map(|value| value / 32 * 32)
        .ok_or_else(|| eyre::eyre!("onboarding event length overflow"))?;
    if data.len() != 64 + padded || data[64 + len..].iter().any(|byte| *byte != 0) {
        eyre::bail!("onboarding event data or padding is non-canonical");
    }
    Ok(data[64..64 + len].to_vec())
}

fn hex_field_u64(value: &serde_json::Value, field: &str, context: &str) -> Result<u64> {
    let encoded = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("{context} has no {field}"))?;
    u64::from_str_radix(encoded.strip_prefix("0x").unwrap_or(encoded), 16)
        .wrap_err_with(|| format!("parse {context} {field}"))
}

fn b256_field(value: &serde_json::Value, field: &str, context: &str) -> Result<B256> {
    let encoded = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("{context} has no {field}"))?;
    encoded
        .parse::<B256>()
        .wrap_err_with(|| format!("parse {context} {field}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use alloy_sol_types::SolCall;
    use outbe_primitives::tee_registry_abi_v1::NodeEnclaveBindingV1View;

    use crate::{
        rpc::FinalityRpc,
        tee::registry::{ExpectedOnboardingBindingV1, NodeBindingSelectorV1},
    };

    struct MockRpc {
        receipt: serde_json::Value,
        canonical_block: serde_json::Value,
        finalized_block: serde_json::Value,
        logs: Vec<serde_json::Value>,
        binding: Vec<u8>,
        binding_call_block_tags: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl FinalityRpc for MockRpc {
        async fn transaction_receipt(
            &self,
            _transaction_hash: &str,
        ) -> Result<Option<serde_json::Value>> {
            Ok(Some(self.receipt.clone()))
        }

        async fn logs(
            &self,
            _address: Address,
            _topics: &[Option<String>],
            _from_block: &str,
            _to_block: &str,
        ) -> Result<Vec<serde_json::Value>> {
            Ok(self.logs.clone())
        }

        async fn block_by_number(&self, _block: u64) -> Result<serde_json::Value> {
            Ok(self.canonical_block.clone())
        }

        async fn finalized_block(&self) -> Result<serde_json::Value> {
            Ok(self.finalized_block.clone())
        }

        async fn call_at(&self, _to: Address, _data: &[u8], block_tag: &str) -> Result<Vec<u8>> {
            self.binding_call_block_tags
                .lock()
                .unwrap()
                .push(block_tag.to_owned());
            Ok(self.binding.clone())
        }
    }

    fn fixture() -> (MockRpc, ExpectedOnboardingBindingV1, String) {
        let tx_hash = format!("0x{}", "11".repeat(32));
        let block_hash = B256::repeat_byte(0x12);
        let expected = ExpectedOnboardingBindingV1 {
            selector: NodeBindingSelectorV1::NodeHost([0x13; 33]),
            chain_id: [0x14; 32],
            genesis_hash: B256::repeat_byte(0x15),
            node_id_hash: B256::repeat_byte(0x16),
            enclave_id: B256::repeat_byte(0x17),
            intent_hash: B256::repeat_byte(0x18),
            recipient_x25519: [0x19; 32],
            tribute_offer_public: [0x1a; 32],
            key_epoch: 2,
            tribute_offer_epoch: 3,
        };
        let artifact = DcapOnboardingArtifactV1 {
            context: outbe_tee::dcap_protocol::DcapOnboardingContextV1 {
                chain_id: expected.chain_id,
                genesis_hash: expected.genesis_hash,
                intent_hash: expected.intent_hash,
                node_id_hash: expected.node_id_hash,
                enclave_id: expected.enclave_id,
                binding_id: B256::repeat_byte(0x1d),
                policy_hash: B256::repeat_byte(0x1e),
                recipient_x25519: expected.recipient_x25519,
                tribute_offer_public: expected.tribute_offer_public,
                key_epoch: expected.key_epoch,
                tribute_offer_epoch: expected.tribute_offer_epoch,
            },
            nonce: [0x1b; 12],
            ciphertext: vec![0x1c; 112],
        }
        .encode_canonical()
        .unwrap();
        let mut event_data = vec![0_u8; 64];
        event_data[..32].copy_from_slice(&U256::from(32).to_be_bytes::<32>());
        event_data[32..64].copy_from_slice(&U256::from(artifact.len()).to_be_bytes::<32>());
        event_data.extend_from_slice(&artifact);
        event_data.resize(64 + artifact.len().div_ceil(32) * 32, 0);
        let topic0 = format!(
            "0x{}",
            hex::encode(ITeeRegistryV1::OfferKeySealedForRegistryV1::SIGNATURE_HASH)
        );
        let topic1 = format!("0x{}", hex::encode(expected.node_id_hash));
        let binding = NodeEnclaveBindingV1View {
            exists: true,
            nodeIdHash: expected.node_id_hash,
            enclaveId: expected.enclave_id,
            bindingId: B256::repeat_byte(0x21),
            intentHash: expected.intent_hash,
            evidenceHash: B256::repeat_byte(0x22),
            policyHash: B256::repeat_byte(0x23),
            bindingVersion: 1,
            registrationVersion: 0,
            renewalNonce: 0,
            transitionNonce: 0,
            leaseStartedAt: 100,
            validUntil: 200,
            collateralValidUntil: 300,
            recipientX25519: B256::from(expected.recipient_x25519),
            attestationEd25519: B256::repeat_byte(0x24),
            noiseResponderX25519: B256::repeat_byte(0x25),
            mrenclave: B256::repeat_byte(0x26),
            mrsigner: B256::repeat_byte(0x27),
            isvProdId: 1,
            isvSvn: 2,
            platformTcbStatus: 1,
            verdictHash: B256::repeat_byte(0x28),
            nodeHostAuthorizationHash: B256::repeat_byte(0x29),
        };
        let binding = ITeeRegistryV1::validatorEnclaveBindingCall::abi_encode_returns(&binding);
        let rpc = MockRpc {
            receipt: serde_json::json!({
                "transactionHash": tx_hash,
                "status": "0x1",
                "blockNumber": "0xa",
                "blockHash": format!("{block_hash:#x}"),
            }),
            canonical_block: serde_json::json!({
                "number": "0xa",
                "hash": format!("{block_hash:#x}"),
            }),
            finalized_block: serde_json::json!({
                "number": "0xc",
                "hash": format!("{:#x}", B256::repeat_byte(0x2a)),
            }),
            logs: vec![serde_json::json!({
                "transactionHash": tx_hash,
                "topics": [topic0, topic1],
                "data": format!("0x{}", hex::encode(event_data)),
            })],
            binding,
            binding_call_block_tags: Default::default(),
        };
        (rpc, expected, tx_hash)
    }

    #[tokio::test]
    async fn exact_finalized_receipt_event_and_binding_are_required() {
        let (rpc, expected, tx_hash) = fixture();
        let binding_call_block_tags = rpc.binding_call_block_tags.clone();
        let result =
            await_finalized_onboarding_v1(&rpc, &tx_hash, &expected, Duration::from_secs(1))
                .await
                .unwrap();
        assert_eq!(result.receipt_block_number, 10);
        assert_eq!(result.finalized_height, 12);
        assert_eq!(result.artifact.context.intent_hash, expected.intent_hash);
        assert_eq!(
            *binding_call_block_tags.lock().unwrap(),
            vec!["0xa".to_owned()]
        );
    }

    #[tokio::test]
    async fn reorged_receipt_never_claims_canonical_join() {
        let (mut rpc, expected, tx_hash) = fixture();
        rpc.canonical_block["hash"] =
            serde_json::Value::String(format!("{:#x}", B256::repeat_byte(0xff)));
        let error =
            await_finalized_onboarding_v1(&rpc, &tx_hash, &expected, Duration::from_secs(1))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("reorged"), "{error}");
    }
}
