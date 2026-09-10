//! Manual, crash-replay-safe TEE lease-renewal reducer.

use std::path::PathBuf;

use alloy_primitives::{keccak256, B256, U256};
use alloy_sol_types::SolCall as _;
use eyre::{Result, WrapErr as _};
use outbe_primitives::{
    addresses::TEE_REGISTRY_ADDRESS,
    tee_attestation_v1::{
        AttestationEvidenceV1, AttestationMode, AttestationOperationV1, DcapEvidenceV1,
        EnclaveInitializationManifestV1, GramineDirectEvidenceV1, RegistrationIntentV1,
        RegistryMutatorV1, TeeRegistryGasScheduleV1,
    },
    tee_registry_abi_v1::ITeeRegistryV1,
};
use outbe_tee::{
    acquire_dcap_collateral_v1, dcap_collateral_validity_window_v1,
    dcap_protocol::dcap_evidence_hash_v1, AuthorizedEnclaveClient, GeneratedDcapQuoteV1,
};

use crate::{
    rpc::RenewalRpc,
    tx::{buffered_gas_price, RelaySignerV1},
};

use super::{
    registry::{
        read_finalized_bound_renewal_view_v1, FinalizedRenewalChainViewV1, NodeBindingSelectorV1,
        RenewalBindingV1,
    },
    renewal_journal::{
        PreparedRenewalV1, RenewalJournalGuard, RenewalJournalSnapshotV1, RenewalJournalStateV1,
    },
};

pub trait RenewalEnclaveV1 {
    fn generate_dcap_quote(
        &mut self,
        intent: &RegistrationIntentV1,
    ) -> Result<GeneratedDcapQuoteV1>;

    fn sign_registration_intent_dev_v1(
        &mut self,
        _intent: &RegistrationIntentV1,
    ) -> Result<[u8; 64]> {
        eyre::bail!("renewal enclave does not support GramineDirectDev intent signing");
    }
}

impl RenewalEnclaveV1 for AuthorizedEnclaveClient {
    fn generate_dcap_quote(
        &mut self,
        intent: &RegistrationIntentV1,
    ) -> Result<GeneratedDcapQuoteV1> {
        AuthorizedEnclaveClient::generate_dcap_quote(self, intent)
            .map_err(|error| eyre::eyre!(error))
    }

    fn sign_registration_intent_dev_v1(
        &mut self,
        intent: &RegistrationIntentV1,
    ) -> Result<[u8; 64]> {
        AuthorizedEnclaveClient::sign_registration_intent_dev_v1(self, intent)
            .map_err(|error| eyre::eyre!(error))
    }
}

pub trait RenewalNodeSignerV1 {
    fn sign_node_hash(&self, hash: B256) -> Result<[u8; 65]>;
}

impl<F> RenewalNodeSignerV1 for F
where
    F: Fn(B256) -> Result<[u8; 65]>,
{
    fn sign_node_hash(&self, hash: B256) -> Result<[u8; 65]> {
        self(hash)
    }
}

#[derive(Clone, Debug)]
pub struct RenewalServiceConfigV1 {
    pub node_data_dir: PathBuf,
    pub selector: NodeBindingSelectorV1,
    pub manifest: EnclaveInitializationManifestV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewalOutcomeV1 {
    NotDue {
        finalized_height: u64,
        opens_at_timestamp: u64,
    },
    Submitted {
        transaction_hash: B256,
        replayed: bool,
    },
    Finalized {
        finalized_height: u64,
        valid_until: u64,
    },
    Abandoned {
        finalized_height: u64,
        reason: String,
    },
}

pub async fn run_renewal_once_v1(
    rpc: &(impl RenewalRpc + Sync),
    evm_signer: &RelaySignerV1,
    enclave: &mut impl RenewalEnclaveV1,
    node_signer: &impl RenewalNodeSignerV1,
    config: &RenewalServiceConfigV1,
) -> Result<RenewalOutcomeV1> {
    // Serialize renewal intent creation against upgrade preparation. Holding
    // this host-only lock across the reducer prevents the two exact-next
    // Registry counter flows from being prepared concurrently.
    let upgrade_guard = super::UpgradeJournalGuardV1::acquire(&config.node_data_dir)?;
    if let Some(upgrade) = upgrade_guard.load()? {
        if matches!(
            upgrade.lifecycle,
            super::UpgradeJournalStateV1::CandidatePrepared { .. }
                | super::UpgradeJournalStateV1::RootCopied { .. }
                | super::UpgradeJournalStateV1::CandidateKeyReady { .. }
                | super::UpgradeJournalStateV1::SubmissionPrepared { .. }
                | super::UpgradeJournalStateV1::Submitted { .. }
                | super::UpgradeJournalStateV1::Finalized { .. }
                | super::UpgradeJournalStateV1::Promoted { .. }
                | super::UpgradeJournalStateV1::TerminalMissedCutoff { .. }
        ) {
            eyre::bail!(
                "renewal is blocked while an enclave upgrade is journaled to preserve exact transition counters"
            );
        }
    }
    let _upgrade_guard = upgrade_guard;
    let journal = RenewalJournalGuard::acquire(&config.node_data_dir)?;
    let view = read_finalized_bound_renewal_view_v1(rpc, &config.selector).await?;
    validate_identity(config, &view)?;

    if let Some(snapshot) = journal.load()? {
        match snapshot.lifecycle {
            RenewalJournalStateV1::Prepared { attempt }
            | RenewalJournalStateV1::Submitted { attempt, .. } => {
                if target_matches(&view.binding, &attempt)? {
                    return finalize(&journal, attempt, &view);
                }
                ensure_source_or_conflict(&view.binding, &attempt.source)?;
                if let Some(reason) =
                    permanent_staleness(&attempt, view.schedule.finalized_timestamp)
                {
                    journal.store(RenewalJournalSnapshotV1::new(
                        RenewalJournalStateV1::Abandoned {
                            attempt,
                            abandoned_at_finalized_height: view.schedule.finalized_height,
                            reason: reason.clone(),
                        },
                    ))?;
                    return Ok(RenewalOutcomeV1::Abandoned {
                        finalized_height: view.schedule.finalized_height,
                        reason,
                    });
                }
                return submit_attempt(
                    rpc,
                    &journal,
                    attempt,
                    view.schedule.finalized_height,
                    true,
                )
                .await;
            }
            RenewalJournalStateV1::Finalized {
                attempt,
                finalized_binding,
                ..
            } => {
                if view.binding == finalized_binding || target_matches(&view.binding, &attempt)? {
                    if !renewal_is_open(
                        &view.binding,
                        view.schedule.finalized_timestamp,
                        view.policy.maximum_lease,
                    )? {
                        return Ok(RenewalOutcomeV1::NotDue {
                            finalized_height: view.schedule.finalized_height,
                            opens_at_timestamp: renewal_opens_at(
                                &view.binding,
                                view.policy.maximum_lease,
                            )?,
                        });
                    }
                } else {
                    eyre::bail!("finalized Registry binding diverged from the renewal journal");
                }
            }
            RenewalJournalStateV1::Abandoned { attempt, .. } => {
                ensure_source_or_conflict(&view.binding, &attempt.source)?;
            }
        }
    }

    if !renewal_is_open(
        &view.binding,
        view.schedule.finalized_timestamp,
        view.policy.maximum_lease,
    )? {
        return Ok(RenewalOutcomeV1::NotDue {
            finalized_height: view.schedule.finalized_height,
            opens_at_timestamp: renewal_opens_at(&view.binding, view.policy.maximum_lease)?,
        });
    }
    let attempt = prepare_attempt(rpc, evm_signer, enclave, node_signer, config, &view).await?;
    journal.store(RenewalJournalSnapshotV1::new(
        RenewalJournalStateV1::Prepared {
            attempt: attempt.clone(),
        },
    ))?;
    submit_attempt(
        rpc,
        &journal,
        attempt,
        view.schedule.finalized_height,
        false,
    )
    .await
}

fn validate_identity(
    config: &RenewalServiceConfigV1,
    view: &FinalizedRenewalChainViewV1,
) -> Result<()> {
    let manifest = &config.manifest;
    let node_id_hash = manifest
        .node_id
        .node_id_hash()
        .map_err(|error| eyre::eyre!("hash manifest node identity: {error}"))?;
    let enclave_id = manifest
        .enclave_id()
        .map_err(|error| eyre::eyre!("derive manifest enclave identity: {error}"))?;
    let authorization = manifest
        .node_host_authorization_hash()
        .map_err(|error| eyre::eyre!("derive manifest NodeHost authorization: {error}"))?;
    let policy_hash = view
        .policy
        .policy_hash()
        .map_err(|error| eyre::eyre!("hash finalized policy: {error}"))?;
    if manifest.chain_id != view.policy.chain_id
        || manifest.genesis_hash != view.policy.genesis_hash
        || node_id_hash != view.binding.node_id_hash
        || enclave_id != view.binding.enclave_id
        || B256::from(manifest.recipient_x25519) != view.binding.recipient_x25519
        || B256::from(manifest.attestation_ed25519) != view.binding.attestation_ed25519
        || B256::from(manifest.noise_responder_x25519) != view.binding.noise_responder_x25519
        || authorization != view.binding.node_host_authorization_hash
        || policy_hash != view.binding.policy_hash
    {
        eyre::bail!("committed NodeHost manifest does not match the finalized Registry binding");
    }
    match &config.selector {
        NodeBindingSelectorV1::NodeHost(public) if public == &manifest.node_id.reth_p2p_public => {}
        _ => {
            eyre::bail!("renewal selector does not match the committed node identity");
        }
    }
    Ok(())
}

async fn prepare_attempt(
    rpc: &(impl RenewalRpc + Sync),
    evm_signer: &RelaySignerV1,
    enclave: &mut impl RenewalEnclaveV1,
    node_signer: &impl RenewalNodeSignerV1,
    config: &RenewalServiceConfigV1,
    view: &FinalizedRenewalChainViewV1,
) -> Result<PreparedRenewalV1> {
    let desired_valid_until = next_renewal_deadline(&view.binding, view.policy.maximum_lease)
        .ok_or_else(|| eyre::eyre!("maximum renewal lease overflows timestamp"))?;
    let intent = renewal_intent(config, view, desired_valid_until)?;
    let generated_evidence = generate_renewal_evidence(
        enclave,
        &intent,
        &view.policy,
        view.schedule.finalized_timestamp,
        desired_valid_until,
    )?;
    let intent_hash = intent
        .intent_hash()
        .map_err(|error| eyre::eyre!("hash renewal intent: {error}"))?;
    let node_signature = node_signer
        .sign_node_hash(intent_hash)
        .wrap_err("sign renewal intent with node authority")?;
    let enclave_signature = generated_evidence.enclave_signature;
    let evidence = generated_evidence.evidence;
    let evidence_hash = generated_evidence.evidence_hash;
    let calldata = ITeeRegistryV1::renewEnclaveCall {
        evidence: evidence.clone().into(),
        nodeSignature: node_signature.to_vec().into(),
        enclaveSignature: enclave_signature.to_vec().into(),
    }
    .abi_encode();
    let gas_limit = TeeRegistryGasScheduleV1::normative()
        .maximum_transaction_gas(
            RegistryMutatorV1::RenewEnclave,
            calldata.len(),
            evidence.len(),
            view.policy.measurement_rules.len(),
            view.policy.attestation_mode,
        )
        .map_err(|error| eyre::eyre!("calculate normative renewal gas: {error}"))?;
    let chain_id = rpc.chain_id().await?;
    let account_nonce = rpc.transaction_count(evm_signer.address()).await?;
    let gas_price = buffered_gas_price(rpc.gas_price().await?);
    let required_balance = gas_price.saturating_mul(U256::from(gas_limit));
    let balance = rpc.balance(evm_signer.address()).await?;
    if balance < required_balance {
        eyre::bail!(
            "renewal EVM signer {} has {balance} but needs at least {required_balance}",
            evm_signer.address()
        );
    }
    let raw = evm_signer.sign_renewal(
        chain_id,
        account_nonce,
        gas_price,
        gas_limit,
        TEE_REGISTRY_ADDRESS,
        &calldata,
    )?;
    let intent_bytes = intent
        .encode_canonical()
        .map_err(|error| eyre::eyre!("encode canonical renewal intent: {error}"))?;
    Ok(PreparedRenewalV1 {
        source: view.binding.clone(),
        intent: intent_bytes,
        intent_hash,
        evidence_hash,
        evidence,
        node_signature: node_signature.to_vec(),
        enclave_signature: enclave_signature.to_vec(),
        calldata_hash: keccak256(&calldata),
        calldata,
        requested_valid_until: intent.requested_valid_until,
        collateral_valid_until: generated_evidence.collateral_valid_until,
        collateral_margin: generated_evidence.collateral_margin,
        // `relay` is retained in the V1 journal shape for restart compatibility;
        // manual renewal binds it to the caller's global EVM signer.
        relay: evm_signer.address(),
        relay_variants: vec![raw],
    })
}

fn renewal_intent(
    config: &RenewalServiceConfigV1,
    view: &FinalizedRenewalChainViewV1,
    requested_valid_until: u64,
) -> Result<RegistrationIntentV1> {
    Ok(RegistrationIntentV1 {
        chain_id: view.policy.chain_id,
        genesis_hash: view.policy.genesis_hash,
        operation: AttestationOperationV1::RenewEnclave,
        attestation_mode: view.policy.attestation_mode,
        policy_hash: view
            .policy
            .policy_hash()
            .map_err(|error| eyre::eyre!("hash active policy: {error}"))?,
        node_id: config.manifest.node_id.clone(),
        enclave_id: view.binding.enclave_id,
        binding_id: view.binding.binding_id,
        binding_version: view.binding.binding_version,
        registration_version: view
            .binding
            .registration_version
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("registration version exhausted"))?,
        renewal_nonce: view
            .binding
            .renewal_nonce
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("renewal nonce exhausted"))?,
        transition_nonce: view.binding.transition_nonce,
        requested_valid_until,
        recipient_x25519: config.manifest.recipient_x25519,
        attestation_ed25519: config.manifest.attestation_ed25519,
        noise_responder_x25519: config.manifest.noise_responder_x25519,
        node_host_authorization_hash: view.binding.node_host_authorization_hash,
    })
}

struct GeneratedRenewalEvidenceV1 {
    evidence: Vec<u8>,
    evidence_hash: B256,
    enclave_signature: [u8; 64],
    collateral_valid_until: u64,
    collateral_margin: u64,
}

fn generate_renewal_evidence(
    enclave: &mut impl RenewalEnclaveV1,
    intent: &RegistrationIntentV1,
    policy: &outbe_primitives::tee_attestation_v1::TeePolicyV1,
    finalized_timestamp: u64,
    desired_valid_until: u64,
) -> Result<GeneratedRenewalEvidenceV1> {
    match policy.attestation_mode {
        AttestationMode::DcapRequired => {
            let (dcap, enclave_signature) = generate_dcap_evidence(enclave, intent, policy)?;
            let window = dcap_collateral_validity_window_v1(&dcap, policy).map_err(|error| {
                eyre::eyre!("validate signed renewal collateral window: {error:?}")
            })?;
            let ceiling = window
                .expiration_ceiling
                .checked_sub(policy.collateral_margin)
                .ok_or_else(|| {
                    eyre::eyre!("renewal collateral cannot satisfy the active margin")
                })?;
            if window.issue_floor > finalized_timestamp || desired_valid_until > ceiling {
                eyre::bail!("fresh Intel collateral cannot cover the exact next renewal deadline");
            }
            let value = AttestationEvidenceV1::Dcap(dcap);
            let evidence = value
                .encode_canonical()
                .map_err(|error| eyre::eyre!("encode canonical renewal evidence: {error}"))?;
            let evidence_hash = dcap_evidence_hash_v1(&evidence)
                .map_err(|code| eyre::eyre!("hash canonical renewal DCAP evidence: {code:?}"))?;
            Ok(GeneratedRenewalEvidenceV1 {
                evidence,
                evidence_hash,
                enclave_signature,
                collateral_valid_until: window.expiration_ceiling,
                collateral_margin: policy.collateral_margin,
            })
        }
        AttestationMode::GramineDirectDev => {
            let enclave_signature = enclave
                .sign_registration_intent_dev_v1(intent)
                .wrap_err("sign renewal intent inside GramineDirectDev enclave")?;
            if !intent.verify_enclave_signature(&enclave_signature) {
                eyre::bail!("GramineDirectDev enclave signature does not bind renewal intent");
            }
            let value = AttestationEvidenceV1::GramineDirectDev(GramineDirectEvidenceV1 {
                intent: intent.clone(),
                dev_attestation_public: intent.attestation_ed25519,
                dev_signature: enclave_signature,
            });
            let evidence_hash = value
                .evidence_hash()
                .map_err(|error| eyre::eyre!("hash canonical renewal evidence: {error}"))?;
            let evidence = value
                .encode_canonical()
                .map_err(|error| eyre::eyre!("encode canonical renewal evidence: {error}"))?;
            Ok(GeneratedRenewalEvidenceV1 {
                evidence,
                evidence_hash,
                enclave_signature,
                collateral_valid_until: u64::MAX,
                collateral_margin: 0,
            })
        }
    }
}

fn generate_dcap_evidence(
    enclave: &mut impl RenewalEnclaveV1,
    intent: &RegistrationIntentV1,
    policy: &outbe_primitives::tee_attestation_v1::TeePolicyV1,
) -> Result<(DcapEvidenceV1, [u8; 64])> {
    let generated = enclave
        .generate_dcap_quote(intent)
        .wrap_err("generate intent-bound renewal quote")?;
    let components = acquire_dcap_collateral_v1(&generated.quote_body)
        .map_err(|error| eyre::eyre!("acquire renewal collateral: {error}"))?;
    let evidence = DcapEvidenceV1 {
        intent: intent.clone(),
        quote: generated.quote_body,
        components,
        transition_key_ready_proof: generated.transition_key_ready_proof,
    };
    dcap_collateral_validity_window_v1(&evidence, policy)
        .map_err(|error| eyre::eyre!("validate renewal collateral: {error:?}"))?;
    Ok((evidence, generated.enclave_signature))
}

async fn submit_attempt(
    rpc: &(impl RenewalRpc + Sync),
    journal: &RenewalJournalGuard,
    attempt: PreparedRenewalV1,
    finalized_height: u64,
    replayed: bool,
) -> Result<RenewalOutcomeV1> {
    let raw = attempt
        .relay_variants
        .last()
        .ok_or_else(|| eyre::eyre!("renewal attempt has no relay transaction"))?;
    let already_observed = replayed && exact_transaction_receipt_exists(rpc, raw).await?;
    let returned_hash = if already_observed {
        raw.transaction_hash
    } else {
        match rpc.send_raw_transaction(&raw.raw_transaction).await {
            Ok(returned) => returned
                .parse::<B256>()
                .wrap_err("parse eth_sendRawTransaction renewal hash")?,
            Err(error) if transaction_is_already_known(&error) => raw.transaction_hash,
            Err(error) if transaction_nonce_is_too_low(&error) => {
                if exact_transaction_receipt_exists(rpc, raw).await? {
                    raw.transaction_hash
                } else {
                    return Err(error).wrap_err(
                        "renewal nonce was consumed without the exact transaction receipt",
                    );
                }
            }
            Err(error) => return Err(error).wrap_err("submit exact renewal transaction"),
        }
    };
    if returned_hash != raw.transaction_hash {
        eyre::bail!("RPC returned a transaction hash different from the signed renewal bytes");
    }
    let hashes = attempt
        .relay_variants
        .iter()
        .map(|variant| variant.transaction_hash)
        .collect();
    journal.store(RenewalJournalSnapshotV1::new(
        RenewalJournalStateV1::Submitted {
            attempt,
            submitted_at_finalized_height: finalized_height,
            transaction_hashes: hashes,
        },
    ))?;
    Ok(RenewalOutcomeV1::Submitted {
        transaction_hash: returned_hash,
        replayed,
    })
}

async fn exact_transaction_receipt_exists(
    rpc: &(impl RenewalRpc + Sync),
    raw: &crate::tx::RawRelayTransactionV1,
) -> Result<bool> {
    let expected_hash = format!("{:#x}", raw.transaction_hash);
    let Some(receipt) = rpc.transaction_receipt(&expected_hash).await? else {
        return Ok(false);
    };
    let observed_hash = receipt
        .get("transactionHash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("exact renewal transaction receipt has no transactionHash"))?;
    eyre::ensure!(
        observed_hash.eq_ignore_ascii_case(&expected_hash),
        "renewal RPC returned a receipt for a different transaction hash"
    );
    let status = receipt
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("exact renewal transaction receipt has no status"))?;
    eyre::ensure!(
        status == "0x1",
        "exact renewal transaction receipt has non-success status {status}"
    );
    Ok(true)
}

fn transaction_is_already_known(error: &eyre::Report) -> bool {
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("already known") || message.contains("known transaction")
}

fn transaction_nonce_is_too_low(error: &eyre::Report) -> bool {
    format!("{error:#}")
        .to_ascii_lowercase()
        .contains("nonce too low")
}

fn finalize(
    journal: &RenewalJournalGuard,
    attempt: PreparedRenewalV1,
    view: &FinalizedRenewalChainViewV1,
) -> Result<RenewalOutcomeV1> {
    journal.store(RenewalJournalSnapshotV1::new(
        RenewalJournalStateV1::Finalized {
            attempt: Box::new(attempt),
            finalized_binding: view.binding.clone(),
            finalized_height: view.schedule.finalized_height,
            finalized_hash: view.schedule.finalized_hash,
        },
    ))?;
    Ok(RenewalOutcomeV1::Finalized {
        finalized_height: view.schedule.finalized_height,
        valid_until: view.binding.valid_until,
    })
}

fn ensure_source_or_conflict(current: &RenewalBindingV1, source: &RenewalBindingV1) -> Result<()> {
    if current != source {
        eyre::bail!("finalized Registry binding matches neither renewal source nor target");
    }
    Ok(())
}

fn target_matches(current: &RenewalBindingV1, attempt: &PreparedRenewalV1) -> Result<bool> {
    let intent = RegistrationIntentV1::decode_canonical(&attempt.intent)
        .map_err(|error| eyre::eyre!("decode journal renewal intent: {error}"))?;
    Ok(current.node_id_hash == attempt.source.node_id_hash
        && current.enclave_id == intent.enclave_id
        && current.binding_id == intent.binding_id
        && current.intent_hash == attempt.intent_hash
        && current.evidence_hash == attempt.evidence_hash
        && current.policy_hash == intent.policy_hash
        && current.binding_version == intent.binding_version
        && current.registration_version == intent.registration_version
        && current.renewal_nonce == intent.renewal_nonce
        && current.transition_nonce == intent.transition_nonce
        && current.valid_until == intent.requested_valid_until
        && current.recipient_x25519 == B256::from(intent.recipient_x25519)
        && current.attestation_ed25519 == B256::from(intent.attestation_ed25519)
        && current.noise_responder_x25519 == B256::from(intent.noise_responder_x25519)
        && current.node_host_authorization_hash == intent.node_host_authorization_hash)
}

fn permanent_staleness(attempt: &PreparedRenewalV1, finalized_timestamp: u64) -> Option<String> {
    if finalized_timestamp >= attempt.collateral_valid_until {
        return Some("finalized consensus time reached the signed collateral expiration".into());
    }
    if finalized_timestamp >= attempt.requested_valid_until {
        return Some("finalized consensus time reached the requested lease expiration".into());
    }
    None
}

fn renewal_opens_at(binding: &RenewalBindingV1, lease_period: u64) -> Result<u64> {
    if lease_period == 0 || !lease_period.is_multiple_of(2) {
        eyre::bail!("finalized Registry lease period is not a positive even duration");
    }
    Ok(binding.valid_until.saturating_sub(lease_period / 2))
}

fn renewal_is_open(
    binding: &RenewalBindingV1,
    finalized_timestamp: u64,
    lease_period: u64,
) -> Result<bool> {
    if finalized_timestamp >= binding.valid_until {
        eyre::bail!("finalized enclave lease expired; run tee join to recover");
    }
    Ok(finalized_timestamp >= renewal_opens_at(binding, lease_period)?)
}

fn next_renewal_deadline(binding: &RenewalBindingV1, lease_period: u64) -> Option<u64> {
    binding.valid_until.checked_add(lease_period)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::rpc::FinalityRpc;
    use crate::tx::RawRelayTransactionV1;
    use alloy_consensus::{
        transaction::SignerRecoverable as _, EthereumTxEnvelope, Transaction as _, TxEip4844,
    };
    use alloy_eips::eip2718::Decodable2718 as _;
    use alloy_primitives::{Address, Bytes, TxKind};
    use ed25519_dalek::Signer as _;
    use k256::ecdsa::signature::hazmat::PrehashSigner as _;
    use outbe_primitives::{
        chain::DEVNET_CHAIN_ID,
        tee_attestation_v1::{
            AttestationMode, DcapCollateralComponentV1, DcapCollateralKind,
            EnclaveInitializationManifestV1, NodeIdV1,
        },
        tee_genesis_v1::{initial_tee_policy_v1, InitialTeeProfileV1, ProductionSgxMeasurementV1},
        tee_operator_v1::TeeRenewalScheduleV1,
        tee_registry_abi_v1::NodeEnclaveBindingV1View,
    };

    struct DirectOnlyEnclave {
        signer: ed25519_dalek::SigningKey,
        dcap_calls: usize,
        direct_calls: usize,
    }

    impl RenewalEnclaveV1 for DirectOnlyEnclave {
        fn generate_dcap_quote(
            &mut self,
            _intent: &RegistrationIntentV1,
        ) -> Result<GeneratedDcapQuoteV1> {
            self.dcap_calls += 1;
            eyre::bail!("DCAP must not be invoked for GramineDirectDev renewal");
        }

        fn sign_registration_intent_dev_v1(
            &mut self,
            intent: &RegistrationIntentV1,
        ) -> Result<[u8; 64]> {
            self.direct_calls += 1;
            Ok(self
                .signer
                .sign(intent.intent_hash().unwrap().as_slice())
                .to_bytes())
        }
    }

    struct PreparationRpc;

    impl FinalityRpc for PreparationRpc {
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
            eyre::bail!("unused finalized_block");
        }

        async fn call_at(&self, _to: Address, _data: &[u8], _block_tag: &str) -> Result<Vec<u8>> {
            eyre::bail!("unused call_at");
        }
    }

    impl RenewalRpc for PreparationRpc {
        async fn chain_id(&self) -> Result<u64> {
            Ok(DEVNET_CHAIN_ID)
        }

        async fn gas_price(&self) -> Result<U256> {
            Ok(U256::from(1_000_000_000_u64))
        }

        async fn transaction_count(&self, _address: Address) -> Result<u64> {
            Ok(7)
        }

        async fn balance(&self, _address: Address) -> Result<U256> {
            Ok(U256::MAX)
        }

        async fn send_raw_transaction(&self, _raw_transaction: &[u8]) -> Result<String> {
            eyre::bail!("unused send_raw_transaction");
        }

        async fn tee_renewal_schedule_v1(&self) -> Result<TeeRenewalScheduleV1> {
            eyre::bail!("unused tee_renewal_schedule_v1");
        }
    }

    struct ReplayRpc {
        policy: outbe_primitives::tee_attestation_v1::TeePolicyV1,
        binding: RenewalBindingV1,
        schedule: TeeRenewalScheduleV1,
        receipt: Arc<Mutex<Option<serde_json::Value>>>,
        send_error: Option<&'static str>,
        receipt_after_send_error: Option<serde_json::Value>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl FinalityRpc for ReplayRpc {
        async fn transaction_receipt(
            &self,
            _transaction_hash: &str,
        ) -> Result<Option<serde_json::Value>> {
            Ok(self.receipt.lock().unwrap().clone())
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
                "stateRoot": format!("{:#x}", B256::repeat_byte(0x81)),
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
                let binding = renewal_binding_view(&self.binding);
                return Ok(
                    ITeeRegistryV1::nodeHostEnclaveBindingCall::abi_encode_returns(&binding),
                );
            }
            if data.starts_with(&ITeeRegistryV1::tributeOfferPublicKeyCall::SELECTOR) {
                return Ok(
                    ITeeRegistryV1::tributeOfferPublicKeyCall::abi_encode_returns(&U256::from(9)),
                );
            }
            eyre::bail!("unexpected Registry call");
        }
    }

    impl RenewalRpc for ReplayRpc {
        async fn chain_id(&self) -> Result<u64> {
            Ok(DEVNET_CHAIN_ID)
        }

        async fn gas_price(&self) -> Result<U256> {
            eyre::bail!("restart replay regenerated gas price");
        }

        async fn transaction_count(&self, _address: Address) -> Result<u64> {
            eyre::bail!("restart replay regenerated account nonce");
        }

        async fn balance(&self, _address: Address) -> Result<U256> {
            eyre::bail!("restart replay rechecked preparation balance");
        }

        async fn send_raw_transaction(&self, raw_transaction: &[u8]) -> Result<String> {
            self.sent.lock().unwrap().push(raw_transaction.to_vec());
            if let Some(error) = self.send_error {
                if let Some(receipt) = &self.receipt_after_send_error {
                    *self.receipt.lock().unwrap() = Some(receipt.clone());
                }
                return Err(eyre::eyre!(error));
            }
            Ok(format!("{:#x}", keccak256(raw_transaction)))
        }

        async fn tee_renewal_schedule_v1(&self) -> Result<TeeRenewalScheduleV1> {
            Ok(self.schedule)
        }
    }

    struct ReplayMustNotPrepare;

    impl RenewalEnclaveV1 for ReplayMustNotPrepare {
        fn generate_dcap_quote(
            &mut self,
            _intent: &RegistrationIntentV1,
        ) -> Result<GeneratedDcapQuoteV1> {
            panic!("restart replay regenerated a DCAP quote")
        }

        fn sign_registration_intent_dev_v1(
            &mut self,
            _intent: &RegistrationIntentV1,
        ) -> Result<[u8; 64]> {
            panic!("restart replay regenerated a DirectDev signature")
        }
    }

    fn renewal_binding_view(binding: &RenewalBindingV1) -> NodeEnclaveBindingV1View {
        NodeEnclaveBindingV1View {
            exists: true,
            nodeIdHash: binding.node_id_hash,
            enclaveId: binding.enclave_id,
            bindingId: binding.binding_id,
            intentHash: binding.intent_hash,
            evidenceHash: binding.evidence_hash,
            policyHash: binding.policy_hash,
            bindingVersion: binding.binding_version,
            registrationVersion: binding.registration_version,
            renewalNonce: binding.renewal_nonce,
            transitionNonce: binding.transition_nonce,
            leaseStartedAt: binding.lease_started_at,
            validUntil: binding.valid_until,
            collateralValidUntil: binding.collateral_valid_until,
            recipientX25519: binding.recipient_x25519,
            attestationEd25519: binding.attestation_ed25519,
            noiseResponderX25519: binding.noise_responder_x25519,
            mrenclave: binding.mrenclave,
            mrsigner: binding.mrsigner,
            isvProdId: binding.isv_prod_id,
            isvSvn: binding.isv_svn,
            platformTcbStatus: binding.platform_tcb_status,
            verdictHash: binding.verdict_hash,
            nodeHostAuthorizationHash: binding.node_host_authorization_hash,
        }
    }

    fn binding() -> RenewalBindingV1 {
        RenewalBindingV1 {
            node_id_hash: B256::repeat_byte(1),
            enclave_id: B256::repeat_byte(2),
            binding_id: B256::repeat_byte(3),
            intent_hash: B256::repeat_byte(4),
            evidence_hash: B256::repeat_byte(5),
            policy_hash: B256::repeat_byte(6),
            binding_version: 1,
            registration_version: 1,
            renewal_nonce: 1,
            transition_nonce: 0,
            lease_started_at: 100,
            valid_until: 400,
            collateral_valid_until: 500,
            recipient_x25519: B256::repeat_byte(7),
            attestation_ed25519: B256::repeat_byte(8),
            noise_responder_x25519: B256::repeat_byte(9),
            mrenclave: B256::repeat_byte(10),
            mrsigner: B256::repeat_byte(11),
            isv_prod_id: 1,
            isv_svn: 1,
            platform_tcb_status: 0,
            verdict_hash: B256::repeat_byte(12),
            node_host_authorization_hash: B256::repeat_byte(13),
        }
    }

    fn replay_fixture(
        node_data_dir: &std::path::Path,
        mode: AttestationMode,
    ) -> (
        ReplayRpc,
        RelaySignerV1,
        RenewalServiceConfigV1,
        PreparedRenewalV1,
    ) {
        let genesis_hash = B256::repeat_byte(0x82);
        let profile = match mode {
            AttestationMode::DcapRequired => {
                InitialTeeProfileV1::DcapRequired(ProductionSgxMeasurementV1 {
                    mrenclave: B256::repeat_byte(0x83),
                    mrsigner: B256::repeat_byte(0x84),
                    isv_prod_id: 1,
                    minimum_isv_svn: 1,
                    minimum_tcb_evaluation_data_number: 1,
                })
            }
            AttestationMode::GramineDirectDev => InitialTeeProfileV1::GramineDirectDev,
        };
        let policy = initial_tee_policy_v1(profile, DEVNET_CHAIN_ID, genesis_hash).unwrap();
        let policy_hash = policy.policy_hash().unwrap();
        let node_signer = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0x85)).into(),
        )
        .unwrap();
        let enclave_signer =
            ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x86));
        let node_id = NodeIdV1 {
            reth_p2p_public: node_signer
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
        };
        let manifest = EnclaveInitializationManifestV1 {
            chain_id: policy.chain_id,
            genesis_hash,
            attestation_mode: policy.attestation_mode,
            node_id: node_id.clone(),
            initialization_challenge: [0x87; 32],
            node_host_noise_x25519: [0x88; 32],
            recipient_x25519: [0x89; 32],
            attestation_ed25519: enclave_signer.verifying_key().to_bytes(),
            noise_responder_x25519: [0x8a; 32],
        };
        let enclave_id = manifest.enclave_id().unwrap();
        let node_host_authorization_hash = manifest.node_host_authorization_hash().unwrap();
        let valid_until = 2_000_000;
        let requested_valid_until = valid_until + policy.maximum_lease;
        let source_collateral_valid_until = match mode {
            AttestationMode::DcapRequired => {
                requested_valid_until
                    .checked_add(policy.collateral_margin)
                    .unwrap()
                    + 1_000
            }
            AttestationMode::GramineDirectDev => u64::MAX,
        };
        let source = RenewalBindingV1 {
            node_id_hash: node_id.node_id_hash().unwrap(),
            enclave_id,
            binding_id: B256::repeat_byte(0x8b),
            intent_hash: B256::repeat_byte(0x8c),
            evidence_hash: B256::repeat_byte(0x8d),
            policy_hash,
            binding_version: 1,
            registration_version: 1,
            renewal_nonce: 1,
            transition_nonce: 0,
            lease_started_at: valid_until - policy.maximum_lease,
            valid_until,
            collateral_valid_until: source_collateral_valid_until,
            recipient_x25519: B256::from(manifest.recipient_x25519),
            attestation_ed25519: B256::from(manifest.attestation_ed25519),
            noise_responder_x25519: B256::from(manifest.noise_responder_x25519),
            mrenclave: B256::repeat_byte(0x83),
            mrsigner: B256::repeat_byte(0x84),
            isv_prod_id: 1,
            isv_svn: 1,
            platform_tcb_status: 0,
            verdict_hash: B256::repeat_byte(0x8e),
            node_host_authorization_hash,
        };
        let intent = RegistrationIntentV1 {
            chain_id: policy.chain_id,
            genesis_hash,
            operation: AttestationOperationV1::RenewEnclave,
            attestation_mode: mode,
            policy_hash,
            node_id,
            enclave_id,
            binding_id: source.binding_id,
            binding_version: source.binding_version,
            registration_version: source.registration_version + 1,
            renewal_nonce: source.renewal_nonce + 1,
            transition_nonce: source.transition_nonce,
            requested_valid_until,
            recipient_x25519: manifest.recipient_x25519,
            attestation_ed25519: manifest.attestation_ed25519,
            noise_responder_x25519: manifest.noise_responder_x25519,
            node_host_authorization_hash,
        };
        let intent_hash = intent.intent_hash().unwrap();
        let (node_signature_body, node_recovery): (
            k256::ecdsa::Signature,
            k256::ecdsa::RecoveryId,
        ) = node_signer.sign_prehash(intent_hash.as_slice()).unwrap();
        let mut node_signature = [0_u8; 65];
        node_signature[..64].copy_from_slice(node_signature_body.to_bytes().as_slice());
        node_signature[64] = node_recovery.to_byte();
        let enclave_signature = enclave_signer.sign(intent_hash.as_slice()).to_bytes();
        let evidence_value = match mode {
            AttestationMode::DcapRequired => AttestationEvidenceV1::Dcap(DcapEvidenceV1 {
                intent: intent.clone(),
                quote: vec![1],
                components: [
                    DcapCollateralKind::PckCertificateChain,
                    DcapCollateralKind::PckCrl,
                    DcapCollateralKind::PckCrlIssuerChain,
                    DcapCollateralKind::RootCaCrl,
                    DcapCollateralKind::TcbInfo,
                    DcapCollateralKind::TcbInfoIssuerChain,
                    DcapCollateralKind::QeIdentity,
                    DcapCollateralKind::QeIdentityIssuerChain,
                ]
                .into_iter()
                .map(|kind| DcapCollateralComponentV1 {
                    kind,
                    bytes: vec![kind as u8],
                })
                .collect(),
                transition_key_ready_proof: None,
            }),
            AttestationMode::GramineDirectDev => {
                AttestationEvidenceV1::GramineDirectDev(GramineDirectEvidenceV1 {
                    intent: intent.clone(),
                    dev_attestation_public: intent.attestation_ed25519,
                    dev_signature: enclave_signature,
                })
            }
        };
        let evidence = evidence_value.encode_canonical().unwrap();
        let evidence_hash = match mode {
            AttestationMode::DcapRequired => dcap_evidence_hash_v1(&evidence).unwrap(),
            AttestationMode::GramineDirectDev => evidence_value.evidence_hash().unwrap(),
        };
        let calldata = ITeeRegistryV1::renewEnclaveCall {
            evidence: evidence.clone().into(),
            nodeSignature: node_signature.to_vec().into(),
            enclaveSignature: enclave_signature.to_vec().into(),
        }
        .abi_encode();
        let gas_limit = TeeRegistryGasScheduleV1::normative()
            .maximum_transaction_gas(
                RegistryMutatorV1::RenewEnclave,
                calldata.len(),
                evidence.len(),
                policy.measurement_rules.len(),
                mode,
            )
            .unwrap();
        let relay = RelaySignerV1::new(&hex::encode([0x8f; 32])).unwrap();
        let raw = relay
            .sign_renewal(
                DEVNET_CHAIN_ID,
                7,
                U256::from(2_000_000_000_u64),
                gas_limit,
                TEE_REGISTRY_ADDRESS,
                &calldata,
            )
            .unwrap();
        let attempt = PreparedRenewalV1 {
            source: source.clone(),
            intent: intent.encode_canonical().unwrap(),
            intent_hash,
            evidence,
            evidence_hash,
            node_signature: node_signature.to_vec(),
            enclave_signature: enclave_signature.to_vec(),
            calldata_hash: keccak256(&calldata),
            calldata,
            requested_valid_until,
            collateral_valid_until: source_collateral_valid_until,
            collateral_margin: match mode {
                AttestationMode::DcapRequired => policy.collateral_margin,
                AttestationMode::GramineDirectDev => 0,
            },
            relay: relay.address(),
            relay_variants: vec![raw],
        };
        let schedule = TeeRenewalScheduleV1 {
            finalized_height: 120,
            finalized_hash: B256::repeat_byte(0x90),
            finalized_timestamp: valid_until - policy.maximum_lease / 2 + 1,
            epoch_number: 2,
            epoch_start_height: 100,
            epoch_length_blocks: 100,
            next_freeze_height: 180,
            planned_activation_height: 200,
            dkg_prepare_window_blocks: 20,
            minimum_block_time_millis: 2_000,
        };
        let sent = Arc::new(Mutex::new(Vec::new()));
        let rpc = ReplayRpc {
            policy,
            binding: source,
            schedule,
            receipt: Arc::new(Mutex::new(None)),
            send_error: None,
            receipt_after_send_error: None,
            sent,
        };
        let config = RenewalServiceConfigV1 {
            node_data_dir: node_data_dir.to_path_buf(),
            selector: NodeBindingSelectorV1::NodeHost(manifest.node_id.reth_p2p_public),
            manifest,
        };
        (rpc, relay, config, attempt)
    }

    fn target_attempt() -> (PreparedRenewalV1, RenewalBindingV1) {
        let public: [u8; 33] =
            k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(1)).into())
                .unwrap()
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();
        let intent = RegistrationIntentV1 {
            chain_id: [1; 32],
            genesis_hash: B256::repeat_byte(20),
            operation: AttestationOperationV1::RenewEnclave,
            attestation_mode: AttestationMode::DcapRequired,
            policy_hash: B256::repeat_byte(6),
            node_id: NodeIdV1 {
                reth_p2p_public: public,
            },
            enclave_id: B256::repeat_byte(2),
            binding_id: B256::repeat_byte(3),
            binding_version: 1,
            registration_version: 2,
            renewal_nonce: 2,
            transition_nonce: 0,
            requested_valid_until: 700,
            recipient_x25519: [7; 32],
            attestation_ed25519: [8; 32],
            noise_responder_x25519: [9; 32],
            node_host_authorization_hash: B256::repeat_byte(13),
        };
        let intent_hash = intent.intent_hash().unwrap();
        let evidence_hash = B256::repeat_byte(30);
        let attempt = PreparedRenewalV1 {
            source: binding(),
            intent: intent.encode_canonical().unwrap(),
            intent_hash,
            evidence: vec![1],
            evidence_hash,
            node_signature: vec![1; 65],
            enclave_signature: vec![2; 64],
            calldata: vec![3],
            calldata_hash: keccak256([3]),
            requested_valid_until: 700,
            collateral_valid_until: 800,
            collateral_margin: 10,
            relay: Address::repeat_byte(40),
            relay_variants: vec![RawRelayTransactionV1 {
                relay: Address::repeat_byte(40),
                chain_id: 1,
                account_nonce: 1,
                gas_price: U256::from(1),
                gas_limit: 1,
                calldata_hash: keccak256([3]),
                raw_transaction: vec![4],
                transaction_hash: keccak256([4]),
            }],
        };
        let mut target = binding();
        target.intent_hash = intent_hash;
        target.evidence_hash = evidence_hash;
        target.registration_version = 2;
        target.renewal_nonce = 2;
        target.valid_until = 700;
        (attempt, target)
    }

    #[test]
    fn renewal_window_is_the_last_half_period_and_excludes_the_deadline() {
        let binding = binding();
        let lease_period = 200;
        assert_eq!(renewal_opens_at(&binding, lease_period).unwrap(), 300);
        assert!(!renewal_is_open(&binding, 299, lease_period).unwrap());
        assert!(renewal_is_open(&binding, 300, lease_period).unwrap());
        assert!(renewal_is_open(&binding, 399, lease_period).unwrap());
        assert!(renewal_is_open(&binding, 400, lease_period).is_err());
        assert_eq!(next_renewal_deadline(&binding, lease_period).unwrap(), 600);
    }

    #[test]
    fn abandon_requires_finalized_time_to_reach_an_irrecoverable_ceiling() {
        let (attempt, _) = target_attempt();
        assert_eq!(permanent_staleness(&attempt, 699), None);
        assert!(permanent_staleness(&attempt, 700)
            .unwrap()
            .contains("lease expiration"));
        let mut collateral_first = attempt;
        collateral_first.requested_valid_until = 900;
        assert!(permanent_staleness(&collateral_first, 800)
            .unwrap()
            .contains("collateral expiration"));
    }

    #[test]
    fn finalization_requires_the_exact_intent_evidence_and_next_counters() {
        let (attempt, target) = target_attempt();
        assert!(target_matches(&target, &attempt).unwrap());
        let mut wrong_nonce = target.clone();
        wrong_nonce.renewal_nonce += 1;
        assert!(!target_matches(&wrong_nonce, &attempt).unwrap());
        let mut wrong_evidence = target;
        wrong_evidence.evidence_hash = B256::repeat_byte(31);
        assert!(!target_matches(&wrong_evidence, &attempt).unwrap());
    }

    #[test]
    fn a_third_registry_state_is_a_conflict_not_a_rebuild_authority() {
        let source = binding();
        assert!(ensure_source_or_conflict(&source, &source).is_ok());
        let mut third = source.clone();
        third.binding_id = B256::repeat_byte(99);
        assert!(ensure_source_or_conflict(&third, &source).is_err());
    }

    #[test]
    fn replay_transport_errors_are_classified_narrowly() {
        assert!(transaction_is_already_known(&eyre::eyre!("already known")));
        assert!(transaction_is_already_known(&eyre::eyre!(
            "known transaction"
        )));
        assert!(!transaction_is_already_known(&eyre::eyre!("nonce too low")));
        assert!(transaction_nonce_is_too_low(&eyre::eyre!(
            "nonce too low: next nonce 1, tx nonce 0"
        )));
        assert!(!transaction_nonce_is_too_low(&eyre::eyre!(
            "replacement transaction underpriced"
        )));
    }

    #[tokio::test]
    async fn prepared_and_submitted_restarts_replay_exact_transaction_in_both_modes() {
        for mode in [
            AttestationMode::DcapRequired,
            AttestationMode::GramineDirectDev,
        ] {
            for starts_submitted in [false, true] {
                let node_data_dir = tempfile::tempdir().unwrap();
                let (rpc, relay, config, attempt) = replay_fixture(node_data_dir.path(), mode);
                let expected_raw = attempt.relay_variants[0].raw_transaction.clone();
                let expected_hash = attempt.relay_variants[0].transaction_hash;
                let lifecycle = if starts_submitted {
                    RenewalJournalStateV1::Submitted {
                        attempt: attempt.clone(),
                        submitted_at_finalized_height: 119,
                        transaction_hashes: vec![expected_hash],
                    }
                } else {
                    RenewalJournalStateV1::Prepared {
                        attempt: attempt.clone(),
                    }
                };
                RenewalJournalGuard::acquire(node_data_dir.path())
                    .unwrap()
                    .store(RenewalJournalSnapshotV1::new(lifecycle))
                    .unwrap();

                let mut enclave = ReplayMustNotPrepare;
                let node_signer = |_hash: B256| -> Result<[u8; 65]> {
                    panic!("restart replay regenerated a NodeHost signature")
                };
                let outcome =
                    run_renewal_once_v1(&rpc, &relay, &mut enclave, &node_signer, &config)
                        .await
                        .unwrap();
                assert_eq!(
                    outcome,
                    RenewalOutcomeV1::Submitted {
                        transaction_hash: expected_hash,
                        replayed: true,
                    }
                );
                assert_eq!(rpc.sent.lock().unwrap().as_slice(), [expected_raw]);
                let replayed = RenewalJournalGuard::acquire(node_data_dir.path())
                    .unwrap()
                    .load()
                    .unwrap()
                    .unwrap();
                let RenewalJournalStateV1::Submitted {
                    attempt: replayed_attempt,
                    transaction_hashes,
                    ..
                } = replayed.lifecycle
                else {
                    panic!("replay did not persist Submitted state");
                };
                assert_eq!(replayed_attempt, attempt);
                assert_eq!(transaction_hashes, vec![expected_hash]);
            }
        }
    }

    #[tokio::test]
    async fn submitted_exact_transaction_observed_before_finality_is_not_rebroadcast() {
        let node_data_dir = tempfile::tempdir().unwrap();
        let (rpc, relay, config, attempt) =
            replay_fixture(node_data_dir.path(), AttestationMode::GramineDirectDev);
        let expected_hash = attempt.relay_variants[0].transaction_hash;
        *rpc.receipt.lock().unwrap() = Some(serde_json::json!({
            "transactionHash": format!("{expected_hash:#x}"),
            "status": "0x1",
        }));
        RenewalJournalGuard::acquire(node_data_dir.path())
            .unwrap()
            .store(RenewalJournalSnapshotV1::new(
                RenewalJournalStateV1::Submitted {
                    attempt,
                    submitted_at_finalized_height: 119,
                    transaction_hashes: vec![expected_hash],
                },
            ))
            .unwrap();

        let mut enclave = ReplayMustNotPrepare;
        let node_signer = |_hash: B256| -> Result<[u8; 65]> {
            panic!("receipt reconciliation regenerated a NodeHost signature")
        };
        let outcome = run_renewal_once_v1(&rpc, &relay, &mut enclave, &node_signer, &config)
            .await
            .unwrap();

        assert_eq!(
            outcome,
            RenewalOutcomeV1::Submitted {
                transaction_hash: expected_hash,
                replayed: true,
            }
        );
        assert!(
            rpc.sent.lock().unwrap().is_empty(),
            "an exact transaction already observed by receipt must not be rebroadcast before finality"
        );
    }

    #[tokio::test]
    async fn nonce_too_low_without_exact_receipt_fails_closed() {
        let node_data_dir = tempfile::tempdir().unwrap();
        let (mut rpc, relay, config, attempt) =
            replay_fixture(node_data_dir.path(), AttestationMode::GramineDirectDev);
        let expected_hash = attempt.relay_variants[0].transaction_hash;
        rpc.send_error = Some("nonce too low: next nonce 1, tx nonce 0");
        RenewalJournalGuard::acquire(node_data_dir.path())
            .unwrap()
            .store(RenewalJournalSnapshotV1::new(
                RenewalJournalStateV1::Submitted {
                    attempt,
                    submitted_at_finalized_height: 119,
                    transaction_hashes: vec![expected_hash],
                },
            ))
            .unwrap();

        let mut enclave = ReplayMustNotPrepare;
        let node_signer = |_hash: B256| -> Result<[u8; 65]> {
            panic!("nonce conflict handling regenerated a NodeHost signature")
        };
        let error = run_renewal_once_v1(&rpc, &relay, &mut enclave, &node_signer, &config)
            .await
            .expect_err("a consumed nonce without the exact receipt must fail closed");

        assert!(
            error
                .to_string()
                .contains("consumed without the exact transaction receipt"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn nonce_too_low_race_accepts_only_the_exact_success_receipt() {
        let node_data_dir = tempfile::tempdir().unwrap();
        let (mut rpc, relay, config, attempt) =
            replay_fixture(node_data_dir.path(), AttestationMode::GramineDirectDev);
        let expected_raw = attempt.relay_variants[0].raw_transaction.clone();
        let expected_hash = attempt.relay_variants[0].transaction_hash;
        rpc.send_error = Some("nonce too low: next nonce 1, tx nonce 0");
        rpc.receipt_after_send_error = Some(serde_json::json!({
            "transactionHash": format!("{expected_hash:#x}"),
            "status": "0x1",
        }));
        RenewalJournalGuard::acquire(node_data_dir.path())
            .unwrap()
            .store(RenewalJournalSnapshotV1::new(
                RenewalJournalStateV1::Submitted {
                    attempt,
                    submitted_at_finalized_height: 119,
                    transaction_hashes: vec![expected_hash],
                },
            ))
            .unwrap();

        let mut enclave = ReplayMustNotPrepare;
        let node_signer = |_hash: B256| -> Result<[u8; 65]> {
            panic!("nonce race handling regenerated a NodeHost signature")
        };
        let outcome = run_renewal_once_v1(&rpc, &relay, &mut enclave, &node_signer, &config)
            .await
            .unwrap();

        assert_eq!(
            outcome,
            RenewalOutcomeV1::Submitted {
                transaction_hash: expected_hash,
                replayed: true,
            }
        );
        assert_eq!(rpc.sent.lock().unwrap().as_slice(), [expected_raw]);
    }

    #[tokio::test]
    async fn exact_receipt_requires_canonical_hash_and_success_status() {
        let node_data_dir = tempfile::tempdir().unwrap();
        let (rpc, _relay, _config, attempt) =
            replay_fixture(node_data_dir.path(), AttestationMode::GramineDirectDev);
        let raw = &attempt.relay_variants[0];
        let expected_hash = raw.transaction_hash;

        for status in ["0x0", "0x00", "0", "0x2", "malformed"] {
            *rpc.receipt.lock().unwrap() = Some(serde_json::json!({
                "transactionHash": format!("{expected_hash:#x}"),
                "status": status,
            }));
            let error = exact_transaction_receipt_exists(&rpc, raw)
                .await
                .expect_err("non-success receipt status must fail closed");
            assert!(error.to_string().contains("non-success status"));
        }

        *rpc.receipt.lock().unwrap() = Some(serde_json::json!({
            "transactionHash": format!("{:#x}", B256::repeat_byte(0x33)),
            "status": "0x1",
        }));
        assert!(exact_transaction_receipt_exists(&rpc, raw).await.is_err());

        *rpc.receipt.lock().unwrap() = Some(serde_json::json!({
            "transactionHash": format!("{expected_hash:#x}"),
        }));
        assert!(exact_transaction_receipt_exists(&rpc, raw).await.is_err());
    }

    #[test]
    fn direct_dev_renewal_uses_only_the_enclave_intent_signature() {
        let genesis_hash = B256::repeat_byte(0x44);
        let policy = initial_tee_policy_v1(
            InitialTeeProfileV1::GramineDirectDev,
            DEVNET_CHAIN_ID,
            genesis_hash,
        )
        .unwrap();
        let signer =
            ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x45));
        let mut intent =
            RegistrationIntentV1::decode_canonical(&target_attempt().0.intent).unwrap();
        intent.chain_id = policy.chain_id;
        intent.genesis_hash = genesis_hash;
        intent.attestation_mode = AttestationMode::GramineDirectDev;
        intent.policy_hash = policy.policy_hash().unwrap();
        intent.attestation_ed25519 = signer.verifying_key().to_bytes();
        intent.enclave_id = intent.derived_enclave_id().unwrap();
        let mut enclave = DirectOnlyEnclave {
            signer,
            dcap_calls: 0,
            direct_calls: 0,
        };

        let generated =
            generate_renewal_evidence(&mut enclave, &intent, &policy, 100, 700).unwrap();
        assert_eq!(enclave.dcap_calls, 0);
        assert_eq!(enclave.direct_calls, 1);
        assert_eq!(generated.collateral_valid_until, u64::MAX);
        assert_eq!(generated.collateral_margin, 0);
        let decoded = AttestationEvidenceV1::decode_canonical(&generated.evidence).unwrap();
        assert_eq!(decoded.evidence_hash().unwrap(), generated.evidence_hash);
        let AttestationEvidenceV1::GramineDirectDev(direct) = decoded else {
            panic!("expected GramineDirectDev evidence");
        };
        assert_eq!(direct.intent, intent);
        assert_eq!(direct.dev_attestation_public, intent.attestation_ed25519);
        assert_eq!(direct.dev_signature, generated.enclave_signature);
    }

    #[tokio::test]
    async fn direct_dev_prepare_builds_the_shared_calldata_and_relay_transaction() {
        let genesis_hash = B256::repeat_byte(0x51);
        let policy = initial_tee_policy_v1(
            InitialTeeProfileV1::GramineDirectDev,
            DEVNET_CHAIN_ID,
            genesis_hash,
        )
        .unwrap();
        let enclave_signer =
            ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x52));
        let node_signer = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0x53)).into(),
        )
        .unwrap();
        let node_id = NodeIdV1 {
            reth_p2p_public: node_signer
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
        };
        let manifest = EnclaveInitializationManifestV1 {
            chain_id: policy.chain_id,
            genesis_hash,
            attestation_mode: policy.attestation_mode,
            node_id: node_id.clone(),
            initialization_challenge: [0x54; 32],
            node_host_noise_x25519: [0x55; 32],
            recipient_x25519: [0x56; 32],
            attestation_ed25519: enclave_signer.verifying_key().to_bytes(),
            noise_responder_x25519: [0x57; 32],
        };
        let binding = RenewalBindingV1 {
            node_id_hash: node_id.node_id_hash().unwrap(),
            enclave_id: manifest.enclave_id().unwrap(),
            binding_id: B256::repeat_byte(0x58),
            intent_hash: B256::repeat_byte(0x59),
            evidence_hash: B256::repeat_byte(0x5a),
            policy_hash: policy.policy_hash().unwrap(),
            binding_version: 1,
            registration_version: 3,
            renewal_nonce: 2,
            transition_nonce: 0,
            lease_started_at: 100,
            valid_until: 1_000,
            collateral_valid_until: u64::MAX,
            recipient_x25519: B256::from(manifest.recipient_x25519),
            attestation_ed25519: B256::from(manifest.attestation_ed25519),
            noise_responder_x25519: B256::from(manifest.noise_responder_x25519),
            mrenclave: policy.measurement_rules[0].mrenclave,
            mrsigner: policy.measurement_rules[0].mrsigner,
            isv_prod_id: policy.measurement_rules[0].isv_prod_id,
            isv_svn: policy.measurement_rules[0].minimum_isv_svn,
            platform_tcb_status: 0,
            verdict_hash: B256::repeat_byte(0x5b),
            node_host_authorization_hash: manifest.node_host_authorization_hash().unwrap(),
        };
        let schedule = TeeRenewalScheduleV1 {
            finalized_height: 120,
            finalized_hash: B256::repeat_byte(0x5c),
            finalized_timestamp: 900,
            epoch_number: 2,
            epoch_start_height: 100,
            epoch_length_blocks: 100,
            next_freeze_height: 180,
            planned_activation_height: 200,
            dkg_prepare_window_blocks: 20,
            minimum_block_time_millis: 2_000,
        };
        let view = FinalizedRenewalChainViewV1 {
            schedule,
            policy,
            binding,
            tribute_offer_public: B256::repeat_byte(0x5d),
        };
        let config = RenewalServiceConfigV1 {
            node_data_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            selector: NodeBindingSelectorV1::NodeHost(node_id.reth_p2p_public),
            manifest,
        };
        let relay = RelaySignerV1::new(&hex::encode([0x5e; 32])).unwrap();
        let mut enclave = DirectOnlyEnclave {
            signer: enclave_signer,
            dcap_calls: 0,
            direct_calls: 0,
        };

        let attempt = prepare_attempt(
            &PreparationRpc,
            &relay,
            &mut enclave,
            &|_| Ok([0x5f; 65]),
            &config,
            &view,
        )
        .await
        .unwrap();
        assert_eq!(enclave.dcap_calls, 0);
        assert_eq!(enclave.direct_calls, 1);
        assert_eq!(attempt.collateral_valid_until, u64::MAX);
        assert_eq!(attempt.collateral_margin, 0);
        let call = ITeeRegistryV1::renewEnclaveCall::abi_decode(&attempt.calldata).unwrap();
        assert_eq!(call.evidence.as_ref(), attempt.evidence);
        assert_eq!(call.nodeSignature.as_ref(), attempt.node_signature);
        assert_eq!(call.enclaveSignature.as_ref(), attempt.enclave_signature);
        assert_eq!(attempt.relay, relay.address());
        assert_eq!(attempt.relay_variants.len(), 1);
        assert_eq!(attempt.relay_variants[0].account_nonce, 7);
        assert_eq!(
            attempt.relay_variants[0].calldata_hash,
            attempt.calldata_hash
        );
        let raw_variant = &attempt.relay_variants[0];
        let mut raw = raw_variant.raw_transaction.as_slice();
        let envelope = EthereumTxEnvelope::<TxEip4844>::decode_2718(&mut raw).unwrap();
        assert!(raw.is_empty());
        assert!(matches!(&envelope, EthereumTxEnvelope::Legacy(_)));
        assert_eq!(envelope.recover_signer().unwrap(), relay.address());
        assert_eq!(envelope.chain_id(), Some(DEVNET_CHAIN_ID));
        assert_eq!(envelope.nonce(), 7);
        let normative_gas = TeeRegistryGasScheduleV1::normative()
            .maximum_transaction_gas(
                RegistryMutatorV1::RenewEnclave,
                attempt.calldata.len(),
                attempt.evidence.len(),
                view.policy.measurement_rules.len(),
                AttestationMode::GramineDirectDev,
            )
            .unwrap();
        assert_eq!(raw_variant.gas_limit, normative_gas);
        assert_eq!(envelope.gas_limit(), raw_variant.gas_limit);
        assert_eq!(
            envelope.gas_price(),
            Some(raw_variant.gas_price.to::<u128>())
        );
        assert_eq!(envelope.kind(), TxKind::Call(TEE_REGISTRY_ADDRESS));
        assert_eq!(envelope.value(), U256::ZERO);
        assert_eq!(envelope.input().as_ref(), attempt.calldata.as_slice());
        assert_eq!(*envelope.tx_hash(), raw_variant.transaction_hash);
    }
}
