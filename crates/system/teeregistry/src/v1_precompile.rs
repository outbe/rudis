//! Active TeeRegistry V1 node-enclave registration ABI.
//!
//! A0 routes the production precompile address here exclusively. The global
//! bootstrap views retain their established selectors, while every V1 mutator
//! authenticates the EVM caller against the canonical NodeHost association.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolInterface};
use outbe_primitives::{
    dispatch::{dispatch_call, reject_value, view},
    error::{PrecompileError, Result},
    storage::{gas::PRECOMPILE_BASE_GAS, StorageHandle},
    tee_attestation_v1::{
        AttestationEvidenceV1, AttestationMode, RegistryMutatorV1, TeeRegistryGasScheduleV1,
        ValidatorNodeBindingV1, MAX_ATTESTATION_EVIDENCE_BYTES, MAX_EVIDENCE_CALL_FRAMING_BYTES,
    },
    tee_registry_abi_v1::{ITeeRegistryV1, NodeEnclaveBindingV1View},
};

use crate::{NodeEnclaveBindingV1, TeeRegistry, V1RegistrationOutcome};

/// TeeRegistry V1 never accepts native token value on any selector.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

/// Feature-gated V1 ABI entry point. Mutations bind the transaction caller to
/// the canonical address-to-NodeHost association before replay handling.
pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;

    let mutator = match data.get(..4) {
        Some(selector) if selector == ITeeRegistryV1::registerEnclaveCall::SELECTOR => {
            Some(RegistryMutatorV1::RegisterEnclave)
        }
        Some(selector) if selector == ITeeRegistryV1::renewEnclaveCall::SELECTOR => {
            Some(RegistryMutatorV1::RenewEnclave)
        }
        Some(selector) if selector == ITeeRegistryV1::replaceEnclaveBindingCall::SELECTOR => {
            Some(RegistryMutatorV1::ReplaceEnclaveBinding)
        }
        Some(selector)
            if selector == ITeeRegistryV1::transitionEnclaveMeasurementCall::SELECTOR =>
        {
            Some(RegistryMutatorV1::TransitionEnclaveMeasurement)
        }
        _ => None,
    };
    let mutation_preflight = if mutator.is_some() {
        if storage.is_static()? {
            return Err(PrecompileError::WriteProtection);
        }
        Some(preflight_evidence_mutator_call(data)?)
    } else {
        None
    };

    let active_policy = if let (Some(kind), Some(preflight)) = (mutator, mutation_preflight) {
        let registry = TeeRegistry::new(storage.clone());
        let policy = if kind == RegistryMutatorV1::TransitionEnclaveMeasurement {
            registry
                .staged_successor_policy_v1()?
                .map(|(_, policy)| policy)
                .ok_or_else(|| PrecompileError::Revert("no successor V1 policy is staged".into()))?
        } else {
            registry.active_policy_v1()?
        };
        deduct_mutator_protocol_gas(
            &storage,
            kind,
            data.len(),
            preflight.evidence.len(),
            policy.measurement_rules.len(),
            policy.attestation_mode,
        )?;
        Some(policy)
    } else {
        None
    };

    dispatch_call(
        data,
        ITeeRegistryV1::ITeeRegistryV1Calls::abi_decode,
        |call| {
            use ITeeRegistryV1::ITeeRegistryV1Calls::*;
            let mut registry = TeeRegistry::new(storage);
            match call {
                isBootstrapped(call) => view(call, |_| registry.is_bootstrapped()),
                tributeOfferPublicKey(call) => view(call, |_| {
                    registry
                        .offer_public_key()
                        .map(|value| U256::from_be_bytes(value.0))
                }),
                policyHash(call) => view(call, |_| {
                    registry
                        .policy_hash()
                        .map(|value| U256::from_be_bytes(value.0))
                }),
                keyEpoch(call) => view(call, |_| registry.key_epoch().map(U256::from)),
                tributeOfferEpoch(call) => {
                    view(call, |_| registry.tribute_offer_epoch().map(U256::from))
                }
                activePolicyV1(call) => view(call, |_| {
                    registry
                        .active_policy_v1()?
                        .encode_canonical()
                        .map(Bytes::from)
                        .map_err(|error| {
                            PrecompileError::Fatal(format!(
                                "active V1 policy cannot be encoded: {error}"
                            ))
                        })
                }),
                stagedSuccessorPolicyV1(call) => view(call, |_| {
                    let Some((proposal_id, policy)) = registry.staged_successor_policy_v1()? else {
                        return Ok(ITeeRegistryV1::stagedSuccessorPolicyV1Return {
                            exists: false,
                            proposalId: U256::ZERO,
                            policy: Bytes::new(),
                        });
                    };
                    let policy = policy
                        .encode_canonical()
                        .map(Bytes::from)
                        .map_err(|error| {
                            PrecompileError::Fatal(format!(
                                "staged successor V1 policy cannot be encoded: {error}"
                            ))
                        })?;
                    Ok(ITeeRegistryV1::stagedSuccessorPolicyV1Return {
                        exists: true,
                        proposalId: proposal_id,
                        policy,
                    })
                }),
                registerEnclave(_) => {
                    let policy = active_policy.as_ref().ok_or_else(|| {
                        PrecompileError::Fatal("V1 registration preflight was bypassed".into())
                    })?;
                    let preflight = mutation_preflight.ok_or_else(|| {
                        PrecompileError::Fatal("V1 registration preflight was bypassed".into())
                    })?;
                    let node_signature: [u8; 65] =
                        preflight.node_signature.try_into().map_err(|_| {
                            PrecompileError::Fatal("preflight node signature mismatch".into())
                        })?;
                    let enclave_signature: [u8; 64] =
                        preflight.enclave_signature.try_into().map_err(|_| {
                            PrecompileError::Fatal("preflight enclave signature mismatch".into())
                        })?;
                    let binding = ValidatorNodeBindingV1::decode_canonical(
                        preflight.validator_node_binding.ok_or_else(|| {
                            PrecompileError::Fatal(
                                "V1 registration binding preflight was bypassed".into(),
                            )
                        })?,
                    )
                    .map_err(|error| {
                        PrecompileError::Revert(format!(
                            "validator NodeHost binding is not canonical: {error}"
                        ))
                    })?;
                    let validator_signature: [u8; 65] = preflight
                        .validator_signature
                        .ok_or_else(|| {
                            PrecompileError::Fatal(
                                "V1 validator signature preflight was bypassed".into(),
                            )
                        })?
                        .try_into()
                        .map_err(|_| {
                            PrecompileError::Fatal("preflight validator signature mismatch".into())
                        })?;
                    let node_binding_signature: [u8; 65] = preflight
                        .node_binding_signature
                        .ok_or_else(|| {
                            PrecompileError::Fatal(
                                "V1 NodeHost binding signature preflight was bypassed".into(),
                            )
                        })?
                        .try_into()
                        .map_err(|_| {
                            PrecompileError::Fatal(
                                "preflight NodeHost binding signature mismatch".into(),
                            )
                        })?;
                    let (node_id_hash, _recipient_x25519) =
                        registration_onboarding_target(preflight.evidence)?;
                    let onboarding = registry.register_enclave_with_onboarding_v1(
                        caller,
                        preflight.evidence,
                        &node_signature,
                        &enclave_signature,
                        &binding,
                        &validator_signature,
                        &node_binding_signature,
                        policy,
                    )?;
                    registry.emit_verified_onboarding_artifact_v1(&onboarding, node_id_hash)?;
                    let outcome = onboarding.registration;
                    Ok(Bytes::from(
                        ITeeRegistryV1::registerEnclaveCall::abi_encode_returns(&matches!(
                            outcome,
                            V1RegistrationOutcome::Created
                        )),
                    ))
                }
                renewEnclave(_) => {
                    let policy = active_policy.as_ref().ok_or_else(|| {
                        PrecompileError::Fatal("V1 renewal preflight was bypassed".into())
                    })?;
                    let preflight = mutation_preflight.ok_or_else(|| {
                        PrecompileError::Fatal("V1 renewal preflight was bypassed".into())
                    })?;
                    let node_signature: [u8; 65] =
                        preflight.node_signature.try_into().map_err(|_| {
                            PrecompileError::Fatal("preflight node signature mismatch".into())
                        })?;
                    let enclave_signature: [u8; 64] =
                        preflight.enclave_signature.try_into().map_err(|_| {
                            PrecompileError::Fatal("preflight enclave signature mismatch".into())
                        })?;
                    let outcome = registry.renew_enclave_with_active_policy_v1(
                        caller,
                        preflight.evidence,
                        &node_signature,
                        &enclave_signature,
                        policy,
                    )?;
                    Ok(Bytes::from(
                        ITeeRegistryV1::renewEnclaveCall::abi_encode_returns(&matches!(
                            outcome,
                            V1RegistrationOutcome::Created
                        )),
                    ))
                }
                replaceEnclaveBinding(_) => {
                    let policy = active_policy.as_ref().ok_or_else(|| {
                        PrecompileError::Fatal("V1 replacement preflight was bypassed".into())
                    })?;
                    let preflight = mutation_preflight.ok_or_else(|| {
                        PrecompileError::Fatal("V1 replacement preflight was bypassed".into())
                    })?;
                    let node_signature: [u8; 65] =
                        preflight.node_signature.try_into().map_err(|_| {
                            PrecompileError::Fatal("preflight node signature mismatch".into())
                        })?;
                    let enclave_signature: [u8; 64] =
                        preflight.enclave_signature.try_into().map_err(|_| {
                            PrecompileError::Fatal("preflight enclave signature mismatch".into())
                        })?;
                    let outcome = registry.replace_enclave_binding_with_active_policy_v1(
                        caller,
                        preflight.evidence,
                        &node_signature,
                        &enclave_signature,
                        policy,
                    )?;
                    Ok(Bytes::from(
                        ITeeRegistryV1::replaceEnclaveBindingCall::abi_encode_returns(&matches!(
                            outcome,
                            V1RegistrationOutcome::Created
                        )),
                    ))
                }
                transitionEnclaveMeasurement(_) => {
                    let preflight = mutation_preflight.ok_or_else(|| {
                        PrecompileError::Fatal(
                            "V1 measurement-transition preflight was bypassed".into(),
                        )
                    })?;
                    let node_signature: [u8; 65] =
                        preflight.node_signature.try_into().map_err(|_| {
                            PrecompileError::Fatal("preflight node signature mismatch".into())
                        })?;
                    let enclave_signature: [u8; 64] =
                        preflight.enclave_signature.try_into().map_err(|_| {
                            PrecompileError::Fatal("preflight enclave signature mismatch".into())
                        })?;
                    let outcome = registry.transition_enclave_measurement_with_staged_policy_v1(
                        caller,
                        preflight.evidence,
                        &node_signature,
                        &enclave_signature,
                    )?;
                    Ok(Bytes::from(
                        ITeeRegistryV1::transitionEnclaveMeasurementCall::abi_encode_returns(
                            &matches!(outcome, V1RegistrationOutcome::Created),
                        ),
                    ))
                }
                validatorEnclaveBinding(call) => view(call, |call| {
                    Ok(binding_view(
                        registry.validator_enclave_binding_v1(call.validator)?,
                    ))
                }),
                nodeHostEnclaveBinding(call) => view(call, |call| {
                    Ok(binding_view(registry.node_host_enclave_binding_v1(
                        full_node_public_key(call.rethP2pPrefix, call.rethP2pX),
                    )?))
                }),
                isValidatorEnclaveReady(call) => view(call, |call| {
                    registry.is_validator_enclave_ready_v1(call.validator)
                }),
                isNodeHostEnclaveReady(call) => view(call, |call| {
                    registry.is_node_host_enclave_ready_v1(full_node_public_key(
                        call.rethP2pPrefix,
                        call.rethP2pX,
                    ))
                }),
            }
        },
    )
}

fn registration_onboarding_target(evidence: &[u8]) -> Result<(B256, [u8; 32])> {
    let decoded = AttestationEvidenceV1::decode_canonical(evidence).map_err(|error| {
        PrecompileError::Revert(format!("attestation evidence is not canonical: {error}"))
    })?;
    let intent = match decoded {
        AttestationEvidenceV1::Dcap(value) => value.intent,
        AttestationEvidenceV1::GramineDirectDev(value) => value.intent,
    };
    let node_id_hash = intent.node_id.node_id_hash().map_err(|error| {
        PrecompileError::Revert(format!("registration node identity is invalid: {error}"))
    })?;
    Ok((node_id_hash, intent.recipient_x25519))
}

fn deduct_mutator_protocol_gas(
    storage: &StorageHandle<'_>,
    kind: RegistryMutatorV1,
    input_len: usize,
    evidence_len: usize,
    active_rule_count: usize,
    attestation_mode: AttestationMode,
) -> Result<()> {
    let schedule = TeeRegistryGasScheduleV1::normative();
    let maximum_transaction_gas = schedule
        .maximum_transaction_gas(
            kind,
            input_len,
            evidence_len,
            active_rule_count,
            attestation_mode,
        )
        .map_err(|error| {
            PrecompileError::Revert(format!("invalid V1 registry gas dimensions: {error}"))
        })?;
    let intrinsic = schedule
        .maximum_calldata_intrinsic_gas(input_len)
        .map_err(|error| {
            PrecompileError::Revert(format!("invalid V1 calldata gas dimensions: {error}"))
        })?;
    let protocol = maximum_transaction_gas
        .checked_sub(intrinsic)
        .ok_or_else(|| PrecompileError::Fatal("V1 protocol gas underflow".into()))?;
    let storage_allowance = schedule.mutator_storage_gas_allowance(kind);
    let prepaid_protocol = protocol.checked_sub(storage_allowance).ok_or_else(|| {
        PrecompileError::Fatal("V1 mutator storage allowance exceeds fixed gas".into())
    })?;
    let dispatch_charge = prepaid_protocol
        .checked_sub(PRECOMPILE_BASE_GAS)
        .ok_or_else(|| {
            PrecompileError::Fatal("V1 protocol gas is below the precompile base charge".into())
        })?;
    storage.deduct_gas(dispatch_charge)
}

#[derive(Clone, Copy)]
struct RegisterPreflight<'a> {
    evidence: &'a [u8],
    node_signature: &'a [u8],
    enclave_signature: &'a [u8],
    validator_node_binding: Option<&'a [u8]>,
    validator_signature: Option<&'a [u8]>,
    node_binding_signature: Option<&'a [u8]>,
}

/// Validates the complete canonical ABI layout without allocating dynamic
/// arguments. Signature lengths, aggregate evidence cap, call-framing cap,
/// offsets, zero padding and trailing bytes reject before policy allocation or
/// native QVL execution.
fn preflight_evidence_mutator_call(data: &[u8]) -> Result<RegisterPreflight<'_>> {
    const MUTATOR_HEAD_WORDS: usize = 3;
    const REGISTER_HEAD_WORDS: usize = 6;
    let is_register =
        data.get(..4) == Some(ITeeRegistryV1::registerEnclaveCall::SELECTOR.as_slice());
    let head_words = if is_register {
        REGISTER_HEAD_WORDS
    } else {
        MUTATOR_HEAD_WORDS
    };
    let head_len = head_words * 32;

    let args = data
        .get(4..)
        .ok_or_else(|| invalid_register_abi("missing function selector"))?;
    let head = args
        .get(..head_len)
        .ok_or_else(|| invalid_register_abi("truncated argument head"))?;
    let evidence_offset = abi_usize(&head[0..32])?;
    let node_signature_offset = abi_usize(&head[32..64])?;
    let enclave_signature_offset = abi_usize(&head[64..96])?;
    if evidence_offset != head_len {
        return Err(invalid_register_abi("non-canonical evidence offset"));
    }

    let (evidence, next_offset) = dynamic_bytes(args, evidence_offset)?;
    if evidence.len() > MAX_ATTESTATION_EVIDENCE_BYTES {
        return Err(PrecompileError::Revert(format!(
            "attestation evidence exceeds {} bytes",
            MAX_ATTESTATION_EVIDENCE_BYTES
        )));
    }
    if node_signature_offset != next_offset {
        return Err(invalid_register_abi("non-canonical node signature offset"));
    }
    let (node_signature, next_offset) = dynamic_bytes(args, node_signature_offset)?;
    if node_signature.len() != 65 {
        return Err(PrecompileError::Revert(
            "node proof-of-possession signature must be 65 bytes".into(),
        ));
    }
    if enclave_signature_offset != next_offset {
        return Err(invalid_register_abi(
            "non-canonical enclave signature offset",
        ));
    }
    let (enclave_signature, next_offset) = dynamic_bytes(args, enclave_signature_offset)?;
    if enclave_signature.len() != 64 {
        return Err(PrecompileError::Revert(
            "enclave proof-of-possession signature must be 64 bytes".into(),
        ));
    }
    let (validator_node_binding, validator_signature, node_binding_signature, final_offset) =
        if is_register {
            let binding_offset = abi_usize(&head[96..128])?;
            let validator_signature_offset = abi_usize(&head[128..160])?;
            let node_binding_signature_offset = abi_usize(&head[160..192])?;
            if binding_offset != next_offset {
                return Err(invalid_register_abi(
                    "non-canonical validator NodeHost binding offset",
                ));
            }
            let (binding, next_offset) = dynamic_bytes(args, binding_offset)?;
            if binding.len() != ValidatorNodeBindingV1::CANONICAL_LEN {
                return Err(PrecompileError::Revert(format!(
                    "validator NodeHost binding must be {} bytes",
                    ValidatorNodeBindingV1::CANONICAL_LEN
                )));
            }
            if validator_signature_offset != next_offset {
                return Err(invalid_register_abi(
                    "non-canonical validator signature offset",
                ));
            }
            let (validator_signature, next_offset) =
                dynamic_bytes(args, validator_signature_offset)?;
            if validator_signature.len() != 65 {
                return Err(PrecompileError::Revert(
                    "validator NodeHost binding signature must be 65 bytes".into(),
                ));
            }
            if node_binding_signature_offset != next_offset {
                return Err(invalid_register_abi(
                    "non-canonical NodeHost binding signature offset",
                ));
            }
            let (node_binding_signature, final_offset) =
                dynamic_bytes(args, node_binding_signature_offset)?;
            if node_binding_signature.len() != 65 {
                return Err(PrecompileError::Revert(
                    "NodeHost binding signature must be 65 bytes".into(),
                ));
            }
            (
                Some(binding),
                Some(validator_signature),
                Some(node_binding_signature),
                final_offset,
            )
        } else {
            (None, None, None, next_offset)
        };
    if final_offset != args.len() {
        return Err(invalid_register_abi("trailing ABI bytes"));
    }
    let framing_len = data
        .len()
        .checked_sub(evidence.len())
        .ok_or_else(|| invalid_register_abi("evidence length exceeds calldata"))?;
    if framing_len > MAX_EVIDENCE_CALL_FRAMING_BYTES {
        return Err(PrecompileError::Revert(format!(
            "evidence call framing exceeds {} bytes",
            MAX_EVIDENCE_CALL_FRAMING_BYTES
        )));
    }

    Ok(RegisterPreflight {
        evidence,
        node_signature,
        enclave_signature,
        validator_node_binding,
        validator_signature,
        node_binding_signature,
    })
}

/// Hardware-free I3 boundary: canonical ABI and full gas precharge stay real;
/// only the already-authenticated enclave outcome is supplied as a typed,
/// test-only capability.
#[cfg(test)]
pub(crate) fn dispatch_register_after_verifier_for_test(
    storage: StorageHandle<'_>,
    caller: Address,
    data: &[u8],
    intent: &outbe_primitives::tee_attestation_v1::RegistrationIntentV1,
    capability: crate::v1::PostVerifierDcapCapabilityV1,
) -> Result<V1RegistrationOutcome> {
    dispatch_mutator_after_verifier_for_test(
        storage,
        caller,
        data,
        intent,
        RegistryMutatorV1::RegisterEnclave,
        capability,
    )
}

/// Hardware-free coverage of registration followed by emission of the exact
/// purpose-bound artifact returned by the verifier enclave.
#[cfg(test)]
pub(crate) fn dispatch_register_with_onboarding_after_verifier_for_test<F>(
    storage: StorageHandle<'_>,
    caller: Address,
    data: &[u8],
    intent: &outbe_primitives::tee_attestation_v1::RegistrationIntentV1,
    capability: crate::v1::PostVerifierDcapCapabilityV1,
    artifact_for_recipient: F,
) -> Result<V1RegistrationOutcome>
where
    F: FnOnce([u8; 32]) -> std::result::Result<Option<Vec<u8>>, String>,
{
    let onboarding_storage = storage.clone();
    let outcome =
        dispatch_register_after_verifier_for_test(storage, caller, data, intent, capability)?;
    let node_id_hash = intent.node_id.node_id_hash().map_err(|error| {
        PrecompileError::Revert(format!("registration node identity is invalid: {error}"))
    })?;
    let artifact = if outcome == V1RegistrationOutcome::Created {
        artifact_for_recipient(intent.recipient_x25519)
            .map_err(PrecompileError::Fatal)?
            .map(|bytes| {
                outbe_tee::dcap_protocol::DcapOnboardingArtifactV1::decode_canonical(&bytes)
                    .map_err(|code| {
                        PrecompileError::Fatal(format!(
                            "test verifier returned a non-canonical onboarding artifact: {:#06x}",
                            code.code()
                        ))
                    })
            })
            .transpose()?
    } else {
        None
    };
    TeeRegistry::new(onboarding_storage).emit_verified_onboarding_artifact_v1(
        &crate::v1::V1OnboardingOutcome {
            registration: outcome,
            artifact,
        },
        node_id_hash,
    )?;
    Ok(outcome)
}

#[cfg(test)]
pub(crate) fn dispatch_renew_after_verifier_for_test(
    storage: StorageHandle<'_>,
    caller: Address,
    data: &[u8],
    intent: &outbe_primitives::tee_attestation_v1::RegistrationIntentV1,
    capability: crate::v1::PostVerifierDcapCapabilityV1,
) -> Result<V1RegistrationOutcome> {
    dispatch_mutator_after_verifier_for_test(
        storage,
        caller,
        data,
        intent,
        RegistryMutatorV1::RenewEnclave,
        capability,
    )
}

#[cfg(test)]
pub(crate) fn dispatch_replace_after_verifier_for_test(
    storage: StorageHandle<'_>,
    caller: Address,
    data: &[u8],
    intent: &outbe_primitives::tee_attestation_v1::RegistrationIntentV1,
    capability: crate::v1::PostVerifierDcapCapabilityV1,
) -> Result<V1RegistrationOutcome> {
    dispatch_mutator_after_verifier_for_test(
        storage,
        caller,
        data,
        intent,
        RegistryMutatorV1::ReplaceEnclaveBinding,
        capability,
    )
}

#[cfg(test)]
pub(crate) fn dispatch_transition_after_verifier_for_test(
    storage: StorageHandle<'_>,
    caller: Address,
    data: &[u8],
    intent: &outbe_primitives::tee_attestation_v1::RegistrationIntentV1,
    capability: crate::v1::PostVerifierDcapCapabilityV1,
) -> Result<V1RegistrationOutcome> {
    dispatch_mutator_after_verifier_for_test(
        storage,
        caller,
        data,
        intent,
        RegistryMutatorV1::TransitionEnclaveMeasurement,
        capability,
    )
}

#[cfg(test)]
fn dispatch_mutator_after_verifier_for_test(
    storage: StorageHandle<'_>,
    caller: Address,
    data: &[u8],
    intent: &outbe_primitives::tee_attestation_v1::RegistrationIntentV1,
    kind: RegistryMutatorV1,
    capability: crate::v1::PostVerifierDcapCapabilityV1,
) -> Result<V1RegistrationOutcome> {
    let preflight = preflight_evidence_mutator_call(data)?;
    let policy = if kind == RegistryMutatorV1::TransitionEnclaveMeasurement {
        TeeRegistry::new(storage.clone())
            .staged_successor_policy_v1()?
            .map(|(_, policy)| policy)
            .ok_or_else(|| PrecompileError::Revert("no successor V1 policy is staged".into()))?
    } else {
        TeeRegistry::new(storage.clone()).active_policy_v1()?
    };
    deduct_mutator_protocol_gas(
        &storage,
        kind,
        data.len(),
        preflight.evidence.len(),
        policy.measurement_rules.len(),
        policy.attestation_mode,
    )?;
    let node_signature: [u8; 65] = preflight
        .node_signature
        .try_into()
        .map_err(|_| PrecompileError::Fatal("preflight node signature mismatch".into()))?;
    let enclave_signature: [u8; 64] = preflight
        .enclave_signature
        .try_into()
        .map_err(|_| PrecompileError::Fatal("preflight enclave signature mismatch".into()))?;
    let mut registry = TeeRegistry::new(storage);
    if kind == RegistryMutatorV1::TransitionEnclaveMeasurement {
        let evidence =
            AttestationEvidenceV1::decode_canonical(preflight.evidence).map_err(|error| {
                PrecompileError::Revert(format!("attestation evidence is not canonical: {error}"))
            })?;
        registry.validate_transition_key_ready_proof_v1(&evidence)?;
    }
    match kind {
        RegistryMutatorV1::RegisterEnclave => {
            let binding = ValidatorNodeBindingV1::decode_canonical(
                preflight.validator_node_binding.ok_or_else(|| {
                    PrecompileError::Fatal("registration binding preflight was bypassed".into())
                })?,
            )
            .map_err(|error| {
                PrecompileError::Revert(format!(
                    "validator NodeHost binding is not canonical: {error}"
                ))
            })?;
            let validator_signature = preflight
                .validator_signature
                .ok_or_else(|| {
                    PrecompileError::Fatal(
                        "registration validator signature preflight was bypassed".into(),
                    )
                })?
                .try_into()
                .map_err(|_| {
                    PrecompileError::Fatal("preflight validator signature mismatch".into())
                })?;
            let node_binding_signature = preflight
                .node_binding_signature
                .ok_or_else(|| {
                    PrecompileError::Fatal(
                        "registration NodeHost binding signature preflight was bypassed".into(),
                    )
                })?
                .try_into()
                .map_err(|_| {
                    PrecompileError::Fatal("preflight NodeHost binding signature mismatch".into())
                })?;
            registry.register_enclave_and_bind_after_verifier_for_test_as(
                caller,
                intent,
                &node_signature,
                &enclave_signature,
                &binding,
                &validator_signature,
                &node_binding_signature,
                capability,
            )
        }
        RegistryMutatorV1::RenewEnclave => registry
            .renew_enclave_after_verifier_with_active_policy_for_test(
                caller,
                intent,
                &node_signature,
                &enclave_signature,
                &policy,
                capability,
            ),
        RegistryMutatorV1::ReplaceEnclaveBinding => registry
            .replace_enclave_binding_after_verifier_with_active_policy_for_test(
                caller,
                intent,
                &node_signature,
                &enclave_signature,
                &policy,
                capability,
            ),
        RegistryMutatorV1::TransitionEnclaveMeasurement => registry
            .transition_enclave_measurement_after_verifier_for_test(
                caller,
                intent,
                &node_signature,
                &enclave_signature,
                capability,
            ),
    }
}

fn dynamic_bytes(args: &[u8], offset: usize) -> Result<(&[u8], usize)> {
    let length_word_end = offset
        .checked_add(32)
        .ok_or_else(|| invalid_register_abi("dynamic offset overflow"))?;
    let length = abi_usize(
        args.get(offset..length_word_end)
            .ok_or_else(|| invalid_register_abi("truncated dynamic length"))?,
    )?;
    let value_end = length_word_end
        .checked_add(length)
        .ok_or_else(|| invalid_register_abi("dynamic length overflow"))?;
    let value = args
        .get(length_word_end..value_end)
        .ok_or_else(|| invalid_register_abi("truncated dynamic value"))?;
    let padded_length = length
        .checked_add(31)
        .map(|length| length / 32 * 32)
        .ok_or_else(|| invalid_register_abi("dynamic padding overflow"))?;
    let padded_end = length_word_end
        .checked_add(padded_length)
        .ok_or_else(|| invalid_register_abi("dynamic padding overflow"))?;
    let padding = args
        .get(value_end..padded_end)
        .ok_or_else(|| invalid_register_abi("truncated dynamic padding"))?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(invalid_register_abi("non-zero dynamic padding"));
    }
    Ok((value, padded_end))
}

fn abi_usize(word: &[u8]) -> Result<usize> {
    let width = core::mem::size_of::<usize>();
    if word.len() != 32 || word[..32 - width].iter().any(|byte| *byte != 0) {
        return Err(invalid_register_abi("ABI integer exceeds host usize"));
    }
    let mut value = [0_u8; core::mem::size_of::<usize>()];
    value.copy_from_slice(&word[32 - width..]);
    Ok(usize::from_be_bytes(value))
}

fn invalid_register_abi(reason: &'static str) -> PrecompileError {
    PrecompileError::Revert(format!("invalid canonical V1 registration ABI: {reason}"))
}

fn full_node_public_key(prefix: u8, x: B256) -> [u8; 33] {
    let mut public = [0_u8; 33];
    public[0] = prefix;
    public[1..].copy_from_slice(x.as_slice());
    public
}

fn binding_view(binding: Option<NodeEnclaveBindingV1>) -> NodeEnclaveBindingV1View {
    let Some(binding) = binding else {
        return NodeEnclaveBindingV1View {
            exists: false,
            nodeIdHash: B256::ZERO,
            enclaveId: B256::ZERO,
            bindingId: B256::ZERO,
            intentHash: B256::ZERO,
            evidenceHash: B256::ZERO,
            policyHash: B256::ZERO,
            bindingVersion: 0,
            registrationVersion: 0,
            renewalNonce: 0,
            transitionNonce: 0,
            leaseStartedAt: 0,
            validUntil: 0,
            collateralValidUntil: 0,
            recipientX25519: B256::ZERO,
            attestationEd25519: B256::ZERO,
            noiseResponderX25519: B256::ZERO,
            mrenclave: B256::ZERO,
            mrsigner: B256::ZERO,
            isvProdId: 0,
            isvSvn: 0,
            platformTcbStatus: 0,
            verdictHash: B256::ZERO,
            nodeHostAuthorizationHash: B256::ZERO,
        };
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolValue;
    use outbe_primitives::{
        chain::TESTNET_CHAIN_ID,
        storage::{hashmap::HashMapStorageProvider, PrecompileStorageProvider},
        tee_attestation_v1::{
            AttestationEvidenceV1, AttestationOperationV1, DcapCollateralComponentV1,
            DcapCollateralKind, DcapEvidenceV1, NodeIdV1, PlatformTcbStatusSetV1, QvlTcbStatusV1,
            RegistrationIntentV1, ResourceScheduleV1, TeeMeasurementRuleV1, TeePolicyV1,
        },
    };

    const GENESIS: B256 = B256::repeat_byte(0x31);
    const CHAIN_ID: u64 = TESTNET_CHAIN_ID;

    fn policy() -> TeePolicyV1 {
        let resources = ResourceScheduleV1::normative().unwrap();
        let mut chain_id = [0_u8; 32];
        chain_id[24..].copy_from_slice(&CHAIN_ID.to_be_bytes());
        TeePolicyV1 {
            policy_version: 1,
            chain_id,
            genesis_hash: GENESIS,
            activation_height: 1,
            predecessor_policy_hash: B256::ZERO,
            attestation_mode: AttestationMode::DcapRequired,
            intel_root_der_hash: B256::repeat_byte(0x43),
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
            resource_schedule_hash: resources.schedule_hash().unwrap(),
            measurement_rules: vec![TeeMeasurementRuleV1 {
                mrenclave: B256::repeat_byte(0x45),
                mrsigner: B256::repeat_byte(0x46),
                isv_prod_id: 7,
                minimum_isv_svn: 2,
                admit_from_height: 1,
                admit_until_height_exclusive: 1_000,
            }],
        }
    }

    #[test]
    fn staged_successor_view_is_canonical_and_distinguishes_absence() {
        let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS);
        provider.set_block_number(10);
        let current = policy();
        provider
            .enter(|storage| TeeRegistry::new(storage).install_initial_policy_v1(&current))
            .unwrap();
        let call = ITeeRegistryV1::stagedSuccessorPolicyV1Call {};
        let empty = provider
            .enter(|storage| dispatch(storage, &call.abi_encode(), Address::ZERO, U256::ZERO))
            .unwrap();
        let empty =
            ITeeRegistryV1::stagedSuccessorPolicyV1Call::abi_decode_returns(&empty).unwrap();
        assert!(!empty.exists);
        assert!(empty.proposalId.is_zero());
        assert!(empty.policy.is_empty());

        let mut successor = current.clone();
        successor.policy_version = 2;
        successor.activation_height = 50;
        successor.predecessor_policy_hash = current.policy_hash().unwrap();
        provider
            .enter(|storage| {
                TeeRegistry::new(storage).stage_successor_policy_v1(U256::from(7), &successor)
            })
            .unwrap();
        let encoded = provider
            .enter(|storage| dispatch(storage, &call.abi_encode(), Address::ZERO, U256::ZERO))
            .unwrap();
        let staged =
            ITeeRegistryV1::stagedSuccessorPolicyV1Call::abi_decode_returns(&encoded).unwrap();
        assert!(staged.exists);
        assert_eq!(staged.proposalId, U256::from(7));
        assert_eq!(
            TeePolicyV1::decode_canonical(&staged.policy).unwrap(),
            successor
        );
    }

    fn call(evidence: Vec<u8>, node_len: usize, enclave_len: usize) -> Vec<u8> {
        ITeeRegistryV1::registerEnclaveCall {
            evidence: Bytes::from(evidence),
            nodeSignature: Bytes::from(vec![0x51; node_len]),
            enclaveSignature: Bytes::from(vec![0x52; enclave_len]),
            validatorNodeBinding: Bytes::from(vec![0x53; ValidatorNodeBindingV1::CANONICAL_LEN]),
            validatorSignature: Bytes::from(vec![0x54; 65]),
            nodeBindingSignature: Bytes::from(vec![0x55; 65]),
        }
        .abi_encode()
    }

    fn mutator_call(
        kind: RegistryMutatorV1,
        evidence: Vec<u8>,
        node_len: usize,
        enclave_len: usize,
    ) -> Vec<u8> {
        let node_signature = Bytes::from(vec![0x51; node_len]);
        let enclave_signature = Bytes::from(vec![0x52; enclave_len]);
        match kind {
            RegistryMutatorV1::RegisterEnclave => ITeeRegistryV1::registerEnclaveCall {
                evidence: Bytes::from(evidence),
                nodeSignature: node_signature,
                enclaveSignature: enclave_signature,
                validatorNodeBinding: Bytes::from(vec![
                    0x53;
                    ValidatorNodeBindingV1::CANONICAL_LEN
                ]),
                validatorSignature: Bytes::from(vec![0x54; 65]),
                nodeBindingSignature: Bytes::from(vec![0x55; 65]),
            }
            .abi_encode(),
            RegistryMutatorV1::RenewEnclave => ITeeRegistryV1::renewEnclaveCall {
                evidence: Bytes::from(evidence),
                nodeSignature: node_signature,
                enclaveSignature: enclave_signature,
            }
            .abi_encode(),
            RegistryMutatorV1::ReplaceEnclaveBinding => ITeeRegistryV1::replaceEnclaveBindingCall {
                evidence: Bytes::from(evidence),
                nodeSignature: node_signature,
                enclaveSignature: enclave_signature,
            }
            .abi_encode(),
            RegistryMutatorV1::TransitionEnclaveMeasurement => {
                ITeeRegistryV1::transitionEnclaveMeasurementCall {
                    evidence: Bytes::from(evidence),
                    nodeSignature: node_signature,
                    enclaveSignature: enclave_signature,
                }
                .abi_encode()
            }
        }
    }

    fn canonical_dcap_evidence(kind: RegistryMutatorV1) -> Vec<u8> {
        let policy = policy();
        let node_key = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0x61)).into(),
        )
        .unwrap();
        let reth_p2p_public = node_key.verifying_key().to_encoded_point(true);
        let mut intent = RegistrationIntentV1 {
            chain_id: policy.chain_id,
            genesis_hash: policy.genesis_hash,
            operation: match kind {
                RegistryMutatorV1::RegisterEnclave => AttestationOperationV1::RegisterEnclave,
                RegistryMutatorV1::RenewEnclave => AttestationOperationV1::RenewEnclave,
                RegistryMutatorV1::TransitionEnclaveMeasurement => {
                    AttestationOperationV1::TransitionEnclaveMeasurement
                }
                RegistryMutatorV1::ReplaceEnclaveBinding => {
                    AttestationOperationV1::ReplaceEnclaveBinding
                }
            },
            attestation_mode: AttestationMode::DcapRequired,
            policy_hash: policy.policy_hash().unwrap(),
            node_id: NodeIdV1 {
                reth_p2p_public: reth_p2p_public.as_bytes().try_into().unwrap(),
            },
            enclave_id: B256::repeat_byte(1),
            binding_id: B256::repeat_byte(2),
            binding_version: 1,
            registration_version: 0,
            renewal_nonce: 0,
            transition_nonce: 0,
            requested_valid_until: 7_200,
            recipient_x25519: [3; 32],
            attestation_ed25519: [4; 32],
            noise_responder_x25519: [5; 32],
            node_host_authorization_hash: B256::repeat_byte(6),
        };
        intent.enclave_id = intent.derived_enclave_id().unwrap();
        AttestationEvidenceV1::Dcap(DcapEvidenceV1 {
            intent,
            quote: vec![7],
            components: (1_u8..=8)
                .map(|value| DcapCollateralComponentV1 {
                    kind: DcapCollateralKind::try_from(value).unwrap(),
                    bytes: vec![value],
                })
                .collect(),
            transition_key_ready_proof: None,
        })
        .encode_canonical()
        .unwrap()
    }

    #[test]
    fn canonical_register_preflight_is_borrowed_and_rejects_noncanonical_framing() {
        let encoded = call(vec![1, 2, 3], 65, 64);
        assert_eq!(
            preflight_evidence_mutator_call(&encoded).unwrap().evidence,
            [1, 2, 3]
        );

        let mut wrong_offset = encoded.clone();
        wrong_offset[35] = 0x80;
        assert!(preflight_evidence_mutator_call(&wrong_offset).is_err());

        let mut nonzero_padding = encoded;
        let evidence_value_start = 4 + 96 + 32;
        nonzero_padding[evidence_value_start + 3] = 1;
        assert!(preflight_evidence_mutator_call(&nonzero_padding).is_err());
        assert!(preflight_evidence_mutator_call(&call(vec![1], 64, 64)).is_err());
        assert!(preflight_evidence_mutator_call(&call(vec![1], 65, 63)).is_err());
    }

    #[test]
    fn register_precharges_exact_protocol_gas_before_evidence_decode() {
        let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS);
        provider.set_block_number(1);
        provider
            .enter(|storage| TeeRegistry::new(storage).install_initial_policy_v1(&policy()))
            .unwrap();
        provider.enable_production_storage_gas_metering();

        // Canonical outer ABI, deliberately malformed canonical evidence. The
        // decoder rejection must occur only after the complete QVL/register
        // protocol charge has been reserved.
        let input = call(vec![1, 1, 0, 0, 0, 0], 65, 64);
        let schedule = TeeRegistryGasScheduleV1::normative();
        let total = schedule
            .maximum_transaction_gas(
                RegistryMutatorV1::RegisterEnclave,
                input.len(),
                6,
                1,
                AttestationMode::DcapRequired,
            )
            .unwrap();
        let intrinsic = schedule
            .maximum_calldata_intrinsic_gas(input.len())
            .unwrap();
        let storage_allowance = schedule.register_storage_gas_allowance();
        let dispatch_charge = total - intrinsic - PRECOMPILE_BASE_GAS - storage_allowance;

        // Actual production-shaped storage gas consumes the allowance already
        // included in `register_fixed`; it must never sit above the normative
        // maximum. The malformed canonical evidence is rejected before verifier
        // invocation and no state write is reachable.
        provider.set_gas_limit(u64::MAX);
        let result = provider
            .enter(|storage| dispatch(storage, &input, Address::repeat_byte(0x77), U256::ZERO));
        assert!(
            matches!(result, Err(PrecompileError::Revert(_))),
            "malformed canonical evidence framing must revert: {result:?}"
        );
        let (policy_reads, writes) = provider.metered_storage_operations();
        assert!(policy_reads > 0);
        assert_eq!(writes, 0);
        let storage_gas = policy_reads * 100;
        let exact_dispatch_gas = dispatch_charge + storage_gas;
        assert_eq!(provider.gas_used(), exact_dispatch_gas);
        assert!(storage_gas <= storage_allowance);
        assert_eq!(
            intrinsic + PRECOMPILE_BASE_GAS + provider.gas_used(),
            total - storage_allowance + storage_gas
        );
        assert!(intrinsic + PRECOMPILE_BASE_GAS + provider.gas_used() <= total);

        provider.set_gas_limit(exact_dispatch_gas);
        let result = provider
            .enter(|storage| dispatch(storage, &input, Address::repeat_byte(0x88), U256::ZERO));
        assert!(
            matches!(result, Err(PrecompileError::Revert(_))),
            "exact-gas malformed evidence must still revert: {result:?}"
        );
        assert_eq!(provider.gas_used(), exact_dispatch_gas);
        assert_eq!(provider.metered_storage_operations(), (policy_reads, 0));

        provider.set_gas_limit(exact_dispatch_gas - 1);
        let result = provider
            .enter(|storage| dispatch(storage, &input, Address::repeat_byte(0x99), U256::ZERO));
        assert!(matches!(result, Err(PrecompileError::OutOfGas)));
        assert_eq!(provider.gas_used(), storage_gas);
        assert_eq!(provider.metered_storage_operations(), (policy_reads, 0));
    }

    #[test]
    fn gramine_direct_dev_register_precharge_uses_active_policy_mode() {
        let mut active_policy = policy();
        active_policy.attestation_mode = AttestationMode::GramineDirectDev;
        let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS);
        provider.set_block_number(1);
        provider
            .enter(|storage| TeeRegistry::new(storage).install_initial_policy_v1(&active_policy))
            .unwrap();
        provider.enable_production_storage_gas_metering();

        // Canonical outer ABI with malformed development evidence reaches the
        // mode-selected precharge and then reverts during evidence decoding.
        // The exact GramineDirectDev maximum must be sufficient; charging the
        // production DCAP schedule here makes the reachable dev transaction
        // consume its entire signed gas limit before validation.
        let input = call(vec![1, 1, 0, 0, 0, 0], 65, 64);
        let schedule = TeeRegistryGasScheduleV1::normative();
        let total = schedule
            .maximum_transaction_gas(
                RegistryMutatorV1::RegisterEnclave,
                input.len(),
                6,
                active_policy.measurement_rules.len(),
                AttestationMode::GramineDirectDev,
            )
            .unwrap();
        let intrinsic = schedule
            .maximum_calldata_intrinsic_gas(input.len())
            .unwrap();
        let storage_allowance = schedule.register_storage_gas_allowance();
        let dispatch_charge = total - intrinsic - PRECOMPILE_BASE_GAS - storage_allowance;

        provider.set_gas_limit(u64::MAX);
        let result = provider
            .enter(|storage| dispatch(storage, &input, Address::repeat_byte(0xA7), U256::ZERO));
        assert!(
            matches!(result, Err(PrecompileError::Revert(_))),
            "malformed development evidence must revert after its mode-selected precharge: {result:?}"
        );
        let (policy_reads, writes) = provider.metered_storage_operations();
        assert!(policy_reads > 0);
        assert_eq!(writes, 0);
        let storage_gas = policy_reads * 100;
        let exact_dispatch_gas = dispatch_charge + storage_gas;
        assert_eq!(provider.gas_used(), exact_dispatch_gas);

        provider.set_gas_limit(exact_dispatch_gas);
        let result = provider
            .enter(|storage| dispatch(storage, &input, Address::repeat_byte(0xA8), U256::ZERO));
        assert!(
            matches!(result, Err(PrecompileError::Revert(_))),
            "exact GramineDirectDev gas must reach canonical evidence rejection: {result:?}"
        );
        assert_eq!(provider.gas_used(), exact_dispatch_gas);
        assert_eq!(provider.metered_storage_operations(), (policy_reads, 0));
    }

    #[test]
    fn unavailable_verifier_never_mutates_or_fails_open_for_renewal_or_replacement() {
        for kind in [
            RegistryMutatorV1::RenewEnclave,
            RegistryMutatorV1::ReplaceEnclaveBinding,
        ] {
            let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS);
            provider.set_block_number(1);
            provider
                .enter(|storage| TeeRegistry::new(storage).install_initial_policy_v1(&policy()))
                .unwrap();
            provider.enable_production_storage_gas_metering();
            provider.set_gas_limit(u64::MAX);

            let evidence = canonical_dcap_evidence(kind);
            let evidence_len = evidence.len();
            let input = mutator_call(kind, evidence, 65, 64);
            let schedule = TeeRegistryGasScheduleV1::normative();
            let total = schedule
                .maximum_transaction_gas(
                    kind,
                    input.len(),
                    evidence_len,
                    1,
                    AttestationMode::DcapRequired,
                )
                .unwrap();
            let intrinsic = schedule
                .maximum_calldata_intrinsic_gas(input.len())
                .unwrap();
            let allowance = schedule.mutator_storage_gas_allowance(kind);

            let result = provider
                .enter(|storage| dispatch(storage, &input, Address::repeat_byte(0xA1), U256::ZERO));
            assert!(
                matches!(result, Err(PrecompileError::Fatal(_))),
                "unexpected pre-verifier result for {kind:?}: {result:?}"
            );
            let (reads, writes) = provider.metered_storage_operations();
            assert!(reads > 0);
            assert_eq!(writes, 0, "verifier outage must not extend registry state");
            let storage_gas = reads * 100;
            assert_eq!(
                intrinsic + PRECOMPILE_BASE_GAS + provider.gas_used(),
                total - allowance + storage_gas
            );
            assert!(storage_gas <= allowance);
            assert!(intrinsic + PRECOMPILE_BASE_GAS + provider.gas_used() <= total);
        }
    }

    #[test]
    fn cap_plus_one_rejects_before_policy_read_or_gas_charge() {
        let input = call(vec![0; MAX_ATTESTATION_EVIDENCE_BYTES + 1], 65, 64);
        let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS);
        provider.set_gas_limit(u64::MAX);
        let result = provider
            .enter(|storage| dispatch(storage, &input, Address::repeat_byte(0x99), U256::ZERO));
        assert!(matches!(result, Err(PrecompileError::Revert(_))));
        assert_eq!(provider.gas_used(), 0);
    }

    #[test]
    fn empty_binding_views_are_fixed_and_not_ready() {
        let validator = Address::repeat_byte(0x61);
        let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS);
        let ready_call = ITeeRegistryV1::isValidatorEnclaveReadyCall { validator };
        let ready = provider
            .enter(|storage| dispatch(storage, &ready_call.abi_encode(), Address::ZERO, U256::ZERO))
            .unwrap();
        assert!(!bool::abi_decode(&ready).unwrap());

        let binding_call = ITeeRegistryV1::validatorEnclaveBindingCall { validator };
        let encoded = provider
            .enter(|storage| {
                dispatch(
                    storage,
                    &binding_call.abi_encode(),
                    Address::ZERO,
                    U256::ZERO,
                )
            })
            .unwrap();
        let binding = NodeEnclaveBindingV1View::abi_decode(&encoded).unwrap();
        assert!(!binding.exists);
        assert_eq!(binding.nodeIdHash, B256::ZERO);
        assert_eq!(encoded.len(), 24 * 32);

        let p2p_signing = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0x62)).into(),
        )
        .unwrap();
        let encoded_public = p2p_signing.verifying_key().to_encoded_point(true);
        let reth_p2p_prefix = encoded_public.as_bytes()[0];
        let reth_p2p_x = B256::from_slice(&encoded_public.as_bytes()[1..]);
        let ready_call = ITeeRegistryV1::isNodeHostEnclaveReadyCall {
            rethP2pPrefix: reth_p2p_prefix,
            rethP2pX: reth_p2p_x,
        };
        let ready = provider
            .enter(|storage| dispatch(storage, &ready_call.abi_encode(), Address::ZERO, U256::ZERO))
            .unwrap();
        assert!(!bool::abi_decode(&ready).unwrap());

        let binding_call = ITeeRegistryV1::nodeHostEnclaveBindingCall {
            rethP2pPrefix: reth_p2p_prefix,
            rethP2pX: reth_p2p_x,
        };
        let encoded = provider
            .enter(|storage| {
                dispatch(
                    storage,
                    &binding_call.abi_encode(),
                    Address::ZERO,
                    U256::ZERO,
                )
            })
            .unwrap();
        assert!(
            !NodeEnclaveBindingV1View::abi_decode(&encoded)
                .unwrap()
                .exists
        );

        let invalid = ITeeRegistryV1::isNodeHostEnclaveReadyCall {
            rethP2pPrefix: 0x04,
            rethP2pX: reth_p2p_x,
        };
        assert!(provider
            .enter(|storage| dispatch(storage, &invalid.abi_encode(), Address::ZERO, U256::ZERO))
            .is_err());
    }
}
