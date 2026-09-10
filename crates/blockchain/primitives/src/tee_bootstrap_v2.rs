//! Canonical block-1 TEE bootstrap payload.
//!
//! Production `DcapRequired` payloads deduplicate complete Intel collateral.
//! A separate `GramineDirectDev` chain uses the same OST3 envelope with direct
//! development evidence and an empty collateral pool.

use std::{cmp::Ordering, collections::BTreeMap};

use alloy_primitives::{keccak256, Address, Bytes, B256};

use crate::system_tx::{
    BOOTSTRAP_BLOCK_GAS_LIMIT, SYSTEM_TX_NON_ZERO_BYTE_GAS, SYSTEM_TX_VISIBLE_GAS_FLOOR,
};
use crate::tee_attestation_v1::{
    AttestationEvidenceV1, AttestationMode, AttestationOperationV1, CodecError,
    DcapCollateralComponentV1, DcapCollateralKind, DcapEvidenceV1, GramineDirectEvidenceV1,
    RegistrationIntentV1, SystemGasScheduleV1, TeeBootstrapGasInputV1, TeePolicyV1,
    TeeRegistryGasScheduleV1, ValidatorNodeBindingV1, MAX_ATTESTATION_EVIDENCE_BYTES,
    MAX_COLLATERAL_COMPONENT_BYTES, MAX_EVIDENCE_CALL_FRAMING_BYTES, MAX_QUOTE_BYTES,
    MAX_TEE_BOOTSTRAP_BYTES,
};

const MAGIC: &[u8; 4] = b"TTB2";
const SIGNING_DOMAIN: &[u8] = b"outbe/tee/bootstrap/v2";
const SYSTEM_CALLDATA_FRAMING_BYTES: usize = 5;
const MAX_BOOTSTRAP_PARTICIPANTS: usize = 256;
const MAX_COLLATERAL_POOL_COMPONENTS: usize = MAX_BOOTSTRAP_PARTICIPANTS * 8;
const MAX_GROUP_PUBLIC_KEY_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TeeBootstrapParticipantEvidenceV2 {
    Dcap {
        quote: Vec<u8>,
        collateral_component_indices: [u16; 8],
    },
    GramineDirectDev {
        dev_attestation_public: [u8; 32],
        dev_signature: [u8; 64],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeBootstrapParticipantV2 {
    pub intent: RegistrationIntentV1,
    pub validator_binding: ValidatorNodeBindingV1,
    pub validator_signature: [u8; 65],
    pub node_binding_signature: [u8; 65],
    pub evidence: TeeBootstrapParticipantEvidenceV2,
    pub node_signature: [u8; 65],
    pub enclave_signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeBootstrapCommitteeSignatureV2 {
    pub validator: Address,
    pub signature: [u8; 65],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeBootstrapParticipantSubmissionV2 {
    pub evidence: AttestationEvidenceV1,
    pub validator_binding: ValidatorNodeBindingV1,
    pub validator_signature: [u8; 65],
    pub node_binding_signature: [u8; 65],
    pub node_signature: [u8; 65],
    pub enclave_signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeBootstrapAuthorityV2 {
    pub policy: TeePolicyV1,
    pub committee_snapshot_hash: B256,
    pub committee_snapshot_block: u64,
    pub key_epoch: u64,
    pub tribute_offer_epoch: u64,
    pub dkg_transcript_hash: B256,
    pub tribute_offer_public_key: B256,
    pub tribute_offer_group_public_key: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeBootstrapV2 {
    pub policy: TeePolicyV1,
    pub committee_snapshot_hash: B256,
    pub committee_snapshot_block: u64,
    pub key_epoch: u64,
    pub tribute_offer_epoch: u64,
    pub dkg_transcript_hash: B256,
    pub tribute_offer_public_key: B256,
    pub tribute_offer_group_public_key: Bytes,
    pub collateral_pool: Vec<DcapCollateralComponentV1>,
    pub participants: Vec<TeeBootstrapParticipantV2>,
    pub committee_signatures: Vec<TeeBootstrapCommitteeSignatureV2>,
}

impl TeeBootstrapV2 {
    /// Assemble the deterministic unsigned body from complete per-validator
    /// evidence and the existing DKG/offer-key result. Committee signature
    /// records are installed in canonical validator order with zeroed bytes so
    /// every node derives the same signing hash; coordination replaces only
    /// those excluded signature bytes.
    pub fn assemble_unsigned(
        authority: TeeBootstrapAuthorityV2,
        submissions: Vec<TeeBootstrapParticipantSubmissionV2>,
    ) -> Result<Self, CodecError> {
        enforce_limit(
            "TEE bootstrap participants",
            MAX_BOOTSTRAP_PARTICIPANTS,
            submissions.len(),
        )?;
        if submissions.is_empty() {
            return Err(CodecError::NonCanonical(
                "TEE bootstrap participant set is empty",
            ));
        }
        let attestation_mode = authority.policy.attestation_mode;
        let mut ordered = submissions
            .into_iter()
            .map(|submission| {
                if submission.evidence.mode() != attestation_mode {
                    return Err(CodecError::NonCanonical(
                        "TEE bootstrap submission mode does not match policy",
                    ));
                }
                let validator = Address::from(submission.validator_binding.validator);
                Ok((
                    validator,
                    submission.evidence,
                    submission.validator_binding,
                    submission.validator_signature,
                    submission.node_binding_signature,
                    submission.node_signature,
                    submission.enclave_signature,
                ))
            })
            .collect::<Result<Vec<_>, CodecError>>()?;
        ordered.sort_by_key(|(validator, ..)| *validator);

        // Consume component byte vectors into the deduplication map. This moves
        // the already-owned submission buffers instead of cloning an aggregate
        // up to participant_count * evidence_cap before the OST3 cap is known.
        let mut component_indices = BTreeMap::<(u8, Vec<u8>), u16>::new();
        let mut participants = Vec::with_capacity(ordered.len());
        for (
            _,
            evidence,
            validator_binding,
            validator_signature,
            node_binding_signature,
            node_signature,
            enclave_signature,
        ) in ordered
        {
            let (intent, evidence) = match evidence {
                AttestationEvidenceV1::Dcap(DcapEvidenceV1 {
                    intent,
                    quote,
                    components,
                    transition_key_ready_proof: _,
                }) => {
                    let components: [DcapCollateralComponentV1; 8] =
                        components.try_into().map_err(|_| {
                            CodecError::NonCanonical(
                                "TEE bootstrap evidence does not contain exactly eight components",
                            )
                        })?;
                    let mut temporary_indices = [0_u16; 8];
                    for (expected_kind, component) in components.into_iter().enumerate() {
                        if component.kind as u8 != (expected_kind + 1) as u8 {
                            return Err(CodecError::NonCanonical(
                                "TEE bootstrap collateral component kind mismatch",
                            ));
                        }
                        let next_index = u16::try_from(component_indices.len())
                            .map_err(|_| CodecError::ArithmeticOverflow)?;
                        temporary_indices[expected_kind] = *component_indices
                            .entry((component.kind as u8, component.bytes))
                            .or_insert(next_index);
                    }
                    (
                        intent,
                        TeeBootstrapParticipantEvidenceV2::Dcap {
                            quote,
                            collateral_component_indices: temporary_indices,
                        },
                    )
                }
                AttestationEvidenceV1::GramineDirectDev(GramineDirectEvidenceV1 {
                    intent,
                    dev_attestation_public,
                    dev_signature,
                }) => (
                    intent,
                    TeeBootstrapParticipantEvidenceV2::GramineDirectDev {
                        dev_attestation_public,
                        dev_signature,
                    },
                ),
            };
            participants.push(TeeBootstrapParticipantV2 {
                intent,
                validator_binding,
                validator_signature,
                node_binding_signature,
                evidence,
                node_signature,
                enclave_signature,
            });
        }

        let mut canonical_index_by_temporary = vec![0_u16; component_indices.len()];
        let collateral_pool = component_indices
            .into_iter()
            .enumerate()
            .map(|(canonical_index, ((kind, bytes), temporary_index))| {
                canonical_index_by_temporary[usize::from(temporary_index)] =
                    u16::try_from(canonical_index).map_err(|_| CodecError::ArithmeticOverflow)?;
                Ok(DcapCollateralComponentV1 {
                    kind: DcapCollateralKind::try_from(kind)?,
                    bytes,
                })
            })
            .collect::<Result<Vec<_>, CodecError>>()?;
        for participant in &mut participants {
            if let TeeBootstrapParticipantEvidenceV2::Dcap {
                collateral_component_indices,
                ..
            } = &mut participant.evidence
            {
                for index in collateral_component_indices {
                    *index = *canonical_index_by_temporary
                        .get(usize::from(*index))
                        .ok_or(CodecError::ArithmeticOverflow)?;
                }
            }
        }
        let committee_signatures = participants
            .iter()
            .map(|participant| {
                Ok(TeeBootstrapCommitteeSignatureV2 {
                    validator: Address::from(participant.validator_binding.validator),
                    signature: [0; 65],
                })
            })
            .collect::<Result<Vec<_>, CodecError>>()?;
        let payload = Self {
            policy: authority.policy,
            committee_snapshot_hash: authority.committee_snapshot_hash,
            committee_snapshot_block: authority.committee_snapshot_block,
            key_epoch: authority.key_epoch,
            tribute_offer_epoch: authority.tribute_offer_epoch,
            dkg_transcript_hash: authority.dkg_transcript_hash,
            tribute_offer_public_key: authority.tribute_offer_public_key,
            tribute_offer_group_public_key: authority.tribute_offer_group_public_key,
            collateral_pool,
            participants,
            committee_signatures,
        };
        payload.preflight()?;
        Ok(payload)
    }

    /// Reject an assembled payload before committee signing when its canonical
    /// bytes or worst-case visible gas cannot fit the bootstrap block.
    pub fn preflight(&self) -> Result<(), CodecError> {
        self.validate()?;
        let full_calldata_len = self
            .canonical_encoded_len()?
            .checked_add(SYSTEM_CALLDATA_FRAMING_BYTES)
            .ok_or(CodecError::ArithmeticOverflow)?;
        let worst_case_intrinsic = u64::try_from(full_calldata_len)
            .map_err(|_| CodecError::ArithmeticOverflow)?
            .checked_mul(SYSTEM_TX_NON_ZERO_BYTE_GAS)
            .and_then(|gas| gas.checked_add(SYSTEM_TX_VISIBLE_GAS_FLOOR))
            .ok_or(CodecError::ArithmeticOverflow)?;
        let protocol_precharge = self.protocol_precharge(
            &SystemGasScheduleV1::normative(),
            &TeeRegistryGasScheduleV1::normative(),
        )?;
        let required_gas = worst_case_intrinsic
            .checked_add(protocol_precharge)
            .ok_or(CodecError::ArithmeticOverflow)?;
        if required_gas > BOOTSTRAP_BLOCK_GAS_LIMIT {
            return Err(CodecError::LimitExceeded {
                field: "TeeBootstrapV2 worst-case visible gas",
                limit: usize::try_from(BOOTSTRAP_BLOCK_GAS_LIMIT)
                    .map_err(|_| CodecError::ArithmeticOverflow)?,
                actual: usize::try_from(required_gas)
                    .map_err(|_| CodecError::ArithmeticOverflow)?,
            });
        }
        Ok(())
    }

    pub fn encode_canonical(&self) -> Result<Bytes, CodecError> {
        self.validate()?;
        let mut out = self.encode_body()?;
        put_len_u16(&mut out, self.committee_signatures.len())?;
        for signature in &self.committee_signatures {
            out.extend_from_slice(signature.validator.as_slice());
            out.extend_from_slice(&signature.signature);
        }
        enforce_full_calldata_cap(out.len())?;
        Ok(Bytes::from(out))
    }

    pub fn signing_hash(&self) -> Result<B256, CodecError> {
        self.validate()?;
        let body = self.encode_body()?;
        let capacity = SIGNING_DOMAIN
            .len()
            .checked_add(body.len())
            .ok_or(CodecError::ArithmeticOverflow)?;
        let mut preimage = Vec::with_capacity(capacity);
        preimage.extend_from_slice(SIGNING_DOMAIN);
        preimage.extend_from_slice(&body);
        Ok(keccak256(preimage))
    }

    pub fn protocol_precharge(
        &self,
        system_schedule: &SystemGasScheduleV1,
        tee_registry_schedule: &TeeRegistryGasScheduleV1,
    ) -> Result<u64, CodecError> {
        self.validate()?;
        let full_calldata_len = self
            .canonical_encoded_len()?
            .checked_add(SYSTEM_CALLDATA_FRAMING_BYTES)
            .ok_or(CodecError::ArithmeticOverflow)?;
        let mut logical_evidence_lengths = Vec::with_capacity(self.participants.len());
        for participant_index in 0..self.participants.len() {
            logical_evidence_lengths.push(
                self.logical_evidence(participant_index)?
                    .encode_canonical()?
                    .len(),
            );
        }
        let collateral_component_count = match self.policy.attestation_mode {
            AttestationMode::DcapRequired => self
                .participants
                .len()
                .checked_mul(8)
                .ok_or(CodecError::ArithmeticOverflow)?,
            AttestationMode::GramineDirectDev => 0,
        };
        system_schedule.tee_bootstrap_precharge(
            tee_registry_schedule,
            TeeBootstrapGasInputV1 {
                full_calldata_len,
                logical_evidence_lengths: &logical_evidence_lengths,
                active_rule_count: self.policy.measurement_rules.len(),
                collateral_component_count,
                committee_signature_count: self.committee_signatures.len(),
            },
        )
    }

    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        let policy = self.policy.encode_canonical()?;
        let mut out = Vec::with_capacity(self.encoded_body_len()?);
        out.extend_from_slice(MAGIC);
        put_bytes_u32(&mut out, &policy)?;
        out.extend_from_slice(self.committee_snapshot_hash.as_slice());
        put_u64(&mut out, self.committee_snapshot_block);
        put_u64(&mut out, self.key_epoch);
        put_u64(&mut out, self.tribute_offer_epoch);
        out.extend_from_slice(self.dkg_transcript_hash.as_slice());
        out.extend_from_slice(self.tribute_offer_public_key.as_slice());
        put_bytes_u32(&mut out, self.tribute_offer_group_public_key.as_ref())?;

        put_len_u16(&mut out, self.collateral_pool.len())?;
        for component in &self.collateral_pool {
            out.push(component.kind as u8);
            put_bytes_u32(&mut out, &component.bytes)?;
        }

        put_len_u16(&mut out, self.participants.len())?;
        for participant in &self.participants {
            put_bytes_u32(&mut out, &participant.intent.encode_canonical()?)?;
            out.extend_from_slice(&participant.validator_binding.encode_canonical()?);
            out.extend_from_slice(&participant.validator_signature);
            out.extend_from_slice(&participant.node_binding_signature);
            out.push(participant.intent.attestation_mode as u8);
            match &participant.evidence {
                TeeBootstrapParticipantEvidenceV2::Dcap {
                    quote,
                    collateral_component_indices,
                } => {
                    put_bytes_u32(&mut out, quote)?;
                    for index in collateral_component_indices {
                        put_u16(&mut out, *index);
                    }
                }
                TeeBootstrapParticipantEvidenceV2::GramineDirectDev {
                    dev_attestation_public,
                    dev_signature,
                } => {
                    out.extend_from_slice(dev_attestation_public);
                    out.extend_from_slice(dev_signature);
                }
            }
            out.extend_from_slice(&participant.node_signature);
            out.extend_from_slice(&participant.enclave_signature);
        }
        Ok(out)
    }

    fn encoded_body_len(&self) -> Result<usize, CodecError> {
        let policy_len = self.policy.encode_canonical()?.len();
        let mut len = 4usize;
        checked_add_len(&mut len, 4)?;
        checked_add_len(&mut len, policy_len)?;
        // committee hash + three epochs/heights + transcript hash + offer key
        checked_add_len(&mut len, 32 + 8 * 3 + 32 + 32)?;
        checked_add_len(&mut len, 4)?;
        checked_add_len(&mut len, self.tribute_offer_group_public_key.len())?;
        checked_add_len(&mut len, 2)?;
        for component in &self.collateral_pool {
            checked_add_len(&mut len, 1 + 4)?;
            checked_add_len(&mut len, component.bytes.len())?;
        }
        checked_add_len(&mut len, 2)?;
        for participant in &self.participants {
            let intent_len = participant.intent.encode_canonical()?.len();
            checked_add_len(&mut len, 4)?;
            checked_add_len(&mut len, intent_len)?;
            checked_add_len(&mut len, ValidatorNodeBindingV1::CANONICAL_LEN + 65 + 65)?;
            checked_add_len(&mut len, 1)?;
            match &participant.evidence {
                TeeBootstrapParticipantEvidenceV2::Dcap { quote, .. } => {
                    checked_add_len(&mut len, 4)?;
                    checked_add_len(&mut len, quote.len())?;
                    checked_add_len(&mut len, 8 * 2)?;
                }
                TeeBootstrapParticipantEvidenceV2::GramineDirectDev { .. } => {
                    checked_add_len(&mut len, 32 + 64)?;
                }
            }
            checked_add_len(&mut len, 65 + 64)?;
        }
        Ok(len)
    }

    fn canonical_encoded_len(&self) -> Result<usize, CodecError> {
        let signature_bytes = self
            .committee_signatures
            .len()
            .checked_mul(20 + 65)
            .ok_or(CodecError::ArithmeticOverflow)?;
        self.encoded_body_len()?
            .checked_add(2)
            .and_then(|len| len.checked_add(signature_bytes))
            .ok_or(CodecError::ArithmeticOverflow)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        enforce_full_calldata_cap(input.len())?;
        let mut decoder = Decoder::new(input);
        if decoder.take(4)? != MAGIC {
            return Err(CodecError::NonCanonical("invalid TeeBootstrapV2 magic"));
        }
        let policy = TeePolicyV1::decode_canonical(
            decoder.bounded_bytes("TEE policy", MAX_EVIDENCE_CALL_FRAMING_BYTES)?,
        )?;
        let committee_snapshot_hash = B256::from(decoder.array::<32>()?);
        let committee_snapshot_block = decoder.u64()?;
        let key_epoch = decoder.u64()?;
        let tribute_offer_epoch = decoder.u64()?;
        let dkg_transcript_hash = B256::from(decoder.array::<32>()?);
        let tribute_offer_public_key = B256::from(decoder.array::<32>()?);
        let tribute_offer_group_public_key = Bytes::copy_from_slice(
            decoder.bounded_bytes("TEE bootstrap group public key", MAX_GROUP_PUBLIC_KEY_BYTES)?,
        );

        let collateral_count = decoder.bounded_count_u16(
            "TEE bootstrap collateral pool",
            MAX_COLLATERAL_POOL_COMPONENTS,
        )?;
        let mut collateral_pool = Vec::with_capacity(collateral_count);
        for _ in 0..collateral_count {
            let kind = DcapCollateralKind::try_from(decoder.u8()?)?;
            let bytes = decoder
                .bounded_bytes("DCAP collateral component", MAX_COLLATERAL_COMPONENT_BYTES)?
                .to_vec();
            collateral_pool.push(DcapCollateralComponentV1 { kind, bytes });
        }

        let participant_count =
            decoder.bounded_count_u16("TEE bootstrap participants", MAX_BOOTSTRAP_PARTICIPANTS)?;
        let mut participants = Vec::with_capacity(participant_count);
        for _ in 0..participant_count {
            let intent = RegistrationIntentV1::decode_canonical(
                decoder.bounded_bytes("registration intent", MAX_EVIDENCE_CALL_FRAMING_BYTES)?,
            )?;
            let validator_binding = ValidatorNodeBindingV1::decode_canonical(
                decoder.take(ValidatorNodeBindingV1::CANONICAL_LEN)?,
            )?;
            let validator_signature = decoder.array()?;
            let node_binding_signature = decoder.array()?;
            let mode = AttestationMode::decode(decoder.u8()?)?;
            let evidence = match mode {
                AttestationMode::DcapRequired => {
                    let quote = decoder
                        .bounded_bytes("SGX quote", MAX_QUOTE_BYTES)?
                        .to_vec();
                    let mut collateral_component_indices = [0_u16; 8];
                    for index in &mut collateral_component_indices {
                        *index = decoder.u16()?;
                    }
                    TeeBootstrapParticipantEvidenceV2::Dcap {
                        quote,
                        collateral_component_indices,
                    }
                }
                AttestationMode::GramineDirectDev => {
                    TeeBootstrapParticipantEvidenceV2::GramineDirectDev {
                        dev_attestation_public: decoder.array()?,
                        dev_signature: decoder.array()?,
                    }
                }
            };
            participants.push(TeeBootstrapParticipantV2 {
                intent,
                validator_binding,
                validator_signature,
                node_binding_signature,
                evidence,
                node_signature: decoder.array()?,
                enclave_signature: decoder.array()?,
            });
        }

        let signature_count = decoder.bounded_count_u16(
            "TEE bootstrap committee signatures",
            MAX_BOOTSTRAP_PARTICIPANTS,
        )?;
        let mut committee_signatures = Vec::with_capacity(signature_count);
        for _ in 0..signature_count {
            committee_signatures.push(TeeBootstrapCommitteeSignatureV2 {
                validator: Address::from(decoder.array::<20>()?),
                signature: decoder.array()?,
            });
        }
        decoder.finish()?;

        let value = Self {
            policy,
            committee_snapshot_hash,
            committee_snapshot_block,
            key_epoch,
            tribute_offer_epoch,
            dkg_transcript_hash,
            tribute_offer_public_key,
            tribute_offer_group_public_key,
            collateral_pool,
            participants,
            committee_signatures,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn logical_evidence(
        &self,
        participant_index: usize,
    ) -> Result<AttestationEvidenceV1, CodecError> {
        let participant =
            self.participants
                .get(participant_index)
                .ok_or(CodecError::NonCanonical(
                    "TEE bootstrap participant index is out of range",
                ))?;
        let evidence = match &participant.evidence {
            TeeBootstrapParticipantEvidenceV2::Dcap {
                quote,
                collateral_component_indices,
            } => {
                let mut components = Vec::with_capacity(8);
                for (expected_kind, index) in collateral_component_indices.iter().enumerate() {
                    let component = self.collateral_pool.get(usize::from(*index)).ok_or(
                        CodecError::NonCanonical(
                            "TEE bootstrap collateral reference is out of range",
                        ),
                    )?;
                    if component.kind as u8 != (expected_kind + 1) as u8 {
                        return Err(CodecError::NonCanonical(
                            "TEE bootstrap collateral reference kind mismatch",
                        ));
                    }
                    components.push(component.clone());
                }
                AttestationEvidenceV1::Dcap(DcapEvidenceV1 {
                    intent: participant.intent.clone(),
                    quote: quote.clone(),
                    components,
                    transition_key_ready_proof: None,
                })
            }
            TeeBootstrapParticipantEvidenceV2::GramineDirectDev {
                dev_attestation_public,
                dev_signature,
            } => AttestationEvidenceV1::GramineDirectDev(GramineDirectEvidenceV1 {
                intent: participant.intent.clone(),
                dev_attestation_public: *dev_attestation_public,
                dev_signature: *dev_signature,
            }),
        };
        evidence.encode_canonical()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), CodecError> {
        let policy_hash = self.policy.policy_hash()?;
        if self.committee_snapshot_hash.is_zero()
            || self.committee_snapshot_block == 0
            || self.tribute_offer_public_key.is_zero()
            || self.tribute_offer_group_public_key.is_empty()
        {
            return Err(CodecError::NonCanonical(
                "TEE bootstrap contains a zero required authority",
            ));
        }
        enforce_limit(
            "TEE bootstrap group public key",
            MAX_GROUP_PUBLIC_KEY_BYTES,
            self.tribute_offer_group_public_key.len(),
        )?;
        enforce_limit(
            "TEE bootstrap collateral pool",
            MAX_COLLATERAL_POOL_COMPONENTS,
            self.collateral_pool.len(),
        )?;
        enforce_limit(
            "TEE bootstrap participants",
            MAX_BOOTSTRAP_PARTICIPANTS,
            self.participants.len(),
        )?;
        if self.participants.is_empty() {
            return Err(CodecError::NonCanonical(
                "TEE bootstrap participant set is empty",
            ));
        }
        if self.committee_signatures.len() != self.participants.len() {
            return Err(CodecError::NonCanonical(
                "TEE bootstrap signatures do not cover every participant",
            ));
        }
        match self.policy.attestation_mode {
            AttestationMode::DcapRequired if self.collateral_pool.is_empty() => {
                return Err(CodecError::NonCanonical(
                    "DCAP TEE bootstrap collateral pool is empty",
                ));
            }
            AttestationMode::GramineDirectDev if !self.collateral_pool.is_empty() => {
                return Err(CodecError::NonCanonical(
                    "GramineDirectDev TEE bootstrap must not carry DCAP collateral",
                ));
            }
            _ => {}
        }

        for component in &self.collateral_pool {
            if component.bytes.is_empty() {
                return Err(CodecError::NonCanonical(
                    "TEE bootstrap collateral component is empty",
                ));
            }
            enforce_limit(
                "DCAP collateral component",
                MAX_COLLATERAL_COMPONENT_BYTES,
                component.bytes.len(),
            )?;
        }
        for pair in self.collateral_pool.windows(2) {
            if compare_components(&pair[0], &pair[1]) != Ordering::Less {
                return Err(CodecError::NonCanonical(
                    "TEE bootstrap collateral pool is not strictly sorted and unique",
                ));
            }
        }
        // Reject aggregate calldata before allocating the used-component bitmap
        // or reconstructing and encoding every participant's logical evidence.
        enforce_full_calldata_cap(self.canonical_encoded_len()?)?;

        let mut used_components = vec![false; self.collateral_pool.len()];
        let mut previous_validator = None;
        for (participant_index, participant) in self.participants.iter().enumerate() {
            if participant.intent.operation != AttestationOperationV1::RegisterEnclave
                || participant.intent.attestation_mode != self.policy.attestation_mode
                || participant.intent.policy_hash != policy_hash
            {
                return Err(CodecError::NonCanonical(
                    "TEE bootstrap participant intent is not a policy-bound NodeHost registration",
                ));
            }
            let validator = Address::from(participant.validator_binding.validator);
            if participant.validator_binding.chain_id != participant.intent.chain_id
                || participant.validator_binding.genesis_hash != participant.intent.genesis_hash
                || participant.validator_binding.node_id_hash
                    != participant.intent.node_id.node_id_hash()?
                || !participant
                    .validator_binding
                    .verify_validator_signature(&participant.validator_signature)
                || !participant
                    .validator_binding
                    .verify_node_signature(&participant.node_binding_signature)
            {
                return Err(CodecError::NonCanonical(
                    "TEE bootstrap validator NodeHost binding is invalid",
                ));
            }
            if previous_validator.is_some_and(|previous| previous >= validator) {
                return Err(CodecError::NonCanonical(
                    "TEE bootstrap participants are not strictly sorted and unique",
                ));
            }
            previous_validator = Some(validator);
            if self.committee_signatures[participant_index].validator != validator {
                return Err(CodecError::NonCanonical(
                    "TEE bootstrap committee signatures do not match participants",
                ));
            }
            match &participant.evidence {
                TeeBootstrapParticipantEvidenceV2::Dcap {
                    quote,
                    collateral_component_indices,
                } if self.policy.attestation_mode == AttestationMode::DcapRequired => {
                    if quote.is_empty() {
                        return Err(CodecError::NonCanonical("TEE bootstrap quote is empty"));
                    }
                    enforce_limit("SGX quote", MAX_QUOTE_BYTES, quote.len())?;
                    for (expected_kind, index) in collateral_component_indices.iter().enumerate() {
                        let index = usize::from(*index);
                        let component =
                            self.collateral_pool
                                .get(index)
                                .ok_or(CodecError::NonCanonical(
                                    "TEE bootstrap collateral reference is out of range",
                                ))?;
                        if component.kind as u8 != (expected_kind + 1) as u8 {
                            return Err(CodecError::NonCanonical(
                                "TEE bootstrap collateral reference kind mismatch",
                            ));
                        }
                        used_components[index] = true;
                    }
                }
                TeeBootstrapParticipantEvidenceV2::GramineDirectDev {
                    dev_attestation_public,
                    dev_signature,
                } if self.policy.attestation_mode == AttestationMode::GramineDirectDev => {
                    if dev_attestation_public != &participant.intent.attestation_ed25519
                        || dev_signature != &participant.enclave_signature
                        || !participant.intent.verify_enclave_signature(dev_signature)
                    {
                        return Err(CodecError::NonCanonical(
                            "GramineDirectDev evidence does not prove the intent attestation key",
                        ));
                    }
                }
                _ => {
                    return Err(CodecError::NonCanonical(
                        "TEE bootstrap participant evidence mode does not match policy",
                    ));
                }
            }
            let evidence = self.logical_evidence(participant_index)?;
            enforce_limit(
                "attestation evidence",
                MAX_ATTESTATION_EVIDENCE_BYTES,
                evidence.encode_canonical()?.len(),
            )?;
        }
        if used_components.iter().any(|used| !used) {
            return Err(CodecError::NonCanonical(
                "TEE bootstrap collateral pool contains an unused component",
            ));
        }
        Ok(())
    }
}

fn checked_add_len(total: &mut usize, value: usize) -> Result<(), CodecError> {
    *total = total
        .checked_add(value)
        .ok_or(CodecError::ArithmeticOverflow)?;
    Ok(())
}

fn compare_components(
    left: &DcapCollateralComponentV1,
    right: &DcapCollateralComponentV1,
) -> Ordering {
    (left.kind as u8)
        .cmp(&(right.kind as u8))
        .then_with(|| left.bytes.cmp(&right.bytes))
}

fn enforce_full_calldata_cap(body_len: usize) -> Result<(), CodecError> {
    let full_len = body_len
        .checked_add(SYSTEM_CALLDATA_FRAMING_BYTES)
        .ok_or(CodecError::ArithmeticOverflow)?;
    enforce_limit(
        "TeeBootstrapV2 full calldata",
        MAX_TEE_BOOTSTRAP_BYTES,
        full_len,
    )
}

fn enforce_limit(field: &'static str, limit: usize, actual: usize) -> Result<(), CodecError> {
    if actual > limit {
        return Err(CodecError::LimitExceeded {
            field,
            limit,
            actual,
        });
    }
    Ok(())
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_len_u16(out: &mut Vec<u8>, value: usize) -> Result<(), CodecError> {
    put_u16(
        out,
        u16::try_from(value).map_err(|_| CodecError::ArithmeticOverflow)?,
    );
    Ok(())
}

fn put_bytes_u32(out: &mut Vec<u8>, value: &[u8]) -> Result<(), CodecError> {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| CodecError::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}

struct Decoder<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(CodecError::ArithmeticOverflow)?;
        let value = self
            .input
            .get(self.cursor..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.cursor = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn bounded_count_u16(
        &mut self,
        field: &'static str,
        limit: usize,
    ) -> Result<usize, CodecError> {
        let actual = usize::from(self.u16()?);
        enforce_limit(field, limit, actual)?;
        Ok(actual)
    }

    fn bounded_bytes(&mut self, field: &'static str, limit: usize) -> Result<&'a [u8], CodecError> {
        let actual = usize::try_from(self.u32()?).map_err(|_| CodecError::ArithmeticOverflow)?;
        enforce_limit(field, limit, actual)?;
        self.take(actual)
    }

    fn finish(self) -> Result<(), CodecError> {
        if self.cursor != self.input.len() {
            return Err(CodecError::TrailingBytes(self.input.len() - self.cursor));
        }
        Ok(())
    }
}
