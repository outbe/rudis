use alloy_primitives::{B256, U256};

use crate::{
    common::{BoundedBytes, ProofBytes},
    error::ProtocolError,
    hash::hash_framed,
    registry::HashDomain,
    schema::{impl_top_level_codec, require, wire_enum_u8, wire_struct, SchemaLimits},
};

wire_enum_u8! {
    pub enum AuctionEntryPriceSource {
        LastClosedDayVwap = 1,
        CurrentVwapFallback = 2,
    }
}

wire_enum_u8! {
    pub enum DayType {
        Green = 1,
        Red = 2,
    }
}

wire_enum_u8! {
    pub enum MetadosisExpectedStatus {
        OffchainPending = 1,
    }
}

wire_enum_u8! {
    pub enum ParentProofKind {
        Finalization = 1,
    }
}

wire_struct! {
    /// One reference currency's frozen auction entry price, with where it came from,
    /// so a fallback stays visible in the receipt.
    pub struct ReferenceEntryPriceV1 {
        pub reference_currency: u16,
        pub entry_price_minor: U256,
        pub source: AuctionEntryPriceSource,
        pub source_day: u32,
    }
}

fn validate_pre_admission_envelope(
    envelope: &PreAdmissionEnvelopeV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    envelope.validate_price_table()
}

wire_struct! {
    pub struct PreAdmissionEnvelopeV1 {
        pub chain_id: u64,
        pub genesis_hash: B256,
        pub fork_id: B256,
        pub wwd: u32,
        pub sealed_tribute_collection_root: B256,
        pub sealed_tribute_count: u32,
        pub sealed_tribute_canonical_body_bytes: u64,
        pub distinct_owner_count: u32,
        pub distinct_reference_currency_count: u16,
        pub fidelity_league_snapshot_root: B256,
        pub oracle_wwd_pair_entries_observed: u32,
        pub active_scurve_entries_observed: u32,
        pub auction_entry_prices: Vec<ReferenceEntryPriceV1>,
        pub oracle_state_version: u64,
        pub fidelity_opening_upper_bound: u32,
        pub oracle_opening_upper_bound: u32,
        pub input_encoded_bytes_upper_bound: u64,
        pub output_record_upper_bound: u32,
        pub result_chunk_bytes_upper_bound: u64,
        pub activation_bytes_upper_bound: u64,
        pub retained_bytes_upper_bound: u64,
        pub correctness_profile_id: B256,
        pub capacity_profile_id: B256,
    }
    validate = validate_pre_admission_envelope;
}
impl_top_level_codec!(PreAdmissionEnvelopeV1, PreAdmissionEnvelopeV1);

wire_struct! {
    pub struct FrozenMetadosisValuesV1 {
        pub day_type: DayType,
        pub day_limit: U256,
        pub previous_vwap: U256,
        pub current_vwap: U256,
        pub gratis_demand: U256,
        pub gratis_supply: U256,
        pub lysis_budget: U256,
        pub auction_base: U256,
        pub auction_entry_prices: Vec<ReferenceEntryPriceV1>,
        pub request_budget_split_receipt_hash: B256,
    }
}

wire_struct! {
    pub struct TributeInputBindingV1 {
        pub wwd: u32,
        pub source_generation: u64,
        pub collection_key: B256,
        pub sealed_collection_root: B256,
        pub exact_count: u32,
        pub exact_nominal_total: U256,
    }
}

wire_struct! {
    pub struct NodTargetPreconditionV1 {
        pub wwd: u32,
        pub target_generation: u64,
        pub namespace_root_before: B256,
        pub max_nod_count: u32,
    }
}

wire_struct! {
    pub struct ContributorTargetPreconditionV1 {
        pub worldwide_day: u32,
        pub expected_series_version: u64,
        pub max_contributor_count: u32,
        pub max_eligible_nominal_total: U256,
    }
}

wire_struct! {
    pub struct MetadosisAttemptPreconditionV1 {
        pub wwd: u32,
        pub pending_nonce: u64,
        pub expected_status: MetadosisExpectedStatus,
        pub state_version: u64,
    }
}

wire_struct! {
    pub struct ActivationPreconditionsV1 {
        pub tribute: TributeInputBindingV1,
        pub nod: NodTargetPreconditionV1,
        pub contributors: ContributorTargetPreconditionV1,
        pub metadosis: MetadosisAttemptPreconditionV1,
    }
}
impl_top_level_codec!(ActivationPreconditionsV1, ActivationPreconditionsV1);

wire_struct! {
    pub struct JobIntentV1 {
        pub chain_id: u64,
        pub genesis_hash: B256,
        pub fork_id: B256,
        pub wwd: u32,
        pub pending_nonce: u64,
        pub attempt: u32,
        pub protocol_bundle_hash: B256,
        pub ce_sealed_root: B256,
        pub sealed_tribute_collection_key: B256,
        pub sealed_tribute_collection_root: B256,
        pub authenticated_day_count: u32,
        pub authenticated_day_nominal: U256,
        pub pre_admission_envelope_hash: B256,
        pub source_availability_policy_id: B256,
        pub frozen_metadosis_values: FrozenMetadosisValuesV1,
        pub logical_evaluation_height: u64,
        pub logical_evaluation_time: u64,
        pub activation_preconditions: ActivationPreconditionsV1,
        pub result_validator_set_epoch: u64,
        pub result_committee_set_hash: B256,
        pub result_ocomp_binding_hash: B256,
        pub result_member_count: u16,
        pub result_quorum_threshold: u16,
        pub custody_committee_epoch_hash: Option<B256>,
    }
    validate = validate_job_intent;
}
impl_top_level_codec!(JobIntentV1, JobIntentV1);

wire_struct! {
    pub struct CertifiedParentAccountingMetadataV2 {
        pub finalized_block_number: u64,
        pub finalized_block_hash: B256,
        pub finalized_epoch: u64,
        pub finalized_view: u64,
        pub parent_view: u64,
        pub ordered_committee: Vec<BoundedBytes>,
        pub signer_bitmap: BoundedBytes,
        pub canonical_commonware_finalization_proof: ProofBytes,
        pub committee_set_hash: B256,
        pub vrf_material_version: u16,
        pub vrf_group_public_key_hash: B256,
        pub proof_kind: ParentProofKind,
        pub missed_proposers: Vec<B256>,
    }
}

wire_struct! {
    pub struct FinalizedIntentProofV1 {
        pub chain_id: u64,
        pub genesis_hash: B256,
        pub fork_id: B256,
        pub protocol_bundle_hash: B256,
        pub canonical_request_header_rlp: ProofBytes,
        pub parent_accounting: CertifiedParentAccountingMetadataV2,
        pub historical_committee_membership_proof: ProofBytes,
        pub canonical_job_intent: BoundedBytes,
        pub intent_account_proof: ProofBytes,
        pub intent_storage_proof: ProofBytes,
    }
}
impl_top_level_codec!(FinalizedIntentProofV1, FinalizedIntentProofV1);

impl PreAdmissionEnvelopeV1 {
    pub fn envelope_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        hash_framed(HashDomain::PreAdmission, &self.encode_canonical(limits)?)
    }

    /// Strictly ascending by currency: the rows are hashed in order, so
    /// two orderings of the same prices would otherwise be two different days.
    pub fn validate_price_table(&self) -> Result<(), ProtocolError> {
        for pair in self.auction_entry_prices.windows(2) {
            require(
                pair[0].reference_currency < pair[1].reference_currency,
                "entry prices strictly ordered by currency",
            )?;
        }
        Ok(())
    }
}

impl ActivationPreconditionsV1 {
    pub fn activation_preconditions_hash(
        &self,
        limits: &SchemaLimits,
    ) -> Result<B256, ProtocolError> {
        hash_framed(
            HashDomain::ActivationPreconditions,
            &self.encode_canonical(limits)?,
        )
    }

    pub fn validate_for_intent(&self, intent: &JobIntentV1) -> Result<(), ProtocolError> {
        require(
            self.tribute.wwd == intent.wwd
                && self.nod.wwd == intent.wwd
                && self.metadosis.wwd == intent.wwd
                && self.contributors.worldwide_day == intent.wwd,
            "activation precondition day binding",
        )?;
        require(
            self.metadosis.pending_nonce == intent.pending_nonce,
            "activation precondition nonce binding",
        )?;
        require(
            self.tribute.exact_count == intent.authenticated_day_count
                && self.tribute.exact_nominal_total == intent.authenticated_day_nominal
                && self.tribute.collection_key == intent.sealed_tribute_collection_key
                && self.tribute.sealed_collection_root == intent.sealed_tribute_collection_root
                && self.nod.max_nod_count == self.tribute.exact_count
                && self.contributors.max_contributor_count == self.tribute.exact_count
                && self.contributors.max_eligible_nominal_total == self.tribute.exact_nominal_total,
            "activation precondition source bounds",
        )
    }
}

impl JobIntentV1 {
    pub fn intent_id(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_semantics()?;
        hash_framed(HashDomain::Intent, &self.encode_canonical(limits)?)
    }

    /// Stable authenticated-source identity shared only by attempts that read
    /// byte-identical chain/opening commitments.
    pub fn input_lease_id(&self) -> Result<B256, ProtocolError> {
        self.validate_semantics()?;
        let mut preimage = Vec::with_capacity(8 + 32 * 8 + 4 + 8 * 3);
        preimage.extend_from_slice(&self.chain_id.to_be_bytes());
        preimage.extend_from_slice(self.genesis_hash.as_slice());
        preimage.extend_from_slice(self.fork_id.as_slice());
        preimage.extend_from_slice(&self.wwd.to_be_bytes());
        preimage.extend_from_slice(self.protocol_bundle_hash.as_slice());
        preimage.extend_from_slice(self.ce_sealed_root.as_slice());
        preimage.extend_from_slice(self.sealed_tribute_collection_key.as_slice());
        preimage.extend_from_slice(self.sealed_tribute_collection_root.as_slice());
        preimage.extend_from_slice(&self.authenticated_day_count.to_be_bytes());
        preimage.extend_from_slice(&self.authenticated_day_nominal.to_be_bytes::<32>());
        preimage.extend_from_slice(self.source_availability_policy_id.as_slice());
        preimage.extend_from_slice(
            &self
                .activation_preconditions
                .tribute
                .source_generation
                .to_be_bytes(),
        );
        preimage.extend_from_slice(&self.logical_evaluation_height.to_be_bytes());
        preimage.extend_from_slice(&self.logical_evaluation_time.to_be_bytes());
        hash_framed(HashDomain::InputLease, &preimage)
    }

    pub fn validate_semantics(&self) -> Result<(), ProtocolError> {
        require(
            self.attempt == 0 && self.pending_nonce == 0,
            "single-attempt OCOMP identity",
        )?;
        let split_total = self
            .frozen_metadosis_values
            .lysis_budget
            .checked_add(self.frozen_metadosis_values.auction_base)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "Metadosis budget split",
            })?;
        // A day issues at most its own nominal; the unissued headroom is credited back to the
        // warehouse, and the exact identity is enforced on the split receipt.
        require(
            split_total <= self.frozen_metadosis_values.day_limit,
            "Metadosis budget split",
        )?;
        self.activation_preconditions.validate_for_intent(self)
    }

    pub fn job_id(
        &self,
        finalized_request_block_hash: B256,
        finalized_request_state_root: B256,
        limits: &SchemaLimits,
    ) -> Result<B256, ProtocolError> {
        job_id_from_intent_id(
            self.intent_id(limits)?,
            finalized_request_block_hash,
            finalized_request_state_root,
        )
    }
}

/// Derives a finalized JobId from an already-authenticated IntentId and exact
/// request block identity.
pub fn job_id_from_intent_id(
    intent_id: B256,
    finalized_request_block_hash: B256,
    finalized_request_state_root: B256,
) -> Result<B256, ProtocolError> {
    let mut payload = Vec::with_capacity(96);
    payload.extend_from_slice(intent_id.as_slice());
    payload.extend_from_slice(finalized_request_block_hash.as_slice());
    payload.extend_from_slice(finalized_request_state_root.as_slice());
    hash_framed(HashDomain::Job, &payload)
}

/// Fixed logical storage key for one canonical intent record.
///
/// The EVM owner may place this key inside its own fixed mapping layout, but
/// proofs and callers must never substitute the raw [`JobIntentV1::intent_id`]
/// as the logical key.
pub fn intent_storage_key(intent_id: B256) -> Result<B256, ProtocolError> {
    hash_framed(HashDomain::IntentSlot, intent_id.as_slice())
}

fn validate_job_intent(intent: &JobIntentV1, _limits: &SchemaLimits) -> Result<(), ProtocolError> {
    intent.validate_semantics()
}

/// Fork/profile authority expected by a finalized-intent verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedFinalizedIntentBindingV1 {
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub fork_id: B256,
    pub protocol_bundle_hash: B256,
}

/// Header identity returned only after the authority adapter has verified the
/// canonical request header and its consensus finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedRequestBindingV1 {
    pub block_number: u64,
    pub block_hash: B256,
    pub state_root: B256,
}

/// Result of verifying one complete finalized-intent proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFinalizedIntentV1 {
    pub intent: JobIntentV1,
    pub intent_id: B256,
    pub intent_storage_key: B256,
    pub job_id: B256,
    pub request: FinalizedRequestBindingV1,
}

/// Stable failure classes returned by the external authority adapter.
///
/// Concrete consensus/trie errors stay behind the adapter seam so the protocol
/// crate does not duplicate Commonware or Ethereum proof implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalizedIntentAuthorityError {
    CanonicalHeader,
    HistoricalCommittee,
    ConsensusFinality,
    IntentAccountProof,
    IntentStorageProof,
}

/// Authenticated operations the protocol codec cannot perform by itself.
///
/// Implementations must derive the request state root from the canonical
/// header, resolve committee material from authenticated history, verify the
/// finalization certificate, and verify the fixed intent storage path.
pub trait FinalizedIntentProofAuthority {
    fn verify_finalized_request(
        &self,
        proof: &FinalizedIntentProofV1,
        limits: &SchemaLimits,
    ) -> Result<FinalizedRequestBindingV1, FinalizedIntentAuthorityError>;

    fn verify_intent_inclusion(
        &self,
        proof: &FinalizedIntentProofV1,
        intent: &JobIntentV1,
        intent_id: B256,
        intent_storage_key: B256,
        request_state_root: B256,
        limits: &SchemaLimits,
    ) -> Result<(), FinalizedIntentAuthorityError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FinalizedIntentVerificationError {
    Protocol(ProtocolError),
    WrongChain,
    WrongGenesis,
    WrongFork,
    WrongProtocolBundle,
    WrongProofKind,
    NonEmptyMissedProposers,
    FinalizedHeaderMetadataMismatch,
    Authority(FinalizedIntentAuthorityError),
}

impl From<ProtocolError> for FinalizedIntentVerificationError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<FinalizedIntentAuthorityError> for FinalizedIntentVerificationError {
    fn from(error: FinalizedIntentAuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl core::fmt::Display for FinalizedIntentVerificationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::WrongChain => formatter.write_str("wrong finalized-intent chain"),
            Self::WrongGenesis => formatter.write_str("wrong finalized-intent genesis"),
            Self::WrongFork => formatter.write_str("wrong finalized-intent fork"),
            Self::WrongProtocolBundle => {
                formatter.write_str("wrong finalized-intent protocol bundle")
            }
            Self::WrongProofKind => {
                formatter.write_str("finalized intent requires a finalization proof")
            }
            Self::NonEmptyMissedProposers => {
                formatter.write_str("finalized intent proof has missed proposers")
            }
            Self::FinalizedHeaderMetadataMismatch => {
                formatter.write_str("finalized header does not match parent metadata")
            }
            Self::Authority(error) => write!(formatter, "finalized intent authority: {error:?}"),
        }
    }
}

impl std::error::Error for FinalizedIntentVerificationError {}

impl FinalizedIntentProofV1 {
    pub fn decoded_intent(&self, limits: &SchemaLimits) -> Result<JobIntentV1, ProtocolError> {
        let intent = JobIntentV1::decode_canonical(&self.canonical_job_intent.0, limits)?;
        require(
            intent.chain_id == self.chain_id,
            "finality proof chain binding",
        )?;
        require(
            intent.genesis_hash == self.genesis_hash,
            "finality proof genesis binding",
        )?;
        require(
            intent.fork_id == self.fork_id,
            "finality proof fork binding",
        )?;
        require(
            intent.protocol_bundle_hash == self.protocol_bundle_hash,
            "finality proof bundle binding",
        )?;
        Ok(intent)
    }

    /// Verifies the complete authority chain and derives the one signable
    /// [`JobIntentV1::job_id`].
    ///
    /// Caller-supplied events, committee bytes and storage keys are never
    /// authority: the adapter must authenticate them against finalized chain
    /// state, while this method closes all protocol-level bindings.
    pub fn verify(
        &self,
        expected: ExpectedFinalizedIntentBindingV1,
        authority: &impl FinalizedIntentProofAuthority,
        limits: &SchemaLimits,
    ) -> Result<VerifiedFinalizedIntentV1, FinalizedIntentVerificationError> {
        if self.chain_id != expected.chain_id {
            return Err(FinalizedIntentVerificationError::WrongChain);
        }
        if self.genesis_hash != expected.genesis_hash {
            return Err(FinalizedIntentVerificationError::WrongGenesis);
        }
        if self.fork_id != expected.fork_id {
            return Err(FinalizedIntentVerificationError::WrongFork);
        }
        if self.protocol_bundle_hash != expected.protocol_bundle_hash {
            return Err(FinalizedIntentVerificationError::WrongProtocolBundle);
        }
        if self.parent_accounting.proof_kind != ParentProofKind::Finalization {
            return Err(FinalizedIntentVerificationError::WrongProofKind);
        }
        if !self.parent_accounting.missed_proposers.is_empty() {
            return Err(FinalizedIntentVerificationError::NonEmptyMissedProposers);
        }

        let intent = self.decoded_intent(limits)?;
        let intent_id = intent.intent_id(limits)?;
        let intent_storage_key = intent_storage_key(intent_id)?;
        let request = authority.verify_finalized_request(self, limits)?;
        if request.block_number != self.parent_accounting.finalized_block_number
            || request.block_hash != self.parent_accounting.finalized_block_hash
        {
            return Err(FinalizedIntentVerificationError::FinalizedHeaderMetadataMismatch);
        }
        authority.verify_intent_inclusion(
            self,
            &intent,
            intent_id,
            intent_storage_key,
            request.state_root,
            limits,
        )?;
        let job_id = intent.job_id(request.block_hash, request.state_root, limits)?;

        Ok(VerifiedFinalizedIntentV1 {
            intent,
            intent_id,
            intent_storage_key,
            job_id,
            request,
        })
    }
}
