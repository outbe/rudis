use alloy_primitives::{B256, U256};

use crate::{
    activation::ActivationCallCoreV1,
    error::ProtocolError,
    hash::hash_framed,
    intent::{
        ContributorTargetPreconditionV1, DayType, NodTargetPreconditionV1, ReferenceEntryPriceV1,
        TributeInputBindingV1,
    },
    registry::HashDomain,
    schema::{
        encode_nested_value, impl_top_level_codec, require, wire_enum_u8, wire_struct, NestedCodec,
        SchemaLimits,
    },
};

wire_enum_u8! {
    pub enum OwnerKind {
        Nod = 1,
        Contributor = 2,
        Tribute = 3,
        CarryOver = 4,
    }
}

wire_enum_u8! {
    pub enum BudgetSplitDestination {
        DesisAuction = 1,
        CarryOver = 2,
    }
}

wire_enum_u8! {
    pub enum ActivationOutcome {
        Applied = 1,
        ConflictResolved = 2,
    }
}

wire_struct! {
    pub struct EffectBindingV1 {
        pub intent_id: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub protocol_bundle_hash: B256,
        pub result_digest: B256,
        pub activation_preconditions_hash: B256,
        pub activation_call_id: B256,
    }
}

wire_struct! {
    pub struct NodBatchReceiptV1 {
        pub binding: EffectBindingV1,
        pub nod_target_precondition: NodTargetPreconditionV1,
        pub nod_count: u32,
        pub nod_root: B256,
        pub nod_amount_total: U256,
        pub nod_gratis_consumed: U256,
        pub issued_at: u64,
        pub state_event_digest: B256,
    }
}
impl_top_level_codec!(NodBatchReceiptV1, NodBatchReceiptV1);

wire_struct! {
    pub struct ContributorReceiptV1 {
        pub binding: EffectBindingV1,
        pub contributor_target_precondition: ContributorTargetPreconditionV1,
        pub contributor_count: u32,
        pub contributor_root: B256,
        pub eligible_nominal_total: U256,
        pub state_event_digest: B256,
    }
}
impl_top_level_codec!(ContributorReceiptV1, ContributorReceiptV1);

wire_struct! {
    pub struct TributeReceiptV1 {
        pub binding: EffectBindingV1,
        pub tribute_input_binding: TributeInputBindingV1,
        pub sealed_collection_root: B256,
        pub consumed_count: u32,
        pub consumed_nominal_total: U256,
        pub retired_generation: u64,
        pub state_event_digest: B256,
    }
}
impl_top_level_codec!(TributeReceiptV1, TributeReceiptV1);

wire_struct! {
    pub struct RequestBudgetSplitReceiptV1 {
        pub protocol_bundle_hash: B256,
        pub wwd: u32,
        pub pending_nonce: u64,
        pub day_type: DayType,
        pub day_limit: U256,
        pub lysis_budget: U256,
        pub auction_base: U256,
        pub destination: BudgetSplitDestination,
        pub desis_brief_hash: Option<B256>,
        pub carry_over_credit: U256,
        pub auction_entry_prices: Vec<ReferenceEntryPriceV1>,
        pub logical_anchor: u64,
    }
    validate = validate_request_budget_split_receipt;
}
impl_top_level_codec!(RequestBudgetSplitReceiptV1, RequestBudgetSplitReceiptV1);

wire_struct! {
    pub struct CarryOverReceiptV1 {
        pub binding: EffectBindingV1,
        pub source_wwd: u32,
        pub before_value: U256,
        pub credited_unused_lysis: U256,
        pub after_value: U256,
        pub state_event_digest: B256,
    }
    validate = validate_carry_over_receipt;
}
impl_top_level_codec!(CarryOverReceiptV1, CarryOverReceiptV1);

wire_struct! {
    pub struct NodStateEventProjectionV1 {
        pub wwd: u32,
        pub target_generation: u64,
        pub namespace_root_before: B256,
        pub nod_count: u32,
        pub nod_root: B256,
        pub nod_amount_total: U256,
        pub nod_gratis_consumed: U256,
        pub issued_at: u64,
    }
}

wire_struct! {
    pub struct ContributorStateEventProjectionV1 {
        pub worldwide_day: u32,
        pub series_version_before: u64,
        pub series_version_after: u64,
        pub contributor_count: u32,
        pub contributor_root: B256,
        pub eligible_nominal_total: U256,
    }
}

wire_struct! {
    pub struct TributeStateEventProjectionV1 {
        pub wwd: u32,
        pub source_generation: u64,
        pub sealed_collection_root: B256,
        pub consumed_count: u32,
        pub consumed_nominal_total: U256,
        pub retired_generation: u64,
    }
}

wire_struct! {
    pub struct CarryOverStateEventProjectionV1 {
        pub source_wwd: u32,
        pub before_value: U256,
        pub credited_unused_lysis: U256,
        pub after_value: U256,
    }
}

wire_struct! {
    pub struct AggregateActivationReceiptV1 {
        pub binding: EffectBindingV1,
        pub outcome: ActivationOutcome,
        pub nod_receipt_hash: Option<B256>,
        pub contributor_receipt_hash: Option<B256>,
        pub tribute_receipt_hash: Option<B256>,
        pub carry_over_receipt_hash: Option<B256>,
        pub request_budget_split_receipt_hash: B256,
        pub active_generation_hash: Option<B256>,
        pub effect_commitment: B256,
        pub event_summary_hash: B256,
        pub activated_at_height: u64,
        pub activated_at_time: u64,
    }
    validate = validate_aggregate_receipt;
}
impl_top_level_codec!(AggregateActivationReceiptV1, AggregateActivationReceiptV1);

impl EffectBindingV1 {
    pub fn validate_call(
        &self,
        call: &ActivationCallCoreV1,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        require(
            self.intent_id == call.intent_id
                && self.job_id == call.job_id
                && self.attempt == call.attempt
                && self.protocol_bundle_hash == call.protocol_bundle_hash
                && self.result_digest == call.result_digest
                && self.activation_preconditions_hash == call.activation_preconditions_hash
                && self.activation_call_id == call.activation_call_id(limits)?,
            "effect binding activation call",
        )
    }
}

pub(crate) fn owner_state_event_digest<T: NestedCodec>(
    owner: OwnerKind,
    binding: &EffectBindingV1,
    projection: &T,
    limits: &SchemaLimits,
) -> Result<B256, ProtocolError> {
    let binding_bytes = encode_nested_value(binding, limits)?;
    let projection_bytes = encode_nested_value(projection, limits)?;
    let projection_len =
        u32::try_from(projection_bytes.len()).map_err(|_| ProtocolError::IntegerOverflow {
            what: "owner projection byte length",
        })?;
    let mut payload = vec![owner as u8];
    payload.extend_from_slice(&binding_bytes);
    payload.extend_from_slice(&projection_len.to_be_bytes());
    payload.extend_from_slice(&projection_bytes);
    hash_framed(HashDomain::StateEvents, &payload)
}

pub fn nod_state_event_digest(
    binding: &EffectBindingV1,
    projection: &NodStateEventProjectionV1,
    limits: &SchemaLimits,
) -> Result<B256, ProtocolError> {
    owner_state_event_digest(OwnerKind::Nod, binding, projection, limits)
}

pub fn contributor_state_event_digest(
    binding: &EffectBindingV1,
    projection: &ContributorStateEventProjectionV1,
    limits: &SchemaLimits,
) -> Result<B256, ProtocolError> {
    owner_state_event_digest(OwnerKind::Contributor, binding, projection, limits)
}

pub fn tribute_state_event_digest(
    binding: &EffectBindingV1,
    projection: &TributeStateEventProjectionV1,
    limits: &SchemaLimits,
) -> Result<B256, ProtocolError> {
    owner_state_event_digest(OwnerKind::Tribute, binding, projection, limits)
}

pub fn carry_over_state_event_digest(
    binding: &EffectBindingV1,
    projection: &CarryOverStateEventProjectionV1,
    limits: &SchemaLimits,
) -> Result<B256, ProtocolError> {
    owner_state_event_digest(OwnerKind::CarryOver, binding, projection, limits)
}

macro_rules! receipt_hash {
    ($type:ty, $method:ident, $domain:ident) => {
        impl $type {
            pub fn $method(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
                hash_framed(HashDomain::$domain, &self.encode_canonical(limits)?)
            }
        }
    };
}

receipt_hash!(NodBatchReceiptV1, receipt_hash, NodReceipt);
receipt_hash!(ContributorReceiptV1, receipt_hash, ContributorReceipt);
receipt_hash!(TributeReceiptV1, receipt_hash, TributeReceipt);
receipt_hash!(
    RequestBudgetSplitReceiptV1,
    receipt_hash,
    BudgetSplitReceipt
);
receipt_hash!(CarryOverReceiptV1, receipt_hash, CarryOverReceipt);

macro_rules! validate_projection_digest {
    ($receipt:ty, $projection:ty, $owner:ident) => {
        impl $receipt {
            pub fn validate_projection(
                &self,
                projection: &$projection,
                limits: &SchemaLimits,
            ) -> Result<(), ProtocolError> {
                require(
                    self.state_event_digest
                        == owner_state_event_digest(
                            OwnerKind::$owner,
                            &self.binding,
                            projection,
                            limits,
                        )?,
                    "receipt state event digest",
                )
            }
        }
    };
}

validate_projection_digest!(NodBatchReceiptV1, NodStateEventProjectionV1, Nod);
validate_projection_digest!(
    ContributorReceiptV1,
    ContributorStateEventProjectionV1,
    Contributor
);
validate_projection_digest!(TributeReceiptV1, TributeStateEventProjectionV1, Tribute);
validate_projection_digest!(
    CarryOverReceiptV1,
    CarryOverStateEventProjectionV1,
    CarryOver
);

impl AggregateActivationReceiptV1 {
    pub fn validate_semantics(&self) -> Result<(), ProtocolError> {
        let all_present = self.nod_receipt_hash.is_some()
            && self.contributor_receipt_hash.is_some()
            && self.tribute_receipt_hash.is_some()
            && self.carry_over_receipt_hash.is_some()
            && self.active_generation_hash.is_some();
        let all_absent = self.nod_receipt_hash.is_none()
            && self.contributor_receipt_hash.is_none()
            && self.tribute_receipt_hash.is_none()
            && self.carry_over_receipt_hash.is_none()
            && self.active_generation_hash.is_none();
        require(
            (self.outcome == ActivationOutcome::Applied && all_present)
                || (self.outcome == ActivationOutcome::ConflictResolved && all_absent),
            "aggregate receipt outcome shape",
        )?;
        let expected = if self.outcome == ActivationOutcome::Applied {
            let (Some(nod), Some(contributor), Some(tribute), Some(carry_over)) = (
                self.nod_receipt_hash,
                self.contributor_receipt_hash,
                self.tribute_receipt_hash,
                self.carry_over_receipt_hash,
            ) else {
                return Err(ProtocolError::InvalidInvariant(
                    "aggregate receipt effect hashes",
                ));
            };
            let mut payload = Vec::with_capacity(128);
            payload.extend_from_slice(nod.as_slice());
            payload.extend_from_slice(contributor.as_slice());
            payload.extend_from_slice(tribute.as_slice());
            payload.extend_from_slice(carry_over.as_slice());
            hash_framed(HashDomain::Effects, &payload)?
        } else {
            hash_framed(HashDomain::Effects, &[])?
        };
        require(expected == self.effect_commitment, "effect commitment")?;
        if self.outcome == ActivationOutcome::ConflictResolved {
            require(
                self.event_summary_hash == empty_apply_event_summary_hash()?,
                "conflict receipt empty apply event summary",
            )?;
        }
        Ok(())
    }

    pub fn validate_applied_event_summary(
        &self,
        owner_digests: [B256; 4],
    ) -> Result<(), ProtocolError> {
        self.validate_semantics()?;
        require(
            self.outcome == ActivationOutcome::Applied,
            "applied receipt outcome",
        )?;
        require(
            self.event_summary_hash == apply_event_summary_hash(owner_digests)?,
            "applied receipt event summary",
        )
    }

    pub fn terminal_receipt_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_semantics()?;
        hash_framed(HashDomain::TerminalReceipt, &self.encode_canonical(limits)?)
    }
}

pub fn apply_event_summary_hash(owner_digests: [B256; 4]) -> Result<B256, ProtocolError> {
    let mut payload = Vec::with_capacity(128);
    for digest in owner_digests {
        payload.extend_from_slice(digest.as_slice());
    }
    hash_framed(HashDomain::ApplyEventSummary, &payload)
}

pub fn empty_apply_event_summary_hash() -> Result<B256, ProtocolError> {
    hash_framed(HashDomain::ApplyEventSummary, &[])
}

/// Canonical hash of the auction brief a request applies. The price table is
/// length-prefixed and hashed in the order given, which the caller keeps ascending.
pub fn desis_request_brief_hash(
    protocol_bundle_hash: B256,
    wwd: u32,
    auction_base: U256,
    auction_entry_prices: &[ReferenceEntryPriceV1],
    logical_anchor: u64,
) -> Result<B256, ProtocolError> {
    let mut payload = Vec::with_capacity(84 + auction_entry_prices.len() * 39);
    payload.extend_from_slice(protocol_bundle_hash.as_slice());
    payload.extend_from_slice(&wwd.to_be_bytes());
    payload.extend_from_slice(&auction_base.to_be_bytes::<32>());
    payload.extend_from_slice(&(auction_entry_prices.len() as u16).to_be_bytes());
    for row in auction_entry_prices {
        payload.extend_from_slice(&row.reference_currency.to_be_bytes());
        payload.extend_from_slice(&row.entry_price_minor.to_be_bytes::<32>());
        payload.push(row.source as u8);
        payload.extend_from_slice(&row.source_day.to_be_bytes());
    }
    payload.extend_from_slice(&logical_anchor.to_be_bytes());
    hash_framed(HashDomain::DesisRequestBrief, &payload)
}

impl RequestBudgetSplitReceiptV1 {
    pub fn validate_semantics(&self) -> Result<(), ProtocolError> {
        let green = self.day_type == DayType::Green
            && self.destination == BudgetSplitDestination::DesisAuction
            && self.desis_brief_hash.is_some();
        let red = self.day_type == DayType::Red
            && self.destination == BudgetSplitDestination::CarryOver
            && self.desis_brief_hash.is_some();
        require(green || red, "request budget split destination")?;
        // The base a red day never opens is still a share of its limit.
        let split_total = self.lysis_budget.checked_add(self.auction_base).ok_or(
            ProtocolError::IntegerOverflow {
                what: "request budget split",
            },
        )?;
        require(split_total <= self.day_limit, "request budget split")?;
        // The day limit is exhausted by what the day briefs, what Lysis takes and what returns to
        // the warehouse; a red day briefs nothing, so its base returns with the headroom.
        let briefed = if green { self.auction_base } else { U256::ZERO };
        let accounted = self
            .lysis_budget
            .checked_add(briefed)
            .and_then(|sum| sum.checked_add(self.carry_over_credit))
            .ok_or(ProtocolError::IntegerOverflow {
                what: "request budget split",
            })?;
        require(accounted == self.day_limit, "request budget split")
    }
}

fn validate_request_budget_split_receipt(
    receipt: &RequestBudgetSplitReceiptV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    receipt.validate_semantics()
}

fn validate_carry_over_receipt(
    receipt: &CarryOverReceiptV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    let expected = receipt
        .before_value
        .checked_add(receipt.credited_unused_lysis)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "carry-over receipt",
        })?;
    require(expected == receipt.after_value, "carry-over receipt")
}

fn validate_aggregate_receipt(
    receipt: &AggregateActivationReceiptV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    receipt.validate_semantics()
}
