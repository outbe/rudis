use alloy_primitives::{B256, U256};
use outbe_ocomp_protocol::{
    hash::hash_framed,
    intent::DayType,
    receipts::{
        apply_event_summary_hash, desis_request_brief_hash, CarryOverReceiptV1,
        CarryOverStateEventProjectionV1, ContributorReceiptV1, ContributorStateEventProjectionV1,
        EffectBindingV1, NodBatchReceiptV1, NodStateEventProjectionV1, RequestBudgetSplitReceiptV1,
        TributeReceiptV1, TributeStateEventProjectionV1,
    },
    registry::HashDomain,
    ProtocolError, SchemaLimits,
};
use outbe_primitives::storage::CertifiedLysisActivation;

use super::apply_plan::LysisApplyPlanV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LysisOwnerReceiptsV1 {
    pub nod: NodBatchReceiptV1,
    pub contributor: ContributorReceiptV1,
    pub tribute: TributeReceiptV1,
    pub carry_over: CarryOverReceiptV1,
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedLysisReceiptsV1 {
    binding: EffectBindingV1,
    request_budget_split_receipt_hash: B256,
    nod_receipt_hash: B256,
    contributor_receipt_hash: B256,
    tribute_receipt_hash: B256,
    carry_over_receipt_hash: B256,
    effect_commitment: B256,
    event_summary_hash: B256,
}

/// One-shot authority for the terminal Metadosis receipt.
///
/// Only [`VerifiedLysisReceiptsV1::terminal_permit`] can construct this type.
/// It is tied to the activation frame lifetime and deliberately implements no
/// clone, codec or serialization traits.
pub struct LysisTerminalPermitV1<'permit, 'frame> {
    capability: &'permit mut CertifiedLysisActivation<'frame>,
    binding: EffectBindingV1,
    request_budget_split_receipt_hash: B256,
    nod_receipt_hash: B256,
    contributor_receipt_hash: B256,
    tribute_receipt_hash: B256,
    carry_over_receipt_hash: B256,
    effect_commitment: B256,
    event_summary_hash: B256,
}

impl LysisTerminalPermitV1<'_, '_> {
    #[must_use]
    pub const fn binding(&self) -> &EffectBindingV1 {
        &self.binding
    }

    #[must_use]
    pub const fn activation_call_id(&self) -> B256 {
        self.binding.activation_call_id
    }

    #[must_use]
    pub const fn request_budget_split_receipt_hash(&self) -> B256 {
        self.request_budget_split_receipt_hash
    }

    #[must_use]
    pub const fn nod_receipt_hash(&self) -> B256 {
        self.nod_receipt_hash
    }

    #[must_use]
    pub const fn contributor_receipt_hash(&self) -> B256 {
        self.contributor_receipt_hash
    }

    #[must_use]
    pub const fn tribute_receipt_hash(&self) -> B256 {
        self.tribute_receipt_hash
    }

    #[must_use]
    pub const fn carry_over_receipt_hash(&self) -> B256 {
        self.carry_over_receipt_hash
    }

    #[must_use]
    pub const fn effect_commitment(&self) -> B256 {
        self.effect_commitment
    }

    #[must_use]
    pub const fn event_summary_hash(&self) -> B256 {
        self.event_summary_hash
    }

    /// Marks the terminal owner step complete after the terminal state and
    /// aggregate receipt have been written successfully.
    pub fn commit_terminal(self) -> Result<(), ProtocolError> {
        self.capability
            .authorize_terminal_receipt()
            .map_err(|_| ProtocolError::InvalidInvariant("Lysis terminal activation cursor"))
    }
}

impl VerifiedLysisReceiptsV1 {
    #[must_use]
    pub const fn binding(&self) -> &EffectBindingV1 {
        &self.binding
    }

    #[must_use]
    pub const fn request_budget_split_receipt_hash(&self) -> B256 {
        self.request_budget_split_receipt_hash
    }

    #[must_use]
    pub const fn nod_receipt_hash(&self) -> B256 {
        self.nod_receipt_hash
    }

    #[must_use]
    pub const fn contributor_receipt_hash(&self) -> B256 {
        self.contributor_receipt_hash
    }

    #[must_use]
    pub const fn tribute_receipt_hash(&self) -> B256 {
        self.tribute_receipt_hash
    }

    #[must_use]
    pub const fn carry_over_receipt_hash(&self) -> B256 {
        self.carry_over_receipt_hash
    }

    #[must_use]
    pub const fn effect_commitment(&self) -> B256 {
        self.effect_commitment
    }

    #[must_use]
    pub const fn event_summary_hash(&self) -> B256 {
        self.event_summary_hash
    }

    pub fn validate_terminal_capability(
        &self,
        capability: &CertifiedLysisActivation<'_>,
    ) -> Result<(), ProtocolError> {
        ensure(
            capability.activation_call_id() == self.binding.activation_call_id,
            "Lysis terminal activation call",
        )
    }

    pub fn terminal_permit<'permit, 'frame>(
        &self,
        capability: &'permit mut CertifiedLysisActivation<'frame>,
    ) -> Result<LysisTerminalPermitV1<'permit, 'frame>, ProtocolError> {
        self.validate_terminal_capability(capability)?;
        Ok(LysisTerminalPermitV1 {
            capability,
            binding: self.binding.clone(),
            request_budget_split_receipt_hash: self.request_budget_split_receipt_hash,
            nod_receipt_hash: self.nod_receipt_hash,
            contributor_receipt_hash: self.contributor_receipt_hash,
            tribute_receipt_hash: self.tribute_receipt_hash,
            carry_over_receipt_hash: self.carry_over_receipt_hash,
            effect_commitment: self.effect_commitment,
            event_summary_hash: self.event_summary_hash,
        })
    }
}

pub fn verify_receipts(
    plan: &LysisApplyPlanV1,
    request_receipt: &RequestBudgetSplitReceiptV1,
    receipts: &LysisOwnerReceiptsV1,
    limits: &SchemaLimits,
) -> Result<VerifiedLysisReceiptsV1, ProtocolError> {
    verify_request_receipt(plan, request_receipt, limits)?;

    verify_nod_receipt(plan, &receipts.nod, limits)?;
    verify_contributor_receipt(plan, &receipts.contributor, limits)?;
    verify_tribute_receipt(plan, &receipts.tribute, limits)?;
    verify_carry_over_receipt(plan, &receipts.carry_over, limits)?;

    let request = plan.request_budget_split();
    ensure(
        plan.nod()
            .nod_gratis_consumed()
            .checked_add(plan.carry_over().credited_unused_lysis())
            == Some(request.lysis_budget),
        "Lysis receipt budget conservation",
    )?;
    // Bounded, not exact: the unissued headroom returns to the warehouse (see the split receipt).
    ensure(
        request
            .lysis_budget
            .checked_add(request.auction_base)
            .is_some_and(|total| total <= request.day_limit),
        "Lysis receipt day conservation",
    )?;

    let nod_receipt_hash = receipts.nod.receipt_hash(limits)?;
    let contributor_receipt_hash = receipts.contributor.receipt_hash(limits)?;
    let tribute_receipt_hash = receipts.tribute.receipt_hash(limits)?;
    let carry_over_receipt_hash = receipts.carry_over.receipt_hash(limits)?;
    let mut effects = Vec::with_capacity(128);
    for receipt_hash in [
        nod_receipt_hash,
        contributor_receipt_hash,
        tribute_receipt_hash,
        carry_over_receipt_hash,
    ] {
        effects.extend_from_slice(receipt_hash.as_slice());
    }
    let effect_commitment = hash_framed(HashDomain::Effects, &effects)?;
    let event_summary_hash = apply_event_summary_hash([
        receipts.nod.state_event_digest,
        receipts.contributor.state_event_digest,
        receipts.tribute.state_event_digest,
        receipts.carry_over.state_event_digest,
    ])?;

    Ok(VerifiedLysisReceiptsV1 {
        binding: plan.binding().clone(),
        request_budget_split_receipt_hash: plan.request_budget_split_receipt_hash(),
        nod_receipt_hash,
        contributor_receipt_hash,
        tribute_receipt_hash,
        carry_over_receipt_hash,
        effect_commitment,
        event_summary_hash,
    })
}

fn verify_request_receipt(
    plan: &LysisApplyPlanV1,
    receipt: &RequestBudgetSplitReceiptV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    receipt.validate_semantics()?;
    ensure(
        receipt.receipt_hash(limits)? == plan.request_budget_split_receipt_hash(),
        "Lysis request receipt hash",
    )?;
    let expected = plan.request_budget_split();
    ensure(
        receipt.protocol_bundle_hash == expected.protocol_bundle_hash
            && receipt.wwd == expected.wwd
            && receipt.day_type == expected.day_type
            && receipt.day_limit == expected.day_limit
            && receipt.lysis_budget == expected.lysis_budget
            && receipt.auction_base == expected.auction_base
            && receipt.auction_entry_prices == expected.auction_entry_prices,
        "Lysis request receipt fields",
    )?;
    ensure(
        receipt.pending_nonce <= expected.pending_nonce,
        "Lysis request receipt effect nonce",
    )?;
    ensure(
        receipt.logical_anchor <= expected.logical_anchor,
        "Lysis request receipt logical anchor",
    )?;
    let briefed_supply = if expected.day_type == DayType::Green {
        expected.auction_base
    } else {
        U256::ZERO
    };
    ensure(
        receipt.desis_brief_hash
            == Some(desis_request_brief_hash(
                expected.protocol_bundle_hash,
                expected.wwd,
                briefed_supply,
                &expected.auction_entry_prices,
                receipt.logical_anchor,
            )?),
        "Lysis request Desis brief",
    )?;
    Ok(())
}

fn verify_nod_receipt(
    plan: &LysisApplyPlanV1,
    receipt: &NodBatchReceiptV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    ensure(receipt.binding == *plan.binding(), "Lysis Nod binding")?;
    let expected = plan.nod();
    ensure(
        receipt.nod_target_precondition == *expected.precondition()
            && receipt.nod_count == expected.exact_counts().nod_count
            && receipt.nod_root == expected.nod_root()
            && receipt.nod_amount_total == expected.nod_amount_total()
            && receipt.nod_gratis_consumed == expected.nod_gratis_consumed()
            && receipt.issued_at == expected.issued_at(),
        "Lysis Nod receipt",
    )?;
    let projection = NodStateEventProjectionV1 {
        wwd: expected.precondition().wwd,
        target_generation: expected.precondition().target_generation,
        namespace_root_before: expected.precondition().namespace_root_before,
        nod_count: expected.exact_counts().nod_count,
        nod_root: expected.nod_root(),
        nod_amount_total: expected.nod_amount_total(),
        nod_gratis_consumed: expected.nod_gratis_consumed(),
        issued_at: expected.issued_at(),
    };
    receipt.validate_projection(&projection, limits)?;
    Ok(())
}

fn verify_contributor_receipt(
    plan: &LysisApplyPlanV1,
    receipt: &ContributorReceiptV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    ensure(
        receipt.binding == *plan.binding(),
        "Lysis contributor binding",
    )?;
    let expected = plan.contributors();
    ensure(
        receipt.contributor_target_precondition == *expected.precondition()
            && receipt.contributor_count == expected.contributor_count()
            && receipt.contributor_root == expected.contributor_root()
            && receipt.eligible_nominal_total == expected.eligible_nominal_total(),
        "Lysis contributor receipt",
    )?;
    let version_after = expected
        .precondition()
        .expected_series_version
        .checked_add(1)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "contributor series version",
        })?;
    let projection = ContributorStateEventProjectionV1 {
        worldwide_day: expected.precondition().worldwide_day,
        series_version_before: expected.precondition().expected_series_version,
        series_version_after: version_after,
        contributor_count: expected.contributor_count(),
        contributor_root: expected.contributor_root(),
        eligible_nominal_total: expected.eligible_nominal_total(),
    };
    receipt.validate_projection(&projection, limits)?;
    Ok(())
}

fn verify_tribute_receipt(
    plan: &LysisApplyPlanV1,
    receipt: &TributeReceiptV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    ensure(receipt.binding == *plan.binding(), "Lysis Tribute binding")?;
    let expected = plan.tribute();
    ensure(
        receipt.tribute_input_binding == *expected.input_binding()
            && receipt.sealed_collection_root == expected.input_binding().sealed_collection_root
            && receipt.consumed_count == expected.consumed_count()
            && receipt.consumed_nominal_total == expected.consumed_nominal_total()
            && receipt.retired_generation == expected.retired_generation(),
        "Lysis Tribute receipt",
    )?;
    let projection = TributeStateEventProjectionV1 {
        wwd: expected.input_binding().wwd,
        source_generation: expected.input_binding().source_generation,
        sealed_collection_root: expected.input_binding().sealed_collection_root,
        consumed_count: expected.consumed_count(),
        consumed_nominal_total: expected.consumed_nominal_total(),
        retired_generation: expected.retired_generation(),
    };
    receipt.validate_projection(&projection, limits)?;
    Ok(())
}

fn verify_carry_over_receipt(
    plan: &LysisApplyPlanV1,
    receipt: &CarryOverReceiptV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    ensure(
        receipt.binding == *plan.binding(),
        "Lysis carry-over binding",
    )?;
    let expected = plan.carry_over();
    ensure(
        receipt.source_wwd == expected.source_wwd()
            && receipt.credited_unused_lysis == expected.credited_unused_lysis()
            && receipt
                .before_value
                .checked_add(receipt.credited_unused_lysis)
                == Some(receipt.after_value),
        "Lysis carry-over receipt",
    )?;
    let projection = CarryOverStateEventProjectionV1 {
        source_wwd: receipt.source_wwd,
        before_value: receipt.before_value,
        credited_unused_lysis: receipt.credited_unused_lysis,
        after_value: receipt.after_value,
    };
    receipt.validate_projection(&projection, limits)?;
    Ok(())
}

fn ensure(condition: bool, invariant: &'static str) -> Result<(), ProtocolError> {
    if condition {
        Ok(())
    } else {
        Err(ProtocolError::InvalidInvariant(invariant))
    }
}
