use alloy_primitives::{B256, U256};
use outbe_ocomp_protocol::{
    activation::ActivationCallCoreV1,
    intent::{
        ContributorTargetPreconditionV1, DayType, NodTargetPreconditionV1, ReferenceEntryPriceV1,
        TributeInputBindingV1,
    },
    receipts::EffectBindingV1,
    result::ExactCountsV1,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RequestBudgetSplitApplyV1 {
    pub protocol_bundle_hash: B256,
    pub wwd: u32,
    pub pending_nonce: u64,
    pub day_type: DayType,
    pub day_limit: U256,
    pub lysis_budget: U256,
    pub auction_base: U256,
    pub auction_entry_prices: Vec<ReferenceEntryPriceV1>,
    pub logical_anchor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodGenerationApplyV1 {
    precondition: NodTargetPreconditionV1,
    nod_root: B256,
    bucket_root: B256,
    output_manifest_root: B256,
    exact_counts: ExactCountsV1,
    nod_amount_total: U256,
    nod_gratis_consumed: U256,
    issued_at: u64,
}

impl NodGenerationApplyV1 {
    #[must_use]
    pub const fn precondition(&self) -> &NodTargetPreconditionV1 {
        &self.precondition
    }

    #[must_use]
    pub const fn nod_root(&self) -> B256 {
        self.nod_root
    }

    #[must_use]
    pub const fn bucket_root(&self) -> B256 {
        self.bucket_root
    }

    #[must_use]
    pub const fn output_manifest_root(&self) -> B256 {
        self.output_manifest_root
    }

    #[must_use]
    pub const fn exact_counts(&self) -> &ExactCountsV1 {
        &self.exact_counts
    }

    #[must_use]
    pub const fn nod_amount_total(&self) -> U256 {
        self.nod_amount_total
    }

    #[must_use]
    pub const fn nod_gratis_consumed(&self) -> U256 {
        self.nod_gratis_consumed
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContributorRootApplyV1 {
    precondition: ContributorTargetPreconditionV1,
    contributor_root: B256,
    contributor_count: u32,
    eligible_nominal_total: U256,
}

impl ContributorRootApplyV1 {
    #[must_use]
    pub const fn precondition(&self) -> &ContributorTargetPreconditionV1 {
        &self.precondition
    }

    #[must_use]
    pub const fn contributor_root(&self) -> B256 {
        self.contributor_root
    }

    #[must_use]
    pub const fn contributor_count(&self) -> u32 {
        self.contributor_count
    }

    #[must_use]
    pub const fn eligible_nominal_total(&self) -> U256 {
        self.eligible_nominal_total
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TributeRetirementApplyV1 {
    input_binding: TributeInputBindingV1,
    consumed_count: u32,
    consumed_nominal_total: U256,
    retired_generation: u64,
}

impl TributeRetirementApplyV1 {
    #[must_use]
    pub const fn input_binding(&self) -> &TributeInputBindingV1 {
        &self.input_binding
    }

    #[must_use]
    pub const fn consumed_count(&self) -> u32 {
        self.consumed_count
    }

    #[must_use]
    pub const fn consumed_nominal_total(&self) -> U256 {
        self.consumed_nominal_total
    }

    #[must_use]
    pub const fn retired_generation(&self) -> u64 {
        self.retired_generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarryOverApplyV1 {
    source_wwd: u32,
    credited_unused_lysis: U256,
}

impl CarryOverApplyV1 {
    #[must_use]
    pub const fn source_wwd(&self) -> u32 {
        self.source_wwd
    }

    #[must_use]
    pub const fn credited_unused_lysis(&self) -> U256 {
        self.credited_unused_lysis
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LysisApplyPlanV1 {
    call_core: ActivationCallCoreV1,
    binding: EffectBindingV1,
    request_budget_split_receipt_hash: B256,
    request_budget_split: RequestBudgetSplitApplyV1,
    nod: NodGenerationApplyV1,
    contributors: ContributorRootApplyV1,
    tribute: TributeRetirementApplyV1,
    carry_over: CarryOverApplyV1,
}

impl LysisApplyPlanV1 {
    #[must_use]
    pub const fn call_core(&self) -> &ActivationCallCoreV1 {
        &self.call_core
    }

    #[must_use]
    pub const fn binding(&self) -> &EffectBindingV1 {
        &self.binding
    }

    #[must_use]
    pub const fn request_budget_split_receipt_hash(&self) -> B256 {
        self.request_budget_split_receipt_hash
    }

    pub(super) const fn request_budget_split(&self) -> &RequestBudgetSplitApplyV1 {
        &self.request_budget_split
    }

    #[must_use]
    pub const fn nod(&self) -> &NodGenerationApplyV1 {
        &self.nod
    }

    #[must_use]
    pub const fn contributors(&self) -> &ContributorRootApplyV1 {
        &self.contributors
    }

    #[must_use]
    pub const fn tribute(&self) -> &TributeRetirementApplyV1 {
        &self.tribute
    }

    #[must_use]
    pub const fn carry_over(&self) -> &CarryOverApplyV1 {
        &self.carry_over
    }
}

pub(super) struct LysisApplyPlanPartsV1 {
    pub call_core: ActivationCallCoreV1,
    pub binding: EffectBindingV1,
    pub request_budget_split_receipt_hash: B256,
    pub request_budget_split: RequestBudgetSplitApplyV1,
    pub nod: NodGenerationApplyV1,
    pub contributors: ContributorRootApplyV1,
    pub tribute: TributeRetirementApplyV1,
    pub carry_over: CarryOverApplyV1,
}

impl From<LysisApplyPlanPartsV1> for LysisApplyPlanV1 {
    fn from(parts: LysisApplyPlanPartsV1) -> Self {
        Self {
            call_core: parts.call_core,
            binding: parts.binding,
            request_budget_split_receipt_hash: parts.request_budget_split_receipt_hash,
            request_budget_split: parts.request_budget_split,
            nod: parts.nod,
            contributors: parts.contributors,
            tribute: parts.tribute,
            carry_over: parts.carry_over,
        }
    }
}

pub(super) struct NodGenerationApplyPartsV1 {
    pub precondition: NodTargetPreconditionV1,
    pub nod_root: B256,
    pub bucket_root: B256,
    pub output_manifest_root: B256,
    pub exact_counts: ExactCountsV1,
    pub nod_amount_total: U256,
    pub nod_gratis_consumed: U256,
    pub issued_at: u64,
}

pub(super) fn nod_apply(parts: NodGenerationApplyPartsV1) -> NodGenerationApplyV1 {
    NodGenerationApplyV1 {
        precondition: parts.precondition,
        nod_root: parts.nod_root,
        bucket_root: parts.bucket_root,
        output_manifest_root: parts.output_manifest_root,
        exact_counts: parts.exact_counts,
        nod_amount_total: parts.nod_amount_total,
        nod_gratis_consumed: parts.nod_gratis_consumed,
        issued_at: parts.issued_at,
    }
}

pub(super) fn contributor_apply(
    precondition: ContributorTargetPreconditionV1,
    contributor_root: B256,
    contributor_count: u32,
    eligible_nominal_total: U256,
) -> ContributorRootApplyV1 {
    ContributorRootApplyV1 {
        precondition,
        contributor_root,
        contributor_count,
        eligible_nominal_total,
    }
}

pub(super) fn tribute_apply(
    input_binding: TributeInputBindingV1,
    consumed_count: u32,
    consumed_nominal_total: U256,
    retired_generation: u64,
) -> TributeRetirementApplyV1 {
    TributeRetirementApplyV1 {
        input_binding,
        consumed_count,
        consumed_nominal_total,
        retired_generation,
    }
}

pub(super) const fn carry_over_apply(
    source_wwd: u32,
    credited_unused_lysis: U256,
) -> CarryOverApplyV1 {
    CarryOverApplyV1 {
        source_wwd,
        credited_unused_lysis,
    }
}
