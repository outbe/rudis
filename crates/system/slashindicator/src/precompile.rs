use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall, SolInterface};
use outbe_primitives::dispatch::{dispatch_call, mutate_void, reject_value, view};
use outbe_primitives::error::Result;
use outbe_primitives::protocol_schedule::OutbeProtocolSchedule;
use outbe_primitives::storage::gas::PRECOMPILE_BASE_GAS;

use crate::schema::SlashIndicator;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/ISlashIndicator.sol"
);

/// Heavy base gas for the BLS-evidence submission selectors.
///
/// Each evidence verifier runs ~2+ BLS12-381 pairings plus ecrecover/storage
/// reads. On the ZeroFee chain those would be near-free to spam, so this charges
/// a heavy base proportional to that work - block gas then bounds how many
/// evidence txs fit in one block, complementing the ACTIVE-validator ACL. The
/// value is the single source of truth in
/// [`OutbeProtocolSchedule::slash_indicator_vrf_evidence_base_gas`], read here
/// rather than duplicated as a local literal. View methods and unknown selectors
/// fall back to the flat default.
fn evidence_submit_base_gas() -> u64 {
    OutbeProtocolSchedule::default().slash_indicator_vrf_evidence_base_gas
}

/// Per-selector base-gas function registered for `SLASH_INDICATOR_ADDRESS`.
pub fn base_gas(input: &[u8]) -> u64 {
    let Some(selector) = input.get(0..4) else {
        return PRECOMPILE_BASE_GAS;
    };
    use ISlashIndicator::*;
    let evidence_selectors: [[u8; 4]; 8] = [
        submitDoubleProposalEvidenceCall::SELECTOR,
        submitConflictingVoteEvidenceCall::SELECTOR,
        submitConflictingNotarizeEvidenceCall::SELECTOR,
        submitConflictingFinalizeEvidenceCall::SELECTOR,
        submitNullifyFinalizeEvidenceCall::SELECTOR,
        submitInvalidVrfProofEvidenceCall::SELECTOR,
        submitSeedPartialEquivocationEvidenceCall::SELECTOR,
        submitInvalidSeedPartialEvidenceCall::SELECTOR,
    ];
    if evidence_selectors.iter().any(|s| s.as_slice() == selector) {
        evidence_submit_base_gas()
    } else {
        PRECOMPILE_BASE_GAS
    }
}

/// Dispatches an ABI-encoded call to the SlashIndicator precompile.
pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    dispatch_call(
        data,
        ISlashIndicator::ISlashIndicatorCalls::abi_decode,
        |call| {
            use ISlashIndicator::ISlashIndicatorCalls::*;
            match call {
                submitDoubleProposalEvidence(c) => mutate_void(c, caller, |sender, c| {
                    let mut si = SlashIndicator::new(storage);
                    si.submit_double_proposal_evidence(sender, &c.block1, &c.block2)
                }),
                submitConflictingVoteEvidence(c) => mutate_void(c, caller, |sender, c| {
                    let mut si = SlashIndicator::new(storage);
                    si.submit_conflicting_vote_evidence(sender, &c.vote1, &c.vote2)
                }),
                submitConflictingNotarizeEvidence(c) => mutate_void(c, caller, |sender, c| {
                    let mut si = SlashIndicator::new(storage);
                    si.submit_conflicting_notarize_evidence(sender, &c.block1, &c.block2)
                }),
                submitConflictingFinalizeEvidence(c) => mutate_void(c, caller, |sender, c| {
                    let mut si = SlashIndicator::new(storage);
                    si.submit_conflicting_finalize_evidence(sender, &c.block1, &c.block2)
                }),
                submitNullifyFinalizeEvidence(c) => mutate_void(c, caller, |sender, c| {
                    let mut si = SlashIndicator::new(storage);
                    si.submit_nullify_finalize_evidence(sender, &c.nullifyBlock, &c.finalizeBlock)
                }),
                submitInvalidVrfProofEvidence(c) => mutate_void(c, caller, |sender, c| {
                    let mut si = SlashIndicator::new(storage);
                    si.submit_invalid_vrf_evidence(sender, &c.evidence)
                }),
                submitSeedPartialEquivocationEvidence(c) => mutate_void(c, caller, |sender, c| {
                    let mut si = SlashIndicator::new(storage);
                    si.submit_seed_partial_equivocation_evidence(sender, &c.evidence)
                }),
                submitInvalidSeedPartialEvidence(c) => mutate_void(c, caller, |sender, c| {
                    let mut si = SlashIndicator::new(storage);
                    si.submit_invalid_seed_partial_evidence(sender, &c.evidence)
                }),
                getProposerMissCount(c) => view(c, |c| {
                    let si = SlashIndicator::new(storage);
                    si.get_proposer_miss_count(c.validator)
                }),
                getVoterMissCount(c) => view(c, |c| {
                    let si = SlashIndicator::new(storage);
                    si.get_voter_miss_count(c.validator)
                }),
                getFelonyCount(c) => view(c, |c| {
                    let si = SlashIndicator::new(storage);
                    si.get_felony_count(c.validator)
                }),
            }
        },
    )
}

#[cfg(test)]
mod gas_tests {
    use super::*;

    #[test]
    fn evidence_selectors_charge_heavy_base_gas() {
        // Evidence-submission selectors (BLS-pairing-bound) charge the heavy base,
        // sourced from the protocol schedule, not a duplicated literal.
        let heavy = OutbeProtocolSchedule::default().slash_indicator_vrf_evidence_base_gas;
        assert_eq!(
            heavy, 200_000,
            "evidence base gas must be the calibrated value, not a placeholder"
        );
        assert_eq!(
            base_gas(&ISlashIndicator::submitDoubleProposalEvidenceCall::SELECTOR),
            heavy
        );
        assert_eq!(
            base_gas(&ISlashIndicator::submitInvalidSeedPartialEvidenceCall::SELECTOR),
            heavy
        );
        // View methods and unknown/short inputs fall back to the flat default.
        assert_eq!(
            base_gas(&ISlashIndicator::getFelonyCountCall::SELECTOR),
            PRECOMPILE_BASE_GAS
        );
        assert_eq!(base_gas(&[]), PRECOMPILE_BASE_GAS);
        assert_eq!(base_gas(&[0xDE, 0xAD, 0xBE, 0xEF]), PRECOMPILE_BASE_GAS);
    }
}
