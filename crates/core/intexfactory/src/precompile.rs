//! ABI dispatch for the IntexFactory precompile at `INTEX_FACTORY_ADDRESS`.
//!
//! Routing only: decode -> runtime -> encode. `settle` / `minePromis` /
//! `setAuthorizedSettler` are user-facing with `caller = msg.sender`. None
//! accept value, except `distribute`, which credits auction proceeds.

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall, SolInterface};

use outbe_intex::SeriesId;
use outbe_primitives::dispatch::{
    dispatch_call, metadata, mutate, mutate_void, mutate_void_payable, reject_value_unless_payable,
    view,
};
use outbe_primitives::error::Result;
use outbe_primitives::storage::gas::{PRECOMPILE_BASE_GAS, ZK_VERIFY_GAS};
use outbe_primitives::storage::StorageHandle;

use crate::runtime;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[IIntexFactory::distributeCall::SELECTOR];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IIntexFactory.sol"
);

/// Base gas charged by the registry before invoking [`dispatch`]: `settle`
/// verifies a PayNote spend proof, which is real native work every validator
/// repeats.
pub fn base_gas(input: &[u8]) -> u64 {
    match input.first_chunk::<4>() {
        Some(&IIntexFactory::settleCall::SELECTOR) => ZK_VERIFY_GAS,
        _ => PRECOMPILE_BASE_GAS,
    }
}

// Arming the proceeds fan-in is production work of the issuance leg, which a
// payout e2e never reaches: it runs no auction, so it issues nothing. This
// stages that one precondition and exists only in a throwaway build.
#[cfg(feature = "e2e-test")]
sol! {
    #[sol(alloy_sol_types = alloy_sol_types)]
    interface IIntexFactoryTestArming {
        function armProceedsForTest(uint32 worldwideDay, uint32[] chains, uint64 deadline) external;
        function seedDayVwapsForTest(uint16 isoCode, uint32 days, uint256 value) external;
        function issueForTest(
            bytes14[] seriesIds,
            uint16[] issuanceCurrencies,
            uint32 worldwideDay,
            uint32 issuedAt,
            uint32 issuedIntexCount,
            uint128 promisLoadMinor,
            uint256 entryPriceMinor,
            uint16 referenceCurrency,
            address[] recipients,
            uint256[] quantities,
            uint32[] recipientChains,
            uint32[] snapshotChains
        ) external;
    }
}

pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    // IntexFactory is a payable route, so the boundary credits value to this
    // address; every selector the module has not published refuses it here.
    reject_value_unless_payable(data, PAYABLE_SELECTORS, &value)?;
    #[cfg(feature = "e2e-test")]
    if let Ok(call) = IIntexFactoryTestArming::seedDayVwapsForTestCall::abi_decode(data) {
        // What `set_vwap` does in this module's own tests: the per-day value keyed by
        // the pair's registry index, and the watermark the begin-block hook would move.
        // Nothing is added to the Oracle crate; only the days it serves are filled in.
        use outbe_oracle::schema::OracleContract;
        use outbe_primitives::time::{previous_date_key, timestamp_to_date_key};

        let oracle = OracleContract::new(storage.clone());
        let pair = outbe_oracle::api::AddressPair::new_coen_to(call.isoCode);
        let pair_id = oracle.pair_index_of(pair)?;
        let mut day = previous_date_key(timestamp_to_date_key(storage.timestamp()?.to::<u64>()));
        for _ in 0..call.days {
            oracle
                .utc_day_vwap_value
                .get_nested(&day)
                .write(&pair_id, call.value)?;
            if oracle.utc_day_vwap_last_finalized.read()? < day {
                oracle.utc_day_vwap_last_finalized.write(day)?;
            }
            day = previous_date_key(day);
        }
        return Ok(Bytes::new());
    }
    #[cfg(feature = "e2e-test")]
    if let Ok(call) = IIntexFactoryTestArming::issueForTestCall::abi_decode(data) {
        // Mirrors the clearing engine: issue every series first, then send the day's
        // legs once. Sending per series would declare a one-chunk day twice, and the
        // second delivery is dropped as a conflicting repeat rather than applied.
        if call.seriesIds.len() != call.issuanceCurrencies.len() {
            return Err(outbe_primitives::error::PrecompileError::Revert(
                "issueForTest: a currency per series".into(),
            ));
        }
        let mut legs = Vec::new();
        let ids = call.seriesIds.clone();
        for (series_id, issuance_currency) in
            call.seriesIds.into_iter().zip(call.issuanceCurrencies)
        {
            legs.extend(crate::api::issue(
                &storage,
                crate::schema::IssuanceParams {
                    series_id: SeriesId::from(series_id),
                    worldwide_day: call.worldwideDay.into(),
                    issued_intex_count: call.issuedIntexCount,
                    promis_load_minor: call.promisLoadMinor,
                    entry_price_minor: call.entryPriceMinor,
                    issuance_currency,
                    reference_currency: call.referenceCurrency,
                    recipients: call.recipients.clone(),
                    quantities: call.quantities.clone(),
                    recipient_chains: call.recipientChains.clone(),
                    snapshot_chains: call.snapshotChains.clone(),
                },
            )?);
        }
        // The Called sweep counts breach days from `issued_at`, so a scenario that
        // seeds those days has to place issuance behind them. Zero keeps the stamp
        // the engine wrote.
        if call.issuedAt != 0 {
            for series_id in ids {
                outbe_intex::api::set_issued_at(
                    &storage,
                    SeriesId::from(series_id),
                    call.issuedAt,
                )?;
            }
        }
        crate::api::send_issuance(&storage, legs)?;
        return Ok(Bytes::new());
    }
    #[cfg(feature = "e2e-test")]
    if let Ok(call) = IIntexFactoryTestArming::armProceedsForTestCall::abi_decode(data) {
        outbe_intex::api::arm_proceeds(
            &storage,
            call.worldwideDay.into(),
            &call.chains,
            call.deadline,
        )?;
        return Ok(Bytes::new());
    }
    dispatch_call(
        data,
        IIntexFactory::IIntexFactoryCalls::abi_decode,
        |call| {
            use IIntexFactory::IIntexFactoryCalls::*;
            match call {
                settle(c) => mutate_void(c, caller, |sender, c| {
                    runtime::settle(
                        &storage,
                        SeriesId::from(c.seriesId),
                        c.intexHolder,
                        sender,
                        c.amount,
                        &c.payNoteProof,
                    )
                }),
                quoteSettlement(c) => metadata::<IIntexFactory::quoteSettlementCall>(|| {
                    let (settlement_currency, amount) = runtime::quote_settlement(
                        &storage,
                        SeriesId::from(c.seriesId),
                        c.paymentToken,
                    )?;
                    Ok(IIntexFactory::quoteSettlementReturn {
                        settlementCurrency: settlement_currency,
                        payableUnits: amount,
                    })
                }),
                // Off-chain the holder brute-forces `nonce` so the work hash
                // SHA256(holder ++ promisAmount_be32 ++ seriesId ++ seq_be4 ++ nonce_be8)
                // has POW_DIFFICULTY leading zero bytes; `seq` is the on-chain
                // per-(series, holder) counter.
                minePromis(c) => mutate(c, caller, |sender, c| {
                    let auth = outbe_promisfactory::api::ModifyAuth {
                        mac: c.mac.0,
                        op_nonce: c.opNonce,
                    };
                    runtime::mine_promis(
                        &storage,
                        SeriesId::from(c.seriesId),
                        sender,
                        c.amount,
                        c.nonce,
                        auth,
                    )
                }),
                setAuthorizedSettler(c) => mutate_void(c, caller, |sender, c| {
                    runtime::set_authorized_settler(
                        &storage,
                        sender,
                        SeriesId::from(c.seriesId),
                        c.settler,
                    )
                }),
                // The only payable selector: credits auction proceeds (msg.value)
                // from the source chain into the day's pot.
                distribute(c) => {
                    mutate_void_payable(c, PAYABLE_SELECTORS, caller, value, |sender, c, val| {
                        runtime::distribute(
                            &storage,
                            sender,
                            c.worldwideDay.into(),
                            c.srcChainId,
                            val,
                        )
                    })
                }
                // Permissionless: the merkle proof is the authorization, so the
                // sender is irrelevant to the outcome.
                payContributorBatch(c) => mutate_void(c, caller, |_sender, c| {
                    runtime::pay_contributor_batch(
                        &storage,
                        c.worldwideDay,
                        c.startIndex,
                        &c.leaves,
                        &c.proof,
                    )
                }),
                contributorPayoutRound(c) => view(c, |c| {
                    runtime::contributor_payout_round(&storage, c.worldwideDay)
                }),
                contributorPaidWord(c) => view(c, |c| {
                    outbe_intex::api::paid_leaves_word(&storage, c.worldwideDay, c.wordIndex)
                }),
            }
        },
    )
}
