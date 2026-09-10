use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall, SolInterface};
use outbe_intex::SeriesId;
use outbe_primitives::dispatch::{dispatch_call, metadata, mutate, mutate_void, view};
use outbe_primitives::error::Result;
use outbe_primitives::storage::gas::{PRECOMPILE_BASE_GAS, ZK_VERIFY_GAS};

use crate::errors::GemFactoryError;
use crate::runtime;
use crate::schema::GemFactoryContract;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IGemFactory.sol"
);

/// Base gas charged by the registry before invoking [`dispatch`]: `settleGem`
/// verifies a PayNote spend proof, which is real native work every validator
/// repeats.
pub fn base_gas(input: &[u8]) -> u64 {
    match input.first_chunk::<4>() {
        Some(&IGemFactory::settleGemCall::SELECTOR) => ZK_VERIFY_GAS,
        _ => PRECOMPILE_BASE_GAS,
    }
}

pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_primitives::dispatch::reject_value(&value)?;
    dispatch_call(data, IGemFactory::IGemFactoryCalls::abi_decode, |call| {
        use IGemFactory::IGemFactoryCalls::*;
        match call {
            issueGemPosition(c) => mutate(c, caller, |sender, c| {
                runtime::issue_gem_position(
                    &storage,
                    sender,
                    SeriesId::from(c.sourceIntexId),
                    c.amount,
                )
            }),
            issueGem(c) => mutate(c, caller, |sender, c| {
                runtime::issue_merchant_gem(&storage, sender, c.positionId, c.owner, c.promisLoad)
            }),
            settleGem(c) => mutate_void(c, caller, |sender, c| {
                runtime::settle_gem(&storage, sender, c.gemId, &c.payNoteProof)
            }),
            minePromis(c) => mutate(c, caller, |sender, c| {
                let auth = outbe_promisfactory::api::ModifyAuth {
                    mac: c.mac.0,
                    op_nonce: c.opNonce,
                };
                runtime::mine_promis(&storage, sender, c.gemId, c.nonce, auth)
            }),
            getStatistics(_) => metadata::<IGemFactory::getStatisticsCall>(|| {
                let factory = GemFactoryContract::new(storage.clone());
                Ok(IGemFactory::getStatisticsReturn {
                    totalGemsIssued: factory.total_gems_issued.read()?,
                    totalIntexParked: factory.total_intex_parked.read()?,
                })
            }),

            quoteSettlement(c) => metadata::<IGemFactory::quoteSettlementCall>(|| {
                let (settlement_currency, amount) =
                    runtime::quote_settlement(&storage, c.gemId, c.asset)?;
                Ok(IGemFactory::quoteSettlementReturn {
                    settlementCurrency: settlement_currency,
                    payableUnits: amount,
                })
            }),

            getPosition(c) => view(c, |c| runtime::position_data(&storage, c.positionId)),

            balanceOf(c) => view(c, |c| {
                GemFactoryContract::new(storage.clone())
                    .balance_of(c.owner)
                    .map(U256::from)
            }),
            ownerOf(c) => view(c, |c| {
                GemFactoryContract::new(storage.clone()).owner_of(c.positionId)
            }),
            tokenURI(c) => view(c, |c| {
                GemFactoryContract::new(storage.clone()).token_uri(c.positionId)
            }),
            tokenOfOwnerByIndex(c) => view(c, |c| {
                let idx = u32::try_from(c.index).map_err(|_| GemFactoryError::IndexOutOfBounds)?;
                GemFactoryContract::new(storage.clone()).token_of_owner_by_index(c.owner, idx)
            }),
        }
    })
}
