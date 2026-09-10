//! ABI dispatch for the credisfactory precompile at `CREDIS_FACTORY_ADDRESS`.
//!
//! `requestCredis` consumes a confidential Gratis pledge (pledge handle + spend
//! authorization) and opens a credis position bound to `smartAccount`.
//! `settle` applies an arbitrary amount interest-first and releases the matching
//! share of the pledged collateral back to the original pledger's encrypted
//! Gratis balance.

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall, SolInterface};

use outbe_primitives::dispatch::{
    dispatch_call, mutate, mutate_payable, reject_value_unless_payable, view,
};
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::runtime;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[ICredisFactory::requestCredisCall::SELECTOR];

sol!("../../../contracts/precompiles/src/ICredisFactory.sol");

pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    // CredisFactory is a payable route, so the boundary credits value to this address
    // before dispatch. Refuse it for every selector except the published one.
    reject_value_unless_payable(data, PAYABLE_SELECTORS, &value)?;
    dispatch_call(
        data,
        ICredisFactory::ICredisFactoryCalls::abi_decode,
        |call| {
            use ICredisFactory::ICredisFactoryCalls::*;
            match call {
                requestCredis(c) => {
                    mutate_payable(c, PAYABLE_SELECTORS, caller, value, |sender, c, val| {
                        let (position_id, amount_stables) = runtime::request_credis(
                            storage.clone(),
                            sender,
                            c.smartAccount,
                            c.pledgeHandle,
                            c.spendAuth.0,
                            c.referenceCurrency,
                            val,
                        )?;
                        Ok(ICredisFactory::requestCredisReturn {
                            positionId: position_id,
                            amountStables: amount_stables,
                        })
                    })
                }
                settle(c) => mutate(c, caller, |sender, c| {
                    let (principal, interest) =
                        runtime::settle(storage.clone(), sender, c.positionId, c.amount)?;
                    Ok(ICredisFactory::settleReturn {
                        principal,
                        interest,
                    })
                }),
                supportsInterface(c) => view(c, |c| {
                    let id: [u8; 4] = c.interfaceId.0;
                    Ok(id == ERC165_INTERFACE_ID)
                }),
            }
        },
    )
}
