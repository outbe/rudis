//! Promisfactory precompile at `0x2337`. ABI dispatch only - the promis
//! mint/burn orchestration + Fidelity bookkeeping lives in [`crate::runtime`].

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};

use outbe_primitives::dispatch::{dispatch_call, mutate, view};
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;
use outbe_promis::api::ModifyAuth;

use crate::runtime;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!("../../../contracts/precompiles/src/IPromisFactory.sol");

pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_primitives::dispatch::reject_value(&value)?;
    dispatch_call(
        data,
        IPromisFactory::IPromisFactoryCalls::abi_decode,
        |call| {
            use IPromisFactory::IPromisFactoryCalls::*;
            match call {
                mineRudis(c) => mutate(c, caller, |sender, c| {
                    let auth = ModifyAuth {
                        mac: c.mac.0,
                        op_nonce: c.opNonce,
                    };
                    runtime::mine_coen(storage.clone(), sender, c.amount, auth)
                }),
                mineGratis(c) => mutate(c, caller, |sender, c| {
                    let promis_auth = ModifyAuth {
                        mac: c.promisMac.0,
                        op_nonce: c.promisOpNonce,
                    };
                    let gratis_auth = ModifyAuth {
                        mac: c.gratisMac.0,
                        op_nonce: c.gratisOpNonce,
                    };
                    runtime::mine_gratis(
                        storage.clone(),
                        sender,
                        c.amount,
                        promis_auth,
                        gratis_auth,
                    )
                }),
                supportsInterface(c) => view(c, |c| {
                    let id: [u8; 4] = c.interfaceId.0;
                    Ok(id == ERC165_INTERFACE_ID)
                }),
            }
        },
    )
}
