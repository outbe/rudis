//! Gratisfactory precompile at `0x2003`. ABI dispatch only - the Gratis balance
//! movement + Fidelity bookkeeping lives in [`crate::runtime`]. Writes are
//! authorized by the caller's Gratis modify key (`mac` + `opNonce`).

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolEvent, SolInterface};

use outbe_gratis::api::ModifyAuth;
use outbe_primitives::addresses::GRATIS_FACTORY_ADDRESS;
use outbe_primitives::dispatch::{dispatch_call, mutate, mutate_void, view};
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::runtime;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!("../../../contracts/precompiles/src/IGratisFactory.sol");

pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_primitives::dispatch::reject_value(&value)?;
    dispatch_call(
        data,
        IGratisFactory::IGratisFactoryCalls::abi_decode,
        |call| {
            use IGratisFactory::IGratisFactoryCalls::*;
            match call {
                pledgeGratis(c) => mutate(c, caller, |sender, c| {
                    let auth = ModifyAuth {
                        mac: c.mac.0,
                        op_nonce: c.opNonce,
                    };
                    let (handle, gratis_amount) = runtime::pledge_gratis(
                        storage.clone(),
                        sender,
                        c.amountStables,
                        c.asset,
                        c.maxGratis,
                        auth,
                    )?;
                    emit_pledged(&storage, sender, &c, gratis_amount, handle)?;
                    Ok(handle)
                }),
                unpledgeGratis(c) => mutate_void(c, caller, |sender, c| {
                    let auth = ModifyAuth {
                        mac: c.mac.0,
                        op_nonce: c.opNonce,
                    };
                    let gratis_amount = runtime::unpledge_gratis(
                        storage.clone(),
                        sender,
                        c.amountStables,
                        c.pledgeHandle,
                        auth,
                    )?;
                    emit_unpledged(&storage, sender, gratis_amount)
                }),
                mineRudis(c) => mutate(c, caller, |sender, c| {
                    let auth = ModifyAuth {
                        mac: c.mac.0,
                        op_nonce: c.opNonce,
                    };
                    runtime::mine_coen(storage.clone(), sender, c.amount, auth)
                }),
                supportsInterface(c) => view(c, |c| {
                    let id: [u8; 4] = c.interfaceId.0;
                    Ok(id == ERC165_INTERFACE_ID)
                }),
            }
        },
    )
}

fn emit_pledged(
    storage: &StorageHandle<'_>,
    account: Address,
    call: &IGratisFactory::pledgeGratisCall,
    gratis_amount: U256,
    pledge_handle: B256,
) -> Result<()> {
    storage.emit_event(
        GRATIS_FACTORY_ADDRESS,
        SolEvent::encode_log_data(&IGratisFactory::GratisPledged {
            account,
            amountStables: call.amountStables,
            asset: call.asset,
            gratisAmount: gratis_amount,
            pledgeHandle: pledge_handle,
        }),
    )
}

fn emit_unpledged(
    storage: &StorageHandle<'_>,
    account: Address,
    gratis_amount: U256,
) -> Result<()> {
    storage.emit_event(
        GRATIS_FACTORY_ADDRESS,
        SolEvent::encode_log_data(&IGratisFactory::GratisUnpledged {
            account,
            gratisAmount: gratis_amount,
        }),
    )
}
