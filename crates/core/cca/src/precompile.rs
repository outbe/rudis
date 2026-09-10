//! ABI decode, dispatch and encode for the CCA registry precompile.
//!
//! A Credis Card Agent originates Credis positions on behalf of card owners.
//! `CredisFactory` needs to gate origination on the agent's standing, so the
//! query side of that contract - [`ICca`] - is published and routed now; the
//! registry that would answer it truthfully is not built yet.
//!
//! Until it is, every address reads back `Active`, which keeps the pre-registry
//! behaviour (nobody is gated) while callers migrate onto the real ABI.

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};

use outbe_primitives::dispatch::{dispatch_call, reject_value, view};
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!("../../../contracts/precompiles/src/ICca.sol");

/// Routes reads into [`crate::api`], which owns the (currently stubbed) answer.
pub fn dispatch(
    storage: StorageHandle,
    data: &[u8],
    _caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    dispatch_call(data, ICca::ICcaCalls::abi_decode, |call| {
        use ICca::ICcaCalls::*;
        match call {
            getCcaState(c) => view(c, |c| crate::api::cca_state(&storage, c.cca)),
            supportsInterface(c) => view(c, |c| {
                let id: [u8; 4] = c.interfaceId.0;
                Ok(id == ERC165_INTERFACE_ID)
            }),
        }
    })
}
