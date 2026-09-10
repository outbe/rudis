use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};
use outbe_primitives::dispatch::{dispatch_call, metadata, view};
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::error::Result;

use crate::schema::Promis;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

/// `IPromis` interface ID (XOR of non-ERC-165 selectors in IPromis). Regenerated
/// when the ABI surface changes; guarded by `test_iface_id_matches_selector_xor`.
pub(crate) const IPROMIS_INTERFACE_ID: [u8; 4] = [0x4b, 0xb3, 0x17, 0xe4];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IPromis.sol"
);

/// Dispatches an ABI-encoded call to the Promis precompile.
///
/// This surface is **read-only**. Balances are confidential: `balanceOf` returns
/// the account's ciphertext blob (`version || AEAD-ct`) for the caller to decrypt
/// with its view key. All state changes go through the enclave-backed
/// [`crate::api`] (called cross-crate by the factories), never this ABI.
pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    data: &[u8],
    _caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_primitives::dispatch::reject_value(&value)?;
    dispatch_call(data, IPromis::IPromisCalls::abi_decode, |call| {
        let promis = Promis::new(storage);
        use IPromis::IPromisCalls::*;
        match call {
            name(_) => metadata::<IPromis::nameCall>(|| Ok(promis.name().to_string())),
            symbol(_) => metadata::<IPromis::symbolCall>(|| Ok(promis.symbol().to_string())),
            decimals(_) => metadata::<IPromis::decimalsCall>(|| Ok(promis.decimals())),
            totalSupply(_) => metadata::<IPromis::totalSupplyCall>(|| promis.total_supply()),

            // Confidential read - return ciphertext; decrypt client-side.
            balanceOf(c) => view(c, |c| promis.balance_ct_of(c.account).map(Bytes::from)),
            opNonceOf(c) => view(c, |c| promis.op_nonce_of(c.account)),

            supportsInterface(c) => view(c, |c| {
                let id: [u8; 4] = c.interfaceId.0;
                Ok(id == ERC165_INTERFACE_ID || id == IPROMIS_INTERFACE_ID)
            }),
        }
    })
}
