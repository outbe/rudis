use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall, SolInterface};
use outbe_compressed_entities::{ExecutionScope, ParentBodySource};
use outbe_primitives::dispatch::{dispatch_call, mutate};
use outbe_primitives::error::Result;
use outbe_primitives::storage::gas::PRECOMPILE_BASE_GAS;

use crate::runtime::OfferTributeInput;
use crate::schema::TributeFactoryContract;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/ITributeFactory.sol"
);

/// `offerTribute` may execute the pinned UltraHonk verifier, so its base gas
/// must bound that work even before storage is available to inspect whether the
/// caller's L2 registration has ZK enabled.
pub fn base_gas(input: &[u8]) -> u64 {
    let Some(selector) = input.get(..4) else {
        return PRECOMPILE_BASE_GAS;
    };
    if selector == ITributeFactory::offerTributeCall::SELECTOR {
        outbe_primitives::storage::gas::ZK_VERIFY_GAS
    } else {
        PRECOMPILE_BASE_GAS
    }
}

/// Dispatch for the tribute factory precompile.
pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_primitives::dispatch::reject_value(&value)?;
    dispatch_call(
        data,
        ITributeFactory::ITributeFactoryCalls::abi_decode,
        |call| {
            use ITributeFactory::ITributeFactoryCalls::*;
            match call {
                offerTribute(c) => mutate(c, caller, |sender, c| {
                    let mut factory = TributeFactoryContract::new(storage);
                    factory
                        .offer_tribute(
                            scope,
                            parent,
                            OfferTributeInput {
                                caller: sender,
                                cipher_text: c.cipherText,
                                nonce: c.nonce,
                                ephemeral_pubkey: c.ephemeralPubkey,
                                worldwide_day: c.worldwideDay.into(),
                                tribute_currency: c.tributeCurrency,
                                reference_currency: c.referenceCurrency,
                                exclude_from_intex_issuance: c.excludeFromIntexIssuance,
                                zk_proof: c.zkProof,
                                zk_merkle_root: c.zkMerkleRoot,
                                signature: c.signature,
                            },
                        )
                        .map(|id| id.to_u256())
                }),
            }
        },
    )
}

#[cfg(test)]
mod gas_tests {
    use super::*;

    #[test]
    fn offer_tribute_charges_zk_verification_base_gas() {
        assert_eq!(
            base_gas(&ITributeFactory::offerTributeCall::SELECTOR),
            outbe_primitives::storage::gas::ZK_VERIFY_GAS
        );
        assert_eq!(base_gas(&[]), PRECOMPILE_BASE_GAS);
        assert_eq!(base_gas(&[0xde, 0xad, 0xbe, 0xef]), PRECOMPILE_BASE_GAS);
    }
}
