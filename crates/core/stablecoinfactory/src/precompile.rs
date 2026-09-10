use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolInterface;
use outbe_primitives::dispatch::{dispatch_call, view};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

pub use crate::abi::IStablecoinFactory;
use crate::errors::StablecoinFactoryError;
use crate::schema::StablecoinFactoryContract;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    _caller: Address,
    value: U256,
) -> Result<Bytes> {
    if !value.is_zero() {
        return Err(StablecoinFactoryError::UnexpectedValue { value }.into());
    }
    dispatch_call(
        data,
        |input| {
            let call = IStablecoinFactory::IStablecoinFactoryCalls::abi_decode(input)
                .map_err(|error| error.to_string())?;
            if call.abi_encode().as_slice() != input {
                return Err("non-canonical ABI calldata or trailing bytes".to_owned());
            }
            Ok(call)
        },
        |call| {
            use IStablecoinFactory::IStablecoinFactoryCalls::*;

            let factory = StablecoinFactoryContract::new(storage);
            match call {
                tokenCount(call) => view(call, |_| factory.token_count()),
                listTokens(call) => view(call, |call| factory.list_tokens(call.offset, call.limit)),
                tokenById(call) => view(call, |call| factory.token_by_id(call.tokenId)),
                tokenByTicker(call) => view(call, |call| factory.token_by_ticker(&call.ticker)),
                tokenIdOf(call) => view(call, |call| factory.token_id_of(call.token)),
                isStablecoin(call) => view(call, |call| factory.is_stablecoin(call.token)),
                predictTokenAddress(call) => view(call, |call| {
                    factory
                        .predict_token_address(call.issuer, &call.ticker)
                        .map(
                            |(token_id, token)| IStablecoinFactory::predictTokenAddressReturn {
                                tokenId: token_id,
                                token,
                            },
                        )
                }),
            }
        },
    )
}
