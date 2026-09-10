//! ABI encoding for Oracle vote submission.
//!
//! Takes U256 fixed-point prices from the aggregator and encodes them
//! into `submitVote(ExchangeRateTuple[])` calldata.

use alloy_primitives::Address;
use alloy_sol_types::SolCall;
use outbe_primitives::asset_type::AssetType;

use crate::abi::IOracle;
use crate::aggregator::AggregatedPrice;

/// Render an already validated Oracle asset for log lines.
fn show_asset(address: Address) -> String {
    match AssetType::from(address) {
        AssetType::Native => outbe_primitives::units::NATIVE_TOKEN_SYMBOL.to_string(),
        AssetType::IsoCurrency(code) => code.to_string(),
        AssetType::ERC20(token) => token.to_string(),
    }
}

/// Decodes ABI-encoded `submitVote` calldata back into a human-readable string.
///
/// Shows exactly what goes on-chain: `COEN/840:rate,vol | ETH/840:rate,vol`
pub fn decode_vote_log(calldata: &[u8]) -> eyre::Result<String> {
    let call = IOracle::submitVoteCall::abi_decode(calldata)
        .map_err(|e| eyre::eyre!("decode submitVote: {e}"))?;
    let parts: Vec<String> = call
        .tuples
        .iter()
        .map(|t| {
            format!(
                "{}/{}:{},{}",
                show_asset(t.base),
                show_asset(t.quote),
                t.exchangeRate,
                t.volume
            )
        })
        .collect();
    Ok(parts.join(" | "))
}

/// Encodes aggregated prices into ABI-encoded `submitVote` calldata.
///
/// Prices and volumes are already in the pair's canonical integer scale from
/// the aggregator: six decimals for COEN/ISO, existing decimal18 otherwise.
pub fn encode_vote(prices: &[AggregatedPrice]) -> Vec<u8> {
    let tuples: Vec<IOracle::ExchangeRateTuple> = prices
        .iter()
        .map(|p| IOracle::ExchangeRateTuple {
            base: p.base,
            quote: p.quote,
            exchangeRate: p.price,
            volume: p.volume,
        })
        .collect();

    let call = IOracle::submitVoteCall { tuples };
    call.abi_encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn test_encode_vote_produces_calldata() {
        let prices = vec![AggregatedPrice {
            base: Address::ZERO,
            quote: AssetType::IsoCurrency(840).into(),
            price: U256::from(1_500_000u64),
            volume: U256::from(10_000_000_000u64),
        }];
        let calldata = encode_vote(&prices);
        // submitVote selector is first 4 bytes
        assert!(calldata.len() > 4);
        let decoded = IOracle::submitVoteCall::abi_decode(&calldata).unwrap();
        let expected_quote: Address = AssetType::IsoCurrency(840).into();
        assert_eq!(decoded.tuples.len(), 1);
        assert_eq!(decoded.tuples[0].base, Address::ZERO);
        assert_eq!(decoded.tuples[0].quote, expected_quote);
        assert_eq!(decoded.tuples[0].exchangeRate, U256::from(1_500_000u64));
        assert_eq!(decoded.tuples[0].volume, U256::from(10_000_000_000u64));
    }
}
