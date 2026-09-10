//! ABI dispatch for the Desis precompile at `DESIS_ADDRESS`.
//!
//! Routes bid ingestion and clearing calls from OriginRouter to the
//! runtime. Encoding only; all logic lives in `runtime.rs`.

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};
use outbe_primitives::dispatch::{dispatch_call, mutate_void, reject_value, view};
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::runtime;
use crate::schema::BidData;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

/// Interface ID probed by `OriginRouter.wire` - `type(IDesis).interfaceId` of the
/// router-facing interface in contracts/intex/src/origin/interfaces/IDesis.sol
/// (XOR of its 4 function selectors).
pub(crate) const IDESIS_INTERFACE_ID: [u8; 4] = [0xf7, 0x8d, 0x15, 0x19];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IDesis.sol"
);

pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    dispatch_call(data, IDesis::IDesisCalls::abi_decode, |call| {
        use IDesis::IDesisCalls::*;
        match call {
            processBidsBatch(c) => mutate_void(c, caller, |sender, c| {
                let bids = bids_from_sol_arrays(&c.bidderAddresses, &c.packedBids)?;
                runtime::process_bids_batch(
                    storage.clone(),
                    sender,
                    c.worldwideDay.into(),
                    c.srcChainId,
                    c.relayGeneration,
                    c.batchIndex,
                    c.totalBatches,
                    bids,
                )
            }),
            processBidsDone(c) => mutate_void(c, caller, |sender, c| {
                runtime::process_bids_done(
                    storage.clone(),
                    sender,
                    c.worldwideDay.into(),
                    c.srcChainId,
                    c.relayGeneration,
                    c.totalBatches,
                    c.totalBids,
                )
            }),
            getAuctionStage(c) => view(c, |c| {
                use crate::schema::DesisContract;
                let contract = storage.contract::<DesisContract>();
                let stage = contract.read_stage(c.worldwideDay.into())?;
                Ok(IDesis::AuctionStage::try_from(stage as u8)
                    .unwrap_or(IDesis::AuctionStage::None))
            }),
            getBidsCount(c) => view(c, |c| {
                use crate::schema::DesisContract;
                let contract = storage.contract::<DesisContract>();
                let count = contract.day_bid_count.read(&c.worldwideDay.into())?;
                Ok(U256::from(count))
            }),
            getChainBidsCount(c) => view(c, |c| {
                use crate::schema::DesisContract;
                let contract = storage.contract::<DesisContract>();
                let key = DesisContract::chain_key(c.worldwideDay.into(), c.srcChainId);
                let count = contract.chain_bid_count.read(&key)?;
                Ok(U256::from(count))
            }),
            isChainDone(c) => view(c, |c| {
                use crate::schema::DesisContract;
                let contract = storage.contract::<DesisContract>();
                let key = DesisContract::chain_key(c.worldwideDay.into(), c.srcChainId);
                Ok(contract.chain_done.read(&key)? != 0)
            }),
            supportsInterface(c) => view(c, |c| {
                let id: [u8; 4] = c.interfaceId.0;
                Ok(id == ERC165_INTERFACE_ID || id == IDESIS_INTERFACE_ID)
            }),
        }
    })
}

/// Mirrors `BridgeMsgCodec.packBid`: one word per bid, low bits up -
/// reference(16) | issuance(16) | timestamp(32) | rate(32) | quantity(16).
fn bids_from_sol_arrays(bidders: &[Address], packed: &[U256]) -> Result<Vec<BidData>> {
    if bidders.len() != packed.len() {
        return Err(outbe_primitives::error::PrecompileError::Revert(
            "processBidsBatch: array length mismatch".into(),
        ));
    }
    Ok(bidders
        .iter()
        .zip(packed)
        .map(|(bidder, word)| {
            let limbs = word.as_limbs();
            let low = limbs[0];
            BidData {
                bidder_address: *bidder,
                reference_currency: low as u16,
                issuance_currency: (low >> 16) as u16,
                timestamp: (low >> 32) as u32,
                intex_bid_rate: (limbs[1]) as u32,
                intex_quantity: (limbs[1] >> 32) as u16,
            }
        })
        .collect())
}
