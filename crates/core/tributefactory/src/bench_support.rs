//! Narrow adapter used by the permanent Tribute creation benchmark.
//!
//! This module is absent from default builds. It exists so the external Cargo
//! benchmark can exercise the same crate-private processor-injection seam as
//! unit tests without making that seam part of TributeFactory's product API.

use alloy_primitives::{Address, Bytes, U256};
use outbe_compressed_entities::{ExecutionScope, ParentBodySource, WwdEntityId};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    error::{PrecompileError, Result},
    storage::StorageHandle,
};
use outbe_tee::protocol::{EncryptedTributeOffer, TributeOfferResult};

use crate::{runtime::OfferTributeInput, schema::TributeFactoryContract};

/// Complete caller-controlled input needed by the benchmark's successful path.
#[derive(Clone, Debug)]
pub struct BenchOfferInput {
    pub caller: Address,
    pub cipher_text: Bytes,
    pub nonce: Bytes,
    pub ephemeral_pubkey: U256,
    pub worldwide_day: WorldwideDay,
    pub tribute_currency: u16,
    pub reference_currency: u16,
    pub exclude_from_intex_issuance: bool,
    pub zk_proof: Bytes,
    pub zk_merkle_root: Bytes,
    pub signature: Bytes,
}

/// Execute one successful creation through the canonical TributeFactory
/// runtime with a caller-supplied benchmark processor. The production processor
/// contract is preserved while the node-local transport remains outside the
/// standalone Cargo benchmark.
pub fn execute_offer_with_processor(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    input: BenchOfferInput,
    processor: impl FnOnce(
        &[EncryptedTributeOffer],
    ) -> core::result::Result<Vec<TributeOfferResult>, PrecompileError>,
) -> Result<WwdEntityId> {
    TributeFactoryContract::new(storage).offer_tribute_with_processor(
        scope,
        parent,
        OfferTributeInput {
            caller: input.caller,
            cipher_text: input.cipher_text,
            nonce: input.nonce,
            ephemeral_pubkey: input.ephemeral_pubkey,
            worldwide_day: input.worldwide_day,
            tribute_currency: input.tribute_currency,
            reference_currency: input.reference_currency,
            exclude_from_intex_issuance: input.exclude_from_intex_issuance,
            zk_proof: input.zk_proof,
            zk_merkle_root: input.zk_merkle_root,
            signature: input.signature,
        },
        processor,
    )
}
