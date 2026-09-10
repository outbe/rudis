//! Typed internal surfaces for Factory creation and token-state reads.
//!
//! There is deliberately no ABI dispatcher for initialization. The governed
//! Factory is the sole protocol module that calls [`StablecoinFactoryApi`].

use alloy_primitives::{Address, B256};
use outbe_primitives::error::Result;
use outbe_primitives::stablecoin::StablecoinCreatePayload;
use outbe_primitives::storage::StorageHandle;

use crate::schema::StablecoinContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryTokenInitialization {
    pub token_address: Address,
    pub token_id: B256,
    pub creation_protocol_version: u64,
    pub payload: StablecoinCreatePayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenIdentity {
    pub token_id: B256,
    pub name: String,
    pub symbol: String,
    pub currency: u16,
    pub decimals: u8,
    pub issuer: Address,
    pub creation_protocol_version: u64,
}

/// Narrow creation capability used by the governed Factory target.
///
/// This is trusted module-to-module Rust API, not a public precompile selector.
#[derive(Clone)]
pub struct StablecoinFactoryApi<'storage> {
    storage: StorageHandle<'storage>,
}

impl<'storage> StablecoinFactoryApi<'storage> {
    pub fn new(storage: StorageHandle<'storage>) -> Self {
        Self { storage }
    }

    pub fn initialize(&self, initialization: &FactoryTokenInitialization) -> Result<()> {
        StablecoinContract::new(self.storage.clone(), initialization.token_address)
            .initialize_from_factory(initialization)
    }
}

pub fn identity(storage: StorageHandle<'_>, token_address: Address) -> Result<TokenIdentity> {
    StablecoinContract::new(storage, token_address).identity()
}

pub fn schema_version(storage: StorageHandle<'_>, token_address: Address) -> Result<u64> {
    StablecoinContract::new(storage, token_address).validated_schema_version()
}
