//! GemPosition NFT bookkeeping: issue (create record + owner index) and the
//! ERC-721-style read views. Positions are single-owner and non-transferable,
//! mirroring the `gem` crate's NFT ledger.

use alloy_primitives::{keccak256, Address, B256, U256};
use base64::Engine;
use outbe_primitives::error::Result;

use crate::errors::GemFactoryError;
use crate::schema::{GemFactoryContract, GemPosition};

impl GemFactoryContract<'_> {
    /// `keccak256(owner || index_be)` - per-owner position enumeration key.
    pub(crate) fn owner_index_key(owner: Address, index: u32) -> B256 {
        let mut buf = [0u8; 24];
        buf[0..20].copy_from_slice(owner.as_slice());
        buf[20..24].copy_from_slice(&index.to_be_bytes());
        keccak256(buf)
    }

    /// Issue a position NFT: create the record and append it to the merchant's
    /// owner index. Rejects a duplicate `position_id`.
    pub(crate) fn add_position(&mut self, pos: &GemPosition) -> Result<()> {
        if self.positions.exists(pos.position_id)? {
            return Err(GemFactoryError::PositionAlreadyExists.into());
        }
        self.positions.create(pos)?;

        let owner_count = self.position_owner_counts.read(&pos.merchant)?;
        self.position_owner_ids.write(
            &Self::owner_index_key(pos.merchant, owner_count),
            pos.position_id,
        )?;
        self.position_owner_counts
            .write(&pos.merchant, owner_count + 1)?;
        Ok(())
    }

    // --- Position NFT views (ERC-721-style, non-transferable) ---

    pub fn balance_of(&self, owner: Address) -> Result<u32> {
        self.position_owner_counts.read(&owner)
    }

    pub fn owner_of(&self, position_id: U256) -> Result<Address> {
        let pos = self
            .positions
            .get(position_id)?
            .ok_or(GemFactoryError::PositionNotFound)?;
        Ok(pos.merchant)
    }

    pub fn token_of_owner_by_index(&self, owner: Address, index: u32) -> Result<U256> {
        let count = self.position_owner_counts.read(&owner)?;
        if index >= count {
            return Err(GemFactoryError::IndexOutOfBounds.into());
        }
        self.position_owner_ids
            .read(&Self::owner_index_key(owner, index))
    }

    pub fn token_uri(&self, position_id: U256) -> Result<String> {
        let pos = self
            .positions
            .get(position_id)?
            .ok_or(GemFactoryError::PositionNotFound)?;
        // TODO: replace hand-rolled JSON with type-safe serialization (serde struct).
        let json = format!(
            "{{\"name\":\"GemPosition #{}\",\"attributes\":[{{\"trait_type\":\"merchant\",\"value\":\"{}\"}},{{\"trait_type\":\"source_intex_id\",\"value\":{}}},{{\"trait_type\":\"remaining_capacity\",\"value\":\"{}\"}},{{\"trait_type\":\"source_entry_price\",\"value\":\"{}\"}},{{\"trait_type\":\"source_floor_price\",\"value\":\"{}\"}},{{\"trait_type\":\"issuance_currency\",\"value\":{}}},{{\"trait_type\":\"reference_currency\",\"value\":{}}},{{\"trait_type\":\"parked_at\",\"value\":{}}}]}}",
            position_id,
            pos.merchant,
            pos.source_intex_id,
            pos.remaining_capacity,
            pos.source_entry_price,
            pos.source_floor_price,
            pos.issuance_currency,
            pos.reference_currency,
            pos.parked_at,
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        Ok(format!("data:application/json;base64,{}", encoded))
    }
}
