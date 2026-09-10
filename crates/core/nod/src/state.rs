use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{
    delete, derive_poseidon_entity_id, list, mint, read, update, BodyInput, EntityRef,
    ExecutionScope, IdPageRequest, ParentBodySource, QueryRef, VerifiedBody, WwdEntityId,
    MAX_ID_PAGE_LIMIT,
};
use outbe_primitives::error::Result;
use outbe_primitives::math::{
    reference_price,
    tree_math::{self, BinTreeStorage},
};

use crate::{
    api::{LoadedNodBucket, LoadedNodItem},
    constants::BIN_STEP_BP,
    errors::NodError,
    schema::{NodBucketState, NodContract, NodItemState},
};

impl NodContract<'_> {
    // --- ID helpers ---

    pub fn parse_nod_id(nod_id: &str) -> Result<WwdEntityId> {
        let trimmed = nod_id.strip_prefix("0x").unwrap_or(nod_id);
        if trimmed.len() != WwdEntityId::len_bytes() * 2 {
            return Err(NodError::InvalidNodIdLength.into());
        }
        trimmed
            .parse::<WwdEntityId>()
            .map_err(|_| NodError::InvalidNodIdHex.into())
    }

    // --- View functions ---

    pub fn total_supply(&self) -> Result<u64> {
        self.total_supply.read()
    }

    pub(crate) fn get_item_verified(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        nod_id: WwdEntityId,
    ) -> Result<Option<VerifiedBody>> {
        read(
            self.storage_handle(),
            scope,
            parent,
            EntityRef::NodItem(nod_id),
        )
    }

    pub(crate) fn get_bucket_verified(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        bucket_id: WwdEntityId,
    ) -> Result<Option<VerifiedBody>> {
        read(
            self.storage_handle(),
            scope,
            parent,
            EntityRef::NodBucket(bucket_id),
        )
    }

    pub(crate) fn read_all(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        owner: Option<Address>,
    ) -> Result<Vec<NodItemState>> {
        let query = owner.map_or(QueryRef::NodAll, QueryRef::NodByOwner);
        let mut records = Vec::new();
        let mut after = None;
        loop {
            let page = list(
                self.storage_handle(),
                scope,
                parent,
                query,
                IdPageRequest {
                    after,
                    limit: MAX_ID_PAGE_LIMIT,
                },
            )?;
            let next_after = page.next_after();
            let bodies = page.into_bodies();
            records.extend(
                bodies
                    .iter()
                    .map(nod_item_from_verified)
                    .collect::<Result<Vec<_>>>()?,
            );
            let Some(next) = next_after else {
                return Ok(records);
            };
            after = Some(next);
        }
    }

    /// Records compact issuance state and delegates both bodies to the generic lifecycle.
    pub(crate) fn record_nod_issued(
        &mut self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        item: &NodItemState,
        entry_price_minor: U256,
    ) -> Result<()> {
        let canonical_id = derive_poseidon_entity_id(item.owner, item.worldwide_day)
            .map_err(|error| outbe_primitives::error::PrecompileError::Fatal(error.to_string()))?;
        if item.nod_id != canonical_id {
            return Err(outbe_primitives::error::PrecompileError::Fatal(format!(
                "Nod item canonical identity mismatch: expected {canonical_id}, found {}",
                item.nod_id
            )));
        }
        // ISO 0 is not a currency, and its bin namespace aliases the
        // un-namespaced key while never appearing in the oracle's
        // reference-currency registry — a bucket parked there would be
        // invisible to the qualifier forever.
        if item.reference_currency == 0 {
            return Err(NodError::ZeroReferenceCurrency.into());
        }

        let canonical_bucket_key = Self::bucket_key(
            item.worldwide_day,
            item.floor_price_minor,
            item.reference_currency,
        );
        if item.bucket_key != canonical_bucket_key {
            return Err(outbe_primitives::error::PrecompileError::Fatal(format!(
                "Nod bucket identity mismatch: expected {canonical_bucket_key}, found {}",
                item.bucket_key
            )));
        }
        if self
            .get_item_verified(scope, parent, item.nod_id)?
            .is_some()
        {
            return Err(outbe_primitives::error::PrecompileError::Revert(
                "nod already exists".into(),
            ));
        }

        let bucket_id = WwdEntityId::from_day_and_digest(item.worldwide_day, item.bucket_key.0);
        let current_bucket = self.get_bucket_verified(scope, parent, bucket_id)?;
        let final_bucket = match current_bucket.as_ref() {
            Some(current) => {
                let mut bucket = nod_bucket_from_verified(current)?;
                bucket.total_nods = bucket.total_nods.checked_add(1).ok_or_else(|| {
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                        "Nod bucket {bucket_id} member count overflow"
                    ))
                })?;
                bucket
            }
            None => {
                let bucket = NodBucketState {
                    bucket_key: item.bucket_key,
                    worldwide_day: item.worldwide_day,
                    floor_price_minor: item.floor_price_minor,
                    is_qualified: false,
                    total_nods: 1,
                    entry_price_minor,
                    reference_currency: item.reference_currency,
                };
                self.bucket_worldwide_day
                    .write(&item.bucket_key, item.worldwide_day)?;
                self.insert_unqualified(
                    item.bucket_key,
                    item.floor_price_minor,
                    item.reference_currency,
                )?;
                bucket
            }
        };

        let supply = self.total_supply.read()?.checked_add(1).ok_or_else(|| {
            outbe_primitives::error::PrecompileError::BodyReadCorruption(
                "Nod total supply overflow during issuance".into(),
            )
        })?;
        self.total_supply.write(supply)?;
        self.insert_bucket_member(item.bucket_key, item.nod_id, final_bucket.total_nods)?;
        let canonical_item = crate::repository::canonical_item(item);
        mint(
            self.storage_handle(),
            scope,
            BodyInput::NodItem(&canonical_item),
        )?;
        let canonical_bucket = crate::repository::canonical_bucket(&final_bucket);
        if let Some(current) = current_bucket {
            update(
                self.storage_handle(),
                scope,
                current,
                BodyInput::NodBucket(&canonical_bucket),
            )
        } else {
            mint(
                self.storage_handle(),
                scope,
                BodyInput::NodBucket(&canonical_bucket),
            )
        }
    }

    /// Records compact removal state using capabilities retained by the caller's checks.
    pub(crate) fn record_nod_removed(
        &mut self,
        scope: &ExecutionScope,
        item: LoadedNodItem,
        bucket: LoadedNodBucket,
    ) -> Result<()> {
        let (item, current_item) = item.into_parts();
        let (mut bucket, current_bucket) = bucket.into_parts();
        let bucket_id = WwdEntityId::from_day_and_digest(item.worldwide_day, item.bucket_key.0);
        if current_bucket.entity_id() != bucket_id {
            return Err(
                outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                    "loaded Nod bucket {} does not match item bucket {bucket_id}",
                    current_bucket.entity_id()
                )),
            );
        }
        bucket.total_nods = bucket.total_nods.checked_sub(1).ok_or_else(|| {
            outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                "Nod bucket {bucket_id} has zero members during removal"
            ))
        })?;

        let supply = self.total_supply.read()?.checked_sub(1).ok_or_else(|| {
            outbe_primitives::error::PrecompileError::BodyReadCorruption(
                "Nod total supply underflow during removal".into(),
            )
        })?;
        self.total_supply.write(supply)?;
        self.remove_bucket_member(item.bucket_key, item.nod_id, bucket.total_nods)?;
        delete(self.storage_handle(), scope, current_item)?;
        if bucket.total_nods == 0 {
            self.bucket_worldwide_day.get(&item.bucket_key).delete()?;
            self.bucket_nod_count.clear(&item.bucket_key)?;
            self.remove_callable_bucket(item.bucket_key)?;
            delete(self.storage_handle(), scope, current_bucket)
        } else {
            let canonical = crate::repository::canonical_bucket(&bucket);
            update(
                self.storage_handle(),
                scope,
                current_bucket,
                BodyInput::NodBucket(&canonical),
            )
        }
    }

    // --- Bin index helpers (PancakeSwap LB-style ladder) -------------------

    /// Maps a six-decimal `floor_price_minor` (or oracle rate) to a 24-bit
    /// bin id on the LB log-spaced ladder. Saturates to `[0, MAX_BIN_ID]` -
    /// see `lb_math::get_id_from_price` for the deviation from LB's revert.
    pub fn price_to_bin(price_minor: U256) -> Result<u32> {
        if price_minor.is_zero() {
            return Ok(0);
        }
        reference_price::coen_iso_price_to_bin_id(price_minor, BIN_STEP_BP)
    }

    /// Inverse of `price_to_bin`: returns the lower edge of bin `bin_id` in
    /// six-decimal minor units. Diagnostic-only - `bin_to_price_floor` may
    /// fail at extreme bin ids whose LB-pow exponent exceeds `2^20`.
    pub fn bin_to_price_floor(bin_id: u32) -> Result<U256> {
        reference_price::bin_id_to_coen_iso_price(bin_id, BIN_STEP_BP)
    }

    /// Namespaces a bin-column key by the bucket's reference currency.
    ///
    /// Mapping keys are left-padded to 32 bytes before hashing, so a wider
    /// integer type alone namespaces nothing - the ISO has to occupy real
    /// high bits. Bin ids are 24-bit and the trie's mid/leaf keys are 16-bit,
    /// so the low 32 bits always hold `key` unambiguously. ISO `0` is the one
    /// value that would alias the un-namespaced key; `record_nod_issued`
    /// rejects it at the funnel so it can never be written.
    pub(crate) const fn scoped(reference_currency: u16, key: u32) -> u64 {
        ((reference_currency as u64) << 32) | key as u64
    }

    /// Storage key for the `index`-th bucket_key parked in bin `bin_id` of
    /// `reference_currency`. Mirrors the `owner_index_key` keccak-of-concat
    /// pattern.
    pub(crate) fn bin_index_key(reference_currency: u16, bin_id: u32, index: u32) -> B256 {
        let mut buf = [0u8; 10];
        buf[0..2].copy_from_slice(&reference_currency.to_be_bytes());
        buf[2..6].copy_from_slice(&bin_id.to_be_bytes());
        buf[6..10].copy_from_slice(&index.to_be_bytes());
        alloy_primitives::keccak256(buf)
    }

    /// Parks `bucket_key` in `reference_currency`'s bin for `floor_price` and
    /// marks the bin non-empty in that currency's bitmap trie. Called from
    /// `record_nod_issued` when a new bucket is created (i.e., the first NOD
    /// with a given `(wwd, floor_price, reference_currency)` triple).
    pub(crate) fn insert_unqualified(
        &mut self,
        bucket_key: B256,
        floor_price: U256,
        reference_currency: u16,
    ) -> Result<()> {
        let bin_id = Self::price_to_bin(floor_price)?;
        let scoped = Self::scoped(reference_currency, bin_id);
        let count = self.unqualified_bin_count.read(&scoped)?;
        self.unqualified_bin_buckets.write(
            &Self::bin_index_key(reference_currency, bin_id, count),
            bucket_key,
        )?;
        let next_count = count.checked_add(1).ok_or_else(|| {
            outbe_primitives::error::PrecompileError::Fatal(format!(
                "Nod unqualified bin {reference_currency}:{bin_id} member count overflow"
            ))
        })?;
        self.unqualified_bin_count.write(&scoped, next_count)?;
        tree_math::add(&CurrencyBins(self, reference_currency), bin_id)?;
        Ok(())
    }

    // --- Bucket member index ------------------------------------------------
    //
    // The compressed-entity store answers "give me this Nod" but never "give me
    // this bucket's Nods", so the forfeit sweep needs its own enumeration. The
    // shape mirrors the unqualified-bin index: a count plus a keccak-of-concat
    // positional map, with a reverse map for O(1) swap-remove.

    /// Storage key for the `index`-th Nod parked in `bucket_key`.
    pub(crate) fn bucket_nod_key(bucket_key: B256, index: u32) -> B256 {
        let mut buf = [0u8; 36];
        buf[0..32].copy_from_slice(bucket_key.as_slice());
        buf[32..36].copy_from_slice(&index.to_be_bytes());
        alloy_primitives::keccak256(buf)
    }

    /// Appends `nod_id` to its bucket's member list. `total_nods` is the loaded
    /// body's post-increment count, so the EVM mirror is written from the same
    /// value the body carries and the two cannot drift.
    pub(crate) fn insert_bucket_member(
        &mut self,
        bucket_key: B256,
        nod_id: WwdEntityId,
        total_nods: u64,
    ) -> Result<()> {
        let index = self.bucket_nod_count.read(&bucket_key)?;
        self.bucket_nods
            .write(&Self::bucket_nod_key(bucket_key, index), nod_id)?;
        self.bucket_nod_index.write(&nod_id, index)?;
        let next = index.checked_add(1).ok_or_else(|| {
            outbe_primitives::error::PrecompileError::Fatal(format!(
                "Nod bucket {bucket_key} member index overflow"
            ))
        })?;
        self.expect_member_parity(bucket_key, next, total_nods)?;
        self.bucket_nod_count.write(&bucket_key, next)?;
        Ok(())
    }

    /// Swap-removes `nod_id` from its bucket's member list. `total_nods` is the
    /// loaded body's post-decrement count.
    pub(crate) fn remove_bucket_member(
        &mut self,
        bucket_key: B256,
        nod_id: WwdEntityId,
        total_nods: u64,
    ) -> Result<()> {
        let index = self.bucket_nod_index.read(&nod_id)?;
        let last = self
            .bucket_nod_count
            .read(&bucket_key)?
            .checked_sub(1)
            .ok_or_else(|| {
                outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                    "Nod bucket {bucket_key} member count underflow during removal"
                ))
            })?;
        let last_key = Self::bucket_nod_key(bucket_key, last);
        if index != last {
            let moved = self.bucket_nods.read(&last_key)?;
            if moved.is_zero() {
                return Err(
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                        "Nod bucket {bucket_key} member slot {last} is empty during removal"
                    )),
                );
            }
            self.bucket_nods
                .write(&Self::bucket_nod_key(bucket_key, index), moved)?;
            self.bucket_nod_index.write(&moved, index)?;
        }
        self.bucket_nods.write(&last_key, WwdEntityId::ZERO)?;
        self.bucket_nod_index.clear(&nod_id)?;
        self.expect_member_parity(bucket_key, last, total_nods)?;
        self.bucket_nod_count.write(&bucket_key, last)?;
        Ok(())
    }

    /// The forfeit sweep enumerates members through the EVM mirror but burns
    /// through the bucket body, so a divergence between the two would silently
    /// under- or over-burn. Fail loudly instead.
    fn expect_member_parity(&self, bucket_key: B256, members: u32, total_nods: u64) -> Result<()> {
        if u64::from(members) == total_nods {
            return Ok(());
        }
        Err(
            outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                "Nod bucket {bucket_key} member index holds {members} entries but the body \
                 counts {total_nods}"
            )),
        )
    }

    // --- Callable-bucket index ----------------------------------------------

    /// Arms a freshly qualified bucket for the daily call scan, snapshotting the
    /// terms the scan needs so it never has to load a bucket body to decide.
    pub(crate) fn insert_callable_bucket(
        &mut self,
        bucket_key: B256,
        call_price: U256,
        reference_currency: u16,
    ) -> Result<()> {
        let index = self.callable_buckets.len()?;
        self.callable_buckets.push(bucket_key)?;
        self.callable_bucket_index.write(&bucket_key, index)?;
        self.callable_bucket_call_price
            .write(&bucket_key, call_price)?;
        self.callable_bucket_currency
            .write(&bucket_key, reference_currency)?;
        Ok(())
    }

    /// Swap-removes a bucket from the callable list and clears its call state.
    /// No-op for a bucket that never qualified, so the removal funnel can call
    /// it unconditionally.
    pub(crate) fn remove_callable_bucket(&mut self, bucket_key: B256) -> Result<()> {
        let len = self.callable_buckets.len()?;
        let index = self.callable_bucket_index.read(&bucket_key)?;
        let listed = index < len
            && self
                .callable_buckets
                .get(index)?
                .is_some_and(|listed| listed == bucket_key);
        if listed {
            let last = len.checked_sub(1).ok_or_else(|| {
                outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                    "Nod callable list underflow removing bucket {bucket_key}"
                ))
            })?;
            if index != last {
                let moved = self.callable_buckets.get(last)?.ok_or_else(|| {
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                        "Nod callable list slot {last} is empty during removal"
                    ))
                })?;
                self.callable_buckets.set(index, moved)?;
                self.callable_bucket_index.write(&moved, index)?;
            }
            self.callable_buckets.pop()?;
        }
        self.callable_bucket_index.clear(&bucket_key)?;
        self.callable_bucket_call_price.clear(&bucket_key)?;
        self.callable_bucket_currency.get(&bucket_key).delete()?;
        self.bucket_called_at.clear(&bucket_key)?;
        Ok(())
    }
}

pub(crate) fn nod_item_from_verified(body: &VerifiedBody) -> Result<NodItemState> {
    let payload = body.payload().as_nod_item().ok_or_else(|| {
        outbe_primitives::error::PrecompileError::Fatal(
            "compressed-entity read returned a non-Nod-item payload".into(),
        )
    })?;
    Ok(crate::repository::from_canonical_item(payload.clone()))
}

pub(crate) fn nod_bucket_from_verified(body: &VerifiedBody) -> Result<NodBucketState> {
    let payload = body.payload().as_nod_bucket().ok_or_else(|| {
        outbe_primitives::error::PrecompileError::Fatal(
            "compressed-entity read returned a non-Nod-bucket payload".into(),
        )
    })?;
    Ok(crate::repository::from_canonical_bucket(payload.clone()))
}

// --- BinTreeStorage impl ---------------------------------------------------
//
// Adapter between one currency's slice of the contract's three bin-tree
// storage columns and the `tree_math::BinTreeStorage` trait. Mirrors
// `outbe_intexfactory::state::QualifiedBinTree`, which runs two tries on one
// contract the same way.
//
// The trait functions take `&self` - storage writes go through the DSL's
// interior-mutable `StorageHandle`, so no `&mut` is needed at any call site.
// Construct the view inline at each `tree_math` call rather than binding it,
// so it never conflicts with a `&mut NodContract` borrow.

pub(crate) struct CurrencyBins<'a, 'storage>(pub(crate) &'a NodContract<'storage>, pub(crate) u16);

impl BinTreeStorage for CurrencyBins<'_, '_> {
    fn read_root(&self) -> Result<U256> {
        self.0.bin_tree_root.read(&self.1)
    }
    fn write_root(&self, value: U256) -> Result<()> {
        self.0.bin_tree_root.write(&self.1, value)
    }
    fn read_mid(&self, key: u32) -> Result<U256> {
        self.0.bin_tree_mid.read(&NodContract::scoped(self.1, key))
    }
    fn write_mid(&self, key: u32, value: U256) -> Result<()> {
        self.0
            .bin_tree_mid
            .write(&NodContract::scoped(self.1, key), value)
    }
    fn read_leaf(&self, key: u32) -> Result<U256> {
        self.0.bin_tree_leaf.read(&NodContract::scoped(self.1, key))
    }
    fn write_leaf(&self, key: u32, value: U256) -> Result<()> {
        self.0
            .bin_tree_leaf
            .write(&NodContract::scoped(self.1, key), value)
    }
}
