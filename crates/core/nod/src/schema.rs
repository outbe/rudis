use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{derive_poseidon_entity_id, WwdEntityId};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_ocomp_protocol::nod_materialization::NodMaterializationHeadV1;
use outbe_primitives::addresses::NOD_ADDRESS;
use outbe_primitives::storage::types::Mapping;
use outbe_primitives::storage::types::StorageKey;
use outbe_primitives::time::WorldwideDay;
use serde::{Deserialize, Serialize};

/// Input for `NodContract::issue`. `nod_id` is derived inside the contract via
/// `NodContract::nod_id(owner, worldwide_day)`; the cost is derived from
/// `entry_price_minor` and `gratis_load_minor` (see
/// [`crate::api::cost_amount_minor`]). `issued_at` is stamped inside `issue`
/// from the current block timestamp and is not part of caller inputs.
#[derive(Debug, Clone, PartialEq)]
pub struct NodIssueParams {
    pub owner: Address,
    pub worldwide_day: WorldwideDay,
    pub league_id: u16,
    pub floor_price_minor: U256,
    pub gratis_load_minor: U256,
    pub entry_price_minor: U256,
    pub issuance_currency: u16,
    /// Reference currency (ISO 4217 numeric) propagated from the originating
    /// Tribute. Used for off-chain pricing references on the Nod.
    pub reference_currency: u16,
}

#[derive(Serialize, Deserialize)]
#[storage_record(exists_field = owner)]
pub struct NodItemState {
    #[key]
    pub nod_id: WwdEntityId,

    #[attribute(order = 0)]
    pub owner: Address,

    #[attribute(order = 1)]
    pub gratis_load_minor: U256,

    #[attribute(order = 2)]
    pub worldwide_day: WorldwideDay,

    #[attribute(order = 3)]
    pub league_id: u16,

    #[attribute(order = 4)]
    pub floor_price_minor: U256,

    #[attribute(order = 5)]
    pub bucket_key: B256,

    #[attribute(order = 6)]
    pub issuance_currency: u16,

    #[attribute(order = 7)]
    pub reference_currency: u16,

    #[attribute(order = 8)]
    pub issued_at: u64,
}

/// Bucket record exists while `total_nods > 0`; the body is dropped when the
/// last NOD in the bucket is mined.
#[derive(Serialize, Deserialize)]
#[storage_record(exists_field = total_nods)]
pub struct NodBucketState {
    #[key]
    pub bucket_key: B256,

    #[attribute(order = 0)]
    pub worldwide_day: WorldwideDay,

    #[attribute(order = 1)]
    pub floor_price_minor: U256,

    #[attribute(order = 2)]
    pub is_qualified: bool,

    #[attribute(order = 3)]
    pub total_nods: u64,

    #[attribute(order = 4)]
    pub entry_price_minor: U256,

    /// Denomination of `floor_price_minor`, propagated from the Nods in the
    /// bucket. The qualifier compares the floor against the COEN rate for this
    /// currency only, and the bin index is namespaced by it.
    #[attribute(order = 5)]
    pub reference_currency: u16,
}

/// Immutable owner projection frozen into one OCOMP activation precondition.
///
/// The values describe the per-WWD certified Nod namespace that OCM-18 later
/// advances atomically. They are active-result state, never a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodOcompTargetProjection {
    pub worldwide_day: WorldwideDay,
    pub target_generation: u64,
    pub namespace_root_before: B256,
}

/// Constant-size public state of one installed certified Nod generation.
///
/// Nod bodies and bucket bodies remain in authenticated result chunks. This
/// projection is the on-chain root authority used to select and prove those
/// bodies without materializing one storage record per Nod during activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodCertifiedGenerationProjection {
    pub worldwide_day: WorldwideDay,
    pub generation: u64,
    pub job_id: B256,
    pub program_semantics_hash: B256,
    pub protocol_bundle_hash: B256,
    pub nod_root: B256,
    pub bucket_root: B256,
    pub output_manifest_root: B256,
    pub tribute_count: u32,
    pub nod_count: u32,
    pub bucket_count: u32,
    pub nod_amount_total: U256,
    pub nod_gratis_consumed: U256,
    pub issued_at: u64,
    pub next_nod_ordinal: u32,
    pub last_progress_height: u64,
}

impl NodCertifiedGenerationProjection {
    /// Packs the owner-specific counts and logical issuance time into one slot.
    ///
    /// Layout, from least-significant bits: `issued_at:u64`,
    /// `tribute_count:u32`, `nod_count:u32`, `bucket_count:u32`; the upper
    /// 96 bits are reserved and must remain zero.
    #[must_use]
    pub fn metadata_word(&self) -> U256 {
        U256::from(self.issued_at)
            | (U256::from(self.tribute_count) << 64)
            | (U256::from(self.nod_count) << 96)
            | (U256::from(self.bucket_count) << 128)
    }
}

/// EVM storage layout for the Nod NFT contract.
///
/// Nod item and bucket bodies live in the compressed-entity store, not here.
/// Bucket key = keccak256(worldwide_day ++ floor_price_minor ++ reference_currency).
///
/// Unqualified buckets are tracked by a PancakeSwap-Liquidity-Book-style
/// 3-level radix-256 bitmap trie indexed by `floor_price_minor`. Each set
/// leaf bit identifies a non-empty price bin; per-bin bucket lists live in
/// `unqualified_bin_count` + `unqualified_bin_buckets`.
///
/// Prices in different currencies are not comparable, so every bin column is
/// namespaced by the bucket's `reference_currency` and each currency gets its
/// own independent trie. See `state::CurrencyBins`.
///
/// Field offsets are dense in `order` sequence, so this struct occupies slots
/// 0..=32 in declaration order. New fields append, which keeps the
/// genesis-seeded materialization FIFO counters at slots 19 and 20.
/// `adr006_tests::nod_contract_slot_layout_is_pinned` is the tripwire.
#[storage_schema]
#[contract(addr = NOD_ADDRESS)]
pub struct NodContract {
    // slot 0: total nod items
    #[attribute(order = 0)]
    pub total_supply: outbe_primitives::storage::dsl::Value<u64>,

    // --- Unqualified-bucket bin index (PancakeSwap LB-style trie) ---

    // slot 1: top-level 256-bit bitmap per currency. Bit `i` is set iff
    // `bin_tree_mid[(iso, i)]` is non-zero. Indexed by bits [16:24] of bin_id.
    #[attribute(order = 10)]
    pub bin_tree_root: outbe_primitives::storage::dsl::Map<u16, U256>,

    // slot 2: mid-level bitmaps. Key = `state::scoped(iso, bits [16:24] of
    // bin_id)`. Bit `j` is set iff `bin_tree_leaf[(key << 8) | j]` is non-zero.
    #[attribute(order = 11)]
    pub bin_tree_mid: outbe_primitives::storage::dsl::Map<u64, U256>,

    // slot 3: leaf-level bitmaps. Key = `state::scoped(iso, bits [8:24] of
    // bin_id)`. Bit `k` is set iff bin `(key << 8) | k` currently holds at
    // least one bucket_key.
    #[attribute(order = 12)]
    pub bin_tree_leaf: outbe_primitives::storage::dsl::Map<u64, U256>,

    // slot 4: per-bin count of bucket_keys parked in the bin, keyed by
    // `state::scoped(iso, bin_id)`.
    #[attribute(order = 13)]
    pub unqualified_bin_count: outbe_primitives::storage::dsl::Map<u64, u32>,

    // slot 5: per-bin bucket index - keccak(iso ++ bin_id ++ index) ->
    // bucket_key. Insertion-ordered; on qualification, the bin is either
    // drained wholesale (count := 0, bit cleared) or compacted (survivors
    // moved up).
    #[attribute(order = 14)]
    pub unqualified_bin_buckets: outbe_primitives::storage::dsl::Map<B256, B256>,

    // slot 6: next bucket position to inspect in a partially processed bin,
    // keyed by `state::scoped(iso, bin_id)`. This keeps begin-block
    // qualification bounded without starving later buckets when the tail bin
    // contains more work than one block can inspect.
    #[attribute(order = 17)]
    pub unqualified_bin_scan_cursor: outbe_primitives::storage::dsl::Map<u64, u32>,

    // Compact reversible WWD prefix for bucket identities parked by bucket_key.
    #[attribute(order = 18)]
    pub bucket_worldwide_day: Mapping<B256, WorldwideDay>,

    /// Per-WWD certified Nod namespace generation. Legacy issuance does not
    /// touch it; OCM-18 compare-and-sets it only through certified activation.
    #[attribute(order = 19)]
    pub ocomp_target_generation: outbe_primitives::storage::dsl::Map<WorldwideDay, u64>,

    /// Root of the certified Nod namespace at the generation above. Generation
    /// zero is represented canonically by the zero root.
    #[attribute(order = 20)]
    pub ocomp_namespace_root: outbe_primitives::storage::dsl::Map<WorldwideDay, B256>,

    /// Certified bucket root paired with `ocomp_namespace_root`.
    #[attribute(order = 21)]
    pub ocomp_bucket_root: outbe_primitives::storage::dsl::Map<WorldwideDay, B256>,

    /// Root of the authenticated result-chunk manifest for this generation.
    #[attribute(order = 22)]
    pub ocomp_output_manifest_root: outbe_primitives::storage::dsl::Map<WorldwideDay, B256>,

    /// Packed logical issuance time and exact Tribute/Nod/bucket counts.
    #[attribute(order = 23)]
    pub ocomp_generation_metadata: outbe_primitives::storage::dsl::Map<WorldwideDay, U256>,

    /// Exact certified Nod amount total.
    #[attribute(order = 24)]
    pub ocomp_nod_amount_total: outbe_primitives::storage::dsl::Map<WorldwideDay, U256>,

    /// Exact certified Gratis consumed by the Nod generation.
    #[attribute(order = 25)]
    pub ocomp_nod_gratis_consumed: outbe_primitives::storage::dsl::Map<WorldwideDay, U256>,

    /// Job whose certified result installed the generation.
    #[attribute(order = 26)]
    pub ocomp_materialization_job_id: outbe_primitives::storage::dsl::Map<WorldwideDay, B256>,

    /// Exact Lysis program semantics used to produce the certified generation.
    #[attribute(order = 27)]
    pub ocomp_materialization_program_semantics_hash:
        outbe_primitives::storage::dsl::Map<WorldwideDay, B256>,

    /// Next canonical Nod ordinal that has not yet been materialized.
    #[attribute(order = 28)]
    pub ocomp_materialization_next_nod_ordinal:
        outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    /// Block height of the latest successful materialization progress.
    #[attribute(order = 29)]
    pub ocomp_materialization_last_progress_height:
        outbe_primitives::storage::dsl::Map<WorldwideDay, u64>,

    /// Sequence of the current FIFO head. Genesis initializes it to one.
    #[attribute(order = 30)]
    pub ocomp_materialization_head_sequence: outbe_primitives::storage::dsl::Value<u64>,

    /// Next-free FIFO sequence. Genesis initializes it to one; equality with
    /// the head denotes an empty FIFO.
    #[attribute(order = 31)]
    pub ocomp_materialization_tail_sequence: outbe_primitives::storage::dsl::Value<u64>,

    /// Worldwide day stored at each occupied FIFO sequence.
    #[attribute(order = 32)]
    pub ocomp_materialization_queue_wwd: Mapping<u64, WorldwideDay>,

    /// Block height associated with the shared per-block attempt counter.
    #[attribute(order = 33)]
    pub ocomp_materialization_attempt_height: outbe_primitives::storage::dsl::Value<u64>,

    /// Number of materialization attempts observed at the height above.
    #[attribute(order = 34)]
    pub ocomp_materialization_attempt_count: outbe_primitives::storage::dsl::Value<u16>,

    // --- Bucket member index: lets the forfeit sweep enumerate a bucket's Nods,
    // which the compressed-entity store cannot do on its own. `WwdEntityId` is a
    // single storage word, so ids are stored whole and need no rebuilding.
    /// Mirror of the bucket body's `total_nods`, written from the loaded body so
    /// the two cannot drift.
    #[attribute(order = 35)]
    pub bucket_nod_count: outbe_primitives::storage::dsl::Map<B256, u32>,

    /// `bucket_nod_key(bucket_key, index)` -> Nod id. Insertion-ordered and
    /// swap-popped, matching the unqualified-bin index.
    #[attribute(order = 36)]
    pub bucket_nods: Mapping<B256, WwdEntityId>,

    /// Nod id -> position in its bucket, for O(1) swap-remove. A Nod belongs to
    /// exactly one bucket, so one global map suffices.
    #[attribute(order = 37)]
    pub bucket_nod_index: outbe_primitives::storage::dsl::Map<WwdEntityId, u32>,

    // --- Callable-bucket index: dense list of the buckets the daily call scan
    // visits. Membership invariant: a bucket is listed iff it has qualified and
    // still has members.
    #[attribute(order = 38)]
    pub callable_buckets: outbe_primitives::storage::dsl::List<B256>,

    #[attribute(order = 39)]
    pub callable_bucket_index: outbe_primitives::storage::dsl::Map<B256, u32>,

    /// `entry_price_minor x (100 + CALL_RATE_PCT) / 100`, snapshotted at qualification so
    /// the daily scan never loads a bucket body just to decide.
    #[attribute(order = 40)]
    pub callable_bucket_call_price: outbe_primitives::storage::dsl::Map<B256, U256>,

    /// Snapshotted with the call price; selects the `COEN/<iso>` VWAP series.
    #[attribute(order = 41)]
    pub callable_bucket_currency: Mapping<B256, u16>,

    /// Block timestamp the bucket was force-called; `0` until called.
    #[attribute(order = 42)]
    pub bucket_called_at: outbe_primitives::storage::dsl::Map<B256, u64>,

    /// Resume position of the daily call scan, stored as `index + 1`. Zero means
    /// the last pass completed and the next starts from the top.
    #[attribute(order = 43)]
    pub call_scan_cursor: outbe_primitives::storage::dsl::Value<u32>,

    /// Protocol bundle the certified generation was produced under. Materialization
    /// reads it here rather than from a runtime job registry, which the node is free
    /// to forget once every job is terminal.
    #[attribute(order = 44)]
    pub ocomp_materialization_protocol_bundle_hash:
        outbe_primitives::storage::dsl::Map<WorldwideDay, B256>,
}

impl<'storage> NodContract<'storage> {
    pub(crate) fn storage_handle(&self) -> outbe_primitives::storage::StorageHandle<'storage> {
        self.storage.clone()
    }

    /// Computes the bucket key from
    /// `(worldwide_day, floor_price_minor, reference_currency)`.
    ///
    /// The currency is part of the preimage because `floor_price_minor` is
    /// denominated in it: two Nods sharing a day and a floor value in
    /// different currencies are priced against different oracle rates and must
    /// not share a bucket. This is the single derivation - the Lysis program
    /// calls it too, so the off-chain and on-chain keys cannot drift.
    pub fn bucket_key(
        worldwide_day: WorldwideDay,
        floor_price_minor: U256,
        reference_currency: u16,
    ) -> B256 {
        use alloy_primitives::keccak256;
        let mut buf = [0u8; 38];
        buf[0..4].copy_from_slice(worldwide_day.key_bytes().as_slice());
        buf[4..36].copy_from_slice(&floor_price_minor.to_be_bytes::<32>());
        buf[36..38].copy_from_slice(&reference_currency.to_be_bytes());
        keccak256(buf)
    }

    /// Deterministic full-width Poseidon NOD identity derived from
    /// `(owner, worldwide_day)`. The typed Nod collection is its namespace.
    pub fn generate_nod_id(
        owner: Address,
        worldwide_day: WorldwideDay,
    ) -> outbe_primitives::error::Result<WwdEntityId> {
        derive_poseidon_entity_id(owner, worldwide_day)
            .map_err(|error| outbe_primitives::error::PrecompileError::Fatal(error.to_string()))
    }

    /// Reads the exact certified target state used by JobIntent construction.
    pub fn ocomp_target_projection(
        &self,
        worldwide_day: WorldwideDay,
    ) -> outbe_primitives::error::Result<NodOcompTargetProjection> {
        Ok(match self.ocomp_certified_generation(worldwide_day)? {
            Some(generation) => NodOcompTargetProjection {
                worldwide_day,
                target_generation: generation.generation,
                namespace_root_before: generation.nod_root,
            },
            None => NodOcompTargetProjection {
                worldwide_day,
                target_generation: 0,
                namespace_root_before: B256::ZERO,
            },
        })
    }

    /// Reads the constant-size active certified generation used by proof-backed
    /// Nod and bucket readers.
    pub fn ocomp_certified_generation(
        &self,
        worldwide_day: WorldwideDay,
    ) -> outbe_primitives::error::Result<Option<NodCertifiedGenerationProjection>> {
        let generation = self.ocomp_target_generation.read(&worldwide_day)?;
        let nod_root = self.ocomp_namespace_root.read(&worldwide_day)?;
        let bucket_root = self.ocomp_bucket_root.read(&worldwide_day)?;
        let output_manifest_root = self.ocomp_output_manifest_root.read(&worldwide_day)?;
        let metadata = self.ocomp_generation_metadata.read(&worldwide_day)?;
        let nod_amount_total = self.ocomp_nod_amount_total.read(&worldwide_day)?;
        let nod_gratis_consumed = self.ocomp_nod_gratis_consumed.read(&worldwide_day)?;
        let job_id = self.ocomp_materialization_job_id.read(&worldwide_day)?;
        let protocol_bundle_hash = self
            .ocomp_materialization_protocol_bundle_hash
            .read(&worldwide_day)?;
        let program_semantics_hash = self
            .ocomp_materialization_program_semantics_hash
            .read(&worldwide_day)?;
        let next_nod_ordinal = self
            .ocomp_materialization_next_nod_ordinal
            .read(&worldwide_day)?;
        let last_progress_height = self
            .ocomp_materialization_last_progress_height
            .read(&worldwide_day)?;

        if generation == 0 {
            if !nod_root.is_zero()
                || !bucket_root.is_zero()
                || !output_manifest_root.is_zero()
                || !metadata.is_zero()
                || !nod_amount_total.is_zero()
                || !nod_gratis_consumed.is_zero()
                || !job_id.is_zero()
                || !protocol_bundle_hash.is_zero()
                || !program_semantics_hash.is_zero()
                || next_nod_ordinal != 0
                || last_progress_height != 0
            {
                return Err(outbe_primitives::error::PrecompileError::Fatal(
                    "absent Nod OCOMP generation has residual state".into(),
                ));
            }
            return Ok(None);
        }

        if nod_root.is_zero()
            || bucket_root.is_zero()
            || output_manifest_root.is_zero()
            || !(metadata >> 160usize).is_zero()
            || job_id.is_zero()
            || protocol_bundle_hash.is_zero()
            || program_semantics_hash.is_zero()
        {
            return Err(outbe_primitives::error::PrecompileError::Fatal(format!(
                "installed Nod OCOMP generation is malformed: day {} generation {generation} \
                 nod_root {nod_root} bucket_root {bucket_root} manifest {output_manifest_root} \
                 job {job_id} bundle {protocol_bundle_hash} semantics {program_semantics_hash}",
                worldwide_day.value()
            )));
        }
        let issued_at = (metadata & U256::from(u64::MAX)).to::<u64>();
        let tribute_count = ((metadata >> 64usize) & U256::from(u32::MAX)).to::<u32>();
        let nod_count = ((metadata >> 96usize) & U256::from(u32::MAX)).to::<u32>();
        let bucket_count = ((metadata >> 128usize) & U256::from(u32::MAX)).to::<u32>();
        if issued_at == 0
            || tribute_count == 0
            || nod_count != tribute_count
            || bucket_count > nod_count
            || next_nod_ordinal > nod_count
            || last_progress_height == 0
        {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "installed Nod OCOMP generation metadata is malformed".into(),
            ));
        }

        Ok(Some(NodCertifiedGenerationProjection {
            worldwide_day,
            generation,
            job_id,
            protocol_bundle_hash,
            program_semantics_hash,
            nod_root,
            bucket_root,
            output_manifest_root,
            tribute_count,
            nod_count,
            bucket_count,
            nod_amount_total,
            nod_gratis_consumed,
            issued_at,
            next_nod_ordinal,
            last_progress_height,
        }))
    }

    /// Clears the transient proof authority after all certified NODs have been
    /// materialized into the ordinary ledger.
    pub fn clear_ocomp_certified_generation(
        &self,
        worldwide_day: WorldwideDay,
    ) -> outbe_primitives::error::Result<()> {
        self.ocomp_target_generation.write(&worldwide_day, 0)?;
        self.ocomp_namespace_root
            .write(&worldwide_day, B256::ZERO)?;
        self.ocomp_bucket_root.write(&worldwide_day, B256::ZERO)?;
        self.ocomp_output_manifest_root
            .write(&worldwide_day, B256::ZERO)?;
        self.ocomp_generation_metadata
            .write(&worldwide_day, U256::ZERO)?;
        self.ocomp_nod_amount_total
            .write(&worldwide_day, U256::ZERO)?;
        self.ocomp_nod_gratis_consumed
            .write(&worldwide_day, U256::ZERO)?;
        self.ocomp_materialization_job_id
            .write(&worldwide_day, B256::ZERO)?;
        self.ocomp_materialization_protocol_bundle_hash
            .write(&worldwide_day, B256::ZERO)?;
        self.ocomp_materialization_program_semantics_hash
            .write(&worldwide_day, B256::ZERO)?;
        self.ocomp_materialization_next_nod_ordinal
            .write(&worldwide_day, 0)?;
        self.ocomp_materialization_last_progress_height
            .write(&worldwide_day, 0)
    }

    /// Reads and validates the current canonical materialization FIFO head.
    pub fn ocomp_materialization_head(
        &self,
    ) -> outbe_primitives::error::Result<Option<NodMaterializationHeadV1>> {
        let head = self.ocomp_materialization_head_sequence.read()?;
        let tail = self.ocomp_materialization_tail_sequence.read()?;
        if head == 0 || tail == 0 || head > tail {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "Nod materialization FIFO bounds are malformed".into(),
            ));
        }
        if head == tail {
            return Ok(None);
        }
        let worldwide_day = self.ocomp_materialization_queue_wwd.read(&head)?;
        if worldwide_day.value() == 0 {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "Nod materialization FIFO head entry is missing".into(),
            ));
        }
        let projection = self
            .ocomp_certified_generation(worldwide_day)?
            .ok_or_else(|| {
                outbe_primitives::error::PrecompileError::Fatal(
                    "Nod materialization FIFO head projection is missing".into(),
                )
            })?;
        if projection.next_nod_ordinal >= projection.nod_count {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "Nod materialization FIFO head is already complete".into(),
            ));
        }
        Ok(Some(NodMaterializationHeadV1 {
            queue_sequence: head,
            job_id: projection.job_id,
            program_semantics_hash: projection.program_semantics_hash,
            worldwide_day: worldwide_day.value(),
            generation: projection.generation,
            nod_root: projection.nod_root,
            nod_count: projection.nod_count,
            next_nod_ordinal: projection.next_nod_ordinal,
            last_progress_height: projection.last_progress_height,
        }))
    }
}
