//! V2 Phase 1 accounting-progress integration tests.
//!
//! Each test maps to an Acceptance Criterion in the.

use alloy_primitives::Address;
use outbe_accounting::{
    read_last_accounted_block_number, record_phase1_progress, schema::Accounting,
};
use outbe_primitives::{
    accounting_progress::AccountingProgressView,
    addresses::ACCOUNTING_PROGRESS_ADDRESS,
    block::{BlockContext, BlockRuntimeContext},
    error::Result,
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};

const CHAIN_ID: u64 = 1;

fn with_ctx<R>(block_number: u64, f: impl FnOnce(&BlockRuntimeContext) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.enter(|handle: StorageHandle| {
        let block = BlockContext::empty_for_tests(block_number, 0, CHAIN_ID);
        let ctx = BlockRuntimeContext::new(block, handle);
        f(&ctx)
    })
}

/// Implementation of `AccountingProgressView` that holds a captured value.
/// Used to prove the trait surface compiles for downstream Cycle/Rewards
/// consumers and to exercise the `last_accounted_block_number` contract
/// without coupling tests to a specific reader.
struct StubProgressView(u64);

impl AccountingProgressView for StubProgressView {
    fn last_accounted_block_number(&self) -> Result<u64> {
        Ok(self.0)
    }
}

/// AC2 / INV1: the canonical address byte sequence is exactly `0x...EE04`
/// and user-issued CALLs to this address do NOT dispatch through the
/// `outbe-evm::precompiles::extend_outbe_precompiles` table.
#[test]
fn accounting_progress_address_is_ee04_and_user_calls_do_not_dispatch() {
    let expected: Address = "0x000000000000000000000000000000000000EE04"
        .parse()
        .expect("valid 0xEE04 address literal");
    assert_eq!(
        ACCOUNTING_PROGRESS_ADDRESS, expected,
        "INV1: ACCOUNTING_PROGRESS_ADDRESS must be exactly 0x...EE04",
    );

    // Real check: the address is NOT in the user precompile DISPATCH set, so a
    // CALL to it never routes into a precompile (it is a system-only marker).
    // Asserts the actual registered set, not source text.
    assert!(
        !outbe_evm::precompiles::outbe_precompile_addresses()
            .contains(&ACCOUNTING_PROGRESS_ADDRESS),
        "ACCOUNTING_PROGRESS_ADDRESS must NOT be a registered dispatching precompile \
         (outbe_precompile_addresses) - it is a system-only marker; user CALLs must not dispatch",
    );
}

/// AC3 / INV4: `record_phase1_progress` and
/// `read_last_accounted_block_number` round-trip the canonical slot 0.
#[test]
fn accounting_progress_slot0_roundtrips_last_accounted_block_number() {
    with_ctx(0, |ctx| {
        record_phase1_progress(ctx, 42).expect("write progress");
        let read = read_last_accounted_block_number(ctx).expect("read progress");
        assert_eq!(read, 42);

        // Subsequent overwrite reflects the new value.
        record_phase1_progress(ctx, 1_000_000).expect("overwrite progress");
        assert_eq!(
            read_last_accounted_block_number(ctx).expect("read overwritten progress"),
            1_000_000,
        );

        // Reading directly through the schema facade returns the same value.
        let accounting: Accounting<'_> = ctx.storage.contract::<Accounting<'_>>();
        let raw = accounting
            .last_accounted_block_number
            .read()
            .expect("raw slot read");
        assert_eq!(raw, 1_000_000);

        // The `AccountingProgressView` trait is the read surface Cycle and
        // Rewards consume; the stub here proves the trait compiles and the
        // returned value matches the storage.
        let view = StubProgressView(raw);
        assert_eq!(
            view.last_accounted_block_number().expect("view read"),
            1_000_000
        );
    });
}

/// AC4 (mirror) / INV3: `ACCOUNTING_PROGRESS_ADDRESS` is in the executor's
/// EIP-161 marker allowlist, ensuring slot 0 is preserved under state-root
/// cleanup. Asserts the real `OUTBE_RUNTIME_MARKER_ADDRESSES` const value.
#[test]
fn accounting_progress_address_is_eip161_preserved() {
    assert!(
        outbe_evm::executor::marker_addresses::OUTBE_RUNTIME_MARKER_ADDRESSES
            .contains(&ACCOUNTING_PROGRESS_ADDRESS),
        "INV3: ACCOUNTING_PROGRESS_ADDRESS must be in the executor's EIP-161 marker \
         allowlist (OUTBE_RUNTIME_MARKER_ADDRESSES) so slot 0 survives state-root cleanup",
    );
}

/// INV2 mirror: a fresh chain (no Phase 1 commit) reads `0` from slot 0.
#[test]
fn genesis_progress_reads_zero_before_first_phase1_write() {
    with_ctx(0, |ctx| {
        let initial = read_last_accounted_block_number(ctx).expect("read genesis slot 0");
        assert_eq!(
            initial, 0,
            "genesis slot 0 must read as zero before any Phase 1 commit",
        );

        // Reserved slots 1..=15 must also be zero on a fresh chain
        // (no field is declared at those slot indices in the schema).
        for slot_index in 1u64..=15 {
            let slot = ctx
                .storage
                .sload(
                    ACCOUNTING_PROGRESS_ADDRESS,
                    alloy_primitives::U256::from(slot_index),
                )
                .expect("read reserved slot");
            assert_eq!(
                slot,
                alloy_primitives::U256::ZERO,
                "INV2: reserved slot {slot_index} must be zero in genesis V2",
            );
        }
    });
}
