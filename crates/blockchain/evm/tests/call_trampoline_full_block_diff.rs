//! **production-bound** skeleton for
//! the canonical Solidity-trampoline full-block byte-equal diff that
//! validates outbe Rust sub-call against an identical Solidity CALL.
//!
//! ## Lifecycle
//!
//! land the test file with `#[ignore]`
//! markers. T(-0.5) stubs return `Ok(empty)` and produce no real CALL,
//! so the two tx-sets diverge by design at this point - the assertion
//! shape is locked but the harness is dormant.
//!
//! acceptance: remove `#[ignore]` and plug in the real
//! block-construction + execution harness. Becomes the canonical
//! `call_trampoline_full_block_diff::byte_equal_state_root_receipts_root`
//! test referenced from.
//!
//! wires up CI to run this test alongside Det-1.
//!
//! ## Why land the skeleton at T0 and not just write a memo
//!
//! keeping a single test file means
//! - the assertion shape is reviewed once;
//! - T6 cannot accidentally diverge from the spec;
//! - removing `#[ignore]` is a single-line diff visible in code review;
//! - the test compiles continuously from T0 onwards, catching API drift
//!   in `storage.call` / `OutbePrecompileProvider::run` early.
//!
//! ## Expected scenarios (T6 will materialize)
//!
//! Three deterministic tx-sets, each compared block-A vs block-B with
//! byte-equal `state_root + receipts_root + logs_bloom +
//! cumulative_gas_used`:
//!
//! 1. **Zero-value CALL** - outbe Rust `storage.call(token, U256::ZERO,
//!    abi_encode(IERC20::balanceOf { account }))` vs Solidity
//!    `Trampoline.subcallTest(token, calldata, 100_000)`.
//! 2. **Value transfer** - outbe Rust `storage.call(recipient, U256::from(100),
//!    Bytes::new())` vs Solidity Trampoline forwarding 100 wei.
//! 3. **Sub-call reverts** - target reverts with payload; both paths
//!    must surface identical revert bytes and identical post-state.

use alloy_primitives::B256;

/// Placeholder post-state snapshot. T6 replaces this with the actual
/// execution-output capture from outbe's block-execution harness
/// (pattern in `crates/blockchain/evm/tests/e2e_system_tx.rs`).
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
struct PostState {
    state_root: B256,
    receipts_root: B256,
    logs_bloom: alloy_primitives::Bloom,
    cumulative_gas_used: u64,
}

/// Test-scenario identifier. Three scenarios listed in module docs.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum Scenario {
    /// Scenario 1 - zero-value CALL to an ERC20 view function.
    ZeroValueErc20View,
    /// Scenario 2 - native value transfer through CALL.
    NativeValueTransfer,
    /// Scenario 3 - sub-call target reverts with explicit payload.
    SubCallRevert,
}

#[test]
#[ignore = "Enabled by requires real run_sub_call_impl and \
            committed Trampoline.bytecode. At T0..T5 storage.call returns \
            Ok(empty), so the assertion is intentionally \
            dormant until the sub-call driver lands."]
fn byte_equal_state_root_receipts_root() {
    // Three scenarios must produce byte-equal post-state across the two
    // execution paths (outbe Rust sub-call vs Solidity Trampoline).
    for scenario in [
        Scenario::ZeroValueErc20View,
        Scenario::NativeValueTransfer,
        Scenario::SubCallRevert,
    ] {
        let block_a = build_block_via_outbe_rust_subcall(scenario);
        let block_b = build_block_via_solidity_trampoline(scenario);
        assert_eq!(
            block_a, block_b,
            "trampoline diff: block A (outbe Rust sub-call) and block B \
             (Solidity Trampoline) must produce byte-equal post-state for \
             scenario {:?}",
            scenario
        );
    }
}

/// Constructs and executes a block where the user-tx invokes an outbe
/// Rust precompile that performs `storage.call(...)`. Returns the
/// post-state snapshot.replaces the placeholder body
/// with the real block-execution harness.
#[allow(dead_code)]
fn build_block_via_outbe_rust_subcall(_scenario: Scenario) -> PostState {
    // T6: construct block per `crates/blockchain/evm/tests/e2e_system_tx.rs`
    // pattern with a user-tx targeting an outbe precompile that calls
    // `storage.call(token, value, calldata)`. Execute via
    // `OutbeEvmFactory::create_evm` + `OutbePrecompileProvider`. Capture
    // post-state from the executor result.
    //
    // Until then this function is unreachable due to `#[ignore]` on the
    // caller. Returning a fixed sentinel keeps the file compiling and
    // makes the placeholder visible in coverage tools.
    PostState {
        state_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: alloy_primitives::Bloom::ZERO,
        cumulative_gas_used: 0,
    }
}

/// Constructs and executes a block where the user-tx invokes a Solidity
/// `Trampoline.subcallTest(target, calldata, gas)` contract. Returns
/// the post-state snapshot for byte-equal comparison.
#[allow(dead_code)]
fn build_block_via_solidity_trampoline(_scenario: Scenario) -> PostState {
    // T6: deploy `localnet/fixtures/Trampoline.{sol,bytecode}` and execute the wrapped CALL on identical
    // pre-state. Capture post-state from the executor result.
    PostState {
        state_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: alloy_primitives::Bloom::ZERO,
        cumulative_gas_used: 0,
    }
}

#[cfg(test)]
mod compile_smoke {
    use super::*;

    /// Sanity: the placeholder `PostState` derives `Eq` so the
    /// `assert_eq!` in the ignored test compiles. Ensures T6 inherits a
    /// usable scaffold.
    #[test]
    fn post_state_eq_compiles() {
        let a = PostState {
            state_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: alloy_primitives::Bloom::ZERO,
            cumulative_gas_used: 0,
        };
        let b = PostState {
            state_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: alloy_primitives::Bloom::ZERO,
            cumulative_gas_used: 0,
        };
        assert_eq!(a, b);
    }
}
