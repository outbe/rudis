//! removed the old Half C-parlia bounded backlog selector tests.
//!
//! Exact-parent certificate waiting now lives in
//! `finalization::selection::FinalizationSelector::await_parent_cert` and is
//! exercised through proposer/handler integration tests. This file is retained
//! only so stale references to the deleted backlog selector cannot silently keep
//! compiling under the old test name.

#[test]
fn legacy_async_backlog_selector_is_not_tested_here() {
    // Intentionally empty: the old 256-block backlog APIs are no longer part
    // of the production path.
}
