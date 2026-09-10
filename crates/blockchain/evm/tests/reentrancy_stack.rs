//! unit tests for [`outbe_evm::storage::ReentrancyStack`].
//!
//! Verifies:
//! 1. First entry succeeds and pushes the address onto the active stack.
//! 2. Second entry for the same address on a nested scope returns `None`.
//! 3. Drop pops the address regardless of unwind path (RAII).
//! 4. Multiple distinct addresses can coexist.
//! 5. Out-of-order drops (programmer error path) remove the right entry,
//!    not the top one.
//!
//! Each test must run on its own thread (or reset the stack at the start)
//! because [`outbe_evm::storage::ReentrancyStack`] uses a thread-local
//! `RefCell<Vec<Address>>`. We use `std::thread::spawn` to isolate.

use std::thread;

use alloy_primitives::Address;
use outbe_evm::storage::ReentrancyStack;

const ADDR_A: Address = Address::new([0xAA; 20]);
const ADDR_B: Address = Address::new([0xBB; 20]);

fn run_isolated<F: FnOnce() + Send + 'static>(test_body: F) {
    let handle = thread::spawn(test_body);
    handle.join().expect("test thread panicked");
}

#[test]
fn first_entry_returns_guard_and_pushes() {
    run_isolated(|| {
        assert_eq!(ReentrancyStack::depth(), 0, "fresh thread starts empty");
        let guard = ReentrancyStack::try_enter(ADDR_A);
        assert!(guard.is_some(), "first entry must succeed");
        assert!(ReentrancyStack::contains(ADDR_A));
        assert_eq!(ReentrancyStack::depth(), 1);
    });
}

#[test]
fn nested_entry_for_same_address_is_denied() {
    run_isolated(|| {
        let _outer = ReentrancyStack::try_enter(ADDR_A).expect("outer entry");
        let inner = ReentrancyStack::try_enter(ADDR_A);
        assert!(
            inner.is_none(),
            "nested entry for the same address must return None"
        );
        // Stack depth unchanged.
        assert_eq!(ReentrancyStack::depth(), 1);
    });
}

#[test]
fn guard_drop_pops_address() {
    run_isolated(|| {
        {
            let _g = ReentrancyStack::try_enter(ADDR_A).expect("enter");
            assert!(ReentrancyStack::contains(ADDR_A));
        }
        assert!(
            !ReentrancyStack::contains(ADDR_A),
            "guard Drop must pop the address"
        );
        assert_eq!(ReentrancyStack::depth(), 0);
    });
}

#[test]
fn distinct_addresses_coexist() {
    run_isolated(|| {
        let _a = ReentrancyStack::try_enter(ADDR_A).expect("A");
        let _b = ReentrancyStack::try_enter(ADDR_B).expect("B");
        assert!(ReentrancyStack::contains(ADDR_A));
        assert!(ReentrancyStack::contains(ADDR_B));
        assert_eq!(ReentrancyStack::depth(), 2);
    });
}

#[test]
fn out_of_order_drop_pops_right_entry() {
    run_isolated(|| {
        let a = ReentrancyStack::try_enter(ADDR_A).expect("A");
        let b = ReentrancyStack::try_enter(ADDR_B).expect("B");
        assert_eq!(ReentrancyStack::depth(), 2);
        drop(a);
        assert!(
            !ReentrancyStack::contains(ADDR_A),
            "dropping A must remove A even though B is still live"
        );
        assert!(ReentrancyStack::contains(ADDR_B));
        assert_eq!(ReentrancyStack::depth(), 1);
        drop(b);
        assert_eq!(ReentrancyStack::depth(), 0);
    });
}

#[test]
fn stack_is_isolated_per_thread() {
    use std::sync::mpsc;
    let (tx_main, rx_main) = mpsc::channel::<()>();
    let (tx_thread, rx_thread) = mpsc::channel::<()>();

    let other = thread::spawn(move || {
        let _g = ReentrancyStack::try_enter(ADDR_A).expect("thread enter");
        // Signal main thread that we are inside.
        tx_thread.send(()).unwrap();
        // Wait for main thread to check its own view.
        rx_main.recv().unwrap();
    });

    rx_thread.recv().unwrap();
    // From this thread's perspective the stack is empty even though the
    // spawned thread is holding ADDR_A.
    assert!(
        !ReentrancyStack::contains(ADDR_A),
        "thread-local isolation: ADDR_A must not appear on main thread"
    );
    assert_eq!(ReentrancyStack::depth(), 0);

    tx_main.send(()).unwrap();
    other.join().expect("spawned thread panicked");
}
