//! Sub-call gas accounting module.
//!
//! Houses [`SubcallGasMeter`], a thin wrapper over [`revm::interpreter::Gas`]
//! that exposes the API surface needed by the outbe sub-call driver
//! ([`crate::sub_call::run_sub_call_impl`].
//!
//! ## Why a separate type
//!
//! The driver constructs and owns its own gas meter per sub-call frame so it
//! can:
//! 1. enforce the EIP-150 forward-cap independently of the outer interpreter's
//!    [`Gas`](revm::interpreter::Gas);
//! 2. capture the settlement triple (Success -> erase_cost + record_refund +
//!    add_state_gas_spent; Revert -> erase_cost only; Halt -> outer unchanged)
//! 3. propagate `reservoir` / `state_gas_spent` back to the outer meter via
//!    `handle_reservoir_remaining_gas`.
//!
//! ## Mirror discipline
//!
//! Every method delegates to the inner [`revm::interpreter::Gas`] instance;
//! semantics are byte-equal by construction. Mirror discipline is enforced
//! by 5 differential proptests in
//! `crates/blockchain/evm/tests/subcall_gas_meter_parity.rs`
//! AC3.

pub mod subcall_meter;

pub use subcall_meter::SubcallGasMeter;
