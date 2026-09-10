//! Outbound sub-call ABI surfaces.
//!
//! Interfaces invoked by the paynote runtime via `StorageHandle::call`. Not
//! the precompile's own inbound ABI (which lives in `precompile.rs::IPayNote`).

use alloy_sol_types::sol;

sol!("../../../contracts/tokens/src/interfaces/IERC20.sol");
