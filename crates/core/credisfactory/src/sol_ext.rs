//! Outbound sub-call ABI surfaces.
//!
//! These are the external contract interfaces the credisfactory runtime
//! invokes via `StorageHandle::call`. They are NOT the precompile's own
//! inbound ABI (which lives in `precompile.rs::ICredisFactory`).

use alloy_sol_types::sol;

sol!("../../../contracts/tokens/src/interfaces/IERC20.sol");

sol!("../../../contracts/tokens/src/interfaces/IReferenceCurrency.sol");
