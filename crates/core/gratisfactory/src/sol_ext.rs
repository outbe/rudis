//! Outbound sub-call ABI surfaces.
//!
//! External contract interfaces the gratisfactory runtime invokes via
//! `StorageHandle::staticcall`. NOT the precompile's own inbound ABI (which
//! lives in `precompile.rs::IGratisFactory`).

use alloy_sol_types::sol;

sol!("../../../contracts/tokens/src/interfaces/IReferenceCurrency.sol");
