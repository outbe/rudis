//! Outbound sub-call ABI surfaces.
//!
//! Interfaces invoked by the gemfactory runtime via `StorageHandle::call`.
//! Not the precompile's own inbound ABI (which lives in
//! `precompile.rs::IGemFactory`).

use alloy_sol_types::sol;

sol!("../../../contracts/tokens/src/interfaces/IERC20.sol");

sol!("../../../contracts/tokens/src/interfaces/IReferenceCurrency.sol");

sol!("../../../contracts/intex/src/shared/interfaces/IIntexNFT1155.sol");
