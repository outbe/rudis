//! External contract ABIs invoked via `storage.call`.
//!
//! `OriginRouter` sends are relay-float-funded: called with value 0, the router quotes and
//! pays the bridge fee from its own native balance, so the precompile passes no fee/options/refund.

use alloy_sol_types::sol;

sol!("../../../contracts/intex/src/origin/interfaces/IOriginRouter.sol");
