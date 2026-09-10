//! Canonical TeeRegistry V1 ABI shared by the native precompile and host
//! operator tooling. Keeping one generated interface pins selectors and tuple
//! layout across consensus and transaction construction.

use alloy_sol_types::sol;

sol!(
    #![sol(extra_derives(Debug, PartialEq, Eq))]
    "../../../contracts/precompiles/src/ITeeRegistryV1.sol"
);
