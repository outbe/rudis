//! Outbound sub-call ABI surfaces.
//!
//! These are the external contract interfaces the vaultrouter runtime
//! invokes via `StorageHandle::call` / `StorageHandle::staticcall`. They are
//! NOT the precompile's own inbound ABI (which lives in
//! `api.rs::IVaultRouter` and its optional cross-chain extension).
//!
//! The Solidity original used OpenZeppelin `SafeERC20` (`forceApprove`,
//! `safeTransferFrom`); here those become plain ERC-20 `approve` / `transferFrom`
//! calls whose boolean return is checked explicitly in the runtime.

use alloy_sol_types::sol;

sol!("../../../contracts/tokens/src/interfaces/IERC20.sol");

sol!("../../../contracts/precompiles/src/IVaultV2.sol");

sol!("../../../contracts/tokens/src/interfaces/IReferenceCurrency.sol");

sol!("../../../contracts/smart-account/src/interfaces/ITokenBundle.sol");

// Bridge sends go through `IERC7786GatewaySource`; the fee estimate comes from
// the gateway's `IGatewayQuote` extension. Both live in the same file.
//
// `docs = false`: this vendored ERC-7786 copy indents its NatSpec four spaces,
// which re-emits as a rustdoc code block and gets compiled as a doctest.
sol!(
    #![sol(docs = false)]
    "../../../contracts/crosschain/src/interfaces/IERC7786.sol"
);

sol!("../../../contracts/intex/src/target/interfaces/IERC7786TokenBridge.sol");
