//! Zero-fee (EIP-7702 sponsored path) protocol constants.
//!
//! Split out of [`crate::addresses`] so the sponsored-target allowlist is easy
//! to find and review as its own protocol surface. The paymaster address
//! itself ([`crate::addresses::ZEROFEE_ADDRESS`]) and the policy log address
//! ([`crate::addresses::ZERO_FEE_POLICY_LOG_ADDRESS`]) stay with the other
//! precompile addresses; only the editable allowlist lives here.

use alloy_primitives::Address;

use crate::addresses::{
    AGENT_REWARD_ADDRESS, CREDIS_ADDRESS, CREDIS_FACTORY_ADDRESS, FIDELITY_ADDRESS,
    GEM_FACTORY_ADDRESS, GRATIS_ADDRESS, GRATIS_FACTORY_ADDRESS, NOD_ADDRESS, NOD_FACTORY_ADDRESS,
    PROMIS_ADDRESS, PROMIS_FACTORY_ADDRESS, TRIBUTE_ADDRESS, TRIBUTE_FACTORY_ADDRESS,
};

/// Whitelist of `to` addresses accepted on the EIP-7702 sponsored
/// (zero-fee) path enabled by [`crate::addresses::ZEROFEE_ADDRESS`].
///
/// Sponsored transactions are restricted to protocol-defined system
/// precompiles - they cannot enter arbitrary EVM execution. The
/// whitelist replaces a global per-block sponsored-tx cap by
/// structurally limiting the reachable code paths: an attacker with N
/// pre-funded addresses can still burn 8 free txs each, but each tx
/// can only invoke one of these audited entrypoints. The set is a
/// strict subset of the registered outbe precompile table because
/// validator-only entrypoints (rewards/staking/oracle) are not
/// reachable through the sponsored path - those have dedicated
/// authorization flows. Editing this list is part of the protocol
/// contract.
pub const SPONSORED_TARGET_WHITELIST: &[Address] = &[
    GRATIS_ADDRESS,
    GRATIS_FACTORY_ADDRESS,
    PROMIS_ADDRESS,
    PROMIS_FACTORY_ADDRESS,
    TRIBUTE_ADDRESS,
    NOD_ADDRESS,
    NOD_FACTORY_ADDRESS,
    CREDIS_ADDRESS,
    CREDIS_FACTORY_ADDRESS,
    TRIBUTE_FACTORY_ADDRESS,
    AGENT_REWARD_ADDRESS,
    FIDELITY_ADDRESS,
    GEM_FACTORY_ADDRESS,
];

/// Compile-time uniqueness check on [`SPONSORED_TARGET_WHITELIST`].
///
/// A duplicate would let the `O(n)` `contains` check silently accept
/// the same address twice and waste cycles, but more importantly
/// flag that an editor has copy-pasted a row by mistake. Anchoring
/// this at compile time makes the protocol contract self-policing.
const _: () = {
    let list = SPONSORED_TARGET_WHITELIST;
    let mut i = 0;
    while i < list.len() {
        let mut j = i + 1;
        while j < list.len() {
            // Compare the underlying 20-byte arrays - `Address` is
            // `repr(transparent)` over `[u8; 20]`.
            let a = list[i].0 .0;
            let b = list[j].0 .0;
            let mut k = 0;
            let mut eq = true;
            while k < 20 {
                if a[k] != b[k] {
                    eq = false;
                    break;
                }
                k += 1;
            }
            if eq {
                panic!("SPONSORED_TARGET_WHITELIST contains a duplicate address");
            }
            j += 1;
        }
        i += 1;
    }
};
