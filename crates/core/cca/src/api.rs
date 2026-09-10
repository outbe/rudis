//! Cross-module API for the CCA registry.
//!
//! Neighbouring modules (CredisFactory) ask about an agent's standing through
//! here rather than through the precompile ABI, and the precompile answers from
//! the same function - so the two views cannot diverge, and the stub below is
//! the single place the real registry has to replace.

use alloy_primitives::Address;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

pub use crate::precompile::ICca;

/// Registration state of `cca`.
///
/// TODO(cca): implement the registry. This must become a storage lookup that
/// returns [`ICca::State::Unknown`] for an address that never registered and the
/// recorded state otherwise. `Unknown` exists in the ABI precisely so an
/// unregistered agent is distinguishable from an active one - the stub cannot
/// make that distinction, so no caller may treat `Active` as proof of
/// registration until this is replaced.
pub fn cca_state(_storage: &StorageHandle<'_>, _cca: Address) -> Result<ICca::State> {
    Ok(ICca::State::Active)
}

/// Whether `cca` is in good standing and may originate.
///
/// Compares discriminants because the bare `sol!` enum derives no `PartialEq`;
/// adding `extra_derives` for one comparison is not worth the macro surface.
pub fn is_active(storage: &StorageHandle<'_>, cca: Address) -> Result<bool> {
    Ok(cca_state(storage, cca)? as u8 == ICca::State::Active as u8)
}
