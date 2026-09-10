//! Module-local error types for ValidatorSet runtime/lifecycle.
//!
//! These are typed errors used at protocol-level boundaries that cannot be
//! expressed cleanly with [`outbe_primitives::error::PrecompileError`] alone
//! (for example: deterministic activation rejections in the consensus stack,
//! where the caller is `eyre`-based).
//!
//! `ActivationError` deliberately stays small and `#[non_exhaustive]` so that
//! future activation failure modes can be added without breaking matches.

use outbe_primitives::error::PrecompileError;

/// Deterministic activation-time failures for the validator set.
///
/// Returned by the boundary-activation path (`activate_reshared_set`) and the
/// VRF/DKG material activation path (`stack.rs`) so the consensus stack can
/// reject the activation without panicking the node.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ActivationError {
    /// `vrf_material_version` reached `u64::MAX` and cannot be incremented.
    ///
    /// The activation must reject deterministically
    /// instead of saturating - both proposer and validator paths see the same
    /// failure rather than diverging on a silently capped value.
    #[error("vrf material version overflow at reshare activation")]
    VrfVersionOverflow,
}

impl From<ActivationError> for PrecompileError {
    fn from(err: ActivationError) -> Self {
        // ActivationError is unrecoverable at the EVM layer: the runtime cannot
        // re-derive valid VRF material in-place. Surface it as fatal.
        PrecompileError::Revert(err.to_string())
    }
}
