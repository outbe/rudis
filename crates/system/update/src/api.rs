use alloy_primitives::U256;
use outbe_primitives::addresses::UPDATE_ADDRESS;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;

use crate::schema::Update;
use crate::ProtocolVersion;

/// Returns the currently active protocol version (`0` = baseline / pre-upgrade chain).
pub fn get_active_version(storage: StorageHandle) -> Result<ProtocolVersion> {
    Update::new(storage).get_active_version()
}

/// Resolves the active version from the exact state used by the current execution.
///
/// Unlike the generic storage codec, this rejects words wider than the canonical
/// `u32` protocol-version encoding instead of saturating them.
pub fn resolve_active_version(storage: StorageHandle) -> Result<ProtocolVersion> {
    let raw = storage.sload(UPDATE_ADDRESS, U256::ZERO)?;
    if raw > U256::from(u32::MAX) {
        return Err(PrecompileError::Fatal(
            "active Outbe protocol version does not fit the canonical u32 codec".into(),
        ));
    }
    Ok(ProtocolVersion::from_raw(raw.to::<u32>()))
}

/// Returns the version recorded at `height` (`0` when no upgrade was recorded there).
pub fn version_at_height(storage: StorageHandle, height: u64) -> Result<ProtocolVersion> {
    Update::new(storage).version_at_height(height)
}

/// Returns `true` when `version` matches the active on-chain version.
pub fn is_version_active_eq(storage: StorageHandle, version: ProtocolVersion) -> Result<bool> {
    Ok(Update::new(storage).get_active_version()? == version)
}

/// Returns `true` when the active on-chain version is >= `version`.
pub fn is_version_active_gte(storage: StorageHandle, version: ProtocolVersion) -> Result<bool> {
    Ok(Update::new(storage).get_active_version()? >= version)
}
