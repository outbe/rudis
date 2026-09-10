//! debug sub-call probe precompile.
//!
//! Registered at [`outbe_primitives::addresses::DEBUG_SUBCALL_PRECOMPILE_ADDRESS`]
//! (`0xF999`). Test-only - exercises the production sub-call path from a
//! live node so a localnet smoke flow can observe end-to-end success and
//! revert propagation without touching real economic precompiles.
//!
//! ## ABI
//!
//! Calldata: `abi.encode(address target, int256 x)` - exactly 64 bytes.
//! - `target` - Solidity contract implementing `inc(int256)` (the canonical
//!   `Counter` fixture lives at `0x...C0DE`, see `e2e/evm/README.md`).
//! - `x` - value to increment by; if the target rejects (e.g. with
//!   `revert NegativeNotAllowed(x)` on `x < 0`) the precompile surfaces
//!   the raw revert bytes back to the EVM caller via
//!   `PrecompileError::RevertBytes`.
//!
//! ## Logging
//!
//! Every step writes to the `outbe::debug_subcall` tracing target at
//! `info` level: entry, decoded args, child sub-call status, gas used,
//! returndata.

use alloy_primitives::{Address, Bytes, U256};
use outbe_primitives::{
    error::{PrecompileError, Result},
    storage::{StorageHandle, SubCallStatus},
};
use tracing::info;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

/// Selector for `inc(int256)` on the target Counter contract.
const INC_SELECTOR: [u8; 4] = [0x62, 0x38, 0x45, 0xd8];

/// Decoded calldata: `(address target, int256 x_raw)` where `x_raw` is the
/// raw 32-byte two's-complement encoding of the signed integer. We don't
/// interpret the sign - the target contract reverts on negative; we just
/// forward the bytes.
struct Args {
    target: Address,
    x_raw: U256,
}

fn decode_args(calldata: &[u8]) -> Result<Args> {
    if calldata.len() != 64 {
        return Err(PrecompileError::Revert(format!(
            "debug_subcall: calldata must be exactly 64 bytes (abi.encode(address, int256)), got {} bytes",
            calldata.len()
        )));
    }
    // First 32-byte word: address right-aligned in the high 12 bytes-zero,
    // low 20 bytes = address.
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&calldata[12..32]);
    let target = Address::from(addr_bytes);
    // Second 32-byte word: int256 raw two's complement.
    let mut x_be = [0u8; 32];
    x_be.copy_from_slice(&calldata[32..64]);
    let x_raw = U256::from_be_bytes(x_be);
    Ok(Args { target, x_raw })
}

/// Build calldata for `Counter.inc(int256 x)`: selector || x_raw (32 bytes).
fn encode_inc_call(x_raw: U256) -> Bytes {
    let mut buf = Vec::with_capacity(4 + 32);
    buf.extend_from_slice(&INC_SELECTOR);
    buf.extend_from_slice(&x_raw.to_be_bytes::<32>());
    Bytes::from(buf)
}

/// Public dispatch entrypoint - wired into [`crate::precompiles::outbe_dispatch_fn`].
pub fn dispatch(
    storage: StorageHandle<'_>,
    calldata: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    info!(
        target: "outbe::debug_subcall",
        ?caller,
        %value,
        calldata_len = calldata.len(),
        "debug_subcall: dispatch entry",
    );

    if !value.is_zero() {
        info!(
            target: "outbe::debug_subcall",
            %value,
            "debug_subcall: rejecting non-zero msg.value",
        );
        return Err(PrecompileError::Revert(
            "debug_subcall does not accept native value transfers".to_string(),
        ));
    }

    let Args { target, x_raw } = decode_args(calldata)?;
    info!(
        target: "outbe::debug_subcall",
        ?target,
        x_raw = %format_args!("{x_raw:#x}"),
        "debug_subcall: decoded args (target, int256 x)",
    );

    let child_calldata = encode_inc_call(x_raw);
    info!(
        target: "outbe::debug_subcall",
        child_calldata = %hex_preview(&child_calldata),
        "debug_subcall: built inc(int256) calldata for sub-call",
    );

    // Counter::inc(int256) is state-changing; STATICCALL would halt on its
    // first SSTORE. Use non-static call via try_call so we observe the full
    // SubCallOutput (status + gas accounting + revert payload). Default
    // gas forwarding is bounded by EIP-150 63/64 cap downstream.
    let output = storage
        .try_call(target, U256::ZERO, child_calldata)
        .map_err(|e| {
            info!(
                target: "outbe::debug_subcall",
                error = ?e,
                "debug_subcall: sub_call driver returned a structured error",
            );
            PrecompileError::SubCall(e)
        })?;

    info!(
        target: "outbe::debug_subcall",
        gas_used = output.gas_used,
        gas_refunded = output.gas_refunded,
        returndata_len = output.returndata.len(),
        "debug_subcall: sub_call returned",
    );

    match output.status {
        SubCallStatus::Success => {
            info!(
                target: "outbe::debug_subcall",
                "debug_subcall: child Counter.inc succeeded; returning empty payload",
            );
            Ok(Bytes::new())
        }
        SubCallStatus::Revert(payload) => {
            info!(
                target: "outbe::debug_subcall",
                payload = %hex_preview(&payload),
                "debug_subcall: child Counter.inc reverted; propagating raw revert bytes",
            );
            // Propagate revert payload byte-identical to what the child
            // returned. Caller can decode `NegativeNotAllowed(int256)` from
            // the first 4 bytes (selector 0x5d32a81e).
            Err(PrecompileError::RevertBytes(payload))
        }
        SubCallStatus::Halt(err) => {
            info!(
                target: "outbe::debug_subcall",
                halt = ?err,
                "debug_subcall: child Counter.inc halted; converting to revert",
            );
            Err(PrecompileError::Revert(format!(
                "debug_subcall: child halted: {err:?}"
            )))
        }
    }
}

fn hex_preview(b: &Bytes) -> String {
    if b.len() <= 64 {
        format!("0x{}", alloy_primitives::hex::encode(b))
    } else {
        format!(
            "0x{}...(+{} bytes)",
            alloy_primitives::hex::encode(&b[..64]),
            b.len() - 64
        )
    }
}
