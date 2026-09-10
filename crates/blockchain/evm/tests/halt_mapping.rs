//! halt-mapping unit coverage for
//! [`outbe_evm::precompiles::map_outbe_precompile_result`].
//!
//! Verifies every variant of `outbe_primitives::error::PrecompileError`
//! routes to the correct revm [`PrecompileResult`] form:
//!
//! - `Ok(bytes)` -> `Ok(PrecompileOutput::new(actual_gas, bytes, 0))`
//! - `OutOfGas` -> `Ok(Halt(OOG))` with zero gas reported
//! - `Revert(msg)` -> `Ok(Revert(Error(string)-encoded msg, actual_gas))`
//! - `RevertBytes(bytes)` -> `Ok(Revert(bytes, actual_gas))` (no re-encoding)
//! - `WriteProtection` -> `Ok(Halt(Other("state change during static call")))`
//! - `SubCall(_)` -> `Err(Fatal(_))` with sub-call error info
//! - `Unsupported` -> `Err(Fatal("precompile reported Unsupported"))`
//! - `Storage(s)` -> `Err(Fatal(s))` (fallback arm)
//! - `Fatal(s)` -> `Err(Fatal(s))` (fallback arm)

use alloy_primitives::Bytes;
use alloy_sol_types::{Revert, SolError};
use outbe_evm::precompiles::map_outbe_precompile_result;
use outbe_primitives::{error::PrecompileError, storage::SubCallError};
use revm::precompile::{PrecompileHalt, PrecompileStatus};

const ACTUAL_GAS: u64 = 1234;

#[test]
fn success_carries_actual_gas_and_bytes() {
    let bytes = Bytes::from_static(b"hello");
    let result = map_outbe_precompile_result(Ok(bytes.clone()), ACTUAL_GAS).expect("ok status");
    assert!(matches!(result.status, PrecompileStatus::Success));
    assert_eq!(result.gas_used, ACTUAL_GAS);
    assert_eq!(result.bytes, bytes);
}

#[test]
fn out_of_gas_halts_with_oog_status() {
    let result = map_outbe_precompile_result(Err(PrecompileError::OutOfGas), ACTUAL_GAS)
        .expect("OOG is non-fatal halt");
    match result.status {
        PrecompileStatus::Halt(reason) => {
            assert!(matches!(reason, PrecompileHalt::OutOfGas));
            assert!(reason.is_oog(), "OOG halt must classify as out-of-gas");
        }
        other => panic!("expected Halt(OOG), got {other:?}"),
    }
}

#[test]
fn revert_msg_becomes_error_string_bytes() {
    let msg = "explicit revert reason".to_string();
    let result = map_outbe_precompile_result(Err(PrecompileError::Revert(msg.clone())), ACTUAL_GAS)
        .expect("revert is non-fatal");
    assert!(matches!(result.status, PrecompileStatus::Revert));
    // Reason is ABI-encoded as the Solidity-standard `Error(string)`
    // (selector 0x08c379a0 ++ abi.encode(reason)) so ethers/viem/foundry
    // can decode it instead of seeing raw UTF-8 ("invalid data length").
    assert_eq!(
        result.bytes,
        Bytes::from(Revert::from(msg.clone()).abi_encode())
    );
    assert_eq!(&result.bytes[..4], &[0x08, 0xc3, 0x79, 0xa0]);
    let decoded = Revert::abi_decode(&result.bytes).expect("decodes as Error(string)");
    assert_eq!(decoded.reason, msg);
    assert_eq!(result.gas_used, ACTUAL_GAS);
}

#[test]
fn revert_bytes_preserves_raw_payload() {
    let raw = Bytes::from_static(&[0x01, 0x02, 0xFF, 0x00]);
    let result =
        map_outbe_precompile_result(Err(PrecompileError::RevertBytes(raw.clone())), ACTUAL_GAS)
            .expect("revert-bytes is non-fatal");
    assert!(matches!(result.status, PrecompileStatus::Revert));
    assert_eq!(result.bytes, raw, "RevertBytes must not re-encode");
    assert_eq!(result.gas_used, ACTUAL_GAS);
}

#[test]
fn write_protection_halts_with_static_call_message() {
    let result = map_outbe_precompile_result(Err(PrecompileError::WriteProtection), ACTUAL_GAS)
        .expect("write-protection is non-fatal halt");
    match result.status {
        PrecompileStatus::Halt(reason) => {
            // The message text is part of the public surface for test
            // assertion; if you rename the literal, update both call sites.
            let msg = format!("{reason:?}");
            assert!(
                msg.contains("state change during static call"),
                "expected static-call write-protection halt message, got {msg}"
            );
            assert!(!reason.is_oog(), "WriteProtection must NOT classify as OOG");
        }
        other => panic!("expected Halt(Other), got {other:?}"),
    }
}

#[test]
fn subcall_error_is_fatal_with_variant_info() {
    let result = map_outbe_precompile_result(
        Err(PrecompileError::SubCall(SubCallError::NotAvailable)),
        ACTUAL_GAS,
    );
    match result {
        Err(revm::precompile::PrecompileError::Fatal(msg)) => {
            assert!(
                msg.contains("sub-call"),
                "fatal message must mention sub-call, got {msg}"
            );
            assert!(
                msg.contains("NotAvailable"),
                "fatal message must surface the variant, got {msg}"
            );
        }
        other => panic!("expected Fatal, got {other:?}"),
    }
}

#[test]
fn unsupported_is_fatal_with_explanatory_message() {
    let result = map_outbe_precompile_result(Err(PrecompileError::Unsupported), ACTUAL_GAS);
    match result {
        Err(revm::precompile::PrecompileError::Fatal(msg)) => {
            assert!(
                msg.contains("Unsupported"),
                "fatal message must mention Unsupported, got {msg}"
            );
        }
        other => panic!("expected Fatal, got {other:?}"),
    }
}

#[test]
fn storage_error_falls_back_to_fatal() {
    let result = map_outbe_precompile_result(
        Err(PrecompileError::Storage("db read failed".into())),
        ACTUAL_GAS,
    );
    match result {
        Err(revm::precompile::PrecompileError::Fatal(msg)) => {
            assert!(
                msg.contains("db read failed"),
                "expected message echo, got {msg}"
            );
        }
        other => panic!("expected Fatal, got {other:?}"),
    }
}

#[test]
fn fatal_passes_through_to_fatal() {
    let result = map_outbe_precompile_result(
        Err(PrecompileError::Fatal("unrecoverable".into())),
        ACTUAL_GAS,
    );
    match result {
        Err(revm::precompile::PrecompileError::Fatal(msg)) => {
            // outbe `PrecompileError::Fatal` Display-formats as "fatal: <msg>";
            // the mapper feeds `e.to_string()` to revm Fatal, so the prefix
            // is expected. The test asserts the original payload survives
            // the round-trip rather than locking the exact format.
            assert!(
                msg.contains("unrecoverable"),
                "expected original payload to survive, got {msg}"
            );
        }
        other => panic!("expected Fatal, got {other:?}"),
    }
}
