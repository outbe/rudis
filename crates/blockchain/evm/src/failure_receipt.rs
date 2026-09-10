//! Soft-failure receipt synthesis for the Outbe executor.
//!
//! When the executor rejects a transaction outside the EVM (zero-fee
//! policy classification or stateful authorization) or when a Phase 1-4
//! begin-zone system transaction fails to execute, the executor no longer
//! aborts the block build. It pushes a synthetic receipt with `success=0`
//! and exactly one log carrying a stable `code` plus a free-form `reason`
//! string, so the failure is observable via `eth_getTransactionReceipt`
//! and `eth_getLogs` without losing block-build availability.
//!
//! The single shared event is:
//!
//! ```solidity
//! event OutbeFailure(uint16 indexed code, string reason);
//! ```
//!
//! Each subsystem owns its own `code` allocation:
//!
//! - zero-fee policy rejections (`outbe-zerofee::ZeroFeePolicyError::code()`):
//!   100-199, emitted from
//!   [`outbe_primitives::addresses::ZERO_FEE_POLICY_LOG_ADDRESS`].
//! - Phase 1-4 system tx failures (`crate::executor::phase_failure_code()`):
//!   200-299, emitted from
//!   [`outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS`].
//!
//! Determinism of the synthetic log encoding is the contract that keeps
//! `receipts_root` byte-equal across proposer and validators; see EPIC

use alloy_primitives::{Address, Log, LogData};
use alloy_sol_types::{sol, SolEvent};

sol! {
    /// Soft-failure marker emitted alongside a `status=0` synthetic receipt.
    ///
    /// `code` is a stable per-subsystem `u16` identifier (zero-fee 100-199,
    /// phase failures 200-299). `reason` is the `Display` rendering of the
    /// underlying Rust error and is intended for human consumption - its
    /// exact text is byte-stable per compiled binary but is not part of the
    /// API contract; downstream consumers should match on `code`.
    #[derive(Debug, PartialEq)]
    event OutbeFailure(uint16 indexed code, string reason);
}

/// Topic0 of the `OutbeFailure` event.
pub const OUTBE_FAILURE_TOPIC0: alloy_primitives::B256 = OutbeFailure::SIGNATURE_HASH;

/// Builds the synthetic `OutbeFailure` log to attach to a soft-failure
/// receipt.
///
/// The encoding is purely a function of the inputs - no environment, no
/// allocation order, no hash-map iteration - so two nodes that build a
/// failure receipt for the same `(log_address, code, reason)` produce
/// byte-equal logs and therefore byte-equal receipts.
pub fn build_outbe_failure_log(log_address: Address, code: u16, reason: String) -> Log<LogData> {
    let event = OutbeFailure { code, reason };
    Log {
        address: log_address,
        data: event.encode_log_data(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, keccak256};

    #[test]
    fn topic0_matches_signature() {
        let expected = keccak256(b"OutbeFailure(uint16,string)");
        assert_eq!(OUTBE_FAILURE_TOPIC0, expected);
    }

    #[test]
    fn log_has_two_topics_with_code_indexed() {
        let log = build_outbe_failure_log(
            address!("0x000000000000000000000000000000000000EE06"),
            107,
            "zero-fee signer is not authorized for this transaction hook".to_string(),
        );
        assert_eq!(
            log.address,
            address!("0x000000000000000000000000000000000000EE06")
        );
        assert_eq!(log.data.topics().len(), 2);
        assert_eq!(log.data.topics()[0], OUTBE_FAILURE_TOPIC0);
        // topic1 is the padded u16 code (right-aligned big-endian per ABI).
        let mut expected_topic1 = [0u8; 32];
        expected_topic1[30] = (107u16 >> 8) as u8;
        expected_topic1[31] = (107u16 & 0xff) as u8;
        assert_eq!(log.data.topics()[1].as_slice(), expected_topic1);
        // data is ABI-encoded `(string)` - non-empty.
        assert!(!log.data.data.is_empty());
    }

    #[test]
    fn distinct_codes_produce_distinct_topic1() {
        let log_a = build_outbe_failure_log(Address::ZERO, 107, "a".to_string());
        let log_b = build_outbe_failure_log(Address::ZERO, 201, "a".to_string());
        assert_ne!(log_a.data.topics()[1], log_b.data.topics()[1]);
    }

    #[test]
    fn empty_reason_still_encodes() {
        let log = build_outbe_failure_log(Address::ZERO, 0, String::new());
        assert_eq!(log.data.topics().len(), 2);
        // Empty string ABI-encodes to 64 bytes: offset(32) + length=0(32).
        assert_eq!(log.data.data.len(), 64);
    }

    // -- Conformance snapshots -----------------------------
    //
    // Pin the exact byte layout of `OutbeFailure(code, reason)` for the four
    // most common production codes. If any of these tests breaks, every
    // historical receipt's `receipts_root` is at stake; fixing the test must
    // be a deliberate hard-fork-or-wipe decision, not a casual change.

    /// ABI-encodes a `string` payload into the `data` portion of the
    /// `OutbeFailure(uint16 indexed code, string reason)` log:
    /// `offset(32) || length(32) || padded utf8 bytes`.
    fn abi_encoded_string_data(reason: &str) -> Vec<u8> {
        let bytes = reason.as_bytes();
        let len = bytes.len();
        let padded_len = len.div_ceil(32) * 32;
        let mut data = Vec::with_capacity(64 + padded_len);
        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        data.extend_from_slice(&offset);
        let mut length = [0u8; 32];
        length[24..].copy_from_slice(&(len as u64).to_be_bytes());
        data.extend_from_slice(&length);
        data.extend_from_slice(bytes);
        data.resize(64 + padded_len, 0);
        data
    }

    fn expected_topic1_for(code: u16) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[30] = (code >> 8) as u8;
        t[31] = (code & 0xff) as u8;
        t
    }

    /// Code 107 (`UnauthorizedSigner`) emitted from the zero-fee log
    /// address - the exact scenario that halted the testnet on 2026-05-15.
    #[test]
    fn snapshot_zero_fee_unauthorized_signer_107() {
        let reason = "zero-fee signer is not authorized for this transaction hook";
        let log = build_outbe_failure_log(
            address!("0x000000000000000000000000000000000000EE06"),
            107,
            reason.to_string(),
        );
        assert_eq!(
            log.address,
            address!("0x000000000000000000000000000000000000EE06")
        );
        assert_eq!(log.data.topics().len(), 2);
        assert_eq!(log.data.topics()[0], OUTBE_FAILURE_TOPIC0);
        assert_eq!(log.data.topics()[1].as_slice(), expected_topic1_for(107));
        assert_eq!(
            log.data.data.as_ref(),
            abi_encoded_string_data(reason).as_slice()
        );
    }

    /// Code 108 (`AlreadyVoted`) - most common zero-fee oracle rejection.
    #[test]
    fn snapshot_zero_fee_already_voted_108() {
        let reason = "zero-fee oracle vote already exists for validator";
        let log = build_outbe_failure_log(
            address!("0x000000000000000000000000000000000000EE06"),
            108,
            reason.to_string(),
        );
        assert_eq!(log.data.topics()[1].as_slice(), expected_topic1_for(108));
        assert_eq!(
            log.data.data.as_ref(),
            abi_encoded_string_data(reason).as_slice()
        );
    }

    /// Code 201 (`PrecompileRevert`) emitted from the system-tx address -
    /// what a begin_block phase precompile revert looks like on-chain.
    #[test]
    fn snapshot_phase_precompile_revert_201() {
        let reason = "system tx CertifiedParentAccounting did not succeed at body_index=0: Revert { gas: ..., logs: [], output: 0x }";
        let log = build_outbe_failure_log(
            address!("0xff00000000000000000000000000000000000001"),
            201,
            reason.to_string(),
        );
        assert_eq!(
            log.address,
            address!("0xff00000000000000000000000000000000000001")
        );
        assert_eq!(log.data.topics()[1].as_slice(), expected_topic1_for(201));
        assert_eq!(
            log.data.data.as_ref(),
            abi_encoded_string_data(reason).as_slice()
        );
    }

    /// Code 204 (`InvariantViolation`) - phase precompile exceeded its
    /// declared gas budget. Synthesised, not from a runtime path.
    #[test]
    fn snapshot_phase_invariant_violation_204() {
        let reason = "system tx OracleSlashWindow exceeded artifact gas limit at body_index=3: 100000 > 80000";
        let log = build_outbe_failure_log(
            address!("0xff00000000000000000000000000000000000001"),
            204,
            reason.to_string(),
        );
        assert_eq!(log.data.topics()[1].as_slice(), expected_topic1_for(204));
        assert_eq!(
            log.data.data.as_ref(),
            abi_encoded_string_data(reason).as_slice()
        );
    }

    /// Reason text encoding is independent of the address - same `(code, reason)`
    /// produced from different addresses differ only in the `Log.address` field,
    /// not in the `data` payload.
    #[test]
    fn reason_encoding_is_address_independent() {
        let reason = "any";
        let a = build_outbe_failure_log(Address::ZERO, 107, reason.to_string());
        let b = build_outbe_failure_log(
            address!("0x000000000000000000000000000000000000EE06"),
            107,
            reason.to_string(),
        );
        assert_eq!(a.data.topics(), b.data.topics());
        assert_eq!(a.data.data, b.data.data);
        assert_ne!(a.address, b.address);
    }

    /// Reason text containing multi-byte UTF-8 must encode by byte length,
    /// not by character count - otherwise indexers see length / data mismatch.
    #[test]
    fn reason_encoding_is_byte_length_not_char_length() {
        // 1 char, 4 UTF-8 bytes.
        let reason = "🦀";
        let log = build_outbe_failure_log(Address::ZERO, 107, reason.to_string());
        assert_eq!(
            log.data.data.as_ref(),
            abi_encoded_string_data(reason).as_slice()
        );
        assert_eq!(reason.len(), 4);
    }
}
