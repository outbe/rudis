//! Detection-level integration tests for the EIP-7702 sponsorship
//! pre-fee hook.
//!
//! The executor pre-fee path makes a single load-bearing decision based
//! on the signer's account `code`:
//!
//! ```text
//! signer.code.eip7702_address() == Some(ZEROFEE_ADDRESS)
//! ```
//!
//! If that probe returns the wrong answer we either bypass the
//! sponsorship path for a legitimately delegated user or - worse - apply
//! it to an unrelated account. These tests bolt the contract down using
//! the revm primitives the executor actually calls.

use alloy_primitives::{address, Address};
use outbe_primitives::addresses::ZEROFEE_ADDRESS;
use revm::state::Bytecode;

const OTHER_PRECOMPILE: Address = address!("0x000000000000000000000000000000000000ee05");

#[test]
fn freshly_constructed_delegation_returns_zerofee_address() {
    let code = Bytecode::new_eip7702(ZEROFEE_ADDRESS);
    assert_eq!(
        code.eip7702_address(),
        Some(ZEROFEE_ADDRESS),
        "executor pre-fee probe must recognise its own delegation target"
    );
    assert!(
        code.is_eip7702(),
        "Bytecode::new_eip7702 must produce EIP-7702 kind"
    );
}

#[test]
fn delegation_to_a_different_address_does_not_trigger_sponsorship() {
    let code = Bytecode::new_eip7702(OTHER_PRECOMPILE);
    assert_eq!(code.eip7702_address(), Some(OTHER_PRECOMPILE));
    assert_ne!(
        code.eip7702_address(),
        Some(ZEROFEE_ADDRESS),
        "an EOA delegated to a different system precompile must NOT \
         enter the sponsored path"
    );
}

#[test]
fn legacy_marker_bytecode_does_not_trigger_sponsorship() {
    // outbe seeds `0xef` marker bytecode at every precompile address to
    // keep accounts alive under EIP-161. The marker is legacy bytecode
    // and must not be misinterpreted as a delegation pointer.
    let marker = Bytecode::new_legacy([0xef].into());
    assert!(!marker.is_eip7702());
    assert_eq!(
        marker.eip7702_address(),
        None,
        "the EIP-161 marker bytecode must not look like an EIP-7702 delegation"
    );
}

#[test]
fn delegation_designator_byte_pattern_matches_expectation() {
    // `signer.code = 0xef0100 ++ ZEROFEE_ADDRESS` - 23 bytes total.
    // This is what the README and the executor code comments both
    // claim; lock it down so a future revm bump that changes the
    // designator layout breaks this test instead of silently breaking
    // the production probe.
    let code = Bytecode::new_eip7702(ZEROFEE_ADDRESS);
    let bytes = code.bytes_slice();
    assert_eq!(
        bytes.len(),
        23,
        "EIP-7702 delegation designator is 3 prefix bytes + 20-byte address"
    );
    assert_eq!(
        &bytes[..3],
        &[0xef, 0x01, 0x00],
        "EIP-7702 designator must begin with `0xef 0x01 0x00`"
    );
    assert_eq!(
        &bytes[3..],
        ZEROFEE_ADDRESS.as_slice(),
        "the trailing 20 bytes must equal the delegation target"
    );
}
