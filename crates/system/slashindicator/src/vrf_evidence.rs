//! - wire codec for `InvalidVrfProofEvidence`.
//!
//! Carries everything `SlashIndicator.submitInvalidVrfProofEvidence(bytes)`
//! needs to:
//!   1. Run admissibility (size/age/epoch-lag/parent-canonical/proposer-attribution).
//!   2. Re-run `outbe_consensus::proof::verify_v2_proof` against the
//!      certified-parent metadata + cert bytes and classify any failure as
//!      a VRF-specific class (only VRF classes are slashable here).
//!   3. Dedup via `invalid_vrf_evidence_hash_v2(child_hash, phase1_tx_hash)`.
//!
//! Wire format is a versioned, length-prefixed binary blob (NOT serde, NOT
//! RLP). Field layout is byte-for-byte deterministic across validators:
//!
//! ```text
//!   magic        4 bytes  = b"IVE2"
//!   version      1 byte   = 0x02
//!   child_block_number   u64 BE
//!   child_block_hash     B256
//!   child_epoch          u64 BE
//!   parent_block_number  u64 BE
//!   parent_block_hash    B256
//!   failure_code         u16 BE   // sender hint; runtime re-classifies
//!   phase1_tx_len        u32 BE
//!   phase1_tx_bytes      [u8; phase1_tx_len]
//! ```
//!
//! Fixed prefix size = 4 + 1 + 8 + 32 + 8 + 8 + 32 + 2 + 4 = 99 bytes.
//! Trailing bytes are rejected. Total size is bounded by
//! `OutbeProtocolSchedule::invalid_vrf_evidence_max_bytes` at the call site;
//! the codec itself only enforces internal consistency.
//!
//! `failure_code` is a non-authoritative hint from the submitter. The
//! runtime ignores it and re-derives the VRF failure class from
//! `verify_v2_proof`'s `V2VerifyError`. Including it on the wire helps
//! off-chain tooling pre-filter without re-running the verifier.

use alloy_primitives::B256;
use outbe_primitives::error::{PrecompileError, Result};

/// Wire-format magic. The trailing `1` is the version family. A breaking
/// wire change bumps both the magic and the `VERSION` byte.
pub const MAGIC: [u8; 4] = *b"IVE2";

/// Current wire format version byte. Bumped together with `MAGIC` on any
/// breaking change.
pub const VERSION: u8 = 0x02;

/// Fixed-size prefix of the wire format (everything before
/// `phase1_tx_bytes`'s payload).
pub const FIXED_PREFIX_LEN: usize = 4    // magic
    + 1                                   // version
    + 8                                   // child_block_number
    + 32                                  // child_block_hash
    + 8                                   // child_epoch
    + 8                                   // parent_block_number
    + 32                                  // parent_block_hash
    + 2                                   // failure_code
    + 4; // phase1_tx_len

/// Decoded `InvalidVrfProofEvidence`. The signed Phase 1 transaction is the
/// single source of truth for metadata/proof bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidVrfProofEvidence {
    /// Child block number being accused (the block whose Phase 1 system
    /// transaction included an invalid VRF proof).
    pub child_block_number: u64,
    /// Hash of the child block. Pinned in the dedup key.
    pub child_block_hash: B256,
    /// Consensus epoch in which the child block lives. Used for epoch-lag
    /// admissibility and committee-snapshot lookup for proposer attribution.
    pub child_epoch: u64,
    /// Number of the canonical parent (=`child_block_number - 1` for V2,
    /// but stored explicitly so historical-lookup code does not have to
    /// re-derive it).
    pub parent_block_number: u64,
    /// Hash of the canonical parent. Used to feed `verify_v2_proof` with
    /// the same parent-hash binding the child's verifier would have used.
    pub parent_block_hash: B256,
    /// Submitter's hint about which VRF failure class they observed.
    /// Non-authoritative: the runtime ignores it and re-derives the class
    /// from `verify_v2_proof`. Wire-carried so off-chain tooling can
    /// pre-filter without re-running the verifier.
    pub failure_code: u16,
    /// Raw bytes of the child block's Phase 1 system transaction. The runtime
    /// recovers the proposer and decodes metadata from this signed envelope.
    pub phase1_tx_bytes: Vec<u8>,
}

impl InvalidVrfProofEvidence {
    /// Encodes evidence into its canonical wire form.
    ///
    /// Output is byte-for-byte deterministic - two encoders running on
    /// identical input produce identical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let total = FIXED_PREFIX_LEN + self.phase1_tx_bytes.len();
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION);
        buf.extend_from_slice(&self.child_block_number.to_be_bytes());
        buf.extend_from_slice(self.child_block_hash.as_slice());
        buf.extend_from_slice(&self.child_epoch.to_be_bytes());
        buf.extend_from_slice(&self.parent_block_number.to_be_bytes());
        buf.extend_from_slice(self.parent_block_hash.as_slice());
        buf.extend_from_slice(&self.failure_code.to_be_bytes());
        buf.extend_from_slice(&(self.phase1_tx_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.phase1_tx_bytes);
        buf
    }

    /// Decodes the wire form. Rejects:
    ///  * input shorter than `FIXED_PREFIX_LEN`
    ///  * wrong magic / unsupported version
    ///  * any length prefix that would read past end-of-input
    ///  * trailing bytes after the final `phase1_tx_bytes` payload
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < FIXED_PREFIX_LEN {
            return Err(PrecompileError::Revert(format!(
                "InvalidVrfProofEvidence: input too short ({} < {} bytes)",
                input.len(),
                FIXED_PREFIX_LEN,
            )));
        }
        let mut cur = 0usize;

        if input[cur..cur + 4] != MAGIC {
            return Err(PrecompileError::Revert(
                "InvalidVrfProofEvidence: bad magic".into(),
            ));
        }
        cur += 4;

        let version = input[cur];
        cur += 1;
        if version != VERSION {
            return Err(PrecompileError::Revert(format!(
                "InvalidVrfProofEvidence: unsupported version {version} (expected {VERSION})",
            )));
        }

        let child_block_number = read_u64_be(input, &mut cur);
        let child_block_hash = read_b256(input, &mut cur);
        let child_epoch = read_u64_be(input, &mut cur);
        let parent_block_number = read_u64_be(input, &mut cur);
        let parent_block_hash = read_b256(input, &mut cur);
        let failure_code = read_u16_be(input, &mut cur);

        let phase1_tx_bytes = read_length_prefixed(input, &mut cur, "phase1_tx")?;

        if cur != input.len() {
            return Err(PrecompileError::Revert(format!(
                "InvalidVrfProofEvidence: {} trailing bytes after phase1_tx",
                input.len() - cur,
            )));
        }

        Ok(Self {
            child_block_number,
            child_block_hash,
            child_epoch,
            parent_block_number,
            parent_block_hash,
            failure_code,
            phase1_tx_bytes,
        })
    }
}

// Field readers below assume the caller has already proved the fixed-prefix
// length is available; they only panic-free read with explicit Result on the
// variable-length section.

fn read_u16_be(input: &[u8], cur: &mut usize) -> u16 {
    let v = u16::from_be_bytes([input[*cur], input[*cur + 1]]);
    *cur += 2;
    v
}

fn read_u64_be(input: &[u8], cur: &mut usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&input[*cur..*cur + 8]);
    *cur += 8;
    u64::from_be_bytes(buf)
}

fn read_b256(input: &[u8], cur: &mut usize) -> B256 {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&input[*cur..*cur + 32]);
    *cur += 32;
    B256::from(buf)
}

fn read_length_prefixed(input: &[u8], cur: &mut usize, field: &str) -> Result<Vec<u8>> {
    // The fixed-prefix check guaranteed 4 bytes for the length itself.
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&input[*cur..*cur + 4]);
    *cur += 4;
    let len = u32::from_be_bytes(len_buf) as usize;

    if input.len() < cur.saturating_add(len) {
        return Err(PrecompileError::Revert(format!(
            "InvalidVrfProofEvidence: {field}_bytes length {len} exceeds remaining input \
             ({} bytes left)",
            input.len().saturating_sub(*cur),
        )));
    }
    let payload = input[*cur..*cur + len].to_vec();
    *cur += len;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    fn sample() -> InvalidVrfProofEvidence {
        InvalidVrfProofEvidence {
            child_block_number: 0x0102_0304_0506_0708,
            child_block_hash: b256!(
                "0x1111111111111111111111111111111111111111111111111111111111111111"
            ),
            child_epoch: 7,
            parent_block_number: 0x0102_0304_0506_0707,
            parent_block_hash: b256!(
                "0x2222222222222222222222222222222222222222222222222222222222222222"
            ),
            failure_code: 0xABCD,
            phase1_tx_bytes: vec![0xAA; 33],
        }
    }

    #[test]
    fn codec_roundtrip_preserves_all_fields() {
        let ev = sample();
        let encoded = ev.encode();
        let decoded = InvalidVrfProofEvidence::decode(&encoded).unwrap();
        assert_eq!(decoded, ev);
    }

    #[test]
    fn codec_is_byte_for_byte_deterministic() {
        let ev = sample();
        let a = ev.encode();
        let b = ev.encode();
        assert_eq!(a, b, "encode() must be byte-deterministic");
    }

    #[test]
    fn encoded_size_matches_formula() {
        let ev = sample();
        let encoded = ev.encode();
        let expected = FIXED_PREFIX_LEN + ev.phase1_tx_bytes.len();
        assert_eq!(encoded.len(), expected);
    }

    #[test]
    fn decode_rejects_short_input() {
        let buf = vec![0u8; FIXED_PREFIX_LEN - 1];
        let err = InvalidVrfProofEvidence::decode(&buf).unwrap_err();
        assert!(format!("{err}").contains("too short"));
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut encoded = sample().encode();
        encoded[0] ^= 0xFF;
        let err = InvalidVrfProofEvidence::decode(&encoded).unwrap_err();
        assert!(format!("{err}").contains("bad magic"));
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut encoded = sample().encode();
        encoded[4] = VERSION.wrapping_add(1);
        let err = InvalidVrfProofEvidence::decode(&encoded).unwrap_err();
        assert!(format!("{err}").contains("unsupported version"));
    }

    #[test]
    fn decode_rejects_length_prefix_overflowing_input() {
        let mut encoded = sample().encode();
        // The only length prefix (phase1_tx_len) is the final fixed-prefix
        // field. Bump it to a value that exceeds the actual payload room.
        let len_off = FIXED_PREFIX_LEN - 4;
        encoded[len_off..len_off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = InvalidVrfProofEvidence::decode(&encoded).unwrap_err();
        assert!(format!("{err}").contains("exceeds remaining input"));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut encoded = sample().encode();
        encoded.push(0xFF);
        let err = InvalidVrfProofEvidence::decode(&encoded).unwrap_err();
        assert!(format!("{err}").contains("trailing bytes"));
    }

    #[test]
    fn decode_accepts_empty_variable_fields() {
        let ev = InvalidVrfProofEvidence {
            child_block_number: 1,
            child_block_hash: B256::ZERO,
            child_epoch: 0,
            parent_block_number: 0,
            parent_block_hash: B256::ZERO,
            failure_code: 0,
            phase1_tx_bytes: Vec::new(),
        };
        let encoded = ev.encode();
        assert_eq!(encoded.len(), FIXED_PREFIX_LEN);
        let decoded = InvalidVrfProofEvidence::decode(&encoded).unwrap();
        assert_eq!(decoded, ev);
    }

    #[test]
    fn changing_any_field_changes_encoding() {
        // Pins that the codec doesn't accidentally collapse fields into
        // the same byte slot - a regression would mean two distinct
        // evidence blobs produce identical wire bytes.
        let base = sample().encode();

        let mut ev = sample();
        ev.child_block_number = ev.child_block_number.wrapping_add(1);
        assert_ne!(ev.encode(), base);

        let mut ev = sample();
        ev.child_block_hash = B256::ZERO;
        assert_ne!(ev.encode(), base);

        let mut ev = sample();
        ev.child_epoch += 1;
        assert_ne!(ev.encode(), base);

        let mut ev = sample();
        ev.parent_block_number = ev.parent_block_number.wrapping_add(1);
        assert_ne!(ev.encode(), base);

        let mut ev = sample();
        ev.parent_block_hash = B256::ZERO;
        assert_ne!(ev.encode(), base);

        let mut ev = sample();
        ev.failure_code = ev.failure_code.wrapping_add(1);
        assert_ne!(ev.encode(), base);

        let mut ev = sample();
        ev.phase1_tx_bytes.push(0xFF);
        assert_ne!(ev.encode(), base);
    }
}
