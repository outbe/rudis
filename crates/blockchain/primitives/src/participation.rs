//! Participation bitmap encoding/decoding for block `extra_data`.
//!
//! Encodes which validators participated in the previous block's finalization
//! as a compact bitmap in the current block's `extra_data` field.
//!
//! # Format
//!
//! ```text
//! [4 bytes: magic "OUTB"]
//! [1 byte:  version = 0x01]
//! [2 bytes: validator_count (big-endian u16)]
//! [ceil(validator_count / 8) bytes: signer bitmap]
//! [1 byte:  missed_proposer_count]
//! [20 * missed_proposer_count bytes: missed proposer addresses]
//! ```
//!
//! For 128 validators with 0 missed: 4 + 1 + 2 + 16 + 1 = 24 bytes.

use alloy_primitives::{Address, Bytes};

use crate::consensus::{ParticipationData, OUTBE_MAX_EXTRA_DATA_SIZE};
use crate::error::{PrecompileError, Result};

/// Magic bytes identifying Outbe participation data.
const MAGIC: &[u8; 4] = b"OUTB";
/// Current encoding version.
const VERSION: u8 = 0x01;

/// Encode participation bitmap into `extra_data` bytes (no missed proposers or byzantine).
pub fn encode_participation(validators: &[Address], signers: &[bool]) -> Result<Bytes> {
    encode_participation_extended(validators, signers, &[], &[])
}

/// Encode participation bitmap, missed proposer addresses, and byzantine validator
/// addresses into `extra_data` bytes.
pub fn encode_participation_extended(
    validators: &[Address],
    signers: &[bool],
    missed_proposers: &[Address],
    byzantine_validators: &[Address],
) -> Result<Bytes> {
    encode_participation_extended_with_limit(
        validators,
        signers,
        missed_proposers,
        byzantine_validators,
        OUTBE_MAX_EXTRA_DATA_SIZE,
    )
}

/// Encode participation metadata with an explicit byte budget.
pub fn encode_participation_extended_with_limit(
    validators: &[Address],
    signers: &[bool],
    missed_proposers: &[Address],
    byzantine_validators: &[Address],
    max_extra_data_size: usize,
) -> Result<Bytes> {
    // Return structured error instead of panicking on length mismatch.
    if validators.len() != signers.len() {
        return Err(PrecompileError::Fatal(format!(
            "validators/signers length mismatch: {} vs {}",
            validators.len(),
            signers.len()
        )));
    }

    if validators.len() > u16::MAX as usize {
        return Err(PrecompileError::Fatal(format!(
            "validator set too large for participation encoding: {}",
            validators.len()
        )));
    }

    if missed_proposers.len() > u8::MAX as usize {
        return Err(PrecompileError::Fatal(format!(
            "missed proposer list too large for participation encoding: {}",
            missed_proposers.len()
        )));
    }

    if byzantine_validators.len() > u8::MAX as usize {
        return Err(PrecompileError::Fatal(format!(
            "byzantine validator list too large for participation encoding: {}",
            byzantine_validators.len()
        )));
    }

    let count = validators.len() as u16;
    let bitmap_len = (count as usize).div_ceil(8);
    let header_len = 4 + 1 + 2 + bitmap_len + 1 + 1; // magic + ver + count + bitmap + 2 count bytes
    let total_len = header_len + (missed_proposers.len() * 20) + (byzantine_validators.len() * 20);

    if total_len > max_extra_data_size {
        return Err(PrecompileError::Fatal(format!(
            "participation metadata exceeds extra_data budget: {total_len} > {max_extra_data_size}"
        )));
    }

    let mut buf = Vec::with_capacity(total_len);

    // Magic
    buf.extend_from_slice(MAGIC);
    // Version
    buf.push(VERSION);
    // Validator count (big-endian)
    buf.extend_from_slice(&count.to_be_bytes());
    // Bitmap
    let mut bitmap = vec![0u8; bitmap_len];
    for (i, &signed) in signers.iter().enumerate() {
        if signed {
            bitmap[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    buf.extend_from_slice(&bitmap);
    // Missed proposer count + addresses
    buf.push(missed_proposers.len() as u8);
    for addr in missed_proposers {
        buf.extend_from_slice(addr.as_slice());
    }
    // Byzantine validator count + addresses
    buf.push(byzantine_validators.len() as u8);
    for addr in byzantine_validators {
        buf.extend_from_slice(addr.as_slice());
    }

    Ok(Bytes::from(buf))
}

/// Result of decoding extended participation data from `extra_data`.
pub struct DecodedParticipation {
    /// Participation data (voters + absent).
    pub participation: ParticipationData,
    /// Validators who missed their proposer slot (view gaps).
    pub missed_proposers: Vec<Address>,
    /// Validators caught in byzantine behavior (equivocation).
    pub byzantine_validators: Vec<Address>,
}

/// Decode participation data from `extra_data` bytes.
///
/// Returns `None` if the data doesn't contain valid participation information
/// (e.g. genesis blocks, blocks before consensus is active).
pub fn decode_participation(
    extra_data: &[u8],
    validators: &[Address],
) -> Option<ParticipationData> {
    decode_participation_extended(extra_data, validators).map(|d| d.participation)
}

/// Decode extended participation data (participation + missed proposers) from `extra_data`.
pub fn decode_participation_extended(
    extra_data: &[u8],
    validators: &[Address],
) -> Option<DecodedParticipation> {
    // Minimum: magic(4) + version(1) + count(2) + at least 1 bitmap byte
    if extra_data.len() < 8 {
        return None;
    }

    // Check magic
    if &extra_data[..4] != MAGIC {
        return None;
    }

    // Check version
    if extra_data[4] != VERSION {
        return None;
    }

    // Read validator count
    let count = u16::from_be_bytes([extra_data[5], extra_data[6]]) as usize;
    let bitmap_len = count.div_ceil(8);

    if extra_data.len() < 7 + bitmap_len {
        return None;
    }

    if count != validators.len() {
        return None;
    }

    let bitmap = &extra_data[7..7 + bitmap_len];

    let mut voters = Vec::new();
    let mut absent = Vec::new();

    for (i, addr) in validators.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        if bitmap[byte_idx] & (1 << bit_idx) != 0 {
            voters.push(*addr);
        } else {
            absent.push(*addr);
        }
    }

    // Decode missed proposers (if present).
    let missed_offset = 7 + bitmap_len;
    let (missed_proposers, after_missed) = if extra_data.len() > missed_offset {
        let missed_count = extra_data[missed_offset] as usize;
        let addrs_offset = missed_offset + 1;
        let needed = addrs_offset + missed_count * 20;
        if extra_data.len() >= needed {
            let addrs = (0..missed_count)
                .map(|i| {
                    let start = addrs_offset + i * 20;
                    Address::from_slice(&extra_data[start..start + 20])
                })
                .collect();
            (addrs, needed)
        } else {
            (Vec::new(), extra_data.len())
        }
    } else {
        (Vec::new(), extra_data.len())
    };

    // Decode byzantine validators (if present, after missed proposers section).
    let byzantine_validators = if extra_data.len() > after_missed {
        let byz_count = extra_data[after_missed] as usize;
        let addrs_offset = after_missed + 1;
        let needed = addrs_offset + byz_count * 20;
        if extra_data.len() >= needed {
            (0..byz_count)
                .map(|i| {
                    let start = addrs_offset + i * 20;
                    Address::from_slice(&extra_data[start..start + 20])
                })
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Some(DecodedParticipation {
        participation: ParticipationData { voters, absent },
        missed_proposers,
        byzantine_validators,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_all_present() {
        let validators: Vec<Address> = (0..4).map(Address::with_last_byte).collect();
        let signers = vec![true, true, true, true];

        let encoded = encode_participation(&validators, &signers).unwrap();
        let decoded = decode_participation(&encoded, &validators).unwrap();

        assert_eq!(decoded.voters.len(), 4);
        assert_eq!(decoded.absent.len(), 0);
    }

    #[test]
    fn test_roundtrip_partial() {
        let validators: Vec<Address> = (0..4).map(Address::with_last_byte).collect();
        let signers = vec![true, false, true, false];

        let encoded = encode_participation(&validators, &signers).unwrap();
        let decoded = decode_participation(&encoded, &validators).unwrap();

        assert_eq!(decoded.voters, vec![validators[0], validators[2]]);
        assert_eq!(decoded.absent, vec![validators[1], validators[3]]);
    }

    #[test]
    fn test_extended_with_missed_proposers() {
        let validators: Vec<Address> = (0..4).map(Address::with_last_byte).collect();
        let signers = vec![true, true, false, true];
        let missed = vec![Address::with_last_byte(0xAA), Address::with_last_byte(0xBB)];

        let encoded = encode_participation_extended(&validators, &signers, &missed, &[]).unwrap();
        let decoded = decode_participation_extended(&encoded, &validators).unwrap();

        assert_eq!(decoded.participation.voters.len(), 3);
        assert_eq!(decoded.participation.absent.len(), 1);
        assert_eq!(decoded.missed_proposers.len(), 2);
        assert_eq!(decoded.missed_proposers[0], Address::with_last_byte(0xAA));
        assert_eq!(decoded.missed_proposers[1], Address::with_last_byte(0xBB));
    }

    #[test]
    fn test_128_validators_with_missed() {
        let validators: Vec<Address> = (0..128u8).map(Address::with_last_byte).collect();
        let mut signers = vec![true; 128];
        signers[0] = false;
        signers[63] = false;
        signers[127] = false;

        let missed = vec![Address::with_last_byte(0xFF)];

        let encoded = encode_participation_extended(&validators, &signers, &missed, &[]).unwrap();
        // 4 + 1 + 2 + 16 + 1 + 20 + 1(byzantine count=0) = 45 bytes
        assert_eq!(encoded.len(), 45);

        let decoded = decode_participation_extended(&encoded, &validators).unwrap();
        assert_eq!(decoded.participation.voters.len(), 125);
        assert_eq!(decoded.participation.absent.len(), 3);
        assert_eq!(decoded.missed_proposers.len(), 1);
        assert_eq!(decoded.missed_proposers[0], Address::with_last_byte(0xFF));
    }

    /// Regression test: encode with sorted order, decode with independently sorted order.
    /// Before the fix, encoder used voters++absent order while decoder used on-chain index
    /// order, causing bitmap bits to map to wrong validators.
    #[test]
    fn test_encode_decode_sorted_independently() {
        let a = Address::with_last_byte(0x11);
        let b = Address::with_last_byte(0x22);
        let c = Address::with_last_byte(0x33);
        let d = Address::with_last_byte(0x44);

        let voters = [b, d];
        let absent = [a, c];

        // Encoder side: sort voters++absent
        let mut encode_order: Vec<Address> = voters.iter().chain(absent.iter()).copied().collect();
        encode_order.sort();
        let voter_set: std::collections::HashSet<_> = voters.iter().collect();
        let signers: Vec<bool> = encode_order
            .iter()
            .map(|addr| voter_set.contains(addr))
            .collect();
        let encoded = encode_participation(&encode_order, &signers).unwrap();

        // Decoder side: sort from a different initial order (simulating get_active_consensus_set)
        let mut decode_order = vec![c, a, d, b];
        decode_order.sort();
        let decoded = decode_participation(&encoded, &decode_order).unwrap();

        assert_eq!(decoded.voters.len(), 2);
        assert_eq!(decoded.absent.len(), 2);
        assert!(decoded.voters.contains(&b));
        assert!(decoded.voters.contains(&d));
        assert!(decoded.absent.contains(&a));
        assert!(decoded.absent.contains(&c));
    }

    /// Demonstrates the bug that existed before sorting was added:
    /// encoding in voters++absent order and decoding in a different order
    /// assigns bitmap bits to wrong validators.
    #[test]
    fn test_unsorted_order_causes_mismatch() {
        let a = Address::with_last_byte(0x11);
        let b = Address::with_last_byte(0x22);
        let c = Address::with_last_byte(0x33);
        let d = Address::with_last_byte(0x44);

        // Consensus says: b and d voted, a and c are absent.

        // OLD BUG: encode in voters++absent order (b, d, a, c) - NO sort.
        let unsorted_encode_order = vec![b, d, a, c];
        let signers_unsorted = vec![true, true, false, false];
        let encoded = encode_participation(&unsorted_encode_order, &signers_unsorted).unwrap();

        // Decoder uses canonical sorted order (a, b, c, d).
        let sorted_decode_order = vec![a, b, c, d];
        let decoded = decode_participation(&encoded, &sorted_decode_order).unwrap();

        // BUG: bitmap says positions 0,1 are signers -> maps to a,b in sorted order.
        // But the ACTUAL signers were b,d. So 'a' is falsely marked as voter
        // and 'd' is falsely marked as absent - wrong slashing!
        assert!(
            decoded.voters.contains(&a), // WRONG: a didn't vote
            "old bug: a falsely marked as voter"
        );
        assert!(
            decoded.absent.contains(&d), // WRONG: d DID vote
            "old bug: d falsely marked as absent"
        );
    }

    /// Length mismatch returns error instead of panicking.
    #[test]
    fn test_encode_length_mismatch_returns_error() {
        let validators: Vec<Address> = (0..4).map(Address::with_last_byte).collect();
        let signers = vec![true, true]; // 2 signers for 4 validators

        let result = encode_participation(&validators, &signers);
        assert!(
            result.is_err(),
            "length mismatch must return error, not panic"
        );
    }

    #[test]
    fn test_decode_invalid_magic() {
        let validators: Vec<Address> = vec![Address::ZERO];
        assert!(decode_participation(b"XXXX\x01\x00\x01\x80\x00", &validators).is_none());
    }

    #[test]
    fn test_decode_empty() {
        let validators: Vec<Address> = vec![Address::ZERO];
        assert!(decode_participation(&[], &validators).is_none());
    }

    #[test]
    fn test_backward_compat_no_missed_section() {
        // Simulate old format without missed proposer section
        let validators: Vec<Address> = (0..4).map(Address::with_last_byte).collect();
        let mut buf = Vec::new();
        buf.extend_from_slice(b"OUTB");
        buf.push(0x01);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.push(0b1111_0000); // all 4 signed
                               // No missed proposer section

        let decoded = decode_participation_extended(&buf, &validators).unwrap();
        assert_eq!(decoded.participation.voters.len(), 4);
        assert_eq!(decoded.missed_proposers.len(), 0);
    }

    #[test]
    fn test_empty_participation_encodes_minimal_header() {
        let encoded = encode_participation_extended(&[], &[], &[], &[]).unwrap();

        assert_eq!(encoded.len(), 9);
        assert_eq!(&encoded[..4], b"OUTB");

        let decoded = decode_participation_extended(&encoded, &Vec::<Address>::new()).unwrap();
        assert!(decoded.participation.voters.is_empty());
        assert!(decoded.participation.absent.is_empty());
    }

    #[test]
    fn test_encode_with_limit_returns_error_on_overflow() {
        let validators: Vec<Address> = (0..4).map(Address::with_last_byte).collect();
        let signers = vec![true, true, true, true];
        let missed = vec![Address::with_last_byte(0xAA); 2];

        let err = encode_participation_extended_with_limit(&validators, &signers, &missed, &[], 40)
            .unwrap_err();

        assert!(matches!(err, PrecompileError::Fatal(_)));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy for generating a validator set of size 1..=128.
    fn validators_and_signers() -> impl Strategy<Value = (Vec<Address>, Vec<bool>)> {
        (1..=128usize).prop_flat_map(|n| {
            let addrs = proptest::collection::vec(any::<[u8; 20]>().prop_map(Address::from), n);
            let signers = proptest::collection::vec(any::<bool>(), n);
            (addrs, signers)
        })
    }

    /// Strategy for generating missed proposer addresses (0..=10).
    fn missed_proposers() -> impl Strategy<Value = Vec<Address>> {
        proptest::collection::vec(any::<[u8; 20]>().prop_map(Address::from), 0..=10)
    }

    proptest! {
        /// Encoding then decoding must produce the original participation data.
        #[test]
        fn roundtrip_participation(
            (validators, signers) in validators_and_signers(),
        ) {
            let encoded = encode_participation(&validators, &signers).unwrap();
            let decoded = decode_participation(&encoded, &validators)
                .expect("decode must succeed for valid encoding");

            let expected_voters: Vec<Address> = validators.iter()
                .zip(signers.iter())
                .filter(|(_, &s)| s)
                .map(|(a, _)| *a)
                .collect();
            let expected_absent: Vec<Address> = validators.iter()
                .zip(signers.iter())
                .filter(|(_, &s)| !s)
                .map(|(a, _)| *a)
                .collect();

            prop_assert_eq!(decoded.voters, expected_voters);
            prop_assert_eq!(decoded.absent, expected_absent);
        }

        /// Extended encoding roundtrip preserves missed proposers too.
        #[test]
        fn roundtrip_extended(
            (validators, signers) in validators_and_signers(),
            missed in missed_proposers(),
        ) {
            let encoded = encode_participation_extended(&validators, &signers, &missed, &[]).unwrap();
            let decoded = decode_participation_extended(&encoded, &validators)
                .expect("decode must succeed for valid encoding");

            // Missed proposers capped at 255 by encoding.
            let expected_missed: Vec<Address> = missed.into_iter().take(255).collect();
            prop_assert_eq!(decoded.missed_proposers, expected_missed);
        }

        /// Encoding is deterministic - same inputs always produce identical bytes.
        #[test]
        fn encoding_deterministic(
            (validators, signers) in validators_and_signers(),
            missed in missed_proposers(),
        ) {
            let a = encode_participation_extended(&validators, &signers, &missed, &[]).unwrap();
            let b = encode_participation_extended(&validators, &signers, &missed, &[]).unwrap();
            prop_assert_eq!(a, b);
        }

        /// Decoding with wrong validator count returns None.
        #[test]
        fn wrong_validator_count_returns_none(
            (validators, signers) in validators_and_signers(),
        ) {
            let encoded = encode_participation(&validators, &signers).unwrap();
            // Add one extra validator to make the count mismatch.
            let mut wrong = validators.clone();
            wrong.push(Address::ZERO);
            prop_assert!(decode_participation(&encoded, &wrong).is_none());
        }

        /// Random garbage bytes never panic - they return None.
        #[test]
        fn random_bytes_no_panic(
            data in proptest::collection::vec(any::<u8>(), 0..512),
            validators in proptest::collection::vec(
                any::<[u8; 20]>().prop_map(Address::from),
                1..=128,
            ),
        ) {
            // Should not panic, may return None or Some.
            let _ = decode_participation_extended(&data, &validators);
        }
    }
}
