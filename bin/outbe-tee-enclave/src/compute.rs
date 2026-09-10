//! Tribute computation - economics + `tribute_id`. Pure, deterministic, integer
//! (U256) only.
//!
//! Economics move the settlement->nominal computation **into the enclave**, faithfully replicating the host's current
//! `outbe-tributefactory::runtime` math, with two intentional differences:
//!
//!   - checked arithmetic (no panics, per project safety rules - the host code
//!     used unchecked ops); on overflow the offer is rejected, not aborted;
//!   - the exact WorldwideDay VWAP legs and reference S-curve are public inputs,
//!     read by the node from committed Oracle state and identical on every validator.
//!
//! `tribute_id` is a Poseidon-BN254 hash over sensitive decrypted data, so it is
//! computed only in the enclave.
//!
//! Settlement arithmetic uses checked `U256` operations. The module-level lint
//! below rejects floating-point arithmetic.

// Deny floating-point arithmetic in the enclave economics module.
// `clippy::` tool lints are accepted (ignored) by plain rustc.
#![deny(clippy::float_arithmetic)]

use alloy_primitives::{Address, B256, U256, U512};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_poseidon::{Poseidon, PoseidonHasher};
use outbe_primitives::units::SCALE_1E6_U256;
use outbe_tee::protocol::WorldwideDay;

/// Circom Poseidon permutation max width.
const MAX_POSEIDON_INPUTS: usize = 12;

/// Canonical Tribute amount parsed once before the ZK/non-ZK paths diverge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalAmount {
    pub(crate) base: u64,
    pub(crate) atto: u64,
    pub(crate) amount_minor: U256,
}

/// Poseidon-BN254 over N BE-encoded field elements packed into `input`
/// The raw input format is the chain's `outbe_evm::zk::poseidon_hash` format
/// (multiple of 32 bytes). The implementation uses the same crate and Circom
/// parameters, but stays local so the enclave does not pull the EVM and
/// Barretenberg backend. Each chunk is reduced mod the BN254 scalar order.
fn poseidon_hash(input: &[u8]) -> Result<[u8; 32], String> {
    if input.is_empty() {
        return Err("poseidon: empty input".to_string());
    }
    if !input.len().is_multiple_of(32) {
        return Err(format!("poseidon: unaligned input ({} bytes)", input.len()));
    }
    let n = input.len() / 32;
    if n > MAX_POSEIDON_INPUTS {
        return Err(format!("poseidon: too many inputs ({n})"));
    }
    let inputs: Vec<Fr> = input.chunks(32).map(Fr::from_be_bytes_mod_order).collect();
    let mut poseidon = Poseidon::<Fr>::new_circom(n).map_err(|e| format!("poseidon setup: {e}"))?;
    let hash = poseidon
        .hash(&inputs)
        .map_err(|e| format!("poseidon hash: {e}"))?;
    let be = hash.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let off = 32 - be.len().min(32);
    out[off..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
    Ok(out)
}

/// Parse the `tribute_draft_id` (a 32-byte value as a hex string, optional `0x`
/// prefix) into raw bytes - mirrors host `parse_su_hashes`.
fn parse_draft_id(draft_id: &str) -> Result<[u8; 32], String> {
    let hex_str = draft_id.strip_prefix("0x").unwrap_or(draft_id);
    let bytes =
        hex::decode(hex_str).map_err(|_| format!("invalid tribute_draft_id hex: {draft_id}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "tribute_draft_id must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `tribute_id = Poseidon(owner, worldwide_day)` - BN254/circom, computed inside
/// the enclave. The id is deterministic in `(owner, worldwide_day)` ALONE: this
/// is what enforces the one-tribute-per-owner-per-day invariant. A second offer
/// for the same owner and day recomputes the same id, so the host's
/// `get_tribute(id).is_some()` check rejects it (`TributeAlreadyExists`). The
/// `tribute_draft_id` is still validated (must be 32-byte hex) but intentionally
/// NOT mixed into the id - mixing it in made the id per-offer-unique and silently
/// allowed duplicate tributes per owner per day.
///
/// Field-element encoding (each reduced mod the BN254 order by `poseidon_hash`):
/// - `owner`: address left-padded to 32 bytes;
/// - `worldwide_day`: its `YYYYMMDD` word as 32-byte big-endian.
pub fn compute_token_id(
    owner: Address,
    worldwide_day: WorldwideDay,
    draft_id: &str,
) -> Result<B256, String> {
    // Validate the draft id (reject malformed input) but keep it out of the hash.
    parse_draft_id(draft_id)?;
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(owner.into_word().as_slice());
    buf.extend_from_slice(&U256::from(worldwide_day.value()).to_be_bytes::<32>());
    Ok(B256::from(poseidon_hash(&buf)?))
}

/// Computes the Tribute-only S-curve pricing contract:
///
/// `effective_ref = max(reference_vwap, reference_scurve)`
/// `nominal = floor(amount * 1_000_000 * reference_vwap /
///                  (issuance_vwap * effective_ref))`
///
/// Intermediate products are widened to 512 bits. Overflow, missing required
/// VWAPs, and a positive result rounded to zero reject the offer.
pub(crate) fn compute_nominal(
    amount_minor: U256,
    issuance_wwd_vwap_minor: U256,
    reference_wwd_vwap_minor: U256,
    reference_scurve_minor: U256,
) -> Result<(U256, U256), String> {
    if issuance_wwd_vwap_minor.is_zero() {
        return Err("issuance WorldwideDay VWAP is zero".to_string());
    }
    if reference_wwd_vwap_minor.is_zero() {
        return Err("reference WorldwideDay VWAP is zero".to_string());
    }
    let effective_reference_price_minor = reference_wwd_vwap_minor.max(reference_scurve_minor);
    let numerator = U512::from(amount_minor)
        .checked_mul(U512::from(SCALE_1E6_U256))
        .and_then(|value| value.checked_mul(U512::from(reference_wwd_vwap_minor)))
        .ok_or_else(|| "nominal amount overflow".to_string())?;
    let denominator = U512::from(issuance_wwd_vwap_minor)
        .checked_mul(U512::from(effective_reference_price_minor))
        .ok_or_else(|| "nominal denominator overflow".to_string())?;
    let quotient = numerator / denominator;
    let nominal = U256::checked_from_limbs_slice(quotient.as_limbs())
        .ok_or_else(|| "nominal amount overflow".to_string())?;
    if !amount_minor.is_zero() && nominal.is_zero() {
        return Err("nominal amount rounds to zero".to_string());
    }
    Ok((nominal, effective_reference_price_minor))
}

fn parse_canonical_u64(value: &str, field: &'static str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{field} must be a canonical u64"))?;
    if parsed.to_string() != value {
        return Err(format!("{field} must be a canonical u64"));
    }
    Ok(parsed)
}

/// Parse the existing `amount_base`/`amount_atto` wire fields into the canonical
/// six-decimal Tribute amount. `amount_base` is a whole unsigned `u64` and the
/// legacy-named `amount_atto` field is the raw remainder `0..999_999`.
pub(crate) fn parse_canonical_amount(
    base_amount: &str,
    atto_amount: &str,
) -> Result<CanonicalAmount, String> {
    let base = parse_canonical_u64(base_amount, "amount_base")?;
    let atto = parse_canonical_u64(atto_amount, "amount_atto")?;
    if U256::from(atto) >= SCALE_1E6_U256 {
        return Err("amount_atto must be less than 1000000".to_string());
    }
    let amount_minor = U256::from(base)
        .checked_mul(SCALE_1E6_U256)
        .and_then(|value| value.checked_add(U256::from(atto)))
        .ok_or_else(|| "amount overflow".to_string())?;
    Ok(CanonicalAmount {
        base,
        atto,
        amount_minor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct CanonicalAmountCases {
        accepted_base: Vec<String>,
        rejected_base: Vec<String>,
        accepted_atto: Vec<String>,
        rejected_atto: Vec<String>,
    }

    fn canonical_amount_cases() -> CanonicalAmountCases {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/tribute/canonical-amounts-v1.json"
        )))
        .unwrap()
    }

    fn parse_amount_minor(base: &str, atto: &str) -> Result<U256, String> {
        Ok(parse_canonical_amount(base, atto)?.amount_minor)
    }

    #[test]
    fn normalize_canonical_base_and_atto_to_six_decimal_units() {
        let cases = canonical_amount_cases();
        for base in cases.accepted_base {
            assert!(
                parse_amount_minor(&base, "0").is_ok(),
                "rejected canonical base {base:?}"
            );
        }
        for atto in cases.accepted_atto {
            assert!(
                parse_amount_minor("1", &atto).is_ok(),
                "rejected canonical atto {atto:?}"
            );
        }
        assert_eq!(
            parse_amount_minor("1", "500000").unwrap(),
            U256::from(1_500_000u64)
        );
        assert_eq!(
            parse_amount_minor("100", "0").unwrap(),
            U256::from(100u64) * SCALE_1E6_U256
        );
        assert_eq!(
            parse_amount_minor(&u64::MAX.to_string(), "999999").unwrap(),
            U256::from(u64::MAX) * SCALE_1E6_U256 + U256::from(999_999u64)
        );
    }

    #[test]
    fn normalize_rejects_noncanonical_base_in_both_amount_fields() {
        let cases = canonical_amount_cases();
        for base in cases.rejected_base {
            assert!(
                parse_amount_minor(&base, "0").is_err(),
                "non-canonical amount_base {base:?} was accepted"
            );
        }
        for atto in cases.rejected_atto {
            assert!(
                parse_amount_minor("1", &atto).is_err(),
                "non-canonical amount_atto {atto:?} was accepted"
            );
        }
    }

    #[test]
    fn same_currency_without_a_higher_curve_preserves_scale_six_nominal() {
        // amount=100 COEN, price=2.0 -> 50 COEN, all expressed as raw units.
        let amount = U256::from(100u64) * SCALE_1E6_U256;
        let price = U256::from(2u64) * SCALE_1E6_U256;
        assert_eq!(
            compute_nominal(amount, price, price, U256::ZERO).unwrap(),
            (U256::from(50u64) * SCALE_1E6_U256, price)
        );
        assert_eq!(
            compute_nominal(amount, price, price, SCALE_1E6_U256).unwrap(),
            (U256::from(50u64) * SCALE_1E6_U256, price),
            "a lower reference curve must not change the effective price"
        );
    }

    #[test]
    fn cross_currency_golden_applies_only_the_reference_curve_brake() {
        assert_eq!(
            compute_nominal(
                U256::from(410_000u64),
                U256::from(10_250_000u64),
                U256::from(250_000u64),
                U256::from(320_000u64),
            )
            .unwrap(),
            (U256::from(31_250u64), U256::from(320_000u64))
        );
    }

    #[test]
    fn pricing_rejects_zero_required_inputs_overflow_and_positive_to_zero() {
        for inputs in [
            (U256::ONE, U256::ZERO, U256::ONE, U256::ZERO),
            (U256::ONE, U256::ONE, U256::ZERO, U256::ZERO),
        ] {
            assert!(compute_nominal(inputs.0, inputs.1, inputs.2, inputs.3).is_err());
        }
        assert!(compute_nominal(U256::MAX, U256::ONE, U256::MAX, U256::ZERO).is_err());
        assert!(
            compute_nominal(U256::ONE, U256::from(2_000_000u64), U256::ONE, U256::ONE,).is_err()
        );
    }

    const DRAFT_A: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const DRAFT_B: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
    const DAY: WorldwideDay = WorldwideDay::new(20250115);
    const NEXT_DAY: WorldwideDay = WorldwideDay::new(20250116);

    #[test]
    fn token_id_deterministic_and_input_bound() {
        let a = Address::repeat_byte(0x11);
        let b = Address::repeat_byte(0x22);
        let base = compute_token_id(a, DAY, DRAFT_A).unwrap();
        assert_eq!(base, compute_token_id(a, DAY, DRAFT_A).unwrap());
        assert_ne!(base, compute_token_id(b, DAY, DRAFT_A).unwrap()); // owner
        assert_ne!(base, compute_token_id(a, NEXT_DAY, DRAFT_A).unwrap()); // day

        // draft_id is deliberately NOT bound into the id - same owner+day yields
        // the same id regardless of draft, which enforces one-per-owner-per-day.
        assert_eq!(base, compute_token_id(a, DAY, DRAFT_B).unwrap());
    }

    #[test]
    fn token_id_rejects_bad_draft_id() {
        assert!(compute_token_id(Address::ZERO, DAY, "not-hex").is_err());
        assert!(compute_token_id(Address::ZERO, DAY, "0x1234").is_err()); // not 32 bytes
    }

    /// Proves our replicated `poseidon_hash` matches a fresh circom hasher (the
    /// same self-consistency check as `outbe_evm::zk::poseidon_hash` uses),
    /// guaranteeing byte-identity with the chain.
    #[test]
    fn poseidon_matches_fresh_circom_hasher() {
        fn fr_be(f: &Fr) -> [u8; 32] {
            let be = f.into_bigint().to_bytes_be();
            let mut out = [0u8; 32];
            let off = 32 - be.len().min(32);
            out[off..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
            out
        }
        let a = Fr::from(7u64);
        let b = Fr::from(20_250_115u64);
        let mut input = Vec::new();
        input.extend_from_slice(&fr_be(&a));
        input.extend_from_slice(&fr_be(&b));

        let mine = poseidon_hash(&input).unwrap();
        let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
        let reference = fr_be(&hasher.hash(&[a, b]).unwrap());
        assert_eq!(mine, reference);
    }
}
