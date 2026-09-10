//! Canonical Stablecoin Factory V1 proposal and token-identity primitives.
//!
//! The proposal codec accepts only the byte-exact JSON form specified by
//! ADR-C-TOK-004. Token identity uses a fixed preimage layout:
//!
//! ```text
//! "OUTBE_STABLECOIN_V1"
//! || chain_id: u64 big-endian (8 bytes)
//! || factory (20 bytes)
//! || issuer (20 bytes)
//! || ticker_length: u8 (1 byte)
//! || ticker bytes
//! ```

use crate::error::PrecompileError;
use alloy_primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical proposal version encoded in the JSON payload.
pub const STABLECOIN_CREATE_VERSION: u8 = 1;
/// Canonical proposal kind encoded in the JSON payload.
pub const STABLECOIN_CREATE_KIND: &str = "StablecoinCreate";
/// Domain separator at the start of every Stablecoin Factory V1 token-id preimage.
pub const STABLECOIN_TOKEN_ID_DOMAIN: &[u8] = b"OUTBE_STABLECOIN_V1";
/// Minimum canonical ticker length in bytes.
pub const MIN_TICKER_LEN: usize = 2;
/// Maximum canonical ticker length in bytes.
pub const MAX_TICKER_LEN: usize = 12;
/// Maximum immutable token-name length in UTF-8 bytes.
pub const MAX_NAME_LEN: usize = 64;
/// Publication date of the protocol-pinned ISO 4217 List One snapshot.
pub const ISO_4217_SNAPSHOT_PUBLISHED: &str = "2026-01-01";
/// SHA-256 of the source SIX List One XML used to derive the numeric-code set.
pub const ISO_4217_SNAPSHOT_SHA256: &str =
    "838dfb991648cf36df939edd5fe3811737962b75a32252847d239cedd1e291c9";
/// Sorted unique numeric codes from SIX ISO 4217 List One published 2026-01-01.
pub const ISO_4217_NUMERIC_CODES: &[u16] = &[
    8, 12, 32, 36, 44, 48, 50, 51, 52, 60, 64, 68, 72, 84, 90, 96, 104, 108, 116, 124, 132, 136,
    144, 152, 156, 170, 174, 188, 192, 203, 208, 214, 222, 230, 232, 238, 242, 262, 270, 292, 320,
    324, 328, 332, 340, 344, 348, 352, 356, 360, 364, 368, 376, 388, 392, 396, 398, 400, 404, 408,
    410, 414, 417, 418, 422, 426, 430, 434, 446, 454, 458, 462, 480, 484, 496, 498, 504, 512, 516,
    524, 532, 533, 548, 554, 558, 566, 578, 586, 590, 598, 600, 604, 608, 634, 643, 646, 654, 682,
    690, 702, 704, 706, 710, 728, 748, 752, 756, 760, 764, 776, 780, 784, 788, 800, 807, 818, 826,
    834, 840, 858, 860, 882, 886, 901, 924, 925, 926, 927, 928, 929, 930, 933, 934, 936, 938, 940,
    941, 943, 944, 946, 947, 948, 949, 950, 951, 952, 953, 955, 956, 957, 958, 959, 960, 961, 962,
    963, 964, 965, 967, 968, 969, 970, 971, 972, 973, 976, 977, 978, 979, 980, 981, 984, 985, 986,
    990, 994, 997, 999,
];

/// Alpha-3 codes positionally aligned with [`ISO_4217_NUMERIC_CODES`], from the
/// same pinned snapshot.
pub const ISO_4217_ALPHA: &[[u8; 3]] = &[
    *b"ALL", *b"DZD", *b"ARS", *b"AUD", *b"BSD", *b"BHD", *b"BDT", *b"AMD", *b"BBD", *b"BMD",
    *b"BTN", *b"BOB", *b"BWP", *b"BZD", *b"SBD", *b"BND", *b"MMK", *b"BIF", *b"KHR", *b"CAD",
    *b"CVE", *b"KYD", *b"LKR", *b"CLP", *b"CNY", *b"COP", *b"KMF", *b"CRC", *b"CUP", *b"CZK",
    *b"DKK", *b"DOP", *b"SVC", *b"ETB", *b"ERN", *b"FKP", *b"FJD", *b"DJF", *b"GMD", *b"GIP",
    *b"GTQ", *b"GNF", *b"GYD", *b"HTG", *b"HNL", *b"HKD", *b"HUF", *b"ISK", *b"INR", *b"IDR",
    *b"IRR", *b"IQD", *b"ILS", *b"JMD", *b"JPY", *b"XAD", *b"KZT", *b"JOD", *b"KES", *b"KPW",
    *b"KRW", *b"KWD", *b"KGS", *b"LAK", *b"LBP", *b"LSL", *b"LRD", *b"LYD", *b"MOP", *b"MWK",
    *b"MYR", *b"MVR", *b"MUR", *b"MXN", *b"MNT", *b"MDL", *b"MAD", *b"OMR", *b"NAD", *b"NPR",
    *b"XCG", *b"AWG", *b"VUV", *b"NZD", *b"NIO", *b"NGN", *b"NOK", *b"PKR", *b"PAB", *b"PGK",
    *b"PYG", *b"PEN", *b"PHP", *b"QAR", *b"RUB", *b"RWF", *b"SHP", *b"SAR", *b"SCR", *b"SGD",
    *b"VND", *b"SOS", *b"ZAR", *b"SSP", *b"SZL", *b"SEK", *b"CHF", *b"SYP", *b"THB", *b"TOP",
    *b"TTD", *b"AED", *b"TND", *b"UGX", *b"MKD", *b"EGP", *b"GBP", *b"TZS", *b"USD", *b"UYU",
    *b"UZS", *b"WST", *b"YER", *b"TWD", *b"ZWG", *b"SLE", *b"VED", *b"UYW", *b"VES", *b"MRU",
    *b"STN", *b"BYN", *b"TMT", *b"GHS", *b"SDG", *b"UYI", *b"RSD", *b"MZN", *b"AZN", *b"RON",
    *b"CHE", *b"CHW", *b"TRY", *b"XAF", *b"XCD", *b"XOF", *b"XPF", *b"XBA", *b"XBB", *b"XBC",
    *b"XBD", *b"XAU", *b"XDR", *b"XAG", *b"XPT", *b"XTS", *b"XPD", *b"XUA", *b"ZMW", *b"SRD",
    *b"MGA", *b"COU", *b"AFN", *b"TJS", *b"AOA", *b"CDF", *b"BAM", *b"EUR", *b"MXV", *b"UAH",
    *b"GEL", *b"BOV", *b"PLN", *b"BRL", *b"CLF", *b"XSU", *b"USN", *b"XXX",
];

const _: () = assert!(ISO_4217_ALPHA.len() == ISO_4217_NUMERIC_CODES.len());

/// The alpha-3 code for an ISO 4217 numeric code, or `None` when the pinned list
/// does not carry it. The two tables are positional, so the numeric list is both
/// the index and the search key.
pub fn iso_4217_alpha(iso_code: u16) -> Option<[u8; 3]> {
    ISO_4217_NUMERIC_CODES
        .binary_search(&iso_code)
        .ok()
        .map(|index| ISO_4217_ALPHA[index])
}

pub fn validate_currency_code(iso_code: u16) -> Result<(), CurrencyCodeError> {
    if iso_4217_alpha(iso_code).is_none() {
        return Err(CurrencyCodeError::InvalidCurrency { currency: iso_code });
    }
    Ok(())
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CurrencyCodeError {
    #[error("Invalid currency code {currency}")]
    InvalidCurrency { currency: u16 },
}

impl From<CurrencyCodeError> for PrecompileError {
    fn from(value: CurrencyCodeError) -> Self {
        PrecompileError::Revert(value.to_string())
    }
}

/// Validated fields carried by a canonical stablecoin-creation proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StablecoinCreatePayload {
    pub issuer: Address,
    pub name: String,
    pub ticker: String,
    pub iso4217: u16,
    pub decimals: u8,
    pub supply_cap: U256,
    pub policy_id: U256,
}

/// Stable error classes for canonical proposal and identity validation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum StablecoinCodecError {
    #[error("stablecoin proposal is not valid UTF-8 JSON")]
    InvalidUtf8,
    #[error("stablecoin proposal is not valid typed JSON")]
    InvalidJson,
    #[error("stablecoin proposal bytes are not canonical")]
    NonCanonicalEncoding,
    #[error("unsupported stablecoin proposal version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid stablecoin proposal kind")]
    InvalidKind,
    #[error("invalid stablecoin Factory address")]
    InvalidFactory,
    #[error("invalid stablecoin issuer address")]
    InvalidIssuer,
    #[error("invalid stablecoin name")]
    InvalidName,
    #[error("invalid stablecoin ticker")]
    InvalidTicker,
    #[error("invalid ISO-4217 numeric code: {0}")]
    InvalidIso4217(u16),
    #[error("invalid stablecoin decimals: {0}")]
    InvalidDecimals(u8),
    #[error("invalid stablecoin supply cap")]
    InvalidSupplyCap,
    #[error("invalid stablecoin policy id")]
    InvalidPolicyId,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePayload {
    version: u8,
    kind: String,
    issuer: String,
    name: String,
    ticker: String,
    iso4217: u16,
    decimals: u8,
    #[serde(rename = "supplyCap")]
    supply_cap: String,
    #[serde(rename = "policyId")]
    policy_id: String,
}

/// Decodes a byte-exact canonical Stablecoin Factory V1 proposal.
///
/// The decoder parses into a fixed typed shape, validates every field, re-encodes it,
/// and requires byte equality. This rejects whitespace, alternate key order, duplicate
/// or unknown keys, non-shortest JSON escaping and alternate numeric spellings.
pub fn decode_canonical_stablecoin_create(
    bytes: &[u8],
) -> Result<StablecoinCreatePayload, StablecoinCodecError> {
    core::str::from_utf8(bytes).map_err(|_| StablecoinCodecError::InvalidUtf8)?;
    let wire: WirePayload =
        serde_json::from_slice(bytes).map_err(|_| StablecoinCodecError::InvalidJson)?;
    let payload = payload_from_wire(&wire)?;
    let canonical = encode_canonical_stablecoin_create(&payload)?;
    if canonical != bytes {
        return Err(StablecoinCodecError::NonCanonicalEncoding);
    }
    Ok(payload)
}

/// Encodes validated fields into the one canonical Stablecoin Factory V1 JSON form.
pub fn encode_canonical_stablecoin_create(
    payload: &StablecoinCreatePayload,
) -> Result<Vec<u8>, StablecoinCodecError> {
    validate_payload(payload)?;
    let wire = WirePayload {
        version: STABLECOIN_CREATE_VERSION,
        kind: STABLECOIN_CREATE_KIND.to_owned(),
        issuer: format!("{:#x}", payload.issuer),
        name: payload.name.clone(),
        ticker: payload.ticker.clone(),
        iso4217: payload.iso4217,
        decimals: payload.decimals,
        supply_cap: payload.supply_cap.to_string(),
        policy_id: payload.policy_id.to_string(),
    };
    serde_json::to_vec(&wire).map_err(|_| StablecoinCodecError::InvalidJson)
}

/// Returns the exact bytes hashed to derive a Stablecoin Factory V1 token id.
pub fn stablecoin_token_id_preimage(
    chain_id: u64,
    factory: Address,
    issuer: Address,
    ticker: &str,
) -> Result<Vec<u8>, StablecoinCodecError> {
    if factory.is_zero() {
        return Err(StablecoinCodecError::InvalidFactory);
    }
    if issuer.is_zero() {
        return Err(StablecoinCodecError::InvalidIssuer);
    }
    validate_ticker(ticker)?;

    let ticker_len = u8::try_from(ticker.len()).map_err(|_| StablecoinCodecError::InvalidTicker)?;
    let mut preimage = Vec::with_capacity(
        STABLECOIN_TOKEN_ID_DOMAIN.len() + 8 + Address::len_bytes() * 2 + 1 + ticker.len(),
    );
    preimage.extend_from_slice(STABLECOIN_TOKEN_ID_DOMAIN);
    preimage.extend_from_slice(&chain_id.to_be_bytes());
    preimage.extend_from_slice(factory.as_slice());
    preimage.extend_from_slice(issuer.as_slice());
    preimage.push(ticker_len);
    preimage.extend_from_slice(ticker.as_bytes());
    Ok(preimage)
}

/// Derives the full 256-bit stablecoin token id.
pub fn stablecoin_token_id(
    chain_id: u64,
    factory: Address,
    issuer: Address,
    ticker: &str,
) -> Result<B256, StablecoinCodecError> {
    Ok(keccak256(stablecoin_token_id_preimage(
        chain_id, factory, issuer, ticker,
    )?))
}

/// Maps a full token id into the reserved two-byte class and rightmost 144 hash bits.
pub fn stablecoin_address(token_id: B256, prefix: [u8; 2]) -> Address {
    let mut bytes = [0u8; Address::len_bytes()];
    bytes[..2].copy_from_slice(&prefix);
    bytes[2..].copy_from_slice(&token_id.as_slice()[14..]);
    Address::from(bytes)
}

/// Derives both the full token id and its reserved-class EVM address.
pub fn predict_stablecoin(
    chain_id: u64,
    factory: Address,
    issuer: Address,
    ticker: &str,
    prefix: [u8; 2],
) -> Result<(B256, Address), StablecoinCodecError> {
    let token_id = stablecoin_token_id(chain_id, factory, issuer, ticker)?;
    Ok((token_id, stablecoin_address(token_id, prefix)))
}

fn payload_from_wire(wire: &WirePayload) -> Result<StablecoinCreatePayload, StablecoinCodecError> {
    if wire.version != STABLECOIN_CREATE_VERSION {
        return Err(StablecoinCodecError::UnsupportedVersion(wire.version));
    }
    if wire.kind != STABLECOIN_CREATE_KIND {
        return Err(StablecoinCodecError::InvalidKind);
    }

    let payload = StablecoinCreatePayload {
        issuer: parse_canonical_address(&wire.issuer)?,
        name: wire.name.clone(),
        ticker: wire.ticker.clone(),
        iso4217: wire.iso4217,
        decimals: wire.decimals,
        supply_cap: parse_canonical_decimal(&wire.supply_cap, true)
            .map_err(|_| StablecoinCodecError::InvalidSupplyCap)?,
        policy_id: parse_canonical_decimal(&wire.policy_id, false)
            .map_err(|_| StablecoinCodecError::InvalidPolicyId)?,
    };
    validate_payload(&payload)?;
    Ok(payload)
}

fn validate_payload(payload: &StablecoinCreatePayload) -> Result<(), StablecoinCodecError> {
    if payload.issuer.is_zero() {
        return Err(StablecoinCodecError::InvalidIssuer);
    }
    let name_len = payload.name.len();
    if name_len == 0 || name_len > MAX_NAME_LEN || payload.name.chars().any(char::is_control) {
        return Err(StablecoinCodecError::InvalidName);
    }
    validate_ticker(&payload.ticker)?;
    if !is_supported_iso4217(payload.iso4217) {
        return Err(StablecoinCodecError::InvalidIso4217(payload.iso4217));
    }
    if payload.decimals > 18 {
        return Err(StablecoinCodecError::InvalidDecimals(payload.decimals));
    }
    if payload.supply_cap.is_zero() {
        return Err(StablecoinCodecError::InvalidSupplyCap);
    }
    Ok(())
}

/// Returns whether a numeric code is present in the protocol-pinned ISO 4217 snapshot.
pub fn is_supported_iso4217(code: u16) -> bool {
    ISO_4217_NUMERIC_CODES.binary_search(&code).is_ok()
}

/// Validates the canonical V1 ticker grammar without deriving an identity.
pub fn validate_ticker(ticker: &str) -> Result<(), StablecoinCodecError> {
    let bytes = ticker.as_bytes();
    if !(MIN_TICKER_LEN..=MAX_TICKER_LEN).contains(&bytes.len())
        || !bytes.first().is_some_and(u8::is_ascii_uppercase)
        || !bytes
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(StablecoinCodecError::InvalidTicker);
    }
    Ok(())
}

fn parse_canonical_address(value: &str) -> Result<Address, StablecoinCodecError> {
    let bytes = value.as_bytes();
    if bytes.len() != 42
        || !value.starts_with("0x")
        || !bytes[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(StablecoinCodecError::InvalidIssuer);
    }
    let mut decoded = [0u8; Address::len_bytes()];
    hex::decode_to_slice(&value[2..], &mut decoded)
        .map_err(|_| StablecoinCodecError::InvalidIssuer)?;
    let address = Address::from(decoded);
    if address.is_zero() {
        return Err(StablecoinCodecError::InvalidIssuer);
    }
    Ok(address)
}

fn parse_canonical_decimal(value: &str, reject_zero: bool) -> Result<U256, StablecoinCodecError> {
    let bytes = value.as_bytes();
    let canonical = value == "0"
        || (!bytes.is_empty()
            && bytes[0].is_ascii_digit()
            && bytes[0] != b'0'
            && bytes.iter().all(u8::is_ascii_digit));
    if !canonical {
        return Err(StablecoinCodecError::InvalidJson);
    }
    let parsed = value
        .parse::<U256>()
        .map_err(|_| StablecoinCodecError::InvalidJson)?;
    if reject_zero && parsed.is_zero() {
        return Err(StablecoinCodecError::InvalidJson);
    }
    Ok(parsed)
}
