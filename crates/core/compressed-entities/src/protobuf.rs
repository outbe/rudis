use alloy_primitives::{Address, B256, U256};
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;

use crate::WwdEntityId;

/// Fork-supported schema for the first three canonical body messages.
pub const BODY_SCHEMA_V1: u32 = 1;

/// Canonical v1 Tribute payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TributeBodyV1 {
    pub tribute_id: WwdEntityId,
    pub owner: Address,
    pub worldwide_day: WorldwideDay,
    pub issuance_amount_minor: U256,
    pub issuance_currency: u16,
    pub nominal_amount_minor: U256,
    pub reference_currency: u16,
    pub tribute_price_minor: U256,
    pub exclude_from_intex_issuance: bool,
}

/// Canonical v1 Nod item payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodItemBodyV1 {
    pub nod_id: WwdEntityId,
    pub owner: Address,
    pub gratis_load_minor: U256,
    pub worldwide_day: WorldwideDay,
    pub league_id: u16,
    pub floor_price_minor: U256,
    pub bucket_key: B256,
    pub issuance_currency: u16,
    pub reference_currency: u16,
    pub issued_at: u64,
}

/// Canonical v1 Nod bucket payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodBucketBodyV1 {
    pub bucket_key: B256,
    pub worldwide_day: WorldwideDay,
    pub floor_price_minor: U256,
    pub is_qualified: bool,
    pub total_nods: u64,
    pub entry_price_minor: U256,
    /// ISO 4217 numeric code denominating `floor_price_minor`. Encoded only
    /// when nonzero, so bodies written before the field existed keep their
    /// exact prior bytes.
    pub reference_currency: u16,
}

impl NodBucketBodyV1 {
    /// Returns the canonical bucket identity `WWD_BE4 || bucket_key`.
    #[must_use]
    pub fn entity_id(&self) -> WwdEntityId {
        WwdEntityId::from_day_and_digest(self.worldwide_day, self.bucket_key)
    }
}

/// Canonical stored value. The schema version is authenticated by the leaf,
/// while the payload is the exact typed Protobuf message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBody {
    schema_version: u32,
    payload: Vec<u8>,
}

impl StoredBody {
    /// Wraps one canonical v1 typed payload.
    pub fn new_v1(payload: Vec<u8>) -> Result<Self, CanonicalBodyError> {
        Self::new(BODY_SCHEMA_V1, payload)
    }

    /// Wraps a non-empty payload with an explicit non-zero schema version.
    pub fn new(schema_version: u32, payload: Vec<u8>) -> Result<Self, CanonicalBodyError> {
        if schema_version == 0 {
            return Err(CanonicalBodyError::ZeroSchemaVersion);
        }
        if payload.is_empty() {
            return Err(CanonicalBodyError::EmptyPayload);
        }
        Ok(Self {
            schema_version,
            payload,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes the one canonical StoredBody wire representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.payload.len() + 16);
        encode_varint_field(1, u64::from(self.schema_version), &mut output);
        encode_bytes_field(2, &self.payload, &mut output);
        output
    }

    /// Strictly decodes, validates, and canonical-re-encodes a StoredBody.
    pub fn decode(bytes: &[u8]) -> Result<Self, CanonicalBodyError> {
        let mut fields = Fields::new(bytes);
        let schema_version = required_varint(&mut fields, 1)?;
        let schema_version = u32::try_from(schema_version)
            .map_err(|_| CanonicalBodyError::IntegerOutOfRange { field: 1 })?;
        let payload = required_bytes(&mut fields, 2)?.to_vec();
        fields.finish()?;
        let body = Self::new(schema_version, payload)?;
        if body.encode() != bytes {
            return Err(CanonicalBodyError::NonCanonicalEncoding);
        }
        Ok(body)
    }
}

/// Encodes and validates the canonical v1 Tribute payload.
pub fn encode_tribute_v1(body: &TributeBodyV1) -> Result<Vec<u8>, CanonicalBodyError> {
    validate_identity_day(body.tribute_id, body.worldwide_day)?;
    let mut output = Vec::with_capacity(192);
    encode_bytes_field(1, body.tribute_id.as_slice(), &mut output);
    encode_bytes_field(2, body.owner.as_slice(), &mut output);
    encode_optional_varint_field(3, u64::from(body.worldwide_day.value()), &mut output);
    encode_bytes_field(
        4,
        &body.issuance_amount_minor.to_be_bytes::<32>(),
        &mut output,
    );
    encode_optional_varint_field(5, u64::from(body.issuance_currency), &mut output);
    encode_bytes_field(
        6,
        &body.nominal_amount_minor.to_be_bytes::<32>(),
        &mut output,
    );
    encode_optional_varint_field(7, u64::from(body.reference_currency), &mut output);
    encode_bytes_field(
        8,
        &body.tribute_price_minor.to_be_bytes::<32>(),
        &mut output,
    );
    encode_optional_varint_field(9, u64::from(body.exclude_from_intex_issuance), &mut output);
    Ok(output)
}

/// Strictly decodes one canonical v1 Tribute payload.
pub fn decode_tribute_v1(bytes: &[u8]) -> Result<TributeBodyV1, CanonicalBodyError> {
    let mut fields = Fields::new(bytes);
    let tribute_id = WwdEntityId::try_from(required_bytes(&mut fields, 1)?)?;
    let owner_bytes = fixed_bytes::<20>(required_bytes(&mut fields, 2)?, 2)?;
    let worldwide_day = WorldwideDay::new(optional_u32(&mut fields, 3)?);
    let issuance_amount_minor = decode_u256(required_bytes(&mut fields, 4)?, 4)?;
    let issuance_currency = optional_u16(&mut fields, 5)?;
    let nominal_amount_minor = decode_u256(required_bytes(&mut fields, 6)?, 6)?;
    let reference_currency = optional_u16(&mut fields, 7)?;
    let tribute_price_minor = decode_u256(required_bytes(&mut fields, 8)?, 8)?;
    let exclude_from_intex_issuance = optional_bool(&mut fields, 9)?;
    fields.finish()?;

    let body = TributeBodyV1 {
        tribute_id,
        owner: Address::from(owner_bytes),
        worldwide_day,
        issuance_amount_minor,
        issuance_currency,
        nominal_amount_minor,
        reference_currency,
        tribute_price_minor,
        exclude_from_intex_issuance,
    };
    validate_identity_day(body.tribute_id, body.worldwide_day)?;
    if encode_tribute_v1(&body)? != bytes {
        return Err(CanonicalBodyError::NonCanonicalEncoding);
    }
    Ok(body)
}

/// Decodes a StoredBody and requires its fork-active Tribute schema.
pub fn decode_stored_tribute_v1(bytes: &[u8]) -> Result<TributeBodyV1, CanonicalBodyError> {
    let stored = decode_active_stored_body(bytes)?;
    decode_tribute_v1(stored.payload())
}

/// Encodes and validates the canonical v1 Nod item payload.
pub fn encode_nod_item_v1(body: &NodItemBodyV1) -> Result<Vec<u8>, CanonicalBodyError> {
    validate_identity_day(body.nod_id, body.worldwide_day)?;
    let mut output = Vec::with_capacity(224);
    encode_bytes_field(1, body.nod_id.as_slice(), &mut output);
    encode_bytes_field(2, body.owner.as_slice(), &mut output);
    encode_bytes_field(3, &body.gratis_load_minor.to_be_bytes::<32>(), &mut output);
    encode_optional_varint_field(4, u64::from(body.worldwide_day.value()), &mut output);
    encode_optional_varint_field(5, u64::from(body.league_id), &mut output);
    encode_bytes_field(6, &body.floor_price_minor.to_be_bytes::<32>(), &mut output);
    encode_bytes_field(7, body.bucket_key.as_slice(), &mut output);
    encode_optional_varint_field(9, u64::from(body.issuance_currency), &mut output);
    encode_optional_varint_field(10, u64::from(body.reference_currency), &mut output);
    encode_optional_varint_field(11, body.issued_at, &mut output);
    Ok(output)
}

/// Strictly decodes one canonical v1 Nod item payload.
pub fn decode_nod_item_v1(bytes: &[u8]) -> Result<NodItemBodyV1, CanonicalBodyError> {
    let mut fields = Fields::new(bytes);
    let nod_id = WwdEntityId::try_from(required_bytes(&mut fields, 1)?)?;
    let owner = Address::from(fixed_bytes::<20>(required_bytes(&mut fields, 2)?, 2)?);
    let gratis_load_minor = decode_u256(required_bytes(&mut fields, 3)?, 3)?;
    let worldwide_day = WorldwideDay::new(optional_u32(&mut fields, 4)?);
    let league_id = optional_u16(&mut fields, 5)?;
    let floor_price_minor = decode_u256(required_bytes(&mut fields, 6)?, 6)?;
    let bucket_key = B256::from(fixed_bytes::<32>(required_bytes(&mut fields, 7)?, 7)?);
    let issuance_currency = optional_u16(&mut fields, 9)?;
    let reference_currency = optional_u16(&mut fields, 10)?;
    let issued_at = optional_varint(&mut fields, 11)?;
    fields.finish()?;

    let body = NodItemBodyV1 {
        nod_id,
        owner,
        gratis_load_minor,
        worldwide_day,
        league_id,
        floor_price_minor,
        bucket_key,
        issuance_currency,
        reference_currency,
        issued_at,
    };
    validate_identity_day(body.nod_id, body.worldwide_day)?;
    if encode_nod_item_v1(&body)? != bytes {
        return Err(CanonicalBodyError::NonCanonicalEncoding);
    }
    Ok(body)
}

/// Decodes a StoredBody and requires its fork-active Nod item schema.
pub fn decode_stored_nod_item_v1(bytes: &[u8]) -> Result<NodItemBodyV1, CanonicalBodyError> {
    let stored = decode_active_stored_body(bytes)?;
    decode_nod_item_v1(stored.payload())
}

/// Encodes the canonical v1 Nod bucket payload.
pub fn encode_nod_bucket_v1(body: &NodBucketBodyV1) -> Result<Vec<u8>, CanonicalBodyError> {
    let mut output = Vec::with_capacity(128);
    encode_bytes_field(1, body.bucket_key.as_slice(), &mut output);
    encode_optional_varint_field(2, u64::from(body.worldwide_day.value()), &mut output);
    encode_bytes_field(3, &body.floor_price_minor.to_be_bytes::<32>(), &mut output);
    encode_optional_varint_field(4, u64::from(body.is_qualified), &mut output);
    encode_optional_varint_field(5, body.total_nods, &mut output);
    encode_bytes_field(6, &body.entry_price_minor.to_be_bytes::<32>(), &mut output);
    encode_optional_varint_field(7, u64::from(body.reference_currency), &mut output);
    Ok(output)
}

/// Strictly decodes one canonical v1 Nod bucket payload.
pub fn decode_nod_bucket_v1(bytes: &[u8]) -> Result<NodBucketBodyV1, CanonicalBodyError> {
    let mut fields = Fields::new(bytes);
    let bucket_key = B256::from(fixed_bytes::<32>(required_bytes(&mut fields, 1)?, 1)?);
    let worldwide_day = WorldwideDay::new(optional_u32(&mut fields, 2)?);
    let floor_price_minor = decode_u256(required_bytes(&mut fields, 3)?, 3)?;
    let is_qualified = optional_bool(&mut fields, 4)?;
    let total_nods = optional_varint(&mut fields, 5)?;
    let entry_price_minor = decode_u256(required_bytes(&mut fields, 6)?, 6)?;
    let reference_currency = optional_u16(&mut fields, 7)?;
    fields.finish()?;

    let body = NodBucketBodyV1 {
        bucket_key,
        worldwide_day,
        floor_price_minor,
        is_qualified,
        total_nods,
        entry_price_minor,
        reference_currency,
    };
    if encode_nod_bucket_v1(&body)? != bytes {
        return Err(CanonicalBodyError::NonCanonicalEncoding);
    }
    Ok(body)
}

/// Decodes a StoredBody and requires its fork-active Nod bucket schema.
pub fn decode_stored_nod_bucket_v1(bytes: &[u8]) -> Result<NodBucketBodyV1, CanonicalBodyError> {
    let stored = decode_active_stored_body(bytes)?;
    decode_nod_bucket_v1(stored.payload())
}

fn decode_active_stored_body(bytes: &[u8]) -> Result<StoredBody, CanonicalBodyError> {
    let stored = StoredBody::decode(bytes)?;
    if stored.schema_version() != BODY_SCHEMA_V1 {
        return Err(CanonicalBodyError::UnsupportedSchema {
            actual: stored.schema_version(),
        });
    }
    Ok(stored)
}

fn validate_identity_day(
    identity: WwdEntityId,
    worldwide_day: WorldwideDay,
) -> Result<(), CanonicalBodyError> {
    if identity.worldwide_day() != worldwide_day {
        return Err(CanonicalBodyError::IdentityDayMismatch);
    }
    Ok(())
}

fn decode_u256(bytes: &[u8], field: u32) -> Result<U256, CanonicalBodyError> {
    Ok(U256::from_be_bytes(fixed_bytes::<32>(bytes, field)?))
}

fn fixed_bytes<const N: usize>(bytes: &[u8], field: u32) -> Result<[u8; N], CanonicalBodyError> {
    bytes
        .try_into()
        .map_err(|_| CanonicalBodyError::InvalidFixedWidth {
            field,
            expected: N,
            actual: bytes.len(),
        })
}

fn encode_optional_varint_field(field: u32, value: u64, output: &mut Vec<u8>) {
    if value != 0 {
        encode_varint_field(field, value, output);
    }
}

fn encode_varint_field(field: u32, value: u64, output: &mut Vec<u8>) {
    encode_varint(u64::from(field) << 3, output);
    encode_varint(value, output);
}

fn encode_bytes_field(field: u32, value: &[u8], output: &mut Vec<u8>) {
    encode_varint((u64::from(field) << 3) | 2, output);
    encode_varint(value.len() as u64, output);
    output.extend_from_slice(value);
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

#[derive(Clone, Copy)]
enum FieldValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

struct Field<'a> {
    number: u32,
    value: FieldValue<'a>,
}

struct Fields<'a> {
    input: &'a [u8],
    offset: usize,
    last_number: u32,
    pending: Option<Field<'a>>,
}

impl<'a> Fields<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            last_number: 0,
            pending: None,
        }
    }

    fn take(&mut self, expected: u32) -> Result<Option<FieldValue<'a>>, CanonicalBodyError> {
        if self.pending.is_none() {
            self.pending = self.next_field()?;
        }
        match self.pending.as_ref() {
            Some(field) if field.number == expected => {
                Ok(self.pending.take().map(|field| field.value))
            }
            Some(field) if field.number < expected => Err(CanonicalBodyError::UnknownField {
                field: field.number,
            }),
            _ => Ok(None),
        }
    }

    fn finish(&mut self) -> Result<(), CanonicalBodyError> {
        if self.pending.is_none() {
            self.pending = self.next_field()?;
        }
        if let Some(field) = self.pending.as_ref() {
            return Err(CanonicalBodyError::UnknownField {
                field: field.number,
            });
        }
        Ok(())
    }

    fn next_field(&mut self) -> Result<Option<Field<'a>>, CanonicalBodyError> {
        if self.offset == self.input.len() {
            return Ok(None);
        }
        let key = self.read_varint()?;
        let number = u32::try_from(key >> 3).map_err(|_| CanonicalBodyError::MalformedProtobuf)?;
        if number == 0 {
            return Err(CanonicalBodyError::MalformedProtobuf);
        }
        if number <= self.last_number {
            return Err(CanonicalBodyError::NonAscendingOrDuplicateField { field: number });
        }
        self.last_number = number;
        let value = match key & 7 {
            0 => FieldValue::Varint(self.read_varint()?),
            2 => {
                let len = usize::try_from(self.read_varint()?)
                    .map_err(|_| CanonicalBodyError::MalformedProtobuf)?;
                let end = self
                    .offset
                    .checked_add(len)
                    .filter(|end| *end <= self.input.len())
                    .ok_or(CanonicalBodyError::MalformedProtobuf)?;
                let bytes = &self.input[self.offset..end];
                self.offset = end;
                FieldValue::Bytes(bytes)
            }
            wire => return Err(CanonicalBodyError::UnsupportedWireType { wire }),
        };
        Ok(Some(Field { number, value }))
    }

    fn read_varint(&mut self) -> Result<u64, CanonicalBodyError> {
        let start = self.offset;
        let mut value = 0_u64;
        for shift in (0..70).step_by(7) {
            let byte = *self
                .input
                .get(self.offset)
                .ok_or(CanonicalBodyError::MalformedProtobuf)?;
            self.offset += 1;
            if shift == 63 && byte > 1 {
                return Err(CanonicalBodyError::MalformedProtobuf);
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if self.offset - start != varint_len(value) {
                    return Err(CanonicalBodyError::NonMinimalVarint);
                }
                return Ok(value);
            }
        }
        Err(CanonicalBodyError::MalformedProtobuf)
    }
}

fn required_varint(fields: &mut Fields<'_>, field: u32) -> Result<u64, CanonicalBodyError> {
    match fields.take(field)? {
        Some(FieldValue::Varint(0)) => Err(CanonicalBodyError::ExplicitDefault { field }),
        Some(FieldValue::Varint(value)) => Ok(value),
        Some(FieldValue::Bytes(_)) => Err(CanonicalBodyError::WrongWireType { field }),
        None => Err(CanonicalBodyError::MissingField { field }),
    }
}

fn optional_varint(fields: &mut Fields<'_>, field: u32) -> Result<u64, CanonicalBodyError> {
    match fields.take(field)? {
        Some(FieldValue::Varint(0)) => Err(CanonicalBodyError::ExplicitDefault { field }),
        Some(FieldValue::Varint(value)) => Ok(value),
        Some(FieldValue::Bytes(_)) => Err(CanonicalBodyError::WrongWireType { field }),
        None => Ok(0),
    }
}

fn required_bytes<'a>(fields: &mut Fields<'a>, field: u32) -> Result<&'a [u8], CanonicalBodyError> {
    match fields.take(field)? {
        Some(FieldValue::Bytes([])) => Err(CanonicalBodyError::ExplicitDefault { field }),
        Some(FieldValue::Bytes(bytes)) => Ok(bytes),
        Some(FieldValue::Varint(_)) => Err(CanonicalBodyError::WrongWireType { field }),
        None => Err(CanonicalBodyError::MissingField { field }),
    }
}

fn optional_u32(fields: &mut Fields<'_>, field: u32) -> Result<u32, CanonicalBodyError> {
    u32::try_from(optional_varint(fields, field)?)
        .map_err(|_| CanonicalBodyError::IntegerOutOfRange { field })
}

fn optional_u16(fields: &mut Fields<'_>, field: u32) -> Result<u16, CanonicalBodyError> {
    u16::try_from(optional_varint(fields, field)?)
        .map_err(|_| CanonicalBodyError::IntegerOutOfRange { field })
}

fn optional_bool(fields: &mut Fields<'_>, field: u32) -> Result<bool, CanonicalBodyError> {
    match optional_varint(fields, field)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CanonicalBodyError::IntegerOutOfRange { field }),
    }
}

/// Strict canonical body validation failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CanonicalBodyError {
    #[error(transparent)]
    InvalidEntityId(#[from] core::array::TryFromSliceError),
    #[error("schema version zero is invalid")]
    ZeroSchemaVersion,
    #[error("stored body payload must not be empty")]
    EmptyPayload,
    #[error("malformed Protobuf wire data")]
    MalformedProtobuf,
    #[error("unsupported Protobuf wire type {wire}")]
    UnsupportedWireType { wire: u64 },
    #[error("field {field} has the wrong wire type")]
    WrongWireType { field: u32 },
    #[error("field {field} is missing")]
    MissingField { field: u32 },
    #[error("unknown field {field} for the declared schema")]
    UnknownField { field: u32 },
    #[error("field {field} is duplicated or not in ascending order")]
    NonAscendingOrDuplicateField { field: u32 },
    #[error("non-minimal Protobuf varint")]
    NonMinimalVarint,
    #[error("explicit default for non-optional scalar field {field}")]
    ExplicitDefault { field: u32 },
    #[error("field {field} is outside its declared integer range")]
    IntegerOutOfRange { field: u32 },
    #[error("field {field} must be exactly {expected} bytes, got {actual}")]
    InvalidFixedWidth {
        field: u32,
        expected: usize,
        actual: usize,
    },
    #[error("body worldwide day does not match its WwdEntityId prefix")]
    IdentityDayMismatch,
    #[error("input is not the canonical Protobuf representation")]
    NonCanonicalEncoding,
    #[error("unsupported body schema version {actual}")]
    UnsupportedSchema { actual: u32 },
}
