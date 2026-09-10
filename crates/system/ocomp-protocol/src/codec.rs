use alloy_primitives::{Address, B256, U256};

use crate::{error::ProtocolError, registry::ObjectKind};

pub const OCB1_MAGIC: [u8; 4] = *b"OCB1";
pub const OCB1_SCHEMA_VERSION: u16 = 1;
pub const OCB1_HEADER_LEN: usize = 12;

/// Explicit limits supplied by the typed protocol layer.
///
/// There is intentionally no `Default`: callers must select the applicable
/// compiled protocol ceiling instead of silently inventing one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecLimits {
    pub max_body_bytes: usize,
    pub max_collection_items: usize,
    pub max_allocation_bytes: usize,
}

impl CodecLimits {
    #[must_use]
    pub const fn new(
        max_body_bytes: usize,
        max_collection_items: usize,
        max_allocation_bytes: usize,
    ) -> Self {
        Self {
            max_body_bytes,
            max_collection_items,
            max_allocation_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationStats {
    pub reservations: usize,
    pub reserved_bytes: usize,
}

/// A bounded writer for one canonical OCB1 body.
#[derive(Debug)]
pub struct CanonicalWriter {
    bytes: Vec<u8>,
    limits: CodecLimits,
}

impl CanonicalWriter {
    #[must_use]
    pub fn new(limits: CodecLimits) -> Self {
        Self {
            bytes: Vec::new(),
            limits,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn write_u8(&mut self, value: u8) -> Result<(), ProtocolError> {
        self.write_raw(&[value])
    }

    pub fn write_u16(&mut self, value: u16) -> Result<(), ProtocolError> {
        self.write_raw(&value.to_be_bytes())
    }

    pub fn write_u32(&mut self, value: u32) -> Result<(), ProtocolError> {
        self.write_raw(&value.to_be_bytes())
    }

    pub fn write_u64(&mut self, value: u64) -> Result<(), ProtocolError> {
        self.write_raw(&value.to_be_bytes())
    }

    pub fn write_u128(&mut self, value: u128) -> Result<(), ProtocolError> {
        self.write_raw(&value.to_be_bytes())
    }

    pub fn write_u256(&mut self, value: U256) -> Result<(), ProtocolError> {
        self.write_raw(&value.to_be_bytes::<32>())
    }

    pub fn write_b256(&mut self, value: B256) -> Result<(), ProtocolError> {
        self.write_raw(value.as_slice())
    }

    pub fn write_address20(&mut self, value: Address) -> Result<(), ProtocolError> {
        self.write_raw(value.as_slice())
    }

    pub fn write_fixed<const N: usize>(&mut self, value: &[u8; N]) -> Result<(), ProtocolError> {
        self.write_raw(value)
    }

    pub fn write_bool(&mut self, value: bool) -> Result<(), ProtocolError> {
        self.write_u8(u8::from(value))
    }

    pub fn write_option<T>(
        &mut self,
        value: Option<&T>,
        encode: impl FnOnce(&mut Self, &T) -> Result<(), ProtocolError>,
    ) -> Result<(), ProtocolError> {
        match value {
            None => self.write_u8(0),
            Some(inner) => {
                self.write_u8(1)?;
                encode(self, inner)
            }
        }
    }

    pub fn write_bounded_bytes(
        &mut self,
        value: &[u8],
        field_cap: usize,
    ) -> Result<(), ProtocolError> {
        check_cap("bounded byte field", field_cap, value.len())?;
        let length = u32::try_from(value.len()).map_err(|_| ProtocolError::IntegerOverflow {
            what: "bounded byte field length",
        })?;
        self.write_u32(length)?;
        self.write_raw(value)
    }

    pub fn write_utf8(&mut self, value: &str, field_cap: usize) -> Result<(), ProtocolError> {
        self.write_bounded_bytes(value.as_bytes(), field_cap)
    }

    pub fn write_ascii(&mut self, value: &str, field_cap: usize) -> Result<(), ProtocolError> {
        if let Some(index) = value.as_bytes().iter().position(|byte| !byte.is_ascii()) {
            return Err(ProtocolError::InvalidAscii { offset: index });
        }
        self.write_bounded_bytes(value.as_bytes(), field_cap)
    }

    pub fn write_vec<T>(
        &mut self,
        values: &[T],
        field_cap: usize,
        mut encode: impl FnMut(&mut Self, &T) -> Result<(), ProtocolError>,
    ) -> Result<(), ProtocolError> {
        let effective_cap = field_cap.min(self.limits.max_collection_items);
        check_cap("collection item count", effective_cap, values.len())?;
        let count = u32::try_from(values.len()).map_err(|_| ProtocolError::IntegerOverflow {
            what: "collection item count",
        })?;
        self.write_u32(count)?;
        for value in values {
            encode(self, value)?;
        }
        Ok(())
    }

    pub fn write_raw(&mut self, value: &[u8]) -> Result<(), ProtocolError> {
        let next_len =
            self.bytes
                .len()
                .checked_add(value.len())
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "canonical body length",
                })?;
        check_cap("canonical body bytes", self.limits.max_body_bytes, next_len)?;
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| ProtocolError::AllocationFailed {
                what: "canonical body",
                bytes: value.len(),
            })?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }
}

/// A bounded reader for one canonical OCB1 body.
#[derive(Debug)]
pub struct CanonicalReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    limits: CodecLimits,
    allocations: AllocationStats,
}

impl<'a> CanonicalReader<'a> {
    pub fn new(bytes: &'a [u8], limits: CodecLimits) -> Result<Self, ProtocolError> {
        check_cap("canonical body bytes", limits.max_body_bytes, bytes.len())?;
        Ok(Self {
            bytes,
            offset: 0,
            limits,
            allocations: AllocationStats::default(),
        })
    }

    #[must_use]
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    #[must_use]
    pub fn allocation_stats(&self) -> AllocationStats {
        self.allocations
    }

    pub fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take_array::<1>()?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    pub fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    pub fn read_u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    pub fn read_u128(&mut self) -> Result<u128, ProtocolError> {
        Ok(u128::from_be_bytes(self.take_array()?))
    }

    pub fn read_u256(&mut self) -> Result<U256, ProtocolError> {
        Ok(U256::from_be_bytes(self.take_array::<32>()?))
    }

    pub fn read_b256(&mut self) -> Result<B256, ProtocolError> {
        Ok(B256::from(self.take_array::<32>()?))
    }

    pub fn read_address20(&mut self) -> Result<Address, ProtocolError> {
        Ok(Address::from(self.take_array::<20>()?))
    }

    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        self.take_array()
    }

    pub fn read_fixed_dynamic(
        &mut self,
        length: usize,
        field_cap: usize,
    ) -> Result<&'a [u8], ProtocolError> {
        check_cap("fixed byte field", field_cap, length)?;
        self.take(length)
    }

    pub fn read_bool(&mut self) -> Result<bool, ProtocolError> {
        let offset = self.offset;
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(ProtocolError::InvalidBoolean { offset, value }),
        }
    }

    pub fn read_enum_u8(&mut self, allowed: &[u8]) -> Result<u8, ProtocolError> {
        let value = self.read_u8()?;
        if allowed.contains(&value) {
            Ok(value)
        } else {
            Err(ProtocolError::UnknownEnum {
                width: 8,
                value: u16::from(value),
            })
        }
    }

    pub fn read_enum_u16(&mut self, allowed: &[u16]) -> Result<u16, ProtocolError> {
        let value = self.read_u16()?;
        if allowed.contains(&value) {
            Ok(value)
        } else {
            Err(ProtocolError::UnknownEnum { width: 16, value })
        }
    }

    pub fn read_option<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, ProtocolError>,
    ) -> Result<Option<T>, ProtocolError> {
        let offset = self.offset;
        match self.read_u8()? {
            0 => Ok(None),
            1 => decode(self).map(Some),
            value => Err(ProtocolError::InvalidOptionTag { offset, value }),
        }
    }

    pub fn read_bounded_bytes(&mut self, field_cap: usize) -> Result<&'a [u8], ProtocolError> {
        let length =
            usize::try_from(self.read_u32()?).map_err(|_| ProtocolError::IntegerOverflow {
                what: "bounded byte field length",
            })?;
        check_cap("bounded byte field", field_cap, length)?;
        self.take(length)
    }

    pub fn read_utf8(&mut self, field_cap: usize) -> Result<&'a str, ProtocolError> {
        let start = self.offset;
        let bytes = self.read_bounded_bytes(field_cap)?;
        core::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidUtf8 { offset: start })
    }

    pub fn read_ascii(&mut self, field_cap: usize) -> Result<&'a str, ProtocolError> {
        let start = self.offset;
        let value = self.read_utf8(field_cap)?;
        if let Some(index) = value.as_bytes().iter().position(|byte| !byte.is_ascii()) {
            return Err(ProtocolError::InvalidAscii {
                offset: start + 4 + index,
            });
        }
        Ok(value)
    }

    pub fn read_vec<T>(
        &mut self,
        field_cap: usize,
        minimum_item_bytes: usize,
        mut decode: impl FnMut(&mut Self) -> Result<T, ProtocolError>,
    ) -> Result<Vec<T>, ProtocolError> {
        let count =
            usize::try_from(self.read_u32()?).map_err(|_| ProtocolError::IntegerOverflow {
                what: "collection item count",
            })?;
        let effective_cap = field_cap.min(self.limits.max_collection_items);
        check_cap("collection item count", effective_cap, count)?;

        let minimum_bytes =
            count
                .checked_mul(minimum_item_bytes)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "minimum collection bytes",
                })?;
        if minimum_bytes > self.remaining() {
            return Err(ProtocolError::UnexpectedEof {
                offset: self.offset,
                needed: minimum_bytes,
                remaining: self.remaining(),
            });
        }

        let allocation_bytes =
            count
                .checked_mul(core::mem::size_of::<T>())
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "collection allocation bytes",
                })?;
        let cumulative = self
            .allocations
            .reserved_bytes
            .checked_add(allocation_bytes)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "cumulative allocation bytes",
            })?;
        check_cap(
            "collection allocation bytes",
            self.limits.max_allocation_bytes,
            cumulative,
        )?;

        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| ProtocolError::AllocationFailed {
                what: "canonical collection",
                bytes: allocation_bytes,
            })?;
        if count != 0 {
            self.allocations.reservations += 1;
            self.allocations.reserved_bytes = cumulative;
        }
        for _ in 0..count {
            values.push(decode(self)?);
        }
        Ok(values)
    }

    pub fn finish(self) -> Result<AllocationStats, ProtocolError> {
        if self.remaining() == 0 {
            Ok(self.allocations)
        } else {
            Err(ProtocolError::TrailingBytes {
                offset: self.offset,
                remaining: self.remaining(),
            })
        }
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let bytes = self.take(N)?;
        let mut value = [0_u8; N];
        value.copy_from_slice(bytes);
        Ok(value)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "decoder offset",
            })?;
        if end > self.bytes.len() {
            return Err(ProtocolError::UnexpectedEof {
                offset: self.offset,
                needed: length,
                remaining: self.remaining(),
            });
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedEnvelope<'a> {
    pub kind: ObjectKind,
    pub body: &'a [u8],
}

pub fn encode_envelope(
    kind: ObjectKind,
    body: &[u8],
    limits: CodecLimits,
) -> Result<Vec<u8>, ProtocolError> {
    check_cap("OCB1 body bytes", limits.max_body_bytes, body.len())?;
    let body_len = u32::try_from(body.len()).map_err(|_| ProtocolError::IntegerOverflow {
        what: "OCB1 body length",
    })?;
    let total_len =
        OCB1_HEADER_LEN
            .checked_add(body.len())
            .ok_or(ProtocolError::IntegerOverflow {
                what: "OCB1 envelope length",
            })?;
    check_cap(
        "OCB1 envelope allocation bytes",
        limits.max_allocation_bytes,
        total_len,
    )?;

    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(total_len)
        .map_err(|_| ProtocolError::AllocationFailed {
            what: "OCB1 envelope",
            bytes: total_len,
        })?;
    encoded.extend_from_slice(&OCB1_MAGIC);
    encoded.extend_from_slice(&kind.tag().to_be_bytes());
    encoded.extend_from_slice(&OCB1_SCHEMA_VERSION.to_be_bytes());
    encoded.extend_from_slice(&body_len.to_be_bytes());
    encoded.extend_from_slice(body);
    Ok(encoded)
}

pub fn decode_envelope(
    encoded: &[u8],
    limits: CodecLimits,
) -> Result<DecodedEnvelope<'_>, ProtocolError> {
    if encoded.len() < OCB1_HEADER_LEN {
        return Err(ProtocolError::UnexpectedEof {
            offset: 0,
            needed: OCB1_HEADER_LEN,
            remaining: encoded.len(),
        });
    }

    let magic = [encoded[0], encoded[1], encoded[2], encoded[3]];
    if magic != OCB1_MAGIC {
        return Err(ProtocolError::InvalidMagic(magic));
    }

    let kind = ObjectKind::try_from(u16::from_be_bytes([encoded[4], encoded[5]]))?;
    let version = u16::from_be_bytes([encoded[6], encoded[7]]);
    if version != OCB1_SCHEMA_VERSION {
        return Err(ProtocolError::UnsupportedSchemaVersion(version));
    }
    let body_len = usize::try_from(u32::from_be_bytes([
        encoded[8],
        encoded[9],
        encoded[10],
        encoded[11],
    ]))
    .map_err(|_| ProtocolError::IntegerOverflow {
        what: "OCB1 body length",
    })?;
    check_cap("OCB1 body bytes", limits.max_body_bytes, body_len)?;
    let remaining = encoded.len() - OCB1_HEADER_LEN;
    if body_len != remaining {
        return Err(ProtocolError::BodyLengthMismatch {
            declared: body_len,
            remaining,
        });
    }
    Ok(DecodedEnvelope {
        kind,
        body: &encoded[OCB1_HEADER_LEN..],
    })
}

pub fn require_canonical_reencoding(
    original: &[u8],
    reencoded: &[u8],
) -> Result<(), ProtocolError> {
    if original == reencoded {
        Ok(())
    } else {
        Err(ProtocolError::NonCanonicalEncoding)
    }
}

pub fn ensure_strictly_increasing<T: Ord>(values: &[T]) -> Result<(), ProtocolError> {
    for (index, pair) in values.windows(2).enumerate() {
        match pair[0].cmp(&pair[1]) {
            core::cmp::Ordering::Less => {}
            core::cmp::Ordering::Equal => {
                return Err(ProtocolError::DuplicateEntry { index: index + 1 });
            }
            core::cmp::Ordering::Greater => {
                return Err(ProtocolError::OutOfOrderEntry { index: index + 1 });
            }
        }
    }
    Ok(())
}

fn check_cap(what: &'static str, limit: usize, actual: usize) -> Result<(), ProtocolError> {
    if actual <= limit {
        Ok(())
    } else {
        Err(ProtocolError::CapacityExceeded {
            what,
            limit,
            actual,
        })
    }
}
