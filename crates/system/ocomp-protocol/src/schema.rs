use crate::{
    codec::{
        decode_envelope, encode_envelope, require_canonical_reencoding, CanonicalReader,
        CanonicalWriter, CodecLimits,
    },
    error::ProtocolError,
    registry::ObjectKind,
};
use alloy_primitives::{Address, B256, U256};

/// Explicit bounds used by every typed OCOMP V1 codec.
///
/// OCM-04 supplies generated compile ceilings. This type deliberately has no
/// default so a caller cannot silently invent consensus limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaLimits {
    pub codec: CodecLimits,
    pub max_bounded_bytes: usize,
    pub max_proof_bytes: usize,
    pub max_opening_bytes: usize,
    pub max_collection_items: usize,
    pub max_action_items: usize,
    pub max_chunk_items: usize,
    pub max_unit_inputs: usize,
    pub max_result_chunk_bytes: u64,
    pub max_control_body_bytes: usize,
}

pub(crate) trait NestedCodec: Sized {
    fn validate(&self, limits: &SchemaLimits) -> Result<(), ProtocolError>;

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError>;

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError>;
}

macro_rules! primitive_codec {
    ($type:ty, $write:ident, $read:ident) => {
        impl NestedCodec for $type {
            fn validate(&self, _limits: &SchemaLimits) -> Result<(), ProtocolError> {
                Ok(())
            }

            fn encode_nested(
                &self,
                output: &mut CanonicalWriter,
                _limits: &SchemaLimits,
            ) -> Result<(), ProtocolError> {
                output.$write(*self)
            }

            fn decode_nested(
                input: &mut CanonicalReader<'_>,
                _limits: &SchemaLimits,
            ) -> Result<Self, ProtocolError> {
                input.$read()
            }
        }
    };
}

primitive_codec!(u8, write_u8, read_u8);
primitive_codec!(u16, write_u16, read_u16);
primitive_codec!(u32, write_u32, read_u32);
primitive_codec!(u64, write_u64, read_u64);
primitive_codec!(bool, write_bool, read_bool);
primitive_codec!(U256, write_u256, read_u256);
primitive_codec!(B256, write_b256, read_b256);
primitive_codec!(Address, write_address20, read_address20);

impl<const N: usize> NestedCodec for [u8; N] {
    fn validate(&self, _limits: &SchemaLimits) -> Result<(), ProtocolError> {
        Ok(())
    }

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        _limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        output.write_fixed(self)
    }

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        _limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        input.read_fixed()
    }
}

impl<T: NestedCodec> NestedCodec for Option<T> {
    fn validate(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        if let Some(value) = self {
            value.validate(limits)?;
        }
        Ok(())
    }

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        output.write_option(self.as_ref(), |writer, value| {
            value.encode_nested(writer, limits)
        })
    }

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        input.read_option(|reader| T::decode_nested(reader, limits))
    }
}

impl<T: NestedCodec> NestedCodec for Vec<T> {
    fn validate(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            self.len() <= limits.max_collection_items,
            "collection item cap",
        )?;
        for value in self {
            value.validate(limits)?;
        }
        Ok(())
    }

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        output.write_vec(self, limits.max_collection_items, |writer, value| {
            value.encode_nested(writer, limits)
        })
    }

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        input.read_vec(limits.max_collection_items, 0, |reader| {
            T::decode_nested(reader, limits)
        })
    }
}

pub(crate) fn encode_top<T: NestedCodec>(
    value: &T,
    kind: ObjectKind,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, ProtocolError> {
    value.validate(limits)?;
    let mut body = CanonicalWriter::new(limits.codec);
    value.encode_nested(&mut body, limits)?;
    encode_envelope(kind, body.as_slice(), limits.codec)
}

pub(crate) fn encode_nested_value<T: NestedCodec>(
    value: &T,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, ProtocolError> {
    value.validate(limits)?;
    let mut output = CanonicalWriter::new(limits.codec);
    value.encode_nested(&mut output, limits)?;
    Ok(output.into_bytes())
}

pub(crate) fn decode_top<T: NestedCodec>(
    encoded: &[u8],
    kind: ObjectKind,
    limits: &SchemaLimits,
) -> Result<T, ProtocolError> {
    let envelope = decode_envelope(encoded, limits.codec)?;
    if envelope.kind != kind {
        return Err(ProtocolError::UnexpectedObjectKind {
            expected: kind.tag(),
            actual: envelope.kind.tag(),
        });
    }
    let mut body = CanonicalReader::new(envelope.body, limits.codec)?;
    let value = T::decode_nested(&mut body, limits)?;
    body.finish()?;
    value.validate(limits)?;
    let reencoded = encode_top(&value, kind, limits)?;
    require_canonical_reencoding(encoded, &reencoded)?;
    Ok(value)
}

pub(crate) fn require(condition: bool, invariant: &'static str) -> Result<(), ProtocolError> {
    if condition {
        Ok(())
    } else {
        Err(ProtocolError::InvalidInvariant(invariant))
    }
}

macro_rules! wire_struct {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            $(pub $field:ident: $type:ty),* $(,)?
        }
        validate = $validator:path;
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            $(pub $field: $type),*
        }

        impl $crate::schema::NestedCodec for $name {
            fn validate(
                &self,
                limits: &$crate::schema::SchemaLimits,
            ) -> Result<(), $crate::error::ProtocolError> {
                $(<$type as $crate::schema::NestedCodec>::validate(&self.$field, limits)?;)*
                $validator(self, limits)
            }

            fn encode_nested(
                &self,
                output: &mut $crate::codec::CanonicalWriter,
                limits: &$crate::schema::SchemaLimits,
            ) -> Result<(), $crate::error::ProtocolError> {
                $(<$type as $crate::schema::NestedCodec>::encode_nested(
                    &self.$field,
                    output,
                    limits,
                )?;)*
                Ok(())
            }

            fn decode_nested(
                input: &mut $crate::codec::CanonicalReader<'_>,
                limits: &$crate::schema::SchemaLimits,
            ) -> Result<Self, $crate::error::ProtocolError> {
                Ok(Self {
                    $($field: <$type as $crate::schema::NestedCodec>::decode_nested(
                        input,
                        limits,
                    )?),*
                })
            }
        }
    };
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            $(pub $field:ident: $type:ty),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            $(pub $field: $type),*
        }

        impl $crate::schema::NestedCodec for $name {
            fn validate(
                &self,
                limits: &$crate::schema::SchemaLimits,
            ) -> Result<(), $crate::error::ProtocolError> {
                $(<$type as $crate::schema::NestedCodec>::validate(&self.$field, limits)?;)*
                Ok(())
            }

            fn encode_nested(
                &self,
                output: &mut $crate::codec::CanonicalWriter,
                limits: &$crate::schema::SchemaLimits,
            ) -> Result<(), $crate::error::ProtocolError> {
                $(<$type as $crate::schema::NestedCodec>::encode_nested(
                    &self.$field,
                    output,
                    limits,
                )?;)*
                Ok(())
            }

            fn decode_nested(
                input: &mut $crate::codec::CanonicalReader<'_>,
                limits: &$crate::schema::SchemaLimits,
            ) -> Result<Self, $crate::error::ProtocolError> {
                Ok(Self {
                    $($field: <$type as $crate::schema::NestedCodec>::decode_nested(
                        input,
                        limits,
                    )?),*
                })
            }
        }
    };
}

pub(crate) use wire_struct;

macro_rules! wire_enum_u8 {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($variant:ident = $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(u8)]
        pub enum $name {
            $($variant = $value),+
        }

        impl $crate::schema::NestedCodec for $name {
            fn validate(
                &self,
                _limits: &$crate::schema::SchemaLimits,
            ) -> Result<(), $crate::error::ProtocolError> {
                Ok(())
            }

            fn encode_nested(
                &self,
                output: &mut $crate::codec::CanonicalWriter,
                _limits: &$crate::schema::SchemaLimits,
            ) -> Result<(), $crate::error::ProtocolError> {
                output.write_u8(*self as u8)
            }

            fn decode_nested(
                input: &mut $crate::codec::CanonicalReader<'_>,
                _limits: &$crate::schema::SchemaLimits,
            ) -> Result<Self, $crate::error::ProtocolError> {
                match input.read_u8()? {
                    $($value => Ok(Self::$variant),)+
                    value => Err($crate::error::ProtocolError::UnknownEnum {
                        width: 8,
                        value: u16::from(value),
                    }),
                }
            }
        }
    };
}

pub(crate) use wire_enum_u8;

macro_rules! impl_top_level_codec {
    ($type:ty, $kind:ident) => {
        impl $type {
            pub fn encode_canonical(
                &self,
                limits: &$crate::schema::SchemaLimits,
            ) -> Result<Vec<u8>, $crate::error::ProtocolError> {
                $crate::schema::encode_top(self, $crate::registry::ObjectKind::$kind, limits)
            }

            pub fn decode_canonical(
                encoded: &[u8],
                limits: &$crate::schema::SchemaLimits,
            ) -> Result<Self, $crate::error::ProtocolError> {
                $crate::schema::decode_top(encoded, $crate::registry::ObjectKind::$kind, limits)
            }
        }
    };
}

pub(crate) use impl_top_level_codec;
