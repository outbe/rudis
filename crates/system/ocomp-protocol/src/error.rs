use core::fmt;

/// Deterministic failures produced by the OCOMP canonical primitives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    CapacityExceeded {
        what: &'static str,
        limit: usize,
        actual: usize,
    },
    IntegerOverflow {
        what: &'static str,
    },
    AllocationFailed {
        what: &'static str,
        bytes: usize,
    },
    InvalidMagic([u8; 4]),
    UnknownObjectKind(u16),
    UnsupportedSchemaVersion(u16),
    UnexpectedObjectKind {
        expected: u16,
        actual: u16,
    },
    BodyLengthMismatch {
        declared: usize,
        remaining: usize,
    },
    UnexpectedEof {
        offset: usize,
        needed: usize,
        remaining: usize,
    },
    TrailingBytes {
        offset: usize,
        remaining: usize,
    },
    InvalidBoolean {
        offset: usize,
        value: u8,
    },
    UnknownEnum {
        width: u8,
        value: u16,
    },
    InvalidOptionTag {
        offset: usize,
        value: u8,
    },
    InvalidUtf8 {
        offset: usize,
    },
    InvalidAscii {
        offset: usize,
    },
    DuplicateEntry {
        index: usize,
    },
    OutOfOrderEntry {
        index: usize,
    },
    NonCanonicalEncoding,
    HashMismatch,
    UnknownListKind(u16),
    InvalidInvariant(&'static str),
    InvalidPublicKey,
    InvalidSignature,
    HighSignatureS,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded {
                what,
                limit,
                actual,
            } => write!(formatter, "{what} exceeds cap: {actual} > {limit}"),
            Self::IntegerOverflow { what } => write!(formatter, "{what} overflows"),
            Self::AllocationFailed { what, bytes } => {
                write!(formatter, "failed to reserve {bytes} bytes for {what}")
            }
            Self::InvalidMagic(magic) => write!(formatter, "invalid OCB1 magic: {magic:?}"),
            Self::UnknownObjectKind(kind) => write!(formatter, "unknown OCB1 object kind: {kind}"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported OCB1 schema version: {version}")
            }
            Self::UnexpectedObjectKind { expected, actual } => {
                write!(
                    formatter,
                    "unexpected OCB1 object kind: expected {expected}, got {actual}"
                )
            }
            Self::BodyLengthMismatch {
                declared,
                remaining,
            } => write!(
                formatter,
                "OCB1 body length mismatch: declared {declared}, remaining {remaining}"
            ),
            Self::UnexpectedEof {
                offset,
                needed,
                remaining,
            } => write!(
                formatter,
                "unexpected end at {offset}: need {needed}, remaining {remaining}"
            ),
            Self::TrailingBytes { offset, remaining } => {
                write!(formatter, "{remaining} trailing bytes at offset {offset}")
            }
            Self::InvalidBoolean { offset, value } => {
                write!(formatter, "invalid boolean {value} at offset {offset}")
            }
            Self::UnknownEnum { width, value } => {
                write!(formatter, "unknown u{width} enum value {value}")
            }
            Self::InvalidOptionTag { offset, value } => {
                write!(formatter, "invalid option tag {value} at offset {offset}")
            }
            Self::InvalidUtf8 { offset } => write!(formatter, "invalid UTF-8 at offset {offset}"),
            Self::InvalidAscii { offset } => write!(formatter, "invalid ASCII at offset {offset}"),
            Self::DuplicateEntry { index } => write!(formatter, "duplicate entry at index {index}"),
            Self::OutOfOrderEntry { index } => {
                write!(formatter, "out-of-order entry at index {index}")
            }
            Self::NonCanonicalEncoding => formatter.write_str("non-canonical re-encoding"),
            Self::HashMismatch => formatter.write_str("hash mismatch"),
            Self::UnknownListKind(kind) => write!(formatter, "unknown list kind: {kind}"),
            Self::InvalidInvariant(name) => write!(formatter, "invalid invariant: {name}"),
            Self::InvalidPublicKey => formatter.write_str("invalid compressed SEC1 public key"),
            Self::InvalidSignature => formatter.write_str("invalid prehash signature"),
            Self::HighSignatureS => formatter.write_str("non-canonical high-s signature"),
        }
    }
}

impl std::error::Error for ProtocolError {}
