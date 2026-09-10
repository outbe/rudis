use crate::{
    codec::{CanonicalReader, CanonicalWriter},
    error::ProtocolError,
    schema::{require, NestedCodec, SchemaLimits},
};

/// Length-prefixed bytes governed by the bundle's ordinary field cap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedBytes(pub Vec<u8>);

impl NestedCodec for BoundedBytes {
    fn validate(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            self.0.len() <= limits.max_bounded_bytes,
            "bounded byte field cap",
        )
    }

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        output.write_bounded_bytes(&self.0, limits.max_bounded_bytes)
    }

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        Ok(Self(
            input.read_bounded_bytes(limits.max_bounded_bytes)?.to_vec(),
        ))
    }
}

/// Length-prefixed proof bytes governed by the stricter proof cap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofBytes(pub Vec<u8>);

impl NestedCodec for ProofBytes {
    fn validate(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            self.0.len() <= limits.max_proof_bytes,
            "proof byte field cap",
        )
    }

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        output.write_bounded_bytes(&self.0, limits.max_proof_bytes)
    }

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        Ok(Self(
            input.read_bounded_bytes(limits.max_proof_bytes)?.to_vec(),
        ))
    }
}
