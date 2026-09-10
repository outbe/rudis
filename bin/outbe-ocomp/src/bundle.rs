//! Resolution of one canonical, hash-pinned Lysis V1 protocol bundle.

use alloy_primitives::B256;
use outbe_ocomp_protocol::{profile::ProtocolBundleV1, ProtocolError, SchemaLimits};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedProtocolBundle {
    bundle: ProtocolBundleV1,
    hash: B256,
}

impl PinnedProtocolBundle {
    pub fn decode_canonical(
        canonical: &[u8],
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        let bundle = ProtocolBundleV1::decode_canonical(canonical, limits)?;
        bundle.validate_lysis_v1_input_codecs()?;
        let hash = bundle.protocol_bundle_hash(limits)?;
        Ok(Self { bundle, hash })
    }

    pub fn decode(
        canonical: &[u8],
        expected_hash: B256,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        let bundle = ProtocolBundleV1::decode_canonical(canonical, limits)?;
        bundle.validate_lysis_v1_input_codecs()?;
        let hash = bundle.protocol_bundle_hash(limits)?;
        if hash != expected_hash {
            return Err(ProtocolError::HashMismatch);
        }
        Ok(Self { bundle, hash })
    }

    #[must_use]
    pub const fn bundle(&self) -> &ProtocolBundleV1 {
        &self.bundle
    }

    #[must_use]
    pub const fn hash(&self) -> B256 {
        self.hash
    }
}
