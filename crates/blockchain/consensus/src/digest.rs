//! Digest newtype wrapping Alloy's B256.
//!
//! Implements Commonware's [`Digest`](commonware_cryptography::Digest) trait
//! so block hashes can be used as consensus payloads.

use alloy_primitives::B256;
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::Digest as CwDigest;
use commonware_utils::{Array, Span};
use std::fmt;

/// Outbe block digest - thin wrapper around a 32-byte block hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
#[repr(transparent)]
pub struct Digest(pub B256);

impl Digest {
    /// Zero-valued digest.
    pub const ZERO: Self = Self(B256::ZERO);
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::ops::Deref for Digest {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl From<B256> for Digest {
    fn from(hash: B256) -> Self {
        Self(hash)
    }
}

impl From<Digest> for B256 {
    fn from(d: Digest) -> Self {
        d.0
    }
}

// --- Commonware trait impls ---

impl FixedSize for Digest {
    const SIZE: usize = 32;
}

impl CwDigest for Digest {
    const EMPTY: Self = Self::ZERO;
}

impl commonware_math::algebra::Random for Digest {
    fn random(mut rng: impl rand_core::CryptoRngCore) -> Self {
        let mut array = B256::ZERO;
        rng.fill_bytes(&mut *array);
        Self(array)
    }
}

impl Write for Digest {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for Digest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let array = <[u8; 32]>::read(buf)?;
        Ok(Self(B256::new(array)))
    }
}

impl Span for Digest {}
impl Array for Digest {}
