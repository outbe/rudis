//! Evidence wire format for VRF seed-partial equivocation slashing.
//!
//! A validator that identity-signs two DIFFERENT `bls_seed_partial`s for the
//! same `(round, vrf_material_version)` has equivocated on its VRF
//! contribution. Each partial is bound to the validator's MinPk identity key by
//! a rider signature (see `outbe_consensus::proof::seed_partial`), so the two
//! identity signatures alone self-authenticate the offense - no committee
//! polynomial is needed, mirroring the existing double-sign / conflicting-vote
//! evidence. An honest validator produces exactly one partial per
//! `(round, version)` and never identity-signs a second distinct one, so a
//! valid pair cannot frame an honest node.
//!
//! Wire (fixed 365 bytes, big-endian scalars):
//! ```text
//! magic[4]=b"SPE1" | version[1]=0x01 | round_epoch[8] | round_view[8] |
//! vrf_version[8] | signer_pubkey[48] | partial_1[48] | identity_sig_1[96] |
//! partial_2[48] | identity_sig_2[96]
//! ```

use alloy_primitives::{keccak256, B256};
use outbe_primitives::error::{PrecompileError, Result};

pub(crate) const SPE1_MAGIC: &[u8; 4] = b"SPE1";
pub(crate) const SPE1_VERSION: u8 = 0x01;
/// Fixed wire length: 4 + 1 + 8 + 8 + 8 + 48 + 48 + 96 + 48 + 96.
pub(crate) const SPE1_LEN: usize = 365;

/// Decoded seed-partial equivocation evidence.
pub(crate) struct SeedPartialEquivocationEvidence {
    pub round_epoch: u64,
    pub round_view: u64,
    pub vrf_version: u64,
    pub signer_pubkey: [u8; 48],
    pub partial_1: [u8; 48],
    pub identity_sig_1: [u8; 96],
    pub partial_2: [u8; 48],
    pub identity_sig_2: [u8; 96],
}

impl SeedPartialEquivocationEvidence {
    /// Decode the fixed-length wire form. Rejects any wrong length (no trailing
    /// bytes), wrong magic, or wrong version.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != SPE1_LEN {
            return Err(PrecompileError::Revert(format!(
                "SPE1 evidence must be exactly {SPE1_LEN} bytes, got {}",
                data.len()
            )));
        }
        if &data[0..4] != SPE1_MAGIC.as_slice() {
            return Err(PrecompileError::Revert("SPE1 evidence bad magic".into()));
        }
        if data[4] != SPE1_VERSION {
            return Err(PrecompileError::Revert("SPE1 evidence bad version".into()));
        }
        let mut pos = 5usize;
        let mut u64_be = || -> u64 {
            let v = u64::from_be_bytes(data[pos..pos + 8].try_into().expect("checked length"));
            pos += 8;
            v
        };
        let round_epoch = u64_be();
        let round_view = u64_be();
        let vrf_version = u64_be();
        // Remaining fixed-size byte fields.
        let signer_pubkey: [u8; 48] = data[pos..pos + 48].try_into().expect("checked length");
        pos += 48;
        let partial_1: [u8; 48] = data[pos..pos + 48].try_into().expect("checked length");
        pos += 48;
        let identity_sig_1: [u8; 96] = data[pos..pos + 96].try_into().expect("checked length");
        pos += 96;
        let partial_2: [u8; 48] = data[pos..pos + 48].try_into().expect("checked length");
        pos += 48;
        let identity_sig_2: [u8; 96] = data[pos..pos + 96].try_into().expect("checked length");
        pos += 96;
        debug_assert_eq!(pos, SPE1_LEN);

        Ok(Self {
            round_epoch,
            round_view,
            vrf_version,
            signer_pubkey,
            partial_1,
            identity_sig_1,
            partial_2,
            identity_sig_2,
        })
    }

    /// keccak256 of the signer's 48-byte identity pubkey, for ValidatorSet
    /// reverse lookup.
    pub fn pubkey_hash(&self) -> B256 {
        keccak256(self.signer_pubkey)
    }

    /// Canonical dedup key: order-independent in the two partials, so the same
    /// equivocation submitted with the partials in either order maps to one
    /// slash. Binds the round and material version so distinct equivocations are
    /// distinct keys.
    pub fn dedup_hash(&self) -> B256 {
        let (lo, hi) = if self.partial_1 <= self.partial_2 {
            (&self.partial_1, &self.partial_2)
        } else {
            (&self.partial_2, &self.partial_1)
        };
        let mut buf = Vec::with_capacity(4 + 24 + 48 + 48 + 48);
        buf.extend_from_slice(SPE1_MAGIC);
        buf.extend_from_slice(&self.round_epoch.to_be_bytes());
        buf.extend_from_slice(&self.round_view.to_be_bytes());
        buf.extend_from_slice(&self.vrf_version.to_be_bytes());
        buf.extend_from_slice(&self.signer_pubkey);
        buf.extend_from_slice(lo);
        buf.extend_from_slice(hi);
        keccak256(buf)
    }
}

// =============================================================================
// Invalid-partial evidence (IPE1) - slashes a single identity-signed partial
// that fails verification against the committee's full VRF polynomial.
// =============================================================================

pub(crate) const IPE1_MAGIC: &[u8; 4] = b"IPE1";
pub(crate) const IPE1_VERSION: u8 = 0x01;
/// Fixed prefix before the variable-length polynomial commitment:
/// magic(4)+version(1)+committee_set_hash(32)+round_epoch(8)+round_view(8)
/// +vrf_version(8)+signer_index(4)+signer_pubkey(48)+partial(48)+identity_sig(96)
/// +commitment_len(4).
pub(crate) const IPE1_PREFIX_LEN: usize = 4 + 1 + 32 + 8 + 8 + 8 + 4 + 48 + 48 + 96 + 4;

/// Decoded invalid-seed-partial evidence.
pub(crate) struct InvalidSeedPartialEvidence {
    pub committee_set_hash: B256,
    pub round_epoch: u64,
    pub round_view: u64,
    pub vrf_version: u64,
    pub signer_index: u32,
    pub signer_pubkey: [u8; 48],
    pub partial: [u8; 48],
    pub identity_sig: [u8; 96],
    /// `commonware_codec::Encode(Sharing<MinSig>)` of the committee polynomial.
    pub commitment: Vec<u8>,
}

impl InvalidSeedPartialEvidence {
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < IPE1_PREFIX_LEN {
            return Err(PrecompileError::Revert(format!(
                "IPE1 evidence too short: need at least {IPE1_PREFIX_LEN} bytes, got {}",
                data.len()
            )));
        }
        if &data[0..4] != IPE1_MAGIC.as_slice() {
            return Err(PrecompileError::Revert("IPE1 evidence bad magic".into()));
        }
        if data[4] != IPE1_VERSION {
            return Err(PrecompileError::Revert("IPE1 evidence bad version".into()));
        }
        let mut pos = 5usize;
        let take = |pos: &mut usize, n: usize| -> &[u8] {
            let s = &data[*pos..*pos + n];
            *pos += n;
            s
        };
        let committee_set_hash = B256::from_slice(take(&mut pos, 32));
        let round_epoch = u64::from_be_bytes(take(&mut pos, 8).try_into().expect("checked"));
        let round_view = u64::from_be_bytes(take(&mut pos, 8).try_into().expect("checked"));
        let vrf_version = u64::from_be_bytes(take(&mut pos, 8).try_into().expect("checked"));
        let signer_index = u32::from_be_bytes(take(&mut pos, 4).try_into().expect("checked"));
        let signer_pubkey: [u8; 48] = take(&mut pos, 48).try_into().expect("checked");
        let partial: [u8; 48] = take(&mut pos, 48).try_into().expect("checked");
        let identity_sig: [u8; 96] = take(&mut pos, 96).try_into().expect("checked");
        let commitment_len =
            u32::from_be_bytes(take(&mut pos, 4).try_into().expect("checked")) as usize;
        debug_assert_eq!(pos, IPE1_PREFIX_LEN);
        let commitment = data
            .get(pos..pos + commitment_len)
            .ok_or_else(|| PrecompileError::Revert("IPE1 commitment length exceeds input".into()))?
            .to_vec();
        if pos + commitment_len != data.len() {
            return Err(PrecompileError::Revert(
                "IPE1 evidence has trailing bytes".into(),
            ));
        }
        Ok(Self {
            committee_set_hash,
            round_epoch,
            round_view,
            vrf_version,
            signer_index,
            signer_pubkey,
            partial,
            identity_sig,
            commitment,
        })
    }

    pub fn pubkey_hash(&self) -> B256 {
        keccak256(self.signer_pubkey)
    }

    /// Dedup key: one slash per `(round, version, signer, partial)`.
    pub fn dedup_hash(&self) -> B256 {
        let mut buf = Vec::with_capacity(4 + 8 + 8 + 8 + 48 + 48);
        buf.extend_from_slice(IPE1_MAGIC);
        buf.extend_from_slice(&self.round_epoch.to_be_bytes());
        buf.extend_from_slice(&self.round_view.to_be_bytes());
        buf.extend_from_slice(&self.vrf_version.to_be_bytes());
        buf.extend_from_slice(&self.signer_pubkey);
        buf.extend_from_slice(&self.partial);
        keccak256(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bytes() -> Vec<u8> {
        let mut data = Vec::with_capacity(SPE1_LEN);
        data.extend_from_slice(SPE1_MAGIC);
        data.push(SPE1_VERSION);
        data.extend_from_slice(&7u64.to_be_bytes()); // round_epoch
        data.extend_from_slice(&9u64.to_be_bytes()); // round_view
        data.extend_from_slice(&2u64.to_be_bytes()); // vrf_version
        data.extend_from_slice(&[0xAA; 48]); // signer_pubkey
        data.extend_from_slice(&[0x01; 48]); // partial_1
        data.extend_from_slice(&[0xB1; 96]); // identity_sig_1
        data.extend_from_slice(&[0x02; 48]); // partial_2
        data.extend_from_slice(&[0xB2; 96]); // identity_sig_2
        data
    }

    #[test]
    fn decode_roundtrip_fields() {
        let ev = SeedPartialEquivocationEvidence::decode(&sample_bytes()).unwrap();
        assert_eq!(ev.round_epoch, 7);
        assert_eq!(ev.round_view, 9);
        assert_eq!(ev.vrf_version, 2);
        assert_eq!(ev.signer_pubkey, [0xAA; 48]);
        assert_eq!(ev.partial_1, [0x01; 48]);
        assert_eq!(ev.identity_sig_1, [0xB1; 96]);
        assert_eq!(ev.partial_2, [0x02; 48]);
        assert_eq!(ev.identity_sig_2, [0xB2; 96]);
    }

    #[test]
    fn decode_rejects_wrong_length_magic_version() {
        let mut short = sample_bytes();
        short.pop();
        assert!(SeedPartialEquivocationEvidence::decode(&short).is_err());

        let mut trailing = sample_bytes();
        trailing.push(0);
        assert!(SeedPartialEquivocationEvidence::decode(&trailing).is_err());

        let mut bad_magic = sample_bytes();
        bad_magic[0] = b'X';
        assert!(SeedPartialEquivocationEvidence::decode(&bad_magic).is_err());

        let mut bad_version = sample_bytes();
        bad_version[4] = 0x09;
        assert!(SeedPartialEquivocationEvidence::decode(&bad_version).is_err());
    }

    fn ipe1_sample(commitment_len: usize) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(IPE1_MAGIC);
        d.push(IPE1_VERSION);
        d.extend_from_slice(&[0xCC; 32]); // committee_set_hash
        d.extend_from_slice(&3u64.to_be_bytes()); // round_epoch
        d.extend_from_slice(&5u64.to_be_bytes()); // round_view
        d.extend_from_slice(&0u64.to_be_bytes()); // vrf_version
        d.extend_from_slice(&2u32.to_be_bytes()); // signer_index
        d.extend_from_slice(&[0xAA; 48]); // signer_pubkey
        d.extend_from_slice(&[0x11; 48]); // partial
        d.extend_from_slice(&[0xB1; 96]); // identity_sig
        d.extend_from_slice(&(commitment_len as u32).to_be_bytes());
        d.extend_from_slice(&vec![0x77u8; commitment_len]);
        d
    }

    #[test]
    fn ipe1_decode_roundtrip_and_rejects_trailing() {
        let ev = InvalidSeedPartialEvidence::decode(&ipe1_sample(100)).unwrap();
        assert_eq!(ev.round_epoch, 3);
        assert_eq!(ev.round_view, 5);
        assert_eq!(ev.signer_index, 2);
        assert_eq!(ev.commitment.len(), 100);

        let mut trailing = ipe1_sample(100);
        trailing.push(0);
        assert!(InvalidSeedPartialEvidence::decode(&trailing).is_err());

        let mut bad_len = ipe1_sample(100);
        // claim a commitment longer than present
        let off = IPE1_PREFIX_LEN - 4;
        bad_len[off..off + 4].copy_from_slice(&9999u32.to_be_bytes());
        assert!(InvalidSeedPartialEvidence::decode(&bad_len).is_err());

        let mut bad_magic = ipe1_sample(8);
        bad_magic[0] = b'X';
        assert!(InvalidSeedPartialEvidence::decode(&bad_magic).is_err());
    }

    #[test]
    fn dedup_hash_is_partial_order_independent() {
        let a = SeedPartialEquivocationEvidence::decode(&sample_bytes()).unwrap();
        // Swap partial_1/partial_2 (and their sigs) -> same dedup hash.
        let mut swapped = sample_bytes();
        // partial_1 at offset 5+24+48 = 77, identity_sig_1 at 125, partial_2 at 221, sig_2 at 269.
        let p1_off = 5 + 24 + 48;
        let s1_off = p1_off + 48;
        let p2_off = s1_off + 96;
        let s2_off = p2_off + 48;
        swapped[p1_off..p1_off + 48].copy_from_slice(&[0x02; 48]);
        swapped[s1_off..s1_off + 96].copy_from_slice(&[0xB2; 96]);
        swapped[p2_off..p2_off + 48].copy_from_slice(&[0x01; 48]);
        swapped[s2_off..s2_off + 96].copy_from_slice(&[0xB1; 96]);
        let b = SeedPartialEquivocationEvidence::decode(&swapped).unwrap();
        assert_eq!(a.dedup_hash(), b.dedup_hash());
    }
}
