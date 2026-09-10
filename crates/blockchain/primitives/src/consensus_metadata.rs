use alloy_primitives::{Address, Bytes, B256};
use alloy_rlp::{Decodable as RlpDecodable, Encodable as RlpEncodable};

use crate::error::{PrecompileError, Result};

// V1 `ConsensusMetadataEnvelope` removed in favour of the V2 slim
// [`CertifiedParentAccountingMetadata`] below. The V1 magic + version are
// dropped; V1 wire bytes are rejected at the system-tx codec boundary
// (`SystemTxInputV2::decode` uses `CertifiedParentAccountingMetadata::decode`,
// which has its own `OAV3` magic).
const CERTIFIED_PARENT_ACCOUNTING_MAGIC: &[u8; 4] = b"OAV3";
const CERTIFIED_PARENT_ACCOUNTING_VERSION: u8 = 1;

// ============================================================================
// V2 - Certified-Parent Accounting metadata
// ============================================================================

/// Which Activity the V2 parent-participation proof came from.
///
/// Phase 1 of block `B+1` always carries an exact-parent proof for block `B`:
/// either the Simplex `Finalization` certificate or, when finalization is
/// pending, the proposer-selected `Activity::Certification` notarization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParentParticipationProof {
    Finalization,
    CertifiedNotarization,
}

impl ParentParticipationProof {
    /// Single-byte tag used by the binary codec to discriminate variants.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Finalization => 0,
            Self::CertifiedNotarization => 1,
        }
    }

    /// Parse the canonical single-byte tag back into a variant.
    pub fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(Self::Finalization),
            1 => Ok(Self::CertifiedNotarization),
            other => Err(PrecompileError::Fatal(format!(
                "invalid ParentParticipationProof tag: {other}"
            ))),
        }
    }
}

/// One missed-proposer event between the carried parent and its predecessor.
///
/// Under V2 the V1 reconstruction of missed proposers from view gaps is
/// removed, so this list is empty in every Phase 1 metadata
/// produced under V2. The type and codec are still defined so that future
/// hard forks can re-introduce the event without a wire change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissedProposerEvent {
    /// View at which the proposer missed its slot.
    pub view: u64,
    /// Validator EVM address (must be a member of `ordered_committee`).
    pub validator: Address,
}

/// V2 Phase 1 system-tx metadata.
///
/// Carries the exact-parent participation proof for block `B-1` (the parent
/// of the block this metadata is included in). Contains **no** money fields
/// and **no** raw consensus public keys - only the canonical
/// `committee_set_hash` and `vrf_group_public_key_hash` (keccak of the
/// encoded BLS group key) so the on-chain footprint stays minimal.
///
/// Wire layout: see [`CertifiedParentAccountingMetadata::encode`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertifiedParentAccountingMetadata {
    /// Exact-parent block number this metadata accounts for (block `B-1`).
    pub finalized_block_number: u64,
    /// Exact-parent block hash this metadata accounts for.
    pub finalized_block_hash: B256,
    /// Consensus epoch of the parent proposal.
    pub finalized_epoch: u64,
    /// Consensus view of the parent proposal.
    pub finalized_view: u64,
    /// Parent view recorded in the parent proposal.
    pub parent_view: u64,
    /// Active committee in participant-index order at the parent epoch.
    pub ordered_committee: Vec<Address>,
    /// One byte per participant in `ordered_committee`: `1` if signed, `0` if
    /// absent.
    pub signer_bitmap: Vec<u8>,
    /// Full encoded `Finalization<HybridScheme<MinSig>, Digest>` or
    /// `Notarization<HybridScheme<MinSig>, Digest>` proof envelope.
    pub proof: Bytes,
    /// Canonical fingerprint of the active committee (see
    /// `outbe_consensus::proof::committee_set_hash_v2`).
    pub committee_set_hash: B256,
    /// Active VRF material version at the parent epoch.
    pub vrf_material_version: u64,
    /// Keccak256 of the encoded VRF group BLS public key.
    pub vrf_group_public_key_hash: B256,
    /// Which Activity the proof came from.
    pub proof_kind: ParentParticipationProof,
    /// Missed-proposer events between this parent and its predecessor.
    /// Always empty under V2; defined for forward-compat.
    #[serde(default)]
    pub missed_proposers: Vec<MissedProposerEvent>,
}

impl Default for CertifiedParentAccountingMetadata {
    fn default() -> Self {
        Self {
            finalized_block_number: 0,
            finalized_block_hash: B256::ZERO,
            finalized_epoch: 0,
            finalized_view: 0,
            parent_view: 0,
            ordered_committee: Vec::new(),
            signer_bitmap: Vec::new(),
            proof: Bytes::new(),
            committee_set_hash: B256::ZERO,
            vrf_material_version: 0,
            vrf_group_public_key_hash: B256::ZERO,
            proof_kind: ParentParticipationProof::Finalization,
            missed_proposers: Vec::new(),
        }
    }
}

impl CertifiedParentAccountingMetadata {
    /// Canonical V2 wire encoding.
    ///
    /// Layout (big-endian unsigned ints):
    ///
    /// ```text
    /// MAGIC(4) "OAV3"
    /// VERSION(1) = 1
    /// finalized_block_number     (u64)
    /// finalized_block_hash       (B256)
    /// finalized_epoch            (u64)
    /// finalized_view             (u64)
    /// parent_view                (u64)
    /// ordered_committee_len      (u16) || ordered_committee_addrs (20*n)
    /// signer_bitmap_len          (u16) || signer_bitmap          (n bytes)
    /// proof_len                  (u32) || proof                  (n bytes)
    /// committee_set_hash         (B256)
    /// vrf_material_version       (u64)
    /// vrf_group_public_key_hash  (B256)
    /// proof_kind                 (u8 tag - see ParentParticipationProof::tag)
    /// missed_proposers_len       (u16) || repeated { view (u64) || validator (20) }
    /// ```
    pub fn encode(&self) -> Result<Bytes> {
        ensure_count_fits_u16("committee", self.ordered_committee.len())?;
        ensure_count_fits_u16("signer bitmap", self.signer_bitmap.len())?;
        ensure_count_fits_u16("missed proposers", self.missed_proposers.len())?;
        ensure_len_fits_u32("proof", self.proof.len())?;

        let mut buf = Vec::new();
        buf.extend_from_slice(CERTIFIED_PARENT_ACCOUNTING_MAGIC);
        buf.push(CERTIFIED_PARENT_ACCOUNTING_VERSION);
        buf.extend_from_slice(&self.finalized_block_number.to_be_bytes());
        buf.extend_from_slice(self.finalized_block_hash.as_slice());
        buf.extend_from_slice(&self.finalized_epoch.to_be_bytes());
        buf.extend_from_slice(&self.finalized_view.to_be_bytes());
        buf.extend_from_slice(&self.parent_view.to_be_bytes());
        encode_addresses(&mut buf, &self.ordered_committee);
        encode_bytes_u16(&mut buf, &self.signer_bitmap)?;
        encode_bytes_u32(&mut buf, self.proof.as_ref());
        buf.extend_from_slice(self.committee_set_hash.as_slice());
        buf.extend_from_slice(&self.vrf_material_version.to_be_bytes());
        buf.extend_from_slice(self.vrf_group_public_key_hash.as_slice());
        buf.push(self.proof_kind.tag());
        buf.extend_from_slice(&(self.missed_proposers.len() as u16).to_be_bytes());
        for ev in &self.missed_proposers {
            buf.extend_from_slice(&ev.view.to_be_bytes());
            buf.extend_from_slice(ev.validator.as_slice());
        }
        Ok(Bytes::from(buf))
    }

    /// Canonical V2 wire decoding. Rejects trailing bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        // Minimum size: 4 + 1 + 8 + 32 + 8 + 8 + 8 + 2 + 2 + 4 + 32 + 8 + 32 + 1 + 2.
        let min_len = 4 + 1 + 8 + 32 + 8 + 8 + 8 + 2 + 2 + 4 + 32 + 8 + 32 + 1 + 2;
        if data.len() < min_len {
            return Err(PrecompileError::Fatal(
                "certified-parent accounting metadata too short".into(),
            ));
        }
        if &data[..4] != CERTIFIED_PARENT_ACCOUNTING_MAGIC {
            return Err(PrecompileError::Fatal(
                "invalid certified-parent accounting magic".into(),
            ));
        }
        if data[4] != CERTIFIED_PARENT_ACCOUNTING_VERSION {
            return Err(PrecompileError::Fatal(format!(
                "unsupported certified-parent accounting version: {}",
                data[4]
            )));
        }

        let mut offset = 5usize;
        let finalized_block_number = read_u64(data, &mut offset)?;
        let finalized_block_hash = read_b256(data, &mut offset)?;
        let finalized_epoch = read_u64(data, &mut offset)?;
        let finalized_view = read_u64(data, &mut offset)?;
        let parent_view = read_u64(data, &mut offset)?;
        let ordered_committee = read_addresses(data, &mut offset)?;
        let signer_bitmap = read_bytes_u16(data, &mut offset)?;
        let proof = Bytes::from(read_bytes_u32(data, &mut offset)?);
        let committee_set_hash = read_b256(data, &mut offset)?;
        let vrf_material_version = read_u64(data, &mut offset)?;
        let vrf_group_public_key_hash = read_b256(data, &mut offset)?;
        let proof_kind = ParentParticipationProof::from_tag(read_u8(data, &mut offset)?)?;
        let missed_proposers = read_missed_proposers(data, &mut offset)?;

        if offset != data.len() {
            return Err(PrecompileError::Fatal(
                "trailing bytes in certified-parent accounting metadata".into(),
            ));
        }

        Ok(Self {
            finalized_block_number,
            finalized_block_hash,
            finalized_epoch,
            finalized_view,
            parent_view,
            ordered_committee,
            signer_bitmap,
            proof,
            committee_set_hash,
            vrf_material_version,
            vrf_group_public_key_hash,
            proof_kind,
            missed_proposers,
        })
    }

    /// RLP wrapper of the canonical encoding (mirrors V1 `encode_rlp`).
    pub fn encode_rlp(&self) -> Result<Bytes> {
        let encoded = self.encode()?;
        let mut out = Vec::new();
        <Bytes as RlpEncodable>::encode(&encoded, &mut out);
        Ok(Bytes::from(out))
    }

    /// RLP wrapper of the canonical decoding (mirrors V1 `decode_rlp`).
    pub fn decode_rlp(data: &[u8]) -> Result<Self> {
        let mut buf = data;
        let encoded = <Bytes as RlpDecodable>::decode(&mut buf).map_err(|error| {
            PrecompileError::Fatal(format!(
                "invalid certified-parent accounting metadata RLP: {error}"
            ))
        })?;
        if !buf.is_empty() {
            return Err(PrecompileError::Fatal(
                "trailing bytes in certified-parent accounting metadata RLP".into(),
            ));
        }
        Self::decode(encoded.as_ref())
    }
}

fn read_u8(data: &[u8], offset: &mut usize) -> Result<u8> {
    let Some(&b) = data.get(*offset) else {
        return Err(PrecompileError::Fatal("unexpected EOF reading u8".into()));
    };
    *offset += 1;
    Ok(b)
}

fn read_missed_proposers(data: &[u8], offset: &mut usize) -> Result<Vec<MissedProposerEvent>> {
    let count_end = offset.saturating_add(2);
    let Some(count_bytes) = data.get(*offset..count_end) else {
        return Err(PrecompileError::Fatal(
            "unexpected EOF reading missed-proposer count".into(),
        ));
    };
    *offset = count_end;
    let count = u16::from_be_bytes(
        count_bytes
            .try_into()
            .map_err(|_| PrecompileError::Fatal("invalid missed-proposer count slice".into()))?,
    ) as usize;

    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        let view = read_u64(data, offset)?;
        let end = offset.saturating_add(20);
        let Some(bytes) = data.get(*offset..end) else {
            return Err(PrecompileError::Fatal(
                "unexpected EOF reading missed-proposer validator".into(),
            ));
        };
        *offset = end;
        let validator = Address::from_slice(bytes);
        events.push(MissedProposerEvent { view, validator });
    }
    Ok(events)
}

fn ensure_count_fits_u16(name: &str, count: usize) -> Result<()> {
    if count > u16::MAX as usize {
        return Err(PrecompileError::Fatal(format!(
            "{name} list exceeds u16 count limit: {count}"
        )));
    }
    Ok(())
}

fn ensure_len_fits_u32(name: &str, len: usize) -> Result<()> {
    if len > u32::MAX as usize {
        return Err(PrecompileError::Fatal(format!(
            "{name} exceeds u32 length limit: {len}"
        )));
    }
    Ok(())
}

fn encode_addresses(buf: &mut Vec<u8>, addrs: &[Address]) {
    buf.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
    for addr in addrs {
        buf.extend_from_slice(addr.as_slice());
    }
}

fn encode_bytes_u16(buf: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    // Callers already guard with `ensure_count_fits_u16`; re-check here and return
    // a structured error instead of panicking (no `unreachable!` on a consensus
    // codec path) so an oversized payload can never silently truncate the u16
    // length prefix.
    ensure_count_fits_u16("bytes payload", data.len())?;
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    Ok(())
}

fn encode_bytes_u32(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64> {
    let end = offset.saturating_add(8);
    let Some(bytes) = data.get(*offset..end) else {
        return Err(PrecompileError::Fatal("unexpected EOF reading u64".into()));
    };
    *offset = end;
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
        PrecompileError::Fatal("invalid u64 slice length".into())
    })?))
}

fn read_b256(data: &[u8], offset: &mut usize) -> Result<B256> {
    let end = offset.saturating_add(32);
    let Some(bytes) = data.get(*offset..end) else {
        return Err(PrecompileError::Fatal("unexpected EOF reading B256".into()));
    };
    *offset = end;
    Ok(B256::from_slice(bytes))
}

fn read_addresses(data: &[u8], offset: &mut usize) -> Result<Vec<Address>> {
    let count_end = offset.saturating_add(2);
    let Some(count_bytes) = data.get(*offset..count_end) else {
        return Err(PrecompileError::Fatal(
            "unexpected EOF reading address count".into(),
        ));
    };
    *offset = count_end;
    let count = u16::from_be_bytes(
        count_bytes
            .try_into()
            .map_err(|_| PrecompileError::Fatal("invalid address count slice length".into()))?,
    ) as usize;

    let bytes_len = count
        .checked_mul(20)
        .ok_or_else(|| PrecompileError::Fatal("address list length overflow".into()))?;
    let end = offset.saturating_add(bytes_len);
    let Some(bytes) = data.get(*offset..end) else {
        return Err(PrecompileError::Fatal(
            "unexpected EOF reading address list".into(),
        ));
    };
    *offset = end;

    let mut addrs = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(20) {
        addrs.push(Address::from_slice(chunk));
    }
    Ok(addrs)
}

fn read_bytes_u16(data: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    let count_end = offset.saturating_add(2);
    let Some(count_bytes) = data.get(*offset..count_end) else {
        return Err(PrecompileError::Fatal(
            "unexpected EOF reading byte length".into(),
        ));
    };
    *offset = count_end;
    let len = u16::from_be_bytes(
        count_bytes
            .try_into()
            .map_err(|_| PrecompileError::Fatal("invalid byte length slice".into()))?,
    ) as usize;
    let end = offset.saturating_add(len);
    let Some(bytes) = data.get(*offset..end) else {
        return Err(PrecompileError::Fatal(
            "unexpected EOF reading bytes".into(),
        ));
    };
    *offset = end;
    Ok(bytes.to_vec())
}

fn read_bytes_u32(data: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    let count_end = offset.saturating_add(4);
    let Some(count_bytes) = data.get(*offset..count_end) else {
        return Err(PrecompileError::Fatal(
            "unexpected EOF reading byte length".into(),
        ));
    };
    *offset = count_end;
    let len = u32::from_be_bytes(
        count_bytes
            .try_into()
            .map_err(|_| PrecompileError::Fatal("invalid byte length slice".into()))?,
    ) as usize;
    let end = offset.saturating_add(len);
    let Some(bytes) = data.get(*offset..end) else {
        return Err(PrecompileError::Fatal(
            "unexpected EOF reading bytes".into(),
        ));
    };
    *offset = end;
    Ok(bytes.to_vec())
}

// legacy `ConsensusMetadataEnvelope` test module dropped along
// with the V1 envelope itself. Coverage for the V2
// [`CertifiedParentAccountingMetadata`] codec lives in
// `crates/blockchain/primitives/tests/consensus_metadata.rs` and exercises
// the canonical `OAV3` wire layout end-to-end.
