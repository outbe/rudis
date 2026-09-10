//! `CommitteeSnapshotStore` - state-backed canonical committee snapshots.
//!
//! The V2 certified-parent accounting flow
//! must verify finalized-parent certificates against the *historical* committee
//! that signed them, not against the current parent-state validator set. At
//! reshare boundaries the parent-state set and the signing set differ, so the
//! verifier needs a deterministic, indexable copy of every active committee
//! keyed by `(epoch, committee_set_hash)`.
//!
//! This module owns the helpers that translate a [`CommitteeSnapshot`] into:
//!
//! * the canonical V2 committee hash ([`committee_set_hash_v2`]); the formula
//!   binds domain, epoch, committee length, ordered `(Address, MinPk pubkey)`
//!   entries, `vrf_material_version`, and the raw encoded VRF group public key
//!   so any drift is a chain split rather than a silent re-encoding;
//! * the storage key ([`committee_snapshot_key`]); the namespace prefix is a
//!   separate domain string so that the snapshot key never collides with the
//!   committee hash itself, even when they share the same `(epoch, hash)`
//!   inputs.
//!
//! The store layout is fixed to ValidatorSet storage slots 31..40 (see
//! [`schema::ValidatorSet`](crate::schema::ValidatorSet)). Writes are
//! field-by-field and **end with the `exists` flag**, so a partial write
//! observed via a checkpoint-rolled-back transaction is never reachable: the
//! reader gates every other slot behind `exists`.

use alloy_primitives::{Address, B256};

use outbe_ocomp_protocol::committee::{
    validator_identity_hash_v1, POC_KEY_EPOCH, RESULT_SIGNATURE_PURPOSE_BITMAP,
};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;

use crate::errors::ActivationError;
use crate::schema::ValidatorSet;

// Canonical V2 committee types and pure-function hashers live in
// `outbe-consensus-proof` (the wire-codec crate). They are re-exported here so
// existing `outbe_validatorset::state::{...}` callers keep compiling, and
// internal storage helpers (`write/read_committee_snapshot`,
// `snapshot_identity`) reference them through the canonical crate.
pub use outbe_consensus::proof::{
    committee_set_hash_v2, committee_snapshot_key, CommitteeEntry, CommitteeSnapshot,
    OUTBE_COMMITTEE_SET_HASH_V2_DOMAIN, OUTBE_COMMITTEE_SNAPSHOT_KEY_V2_DOMAIN,
    VRF_MATERIAL_VERSION_GENESIS,
};

/// Returns the next `vrf_material_version` after a successful reshare activation.
///
/// invariant: the version is strictly
/// monotonic, incremented by exactly 1, and **never saturates**. Overflow at
/// `u64::MAX` is a deterministic activation error - both proposer and
/// validator paths reject the activation rather than silently capping the
/// value, which would otherwise let two distinct DKG outputs share a version
/// and break the V2 metadata binding.
pub fn next_vrf_material_version(previous: u64) -> std::result::Result<u64, ActivationError> {
    previous
        .checked_add(1)
        .ok_or(ActivationError::VrfVersionOverflow)
}

/// Splits the 48-byte BLS MinPk pubkey into the schema's `lo`/`hi` halves.
fn split_pubkey(pubkey: &[u8; 48]) -> (B256, B256) {
    let lo = B256::from_slice(&pubkey[..32]);
    let mut hi_bytes = [0u8; 32];
    hi_bytes[..16].copy_from_slice(&pubkey[32..48]);
    (lo, B256::from(hi_bytes))
}

/// Rejoins the schema's `lo`/`hi` halves back into a 48-byte pubkey.
fn join_pubkey(lo: B256, hi: B256) -> [u8; 48] {
    let mut pubkey = [0u8; 48];
    pubkey[..32].copy_from_slice(&lo.0);
    pubkey[32..48].copy_from_slice(&hi.0[..16]);
    pubkey
}

/// Number of recent epochs whose committee snapshots stay live. Every reader
/// (`read_committee_snapshot`) only touches the current finalized epoch +/- the
/// K-block late-finalize window (<< 1 epoch), so this is a generous retention;
/// `write_committee_snapshot` prunes older snapshots to bound state growth.
/// Changing it is a hard fork (it changes which slots are zero -> the state root).
pub const COMMITTEE_SNAPSHOT_RETAIN_EPOCHS: u64 = 8;

/// Domain separator for the historical OCOMP-key binding attached to an
/// otherwise unchanged consensus committee snapshot.
pub const OUTBE_OCOMP_SNAPSHOT_BINDING_V1_DOMAIN: &[u8] = b"OUTBE_OCOMP_SNAPSHOT_BINDING_V1";

/// OCOMP metadata stored alongside a consensus committee snapshot.
///
/// This is an extension, not part of [`CommitteeSnapshot`], so adding or
/// rotating an OCOMP key cannot alter `committee_set_hash_v2` or any finality
/// proof that is bound to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OcompSnapshotExtensionV1 {
    pub epoch: u64,
    pub committee_set_hash: B256,
    pub ocomp_binding_hash: B256,
    pub member_count: u16,
}

/// OCOMP material for one validator at its consensus-snapshot index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OcompSnapshotMemberV1 {
    pub validator_address: Address,
    pub ocomp_public_key_sec1: [u8; 33],
    pub key_epoch: u64,
}

/// Hash the ordered OCOMP extension for one historical consensus snapshot.
#[must_use]
pub fn ocomp_binding_hash_v1(
    epoch: u64,
    committee_set_hash: B256,
    members: &[OcompSnapshotMemberV1],
) -> B256 {
    let mut preimage = Vec::with_capacity(
        OUTBE_OCOMP_SNAPSHOT_BINDING_V1_DOMAIN.len() + 8 + 32 + 8 + members.len() * (20 + 33 + 8),
    );
    preimage.extend_from_slice(OUTBE_OCOMP_SNAPSHOT_BINDING_V1_DOMAIN);
    preimage.extend_from_slice(&epoch.to_be_bytes());
    preimage.extend_from_slice(committee_set_hash.as_slice());
    preimage.extend_from_slice(&(members.len() as u64).to_be_bytes());
    for member in members {
        preimage.extend_from_slice(member.validator_address.as_slice());
        preimage.extend_from_slice(&member.ocomp_public_key_sec1);
        preimage.extend_from_slice(&member.key_epoch.to_be_bytes());
    }
    alloy_primitives::keccak256(preimage)
}

fn split_ocomp_public_key(public_key: &[u8; 33]) -> (B256, B256) {
    let lo = B256::from_slice(&public_key[..32]);
    let mut hi = [0u8; 32];
    hi[0] = public_key[32];
    (lo, B256::from(hi))
}

fn join_ocomp_public_key(lo: B256, hi: B256) -> Result<[u8; 33]> {
    if hi.0[1..].iter().any(|byte| *byte != 0) {
        return Err(PrecompileError::Fatal(
            "stored OCOMP snapshot public-key padding is non-zero".into(),
        ));
    }
    let mut public_key = [0u8; 33];
    public_key[..32].copy_from_slice(lo.as_slice());
    public_key[32] = hi.0[0];
    Ok(public_key)
}

/// Zeroes every slot of the committee snapshot at `key` - the inverse of
/// [`write_committee_snapshot`] - reclaiming its EVM storage (a slot set to its
/// default is empty in the state trie). All loop bounds are read before
/// `exists` is cleared; otherwise the guard needed to discover them could turn
/// the clear into a no-op. The flag is cleared only after every field is
/// reclaimed; callers perform eviction inside the enclosing boundary
/// checkpoint, so failure cannot commit a half-clear. No-op if absent.
pub fn clear_committee_snapshot(storage: StorageHandle, key: B256) -> Result<()> {
    let vs = ValidatorSet::new(storage);
    if !vs.committee_snapshot_exists.read(&key)? {
        return Ok(());
    }
    let committee_len = vs.committee_snapshot_len.read(&key)?;
    let vrf_pk_len = vs.committee_snapshot_vrf_group_public_key_len.read(&key)?;
    let ocomp_member_count = vs.committee_snapshot_ocomp_member_count.read(&key)?;

    for i in 0..committee_len {
        vs.committee_snapshot_address_at
            .get_nested(&key)
            .write(&i, Address::ZERO)?;
        vs.committee_snapshot_pubkey_lo_at
            .get_nested(&key)
            .write(&i, B256::ZERO)?;
        vs.committee_snapshot_pubkey_hi_at
            .get_nested(&key)
            .write(&i, B256::ZERO)?;
    }
    vs.committee_snapshot_len.write(&key, 0)?;

    let num_chunks = if vrf_pk_len > 0 {
        vrf_pk_len.div_ceil(32)
    } else {
        0
    };
    for i in 0..num_chunks {
        vs.committee_snapshot_vrf_group_public_key_chunk_at
            .get_nested(&key)
            .write(&i, B256::ZERO)?;
    }
    vs.committee_snapshot_vrf_material_version.write(&key, 0)?;
    vs.committee_snapshot_vrf_group_public_key_hash
        .write(&key, B256::ZERO)?;
    vs.committee_snapshot_vrf_group_public_key_len
        .write(&key, 0)?;
    vs.committee_snapshot_vrf_public_polynomial_hash
        .write(&key, B256::ZERO)?;

    for i in 0..ocomp_member_count {
        vs.committee_snapshot_ocomp_key_lo_at
            .get_nested(&key)
            .write(&i, B256::ZERO)?;
        vs.committee_snapshot_ocomp_key_hi_at
            .get_nested(&key)
            .write(&i, B256::ZERO)?;
        vs.committee_snapshot_ocomp_key_epoch_at
            .get_nested(&key)
            .write(&i, 0)?;
    }
    vs.committee_snapshot_ocomp_epoch.write(&key, 0)?;
    vs.committee_snapshot_ocomp_consensus_hash
        .write(&key, B256::ZERO)?;
    vs.committee_snapshot_ocomp_binding_hash
        .write(&key, B256::ZERO)?;
    vs.committee_snapshot_ocomp_member_count.write(&key, 0)?;
    vs.committee_snapshot_exists.write(&key, false)
}

/// Writes a committee snapshot into the store at the canonical
/// `(epoch, committee_set_hash)` key derived from `snapshot`.
///
/// Returns `(committee_set_hash, snapshot_key)`. The function is "atomic per
/// boundary block" in the sense that all writes happen inside the current EVM
/// journal - wrap the caller in a [`outbe_primitives::storage::CheckpointGuard`]
/// to roll back on artifact rejection.
///
/// The `exists` flag is intentionally written *last*: even if a checkpoint
/// commit observes a partial write (e.g., because of an out-of-gas error
/// mid-write), no reader will treat the half-written snapshot as present.
pub fn write_committee_snapshot(
    storage: StorageHandle,
    epoch: u64,
    snapshot: &CommitteeSnapshot,
) -> Result<(B256, B256)> {
    let hash = committee_set_hash_v2(epoch, snapshot);
    let key = committee_snapshot_key(epoch, hash);

    let committee_len: u64 = snapshot
        .committee
        .len()
        .try_into()
        .map_err(|_| PrecompileError::Revert("committee snapshot length exceeds u64".into()))?;
    let vrf_pk_len: u64 = snapshot
        .vrf_group_public_key_bytes
        .len()
        .try_into()
        .map_err(|_| PrecompileError::Revert("vrf group pk bytes length exceeds u64".into()))?;
    let vrf_pk_hash = alloy_primitives::keccak256(&snapshot.vrf_group_public_key_bytes);

    let vs = ValidatorSet::new(storage.clone());

    // Resolve and validate the full extension before the first mutation. A
    // consensus member without admitted OCOMP material is a broken state
    // invariant and must not leave a partially-written snapshot behind.
    let mut ocomp_members = Vec::with_capacity(snapshot.committee.len());
    for entry in &snapshot.committee {
        let registration = vs.ocomp_registration(entry.address)?.ok_or_else(|| {
            PrecompileError::Fatal(format!(
                "active validator {} has no admitted OCOMP registration",
                entry.address
            ))
        })?;
        let expected_identity = validator_identity_hash_v1(entry.address, &entry.consensus_pubkey)
            .map_err(|error| {
                PrecompileError::Fatal(format!(
                    "cannot derive OCOMP identity for active validator {}: {error}",
                    entry.address
                ))
            })?;
        if registration.core.validator_identity_hash != expected_identity
            || registration.core.key_epoch != POC_KEY_EPOCH
            || registration.core.allowed_purpose_bitmap != RESULT_SIGNATURE_PURPOSE_BITMAP
        {
            return Err(PrecompileError::Fatal(format!(
                "active validator {} has stale or invalid OCOMP registration",
                entry.address
            )));
        }
        ocomp_members.push(OcompSnapshotMemberV1 {
            validator_address: entry.address,
            ocomp_public_key_sec1: registration.core.ocomp_public_key_sec1,
            key_epoch: registration.core.key_epoch,
        });
    }
    let ocomp_member_count: u16 = ocomp_members
        .len()
        .try_into()
        .map_err(|_| PrecompileError::Fatal("OCOMP snapshot member count exceeds u16".into()))?;
    let ocomp_binding_hash = ocomp_binding_hash_v1(epoch, hash, &ocomp_members);

    if vs.committee_snapshot_exists.read(&key)? {
        let stored_snapshot = read_committee_snapshot(storage.clone(), key)?.ok_or_else(|| {
            PrecompileError::Fatal("committee snapshot exists flag has no readable record".into())
        })?;
        let expected_extension = OcompSnapshotExtensionV1 {
            epoch,
            committee_set_hash: hash,
            ocomp_binding_hash,
            member_count: ocomp_member_count,
        };
        let stored_extension = read_ocomp_snapshot_extension(storage.clone(), key)?;
        let mut members_match = stored_extension.as_ref() == Some(&expected_extension);
        if members_match {
            for (index, expected_member) in ocomp_members.iter().enumerate() {
                let index = index as u16;
                if read_ocomp_snapshot_member_at(storage.clone(), key, index)?.as_ref()
                    != Some(expected_member)
                {
                    members_match = false;
                    break;
                }
            }
        }
        if stored_snapshot != *snapshot || !members_match {
            return Err(PrecompileError::Fatal(format!(
                "committee snapshot replay mismatch for key {key}"
            )));
        }
        return Ok((hash, key));
    }

    // Evict the colliding ring record in the same enclosing boundary
    // checkpoint, before any replacement fields become reachable.
    let ring_idx = epoch % COMMITTEE_SNAPSHOT_RETAIN_EPOCHS;
    let evicted = vs.committee_snapshot_key_ring.read(&ring_idx)?;
    if evicted != B256::ZERO && evicted != key {
        clear_committee_snapshot(storage.clone(), evicted)?;
    }

    vs.committee_snapshot_len.write(&key, committee_len)?;
    for (i, entry) in snapshot.committee.iter().enumerate() {
        let idx = i as u64;
        vs.committee_snapshot_address_at
            .get_nested(&key)
            .write(&idx, entry.address)?;

        let (lo, hi) = split_pubkey(&entry.consensus_pubkey);
        vs.committee_snapshot_pubkey_lo_at
            .get_nested(&key)
            .write(&idx, lo)?;
        vs.committee_snapshot_pubkey_hi_at
            .get_nested(&key)
            .write(&idx, hi)?;
    }
    vs.committee_snapshot_vrf_material_version
        .write(&key, snapshot.vrf_material_version)?;
    vs.committee_snapshot_vrf_group_public_key_hash
        .write(&key, vrf_pk_hash)?;
    vs.committee_snapshot_vrf_group_public_key_len
        .write(&key, vrf_pk_len)?;
    vs.committee_snapshot_vrf_public_polynomial_hash
        .write(&key, snapshot.vrf_public_polynomial_hash)?;
    for (i, chunk) in snapshot.vrf_group_public_key_bytes.chunks(32).enumerate() {
        let idx = i as u64;
        let mut buf = [0u8; 32];
        buf[..chunk.len()].copy_from_slice(chunk);
        vs.committee_snapshot_vrf_group_public_key_chunk_at
            .get_nested(&key)
            .write(&idx, B256::from(buf))?;
    }

    vs.committee_snapshot_ocomp_epoch.write(&key, epoch)?;
    vs.committee_snapshot_ocomp_consensus_hash
        .write(&key, hash)?;
    vs.committee_snapshot_ocomp_binding_hash
        .write(&key, ocomp_binding_hash)?;
    vs.committee_snapshot_ocomp_member_count
        .write(&key, u64::from(ocomp_member_count))?;
    for (index, member) in ocomp_members.iter().enumerate() {
        let index = index as u64;
        let (lo, hi) = split_ocomp_public_key(&member.ocomp_public_key_sec1);
        vs.committee_snapshot_ocomp_key_lo_at
            .get_nested(&key)
            .write(&index, lo)?;
        vs.committee_snapshot_ocomp_key_hi_at
            .get_nested(&key)
            .write(&index, hi)?;
        vs.committee_snapshot_ocomp_key_epoch_at
            .get_nested(&key)
            .write(&index, member.key_epoch)?;
    }

    // Prune ring: retain only the last COMMITTEE_SNAPSHOT_RETAIN_EPOCHS epochs.
    // A boundary writes outgoing(epoch-1) + incoming(epoch) - distinct epochs ->
    // distinct ring slots. Writing epoch E evicts the snapshot from epoch E-RETAIN.
    vs.committee_snapshot_key_ring.write(&ring_idx, key)?;

    // `exists` LAST: gates every read path on a fully-written snapshot and
    // its completed ring replacement.
    vs.committee_snapshot_exists.write(&key, true)?;

    Ok((hash, key))
}

/// Read OCOMP metadata attached to `snapshot_key` without decoding the full
/// committee. The consensus `exists` flag gates the extension as well.
pub fn read_ocomp_snapshot_extension(
    storage: StorageHandle,
    snapshot_key: B256,
) -> Result<Option<OcompSnapshotExtensionV1>> {
    let vs = ValidatorSet::new(storage);
    if !vs.committee_snapshot_exists.read(&snapshot_key)? {
        return Ok(None);
    }
    let member_count = vs
        .committee_snapshot_ocomp_member_count
        .read(&snapshot_key)?;
    let member_count: u16 = member_count.try_into().map_err(|_| {
        PrecompileError::Fatal("stored OCOMP snapshot member count exceeds u16".into())
    })?;
    Ok(Some(OcompSnapshotExtensionV1 {
        epoch: vs.committee_snapshot_ocomp_epoch.read(&snapshot_key)?,
        committee_set_hash: vs
            .committee_snapshot_ocomp_consensus_hash
            .read(&snapshot_key)?,
        ocomp_binding_hash: vs
            .committee_snapshot_ocomp_binding_hash
            .read(&snapshot_key)?,
        member_count,
    }))
}

/// Strictly resolve an OCOMP extension by all three historical bindings.
/// A prune-ring collision or stale key is reported as missing, never replaced
/// with the current committee.
pub fn read_ocomp_snapshot_extension_for_binding(
    storage: StorageHandle,
    epoch: u64,
    committee_set_hash: B256,
    ocomp_binding_hash: B256,
) -> Result<Option<OcompSnapshotExtensionV1>> {
    let key = committee_snapshot_key(epoch, committee_set_hash);
    let Some(extension) = read_ocomp_snapshot_extension(storage, key)? else {
        return Ok(None);
    };
    if extension.epoch != epoch
        || extension.committee_set_hash != committee_set_hash
        || extension.ocomp_binding_hash != ocomp_binding_hash
    {
        return Ok(None);
    }
    Ok(Some(extension))
}

/// Resolves the one canonical snapshot retained for `epoch` from the bounded
/// ring and validates both its consensus and OCOMP bindings. A missing,
/// evicted or colliding record returns `None`; it is never substituted with a
/// snapshot from another epoch.
pub fn read_ocomp_snapshot_extension_at_epoch(
    storage: StorageHandle,
    epoch: u64,
) -> Result<Option<(B256, OcompSnapshotExtensionV1)>> {
    let vs = ValidatorSet::new(storage.clone());
    let ring_index = epoch % COMMITTEE_SNAPSHOT_RETAIN_EPOCHS;
    let snapshot_key = vs.committee_snapshot_key_ring.read(&ring_index)?;
    if snapshot_key.is_zero() {
        return Ok(None);
    }
    let Some(snapshot) = read_committee_snapshot(storage.clone(), snapshot_key)? else {
        return Ok(None);
    };
    let committee_set_hash = committee_set_hash_v2(epoch, &snapshot);
    if committee_snapshot_key(epoch, committee_set_hash) != snapshot_key {
        return Ok(None);
    }
    let Some(extension) = read_ocomp_snapshot_extension(storage.clone(), snapshot_key)? else {
        return Ok(None);
    };
    if extension.epoch != epoch
        || extension.committee_set_hash != committee_set_hash
        || usize::from(extension.member_count) != snapshot.committee.len()
    {
        return Ok(None);
    }

    let mut members = Vec::with_capacity(usize::from(extension.member_count));
    for index in 0..extension.member_count {
        let Some(member) = read_ocomp_snapshot_member_at(storage.clone(), snapshot_key, index)?
        else {
            return Ok(None);
        };
        members.push(member);
    }
    if ocomp_binding_hash_v1(epoch, committee_set_hash, &members) != extension.ocomp_binding_hash {
        return Ok(None);
    }
    Ok(Some((snapshot_key, extension)))
}

/// Read one OCOMP member at the consensus committee's stable ordered index.
pub fn read_ocomp_snapshot_member_at(
    storage: StorageHandle,
    snapshot_key: B256,
    index: u16,
) -> Result<Option<OcompSnapshotMemberV1>> {
    let vs = ValidatorSet::new(storage);
    if !vs.committee_snapshot_exists.read(&snapshot_key)? {
        return Ok(None);
    }
    let member_count = vs
        .committee_snapshot_ocomp_member_count
        .read(&snapshot_key)?;
    if u64::from(index) >= member_count {
        return Ok(None);
    }
    let index = u64::from(index);
    let lo = vs
        .committee_snapshot_ocomp_key_lo_at
        .get_nested(&snapshot_key)
        .read(&index)?;
    let hi = vs
        .committee_snapshot_ocomp_key_hi_at
        .get_nested(&snapshot_key)
        .read(&index)?;
    Ok(Some(OcompSnapshotMemberV1 {
        validator_address: vs
            .committee_snapshot_address_at
            .get_nested(&snapshot_key)
            .read(&index)?,
        ocomp_public_key_sec1: join_ocomp_public_key(lo, hi)?,
        key_epoch: vs
            .committee_snapshot_ocomp_key_epoch_at
            .get_nested(&snapshot_key)
            .read(&index)?,
    }))
}

/// Reads a previously-written committee snapshot from the store, or returns
/// `Ok(None)` when no snapshot exists at `snapshot_key`.
///
/// Returns the snapshot data without `epoch`; the caller already supplied the
/// `(epoch, committee_set_hash)` pair that produced `snapshot_key`.
pub fn read_committee_snapshot(
    storage: StorageHandle,
    snapshot_key: B256,
) -> Result<Option<CommitteeSnapshot>> {
    let vs = ValidatorSet::new(storage);
    if !vs.committee_snapshot_exists.read(&snapshot_key)? {
        return Ok(None);
    }

    let committee_len = vs.committee_snapshot_len.read(&snapshot_key)?;
    let mut committee = Vec::with_capacity(committee_len as usize);
    for i in 0..committee_len {
        let address = vs
            .committee_snapshot_address_at
            .get_nested(&snapshot_key)
            .read(&i)?;
        let lo: B256 = vs
            .committee_snapshot_pubkey_lo_at
            .get_nested(&snapshot_key)
            .read(&i)?;
        let hi: B256 = vs
            .committee_snapshot_pubkey_hi_at
            .get_nested(&snapshot_key)
            .read(&i)?;
        committee.push(CommitteeEntry {
            address,
            consensus_pubkey: join_pubkey(lo, hi),
        });
    }

    let vrf_material_version = vs
        .committee_snapshot_vrf_material_version
        .read(&snapshot_key)?;
    let vrf_pk_len = vs
        .committee_snapshot_vrf_group_public_key_len
        .read(&snapshot_key)?;
    let vrf_pk_len_usize: usize = vrf_pk_len
        .try_into()
        .map_err(|_| PrecompileError::Revert("vrf group pk length exceeds usize".into()))?;
    let mut vrf_group_public_key_bytes = Vec::with_capacity(vrf_pk_len_usize);
    if vrf_pk_len > 0 {
        let num_chunks = vrf_pk_len.div_ceil(32);
        let last_chunk_take = (vrf_pk_len % 32) as usize;
        let last_chunk_take = if last_chunk_take == 0 {
            32
        } else {
            last_chunk_take
        };
        for i in 0..num_chunks {
            let chunk: B256 = vs
                .committee_snapshot_vrf_group_public_key_chunk_at
                .get_nested(&snapshot_key)
                .read(&i)?;
            let take = if i + 1 == num_chunks {
                last_chunk_take
            } else {
                32
            };
            vrf_group_public_key_bytes.extend_from_slice(&chunk.0[..take]);
        }
    }

    let vrf_public_polynomial_hash = vs
        .committee_snapshot_vrf_public_polynomial_hash
        .read(&snapshot_key)?;

    Ok(Some(CommitteeSnapshot {
        committee,
        vrf_material_version,
        vrf_group_public_key_bytes,
        vrf_public_polynomial_hash,
    }))
}

/// Read the committee snapshot for `epoch` via the prune ring (slot 44), WITHOUT
/// needing the `committee_set_hash`.
///
/// The ring maps `epoch % COMMITTEE_SNAPSHOT_RETAIN_EPOCHS -> snapshot_key`. For
/// an epoch within the retained window the slot holds that epoch's key. For an
/// older epoch, the slot may have been overwritten by a newer colliding epoch;
/// the reader recomputes the requested epoch's canonical key from the decoded
/// snapshot and returns `None` on mismatch. This keeps evidence lookup
/// fail-closed even when both epochs have an identical committee.
pub fn read_committee_snapshot_for_epoch(
    storage: StorageHandle,
    epoch: u64,
) -> Result<Option<CommitteeSnapshot>> {
    let key = {
        let vs = ValidatorSet::new(storage.clone());
        let ring_idx = epoch % COMMITTEE_SNAPSHOT_RETAIN_EPOCHS;
        vs.committee_snapshot_key_ring.read(&ring_idx)?
    };
    if key == B256::ZERO {
        return Ok(None);
    }
    let Some(snapshot) = read_committee_snapshot(storage, key)? else {
        return Ok(None);
    };
    let (_, expected_key) = snapshot_identity(epoch, &snapshot);
    if key != expected_key {
        return Ok(None);
    }
    Ok(Some(snapshot))
}

/// Pre-computes `(committee_set_hash, snapshot_key)` without touching storage.
///
/// Useful for callers that need the key before deciding whether to write
/// (e.g., dedup checks).
pub fn snapshot_identity(epoch: u64, snapshot: &CommitteeSnapshot) -> (B256, B256) {
    let hash = committee_set_hash_v2(epoch, snapshot);
    let key = committee_snapshot_key(epoch, hash);
    (hash, key)
}
