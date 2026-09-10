//! Node-local durable recovery for DKG dealer and player state.
//!
//! The wire protocol is unchanged. This module persists enough local input to
//! reconstruct the exact in-memory `Dealer` and `Player` state after restart.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use alloy_primitives::{keccak256, B256};
use commonware_codec::{Encode, Read as _, ReadExt as _};
use commonware_cryptography::bls12381::{
    self,
    dkg::feldman_desmedt::{DealerPrivMsg, DealerPubMsg, Info, Player, PlayerAck},
    primitives::variant::MinSig,
};
use commonware_utils::N3f1;
use eyre::Result;

use super::wire::DkgCeremonyId;

pub(crate) const DKG_DEALER_RETRY_FILE: &str = "dkg_dealer_retry.hex";
pub(crate) const DKG_PLAYER_RETRY_FILE: &str = "dkg_player_retry.hex";
const DKG_DEALER_RETRY_MAGIC: &[u8; 8] = b"ODKGDR01";
const DKG_PLAYER_RETRY_MAGIC: &[u8; 8] = b"ODKGPR01";
const DKG_DEALER_RETRY_HEADER_LEN: usize = 8 + 8 + 32 + 32 + 4;
const DKG_PLAYER_RETRY_HEADER_LEN: usize = 8 + 8 + 32 + 4;
const MAX_DKG_PLAYER_RETRY_BYTES: usize = 64 * 1024 * 1024;
const MAX_DKG_PLAYER_RETRY_STORED_BYTES: u64 = (MAX_DKG_PLAYER_RETRY_BYTES as u64) * 2 + 4096;

#[derive(Clone, Debug)]
pub(super) struct DkgDealerRetrySnapshot {
    pub(super) ceremony_id: DkgCeremonyId,
    pub(super) seed: [u8; 32],
    pub(super) accepted_acks: BTreeMap<bls12381::PublicKey, PlayerAck<bls12381::PublicKey>>,
}

#[derive(Clone, Debug)]
struct AcceptedPlayerDealing {
    pub_msg: DealerPubMsg<MinSig>,
    priv_msg: DealerPrivMsg,
    ack: PlayerAck<bls12381::PublicKey>,
}

#[derive(Clone, Debug)]
pub(super) struct DkgPlayerRetrySnapshot {
    ceremony_id: DkgCeremonyId,
    accepted_dealings: BTreeMap<bls12381::PublicKey, AcceptedPlayerDealing>,
}

impl DkgPlayerRetrySnapshot {
    pub(super) fn empty(ceremony_id: DkgCeremonyId) -> Self {
        Self {
            ceremony_id,
            accepted_dealings: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum PlayerBundleAction {
    SendAck(PlayerAck<bls12381::PublicKey>),
    DuplicateAck(PlayerAck<bls12381::PublicKey>),
    Invalid,
    Equivocation { previous: B256, received: B256 },
}

/// Durable DKG transcript storage for both local protocol roles.
///
/// Dealer and player files remain separate so the existing dealer format and
/// its operational recovery behavior stay byte-for-byte compatible.
#[derive(Clone, Debug)]
pub struct DkgRetryStore {
    dealer_path: PathBuf,
    player_path: PathBuf,
    backend: crate::bls::KeyBackend,
}

impl DkgRetryStore {
    #[must_use]
    pub fn in_keys_dir(keys_dir: &Path, backend: crate::bls::KeyBackend) -> Self {
        Self {
            dealer_path: keys_dir.join(DKG_DEALER_RETRY_FILE),
            player_path: keys_dir.join(DKG_PLAYER_RETRY_FILE),
            backend,
        }
    }

    pub(super) fn load_dealer(
        &self,
        ceremony_id: DkgCeremonyId,
    ) -> Result<Option<DkgDealerRetrySnapshot>> {
        if !self.dealer_path.exists() {
            return Ok(None);
        }
        let bytes = crate::bls::load_raw(&self.dealer_path, &self.backend)
            .map_err(|error| eyre::eyre!("failed to load DKG dealer retry snapshot: {error}"))?;
        let snapshot = decode_dealer_retry_snapshot(&bytes)?;
        Ok((snapshot.ceremony_id == ceremony_id).then_some(snapshot))
    }

    pub(super) fn save_dealer(&self, snapshot: &DkgDealerRetrySnapshot) -> Result<()> {
        save_snapshot(
            &self.dealer_path,
            &encode_dealer_retry_snapshot(snapshot)?,
            &self.backend,
            "dealer",
        )
    }

    fn load_player(
        &self,
        ceremony_id: DkgCeremonyId,
        max_players: NonZeroU32,
    ) -> Result<Option<DkgPlayerRetrySnapshot>> {
        if !self.player_path.exists() {
            return Ok(None);
        }
        let stored_len = std::fs::metadata(&self.player_path)
            .map_err(|error| eyre::eyre!("failed to stat DKG player retry snapshot: {error}"))?
            .len();
        if stored_len > MAX_DKG_PLAYER_RETRY_STORED_BYTES {
            return Err(eyre::eyre!(
                "stored DKG player retry snapshot exceeds {MAX_DKG_PLAYER_RETRY_STORED_BYTES} bytes"
            ));
        }
        let bytes = crate::bls::load_raw(&self.player_path, &self.backend)
            .map_err(|error| eyre::eyre!("failed to load DKG player retry snapshot: {error}"))?;
        let snapshot = decode_player_retry_snapshot(&bytes, max_players)?;
        Ok((snapshot.ceremony_id == ceremony_id).then_some(snapshot))
    }

    fn save_player(&self, snapshot: &DkgPlayerRetrySnapshot) -> Result<()> {
        save_snapshot(
            &self.player_path,
            &encode_player_retry_snapshot(snapshot)?,
            &self.backend,
            "player",
        )
    }

    /// Remove both transcripts only after the matching DKG output has been
    /// durably promoted at its canonical activation boundary.
    pub fn clear(&self) -> Result<()> {
        crate::bls::remove_raw(&self.dealer_path, &self.backend)
            .map_err(|error| eyre::eyre!("failed to clear DKG dealer retry snapshot: {error}"))?;
        crate::bls::remove_raw(&self.player_path, &self.backend)
            .map_err(|error| eyre::eyre!("failed to clear DKG player retry snapshot: {error}"))
    }
}

pub(super) fn restore_player(
    info: Info<MinSig, bls12381::PublicKey>,
    signing_key: bls12381::PrivateKey,
    ceremony_id: DkgCeremonyId,
    max_players: NonZeroU32,
    retry_store: Option<&DkgRetryStore>,
) -> Result<(Player<MinSig, bls12381::PrivateKey>, DkgPlayerRetrySnapshot)> {
    let mut player = Player::<MinSig, bls12381::PrivateKey>::new(info, signing_key)
        .map_err(|error| eyre::eyre!("failed to create player: {error:?}"))?;
    let snapshot = match retry_store {
        Some(store) => store
            .load_player(ceremony_id, max_players)?
            .unwrap_or_else(|| DkgPlayerRetrySnapshot::empty(ceremony_id)),
        None => DkgPlayerRetrySnapshot::empty(ceremony_id),
    };

    for (dealer, accepted) in &snapshot.accepted_dealings {
        let replayed_ack = player
            .dealer_message::<N3f1>(
                dealer.clone(),
                accepted.pub_msg.clone(),
                accepted.priv_msg.clone(),
            )
            .ok_or_else(|| {
                eyre::eyre!("persisted DKG player dealing is invalid during restart replay")
            })?;
        if replayed_ack.encode() != accepted.ack.encode() {
            return Err(eyre::eyre!(
                "persisted DKG player dealing produced a different ACK during restart replay"
            ));
        }
    }

    Ok((player, snapshot))
}

pub(super) fn handle_player_bundle(
    player: &mut Player<MinSig, bls12381::PrivateKey>,
    snapshot: &mut DkgPlayerRetrySnapshot,
    retry_store: Option<&DkgRetryStore>,
    dealer: bls12381::PublicKey,
    pub_msg: DealerPubMsg<MinSig>,
    priv_msg: DealerPrivMsg,
) -> Result<PlayerBundleAction> {
    let received = dealer_bundle_hash(&pub_msg, &priv_msg);
    if let Some(accepted) = snapshot.accepted_dealings.get(&dealer) {
        let previous = dealer_bundle_hash(&accepted.pub_msg, &accepted.priv_msg);
        if previous == received
            && accepted.pub_msg.encode() == pub_msg.encode()
            && accepted.priv_msg.encode() == priv_msg.encode()
        {
            return Ok(PlayerBundleAction::DuplicateAck(accepted.ack.clone()));
        }
        return Ok(PlayerBundleAction::Equivocation { previous, received });
    }

    let Some(ack) =
        player.dealer_message::<N3f1>(dealer.clone(), pub_msg.clone(), priv_msg.clone())
    else {
        return Ok(PlayerBundleAction::Invalid);
    };
    snapshot.accepted_dealings.insert(
        dealer,
        AcceptedPlayerDealing {
            pub_msg,
            priv_msg,
            ack: ack.clone(),
        },
    );
    if let Some(store) = retry_store {
        store.save_player(snapshot)?;
    }
    Ok(PlayerBundleAction::SendAck(ack))
}

fn dealer_bundle_hash(pub_msg: &DealerPubMsg<MinSig>, priv_msg: &DealerPrivMsg) -> B256 {
    let pub_bytes = pub_msg.encode();
    let priv_bytes = priv_msg.encode();
    let mut bytes = Vec::with_capacity(8 + pub_bytes.len() + priv_bytes.len());
    bytes.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&pub_bytes);
    bytes.extend_from_slice(&(priv_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&priv_bytes);
    keccak256(bytes)
}

fn save_snapshot(
    path: &Path,
    bytes: &[u8],
    backend: &crate::bls::KeyBackend,
    role: &str,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            eyre::eyre!(
                "failed to create DKG {role} retry directory {}: {error}",
                parent.display()
            )
        })?;
    }
    crate::bls::save_raw(path, bytes, backend)
        .map_err(|error| eyre::eyre!("failed to persist DKG {role} retry snapshot: {error}"))
}

pub(super) fn encode_dealer_retry_snapshot(snapshot: &DkgDealerRetrySnapshot) -> Result<Vec<u8>> {
    let ack_count: u32 = snapshot
        .accepted_acks
        .len()
        .try_into()
        .map_err(|_| eyre::eyre!("too many DKG dealer retry ACKs"))?;
    let mut bytes = Vec::with_capacity(DKG_DEALER_RETRY_HEADER_LEN);
    bytes.extend_from_slice(DKG_DEALER_RETRY_MAGIC);
    bytes.extend_from_slice(&snapshot.ceremony_id.round.to_be_bytes());
    bytes.extend_from_slice(snapshot.ceremony_id.info_hash.as_slice());
    bytes.extend_from_slice(&snapshot.seed);
    bytes.extend_from_slice(&ack_count.to_be_bytes());
    for (player, ack) in &snapshot.accepted_acks {
        push_retry_snapshot_field(&mut bytes, &player.encode())?;
        push_retry_snapshot_field(&mut bytes, &ack.encode())?;
    }
    Ok(bytes)
}

pub(super) fn decode_dealer_retry_snapshot(bytes: &[u8]) -> Result<DkgDealerRetrySnapshot> {
    if bytes.len() < DKG_DEALER_RETRY_HEADER_LEN {
        return Err(eyre::eyre!(
            "invalid DKG dealer retry snapshot length: expected at least {DKG_DEALER_RETRY_HEADER_LEN}, got {}",
            bytes.len()
        ));
    }
    if &bytes[..DKG_DEALER_RETRY_MAGIC.len()] != DKG_DEALER_RETRY_MAGIC {
        return Err(eyre::eyre!("invalid DKG dealer retry snapshot magic"));
    }
    let round = u64::from_be_bytes(bytes[8..16].try_into()?);
    let info_hash = B256::from(<[u8; 32]>::try_from(&bytes[16..48])?);
    let seed = <[u8; 32]>::try_from(&bytes[48..80])?;
    let ack_count = u32::from_be_bytes(bytes[80..84].try_into()?);
    ensure_entry_count(ack_count, "dealer ACK")?;
    let mut cursor = 84usize;
    let mut accepted_acks = BTreeMap::new();
    for _ in 0..ack_count {
        let player = decode_exact(
            take_retry_snapshot_field(bytes, &mut cursor, "player")?,
            |reader| bls12381::PublicKey::read(reader),
            "player key",
        )?;
        let ack = decode_exact(
            take_retry_snapshot_field(bytes, &mut cursor, "ACK")?,
            |reader| PlayerAck::<bls12381::PublicKey>::read(reader),
            "ACK",
        )?;
        if accepted_acks.insert(player, ack).is_some() {
            return Err(eyre::eyre!("duplicate player in DKG retry snapshot"));
        }
    }
    ensure_exact_end(bytes, cursor, "dealer")?;
    Ok(DkgDealerRetrySnapshot {
        ceremony_id: DkgCeremonyId { round, info_hash },
        seed,
        accepted_acks,
    })
}

fn encode_player_retry_snapshot(snapshot: &DkgPlayerRetrySnapshot) -> Result<Vec<u8>> {
    let dealing_count: u32 = snapshot
        .accepted_dealings
        .len()
        .try_into()
        .map_err(|_| eyre::eyre!("too many DKG player retry dealings"))?;
    let mut bytes = Vec::with_capacity(DKG_PLAYER_RETRY_HEADER_LEN);
    bytes.extend_from_slice(DKG_PLAYER_RETRY_MAGIC);
    bytes.extend_from_slice(&snapshot.ceremony_id.round.to_be_bytes());
    bytes.extend_from_slice(snapshot.ceremony_id.info_hash.as_slice());
    bytes.extend_from_slice(&dealing_count.to_be_bytes());
    for (dealer, accepted) in &snapshot.accepted_dealings {
        push_retry_snapshot_field(&mut bytes, &dealer.encode())?;
        push_retry_snapshot_field(&mut bytes, &accepted.pub_msg.encode())?;
        push_retry_snapshot_field(&mut bytes, &accepted.priv_msg.encode())?;
        push_retry_snapshot_field(&mut bytes, &accepted.ack.encode())?;
    }
    if bytes.len() > MAX_DKG_PLAYER_RETRY_BYTES {
        return Err(eyre::eyre!(
            "DKG player retry snapshot exceeds {} bytes",
            MAX_DKG_PLAYER_RETRY_BYTES
        ));
    }
    Ok(bytes)
}

fn decode_player_retry_snapshot(
    bytes: &[u8],
    max_players: NonZeroU32,
) -> Result<DkgPlayerRetrySnapshot> {
    if bytes.len() < DKG_PLAYER_RETRY_HEADER_LEN || bytes.len() > MAX_DKG_PLAYER_RETRY_BYTES {
        return Err(eyre::eyre!(
            "invalid DKG player retry snapshot length: {}",
            bytes.len()
        ));
    }
    if &bytes[..DKG_PLAYER_RETRY_MAGIC.len()] != DKG_PLAYER_RETRY_MAGIC {
        return Err(eyre::eyre!("invalid DKG player retry snapshot magic"));
    }
    let round = u64::from_be_bytes(bytes[8..16].try_into()?);
    let info_hash = B256::from(<[u8; 32]>::try_from(&bytes[16..48])?);
    let dealing_count = u32::from_be_bytes(bytes[48..52].try_into()?);
    ensure_entry_count(dealing_count, "player dealing")?;
    let mut cursor = 52usize;
    let mut accepted_dealings = BTreeMap::new();
    for _ in 0..dealing_count {
        let dealer = decode_exact(
            take_retry_snapshot_field(bytes, &mut cursor, "dealer")?,
            |reader| bls12381::PublicKey::read(reader),
            "dealer key",
        )?;
        let pub_msg = decode_exact(
            take_retry_snapshot_field(bytes, &mut cursor, "public message")?,
            |reader| DealerPubMsg::<MinSig>::read_cfg(reader, &max_players),
            "public message",
        )?;
        let priv_msg = decode_exact(
            take_retry_snapshot_field(bytes, &mut cursor, "private message")?,
            |reader| DealerPrivMsg::read(reader),
            "private message",
        )?;
        let ack = decode_exact(
            take_retry_snapshot_field(bytes, &mut cursor, "ACK")?,
            |reader| PlayerAck::<bls12381::PublicKey>::read(reader),
            "ACK",
        )?;
        if accepted_dealings
            .insert(
                dealer,
                AcceptedPlayerDealing {
                    pub_msg,
                    priv_msg,
                    ack,
                },
            )
            .is_some()
        {
            return Err(eyre::eyre!("duplicate dealer in DKG player retry snapshot"));
        }
    }
    ensure_exact_end(bytes, cursor, "player")?;
    Ok(DkgPlayerRetrySnapshot {
        ceremony_id: DkgCeremonyId { round, info_hash },
        accepted_dealings,
    })
}

fn push_retry_snapshot_field(bytes: &mut Vec<u8>, field: &[u8]) -> Result<()> {
    let len: u32 = field
        .len()
        .try_into()
        .map_err(|_| eyre::eyre!("DKG retry field exceeds u32 length"))?;
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(field);
    Ok(())
}

fn take_retry_snapshot_field<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    field: &str,
) -> Result<&'a [u8]> {
    let len_end = cursor
        .checked_add(4)
        .ok_or_else(|| eyre::eyre!("DKG retry {field} length overflow"))?;
    let len_bytes = bytes
        .get(*cursor..len_end)
        .ok_or_else(|| eyre::eyre!("truncated DKG retry {field} length"))?;
    let len = u32::from_be_bytes(len_bytes.try_into()?) as usize;
    let value_end = len_end
        .checked_add(len)
        .ok_or_else(|| eyre::eyre!("DKG retry {field} value overflow"))?;
    let value = bytes
        .get(len_end..value_end)
        .ok_or_else(|| eyre::eyre!("truncated DKG retry {field} value"))?;
    *cursor = value_end;
    Ok(value)
}

fn decode_exact<T, E>(
    bytes: &[u8],
    decode: impl FnOnce(&mut &[u8]) -> std::result::Result<T, E>,
    field: &str,
) -> Result<T>
where
    E: std::fmt::Display,
{
    let mut reader = bytes;
    let value =
        decode(&mut reader).map_err(|error| eyre::eyre!("invalid DKG retry {field}: {error}"))?;
    if !reader.is_empty() {
        return Err(eyre::eyre!("trailing bytes in DKG retry {field}"));
    }
    Ok(value)
}

fn ensure_entry_count(count: u32, kind: &str) -> Result<()> {
    if count > crate::bls::MAX_VALIDATORS {
        return Err(eyre::eyre!(
            "DKG retry {kind} count {count} exceeds validator limit"
        ));
    }
    Ok(())
}

fn ensure_exact_end(bytes: &[u8], cursor: usize, role: &str) -> Result<()> {
    if cursor != bytes.len() {
        return Err(eyre::eyre!("trailing bytes in DKG {role} retry snapshot"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Signer as _;
    use commonware_utils::ordered::Set;

    fn fixture() -> (
        Info<MinSig, bls12381::PublicKey>,
        bls12381::PrivateKey,
        bls12381::PublicKey,
        DealerPubMsg<MinSig>,
        DealerPrivMsg,
        DkgCeremonyId,
    ) {
        let mut keys: Vec<_> = (1..=3).map(bls12381::PrivateKey::from_seed).collect();
        keys.sort_by_key(|key| key.public_key().encode());
        let participant_keys = keys
            .iter()
            .map(commonware_cryptography::Signer::public_key)
            .collect::<Vec<_>>();
        let participants: Set<_> = participant_keys.try_into().unwrap();
        let info = Info::<MinSig, bls12381::PublicKey>::new::<N3f1>(
            &crate::config::outbe_app_namespace(),
            0,
            None,
            commonware_cryptography::bls12381::primitives::sharing::Mode::NonZeroCounter,
            participants.clone(),
            participants.clone(),
        )
        .unwrap();
        let dealer_key = keys[0].clone();
        let player_key = keys[1].clone();
        let player_pk = player_key.public_key();
        let dealer_pk = dealer_key.public_key();
        let (_, pub_msg, priv_msgs) =
            commonware_cryptography::bls12381::dkg::feldman_desmedt::Dealer::<
                MinSig,
                bls12381::PrivateKey,
            >::start::<N3f1>(rand_core::OsRng, info.clone(), dealer_key, None)
            .unwrap();
        let priv_msg = priv_msgs
            .into_iter()
            .find(|(key, _)| key == &player_pk)
            .unwrap()
            .1;
        let ceremony_id = DkgCeremonyId::new(
            &crate::config::outbe_app_namespace(),
            0,
            None,
            &participants,
        );
        (info, player_key, dealer_pk, pub_msg, priv_msg, ceremony_id)
    }

    #[test]
    fn player_dealing_survives_restart_and_replays_the_same_ack() {
        let (info, player_key, dealer, pub_msg, priv_msg, ceremony_id) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let store = DkgRetryStore::in_keys_dir(dir.path(), crate::bls::KeyBackend::Plaintext);
        let max_players = NonZeroU32::new(3).unwrap();
        let (mut player, mut snapshot) = restore_player(
            info.clone(),
            player_key.clone(),
            ceremony_id,
            max_players,
            Some(&store),
        )
        .unwrap();
        let first = handle_player_bundle(
            &mut player,
            &mut snapshot,
            Some(&store),
            dealer.clone(),
            pub_msg.clone(),
            priv_msg.clone(),
        )
        .unwrap();
        let PlayerBundleAction::SendAck(first_ack) = first else {
            panic!("first valid dealing must be acknowledged");
        };

        let (mut restarted, mut recovered) =
            restore_player(info, player_key, ceremony_id, max_players, Some(&store)).unwrap();
        let duplicate = handle_player_bundle(
            &mut restarted,
            &mut recovered,
            Some(&store),
            dealer,
            pub_msg,
            priv_msg,
        )
        .unwrap();
        let PlayerBundleAction::DuplicateAck(replayed_ack) = duplicate else {
            panic!("replayed dealing must reuse its durable ACK");
        };
        assert_eq!(first_ack.encode(), replayed_ack.encode());
    }

    #[test]
    fn clear_removes_both_role_snapshots() {
        let (_, _, _, _, _, ceremony_id) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let store = DkgRetryStore::in_keys_dir(dir.path(), crate::bls::KeyBackend::Plaintext);
        store
            .save_dealer(&DkgDealerRetrySnapshot {
                ceremony_id,
                seed: [7; 32],
                accepted_acks: BTreeMap::new(),
            })
            .unwrap();
        store
            .save_player(&DkgPlayerRetrySnapshot::empty(ceremony_id))
            .unwrap();

        store.clear().unwrap();

        assert!(!dir.path().join(DKG_DEALER_RETRY_FILE).exists());
        assert!(!dir.path().join(DKG_PLAYER_RETRY_FILE).exists());
    }

    #[test]
    fn persistence_failure_prevents_acknowledgement() {
        let (info, player_key, dealer, pub_msg, priv_msg, ceremony_id) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let invalid_keys_dir = dir.path().join("not-a-directory");
        std::fs::write(&invalid_keys_dir, b"file").unwrap();
        let store =
            DkgRetryStore::in_keys_dir(&invalid_keys_dir, crate::bls::KeyBackend::Plaintext);
        let (mut player, mut snapshot) = restore_player(
            info,
            player_key,
            ceremony_id,
            NonZeroU32::new(3).unwrap(),
            Some(&store),
        )
        .unwrap();

        let error = handle_player_bundle(
            &mut player,
            &mut snapshot,
            Some(&store),
            dealer,
            pub_msg,
            priv_msg,
        )
        .unwrap_err();

        assert!(error.to_string().contains("player retry"));
    }

    #[test]
    fn player_snapshot_is_ceremony_scoped_and_truncation_fails_closed() {
        let (_, _, _, _, _, ceremony_id) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let store = DkgRetryStore::in_keys_dir(dir.path(), crate::bls::KeyBackend::Plaintext);
        store
            .save_player(&DkgPlayerRetrySnapshot::empty(ceremony_id))
            .unwrap();

        assert!(store
            .load_player(
                DkgCeremonyId {
                    round: ceremony_id.round + 1,
                    info_hash: ceremony_id.info_hash,
                },
                NonZeroU32::new(3).unwrap(),
            )
            .unwrap()
            .is_none());

        crate::bls::save_raw(
            &store.player_path,
            b"ODKGPR01",
            &crate::bls::KeyBackend::Plaintext,
        )
        .unwrap();
        assert!(store
            .load_player(ceremony_id, NonZeroU32::new(3).unwrap())
            .is_err());
    }

    #[test]
    fn duplicate_dealer_in_player_snapshot_fails_closed() {
        let (info, player_key, dealer, pub_msg, priv_msg, ceremony_id) = fixture();
        let (mut player, mut snapshot) = restore_player(
            info,
            player_key,
            ceremony_id,
            NonZeroU32::new(3).unwrap(),
            None,
        )
        .unwrap();
        assert!(matches!(
            handle_player_bundle(&mut player, &mut snapshot, None, dealer, pub_msg, priv_msg,)
                .unwrap(),
            PlayerBundleAction::SendAck(_)
        ));
        let encoded = encode_player_retry_snapshot(&snapshot).unwrap();
        let first_entry = &encoded[DKG_PLAYER_RETRY_HEADER_LEN..];
        let mut duplicated = encoded[..DKG_PLAYER_RETRY_HEADER_LEN].to_vec();
        duplicated[48..52].copy_from_slice(&2u32.to_be_bytes());
        duplicated.extend_from_slice(first_entry);
        duplicated.extend_from_slice(first_entry);

        let error =
            decode_player_retry_snapshot(&duplicated, NonZeroU32::new(3).unwrap()).unwrap_err();
        assert!(error.to_string().contains("duplicate dealer"));
    }

    #[test]
    fn restarted_player_finalizes_with_a_private_share() {
        use commonware_cryptography::bls12381::dkg::feldman_desmedt::{Dealer, Logs};
        use commonware_parallel::Sequential;

        let mut keys: Vec<_> = (101..=103).map(bls12381::PrivateKey::from_seed).collect();
        keys.sort_by_key(|key| key.public_key().encode());
        let participants: Set<_> = keys
            .iter()
            .map(commonware_cryptography::Signer::public_key)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let info = Info::<MinSig, bls12381::PublicKey>::new::<N3f1>(
            &crate::config::outbe_app_namespace(),
            0,
            None,
            commonware_cryptography::bls12381::primitives::sharing::Mode::NonZeroCounter,
            participants.clone(),
            participants.clone(),
        )
        .unwrap();
        let ceremony_id = DkgCeremonyId::new(
            &crate::config::outbe_app_namespace(),
            0,
            None,
            &participants,
        );
        let target_key = keys[1].clone();
        let target_pk = target_key.public_key();
        let dir = tempfile::tempdir().unwrap();
        let store = DkgRetryStore::in_keys_dir(dir.path(), crate::bls::KeyBackend::Plaintext);
        let max_players = NonZeroU32::new(3).unwrap();
        let (mut target_player, mut snapshot) = restore_player(
            info.clone(),
            target_key.clone(),
            ceremony_id,
            max_players,
            Some(&store),
        )
        .unwrap();
        let mut dealer_logs = BTreeMap::new();

        for dealer_key in &keys {
            let dealer_pk = dealer_key.public_key();
            let (mut dealer, pub_msg, priv_msgs) =
                Dealer::<MinSig, bls12381::PrivateKey>::start::<N3f1>(
                    rand_core::OsRng,
                    info.clone(),
                    dealer_key.clone(),
                    None,
                )
                .unwrap();
            for (player_pk, priv_msg) in priv_msgs {
                let ack = if player_pk == target_pk {
                    match handle_player_bundle(
                        &mut target_player,
                        &mut snapshot,
                        Some(&store),
                        dealer_pk.clone(),
                        pub_msg.clone(),
                        priv_msg,
                    )
                    .unwrap()
                    {
                        PlayerBundleAction::SendAck(ack) => ack,
                        other => panic!("unexpected target Player action: {other:?}"),
                    }
                } else {
                    let player_key = keys
                        .iter()
                        .find(|key| key.public_key() == player_pk)
                        .unwrap();
                    let mut player = Player::<MinSig, bls12381::PrivateKey>::new(
                        info.clone(),
                        player_key.clone(),
                    )
                    .unwrap();
                    player
                        .dealer_message::<N3f1>(dealer_pk.clone(), pub_msg.clone(), priv_msg)
                        .unwrap()
                };
                dealer.receive_player_ack(player_pk, ack).unwrap();
            }
            let signed_log = dealer.finalize::<N3f1>();
            let (checked_dealer, log) =
                signed_log.check(&info).expect("valid finalized dealer log");
            assert_eq!(checked_dealer, dealer_pk);
            dealer_logs.insert(checked_dealer, log);
        }

        drop(target_player);
        let (restarted_player, _) = restore_player(
            info.clone(),
            target_key,
            ceremony_id,
            max_players,
            Some(&store),
        )
        .unwrap();
        let mut logs = Logs::<MinSig, bls12381::PublicKey, N3f1>::new(info);
        for (dealer, log) in dealer_logs {
            logs.record(dealer, log);
        }
        let (output, _private_share) = restarted_player
            .finalize::<N3f1, commonware_cryptography::bls12381::Batch>(
                &mut rand_core::OsRng,
                logs,
                &Sequential,
            )
            .expect("restarted target Player must finalize with a private share");
        assert_eq!(output.players(), &participants);
    }

    #[test]
    fn oversized_stored_player_snapshot_is_rejected_before_read() {
        let (_, _, _, _, _, ceremony_id) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let store = DkgRetryStore::in_keys_dir(dir.path(), crate::bls::KeyBackend::Plaintext);
        let file = std::fs::File::create(&store.player_path).unwrap();
        file.set_len(MAX_DKG_PLAYER_RETRY_STORED_BYTES + 1).unwrap();

        let error = store
            .load_player(ceremony_id, NonZeroU32::new(3).unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("stored DKG player retry"));
    }

    #[test]
    fn replay_inconsistent_ack_fails_closed() {
        let (info, player_key, dealer, pub_msg, priv_msg, ceremony_id) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let store = DkgRetryStore::in_keys_dir(dir.path(), crate::bls::KeyBackend::Plaintext);
        let max_players = NonZeroU32::new(3).unwrap();
        let (mut player, mut snapshot) = restore_player(
            info.clone(),
            player_key.clone(),
            ceremony_id,
            max_players,
            None,
        )
        .unwrap();
        handle_player_bundle(
            &mut player,
            &mut snapshot,
            None,
            dealer.clone(),
            pub_msg,
            priv_msg,
        )
        .unwrap();

        let (_, _, _, other_pub_msg, other_priv_msg, _) = fixture();
        let mut other_player =
            Player::<MinSig, bls12381::PrivateKey>::new(info.clone(), player_key.clone()).unwrap();
        let different_ack = other_player
            .dealer_message::<N3f1>(dealer.clone(), other_pub_msg, other_priv_msg)
            .unwrap();
        snapshot.accepted_dealings.get_mut(&dealer).unwrap().ack = different_ack;
        store.save_player(&snapshot).unwrap();

        let error = match restore_player(info, player_key, ceremony_id, max_players, Some(&store)) {
            Ok(_) => panic!("replay-inconsistent ACK must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("different ACK"));
    }
}
