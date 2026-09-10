//! Wire format for DKG P2P messages.
//!
//! Messages exchanged between validators during the DKG ceremony.
//! Each message is wrapped in a ceremony-scoped envelope so stale/cross-round
//! traffic is rejected before it mutates the DKG state machine.

use alloy_primitives::{keccak256, B256};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::bls12381::{
    self,
    dkg::feldman_desmedt::{DealerPrivMsg, DealerPubMsg, Output, PlayerAck, SignedDealerLog},
    primitives::variant::MinSig,
};
use commonware_utils::ordered::Set;
use std::num::NonZeroU32;

/// Current DKG wire-envelope version.
const DKG_WIRE_VERSION: u8 = 0x01;

/// Discriminator bytes for wire messages.
const DEALER_BUNDLE_TAG: u8 = 0x00;
const ACK_TAG: u8 = 0x01;
const FINALIZED_LOG_TAG: u8 = 0x02;

/// Stable identity for one DKG ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DkgCeremonyId {
    /// DKG round number: 0 for initial DKG, incremented for reshares.
    pub round: u64,
    /// Hash of namespace, round, previous output, and participant set.
    pub info_hash: B256,
}

impl DkgCeremonyId {
    pub fn new(
        namespace: &[u8],
        round: u64,
        previous_output: Option<&Output<MinSig, bls12381::PublicKey>>,
        participants: &Set<bls12381::PublicKey>,
    ) -> Self {
        let previous_output_hash = previous_output
            .map(|output| keccak256(output.encode()))
            .unwrap_or(B256::ZERO);
        let participants_hash = hash_participants(participants);

        let mut bytes = Vec::with_capacity(
            namespace.len() + std::mem::size_of::<u64>() + B256::len_bytes() * 2,
        );
        bytes.extend_from_slice(namespace);
        bytes.extend_from_slice(&round.to_be_bytes());
        bytes.extend_from_slice(previous_output_hash.as_slice());
        bytes.extend_from_slice(participants_hash.as_slice());

        Self {
            round,
            info_hash: keccak256(bytes),
        }
    }

    fn encode_size() -> usize {
        std::mem::size_of::<u64>() + B256::len_bytes()
    }

    fn write(&self, writer: &mut impl BufMut) {
        writer.put_u64(self.round);
        writer.put_slice(self.info_hash.as_slice());
    }

    fn read(reader: &mut impl Buf) -> Result<Self, Error> {
        if reader.remaining() < Self::encode_size() {
            return Err(Error::EndOfBuffer);
        }
        let round = reader.get_u64();
        let mut hash = [0u8; 32];
        reader.copy_to_slice(&mut hash);
        Ok(Self {
            round,
            info_hash: B256::from(hash),
        })
    }
}

fn hash_participants(participants: &Set<bls12381::PublicKey>) -> B256 {
    let mut bytes = Vec::new();
    for participant in participants.iter() {
        let encoded = participant.encode();
        bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    keccak256(bytes)
}

/// Decode-time context for DKG wire messages.
#[derive(Clone, Copy, Debug)]
pub struct DkgWireConfig {
    pub max_players: NonZeroU32,
    pub expected_ceremony_id: DkgCeremonyId,
}

#[derive(Debug)]
pub enum DkgMessageReadError {
    Codec(Error),
    WrongCeremonyId {
        expected: DkgCeremonyId,
        received: DkgCeremonyId,
    },
}

impl From<Error> for DkgMessageReadError {
    fn from(error: Error) -> Self {
        Self::Codec(error)
    }
}

/// DKG wire message.
///
/// Three message types:
/// - `DealerBundle`: dealer sends polynomial commitment + private share to a player
/// - `Ack`: player sends acknowledgment back to dealer
/// - `FinalizedLog`: dealer broadcasts finalized log to all (initial ceremony only)
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum DkgMessage {
    /// Dealer -> Player: polynomial commitment + private evaluation.
    DealerBundle {
        ceremony_id: DkgCeremonyId,
        pub_msg: DealerPubMsg<MinSig>,
        priv_msg: DealerPrivMsg,
    },
    /// Player -> Dealer: acknowledgment of valid dealing.
    Ack {
        ceremony_id: DkgCeremonyId,
        ack: PlayerAck<bls12381::PublicKey>,
    },
    /// Dealer -> All: finalized dealer log (broadcast in initial ceremony).
    FinalizedLog {
        ceremony_id: DkgCeremonyId,
        signed_log: SignedDealerLog<MinSig, bls12381::PrivateKey>,
    },
}

impl EncodeSize for DkgMessage {
    fn encode_size(&self) -> usize {
        1 + DkgCeremonyId::encode_size()
            + 1
            + match self {
                Self::DealerBundle {
                    pub_msg, priv_msg, ..
                } => pub_msg.encode_size() + priv_msg.encode_size(),
                Self::Ack { ack, .. } => ack.encode_size(),
                Self::FinalizedLog { signed_log, .. } => signed_log.encode_size(),
            }
    }
}

impl Write for DkgMessage {
    fn write(&self, writer: &mut impl BufMut) {
        writer.put_u8(DKG_WIRE_VERSION);
        self.ceremony_id().write(writer);
        match self {
            Self::DealerBundle {
                pub_msg, priv_msg, ..
            } => {
                writer.put_u8(DEALER_BUNDLE_TAG);
                pub_msg.write(writer);
                priv_msg.write(writer);
            }
            Self::Ack { ack, .. } => {
                writer.put_u8(ACK_TAG);
                ack.write(writer);
            }
            Self::FinalizedLog { signed_log, .. } => {
                writer.put_u8(FINALIZED_LOG_TAG);
                signed_log.write(writer);
            }
        }
    }
}

impl DkgMessage {
    pub fn ceremony_id(&self) -> DkgCeremonyId {
        match self {
            Self::DealerBundle { ceremony_id, .. }
            | Self::Ack { ceremony_id, .. }
            | Self::FinalizedLog { ceremony_id, .. } => *ceremony_id,
        }
    }

    pub fn read_for_ceremony(
        reader: &mut impl Buf,
        cfg: &DkgWireConfig,
    ) -> Result<Self, DkgMessageReadError> {
        if reader.remaining() < 1 {
            return Err(Error::EndOfBuffer.into());
        }
        let version = reader.get_u8();
        if version != DKG_WIRE_VERSION {
            return Err(Error::Invalid("DkgMessage", "unsupported wire version").into());
        }
        let ceremony_id = DkgCeremonyId::read(reader)?;
        if ceremony_id != cfg.expected_ceremony_id {
            return Err(DkgMessageReadError::WrongCeremonyId {
                expected: cfg.expected_ceremony_id,
                received: ceremony_id,
            });
        }
        if reader.remaining() < 1 {
            return Err(Error::EndOfBuffer.into());
        }
        let tag = reader.get_u8();
        match tag {
            DEALER_BUNDLE_TAG => {
                let pub_msg = DealerPubMsg::<MinSig>::read_cfg(reader, &cfg.max_players)?;
                let priv_msg = DealerPrivMsg::read(reader)?;
                Ok(Self::DealerBundle {
                    ceremony_id,
                    pub_msg,
                    priv_msg,
                })
            }
            ACK_TAG => {
                let ack = PlayerAck::<bls12381::PublicKey>::read(reader)?;
                Ok(Self::Ack { ceremony_id, ack })
            }
            FINALIZED_LOG_TAG => {
                let signed_log = SignedDealerLog::<MinSig, bls12381::PrivateKey>::read_cfg(
                    reader,
                    &cfg.max_players,
                )?;
                Ok(Self::FinalizedLog {
                    ceremony_id,
                    signed_log,
                })
            }
            _ => Err(Error::Invalid("DkgMessage", "unknown tag").into()),
        }
    }
}

impl Read for DkgMessage {
    type Cfg = DkgWireConfig;

    fn read_cfg(reader: &mut impl Buf, cfg: &DkgWireConfig) -> Result<Self, Error> {
        Self::read_for_ceremony(reader, cfg).map_err(|error| match error {
            DkgMessageReadError::Codec(error) => error,
            DkgMessageReadError::WrongCeremonyId { .. } => {
                Error::Invalid("DkgMessage", "wrong ceremony id")
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_cryptography::bls12381::{
        self,
        dkg::feldman_desmedt::{Dealer, Info, Player},
        primitives::sharing::Mode,
    };
    use commonware_math::algebra::Random;
    use commonware_utils::{ordered::Set, N3f1, TryCollect as _};

    /// Create a minimal DKG setup with n validators, returning
    /// (info, keys, dealers, players) for testing wire messages.
    fn setup_dkg(
        n: u32,
    ) -> (
        Info<MinSig, bls12381::PublicKey>,
        Vec<bls12381::PrivateKey>,
        Set<bls12381::PublicKey>,
    ) {
        let mut keys: Vec<bls12381::PrivateKey> = (0..n)
            .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
            .collect();
        keys.sort_by(|a, b| {
            use commonware_cryptography::Signer;
            a.public_key().encode().cmp(&b.public_key().encode())
        });

        let participants: Set<bls12381::PublicKey> = keys
            .iter()
            .map(commonware_cryptography::Signer::public_key)
            .try_collect()
            .unwrap();

        let info = Info::<MinSig, bls12381::PublicKey>::new::<N3f1>(
            b"test",
            0,
            None,
            Mode::NonZeroCounter,
            participants.clone(),
            participants.clone(),
        )
        .unwrap();

        (info, keys, participants)
    }

    fn wire_cfg(max_players: NonZeroU32, participants: &Set<bls12381::PublicKey>) -> DkgWireConfig {
        DkgWireConfig {
            max_players,
            expected_ceremony_id: DkgCeremonyId::new(b"test", 0, None, participants),
        }
    }

    #[test]
    fn test_dealer_bundle_codec_roundtrip() {
        let (info, keys, participants) = setup_dkg(3);
        let max_players = NonZeroU32::new(3).unwrap();
        let cfg = wire_cfg(max_players, &participants);

        let (_, pub_msg, priv_msgs) = Dealer::<MinSig, bls12381::PrivateKey>::start::<N3f1>(
            rand_core::OsRng,
            info,
            keys[0].clone(),
            None,
        )
        .unwrap();

        let (_, priv_msg) = priv_msgs.into_iter().nth(1).unwrap();
        let msg = DkgMessage::DealerBundle {
            ceremony_id: cfg.expected_ceremony_id,
            pub_msg,
            priv_msg,
        };

        let encoded = msg.encode();
        assert_eq!(encoded[0], DKG_WIRE_VERSION);

        let decoded = DkgMessage::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
        match decoded {
            DkgMessage::DealerBundle { .. } => {}
            other => panic!("expected DealerBundle, got {:?}", other),
        }
    }

    #[test]
    fn test_ack_codec_roundtrip() {
        let (info, keys, participants) = setup_dkg(3);
        let max_players = NonZeroU32::new(3).unwrap();
        let cfg = wire_cfg(max_players, &participants);

        // Dealer 0 sends to Player 1, Player 1 produces an ack.
        let (_, pub_msg, priv_msgs) = Dealer::<MinSig, bls12381::PrivateKey>::start::<N3f1>(
            rand_core::OsRng,
            info.clone(),
            keys[0].clone(),
            None,
        )
        .unwrap();

        let pk1 = commonware_cryptography::Signer::public_key(&keys[1]);
        let priv_msg = priv_msgs.into_iter().find(|(pk, _)| *pk == pk1).unwrap().1;

        let mut player =
            Player::<MinSig, bls12381::PrivateKey>::new(info, keys[1].clone()).unwrap();

        let ack = player
            .dealer_message::<N3f1>(
                commonware_cryptography::Signer::public_key(&keys[0]),
                pub_msg,
                priv_msg,
            )
            .expect("player should produce an ack");

        let msg = DkgMessage::Ack {
            ceremony_id: cfg.expected_ceremony_id,
            ack,
        };
        let encoded = msg.encode();
        assert_eq!(encoded[0], DKG_WIRE_VERSION);

        let decoded = DkgMessage::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
        match decoded {
            DkgMessage::Ack { .. } => {}
            other => panic!("expected Ack, got {:?}", other),
        }
    }

    #[test]
    fn test_finalized_log_codec_roundtrip() {
        let (info, keys, participants) = setup_dkg(3);
        let max_players = NonZeroU32::new(3).unwrap();
        let cfg = wire_cfg(max_players, &participants);

        // Create a dealer, give it acks, then finalize.
        let (mut dealer, pub_msg, priv_msgs) =
            Dealer::<MinSig, bls12381::PrivateKey>::start::<N3f1>(
                rand_core::OsRng,
                info.clone(),
                keys[0].clone(),
                None,
            )
            .unwrap();

        // All players ack.
        for (player_pk, priv_msg) in &priv_msgs {
            let key = keys
                .iter()
                .find(|k| &commonware_cryptography::Signer::public_key(*k) == player_pk)
                .unwrap();
            let mut player =
                Player::<MinSig, bls12381::PrivateKey>::new(info.clone(), key.clone()).unwrap();
            if let Some(ack) = player.dealer_message::<N3f1>(
                commonware_cryptography::Signer::public_key(&keys[0]),
                pub_msg.clone(),
                priv_msg.clone(),
            ) {
                dealer.receive_player_ack(player_pk.clone(), ack).unwrap();
            }
        }

        let signed_log = dealer.finalize::<N3f1>();
        let msg = DkgMessage::FinalizedLog {
            ceremony_id: cfg.expected_ceremony_id,
            signed_log,
        };
        let encoded = msg.encode();
        assert_eq!(encoded[0], DKG_WIRE_VERSION);

        let decoded = DkgMessage::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
        match decoded {
            DkgMessage::FinalizedLog { .. } => {}
            other => panic!("expected FinalizedLog, got {:?}", other),
        }
    }

    #[test]
    fn test_unknown_tag_rejected() {
        let max_players = NonZeroU32::new(3).unwrap();
        let (_, _, participants) = setup_dkg(3);
        let cfg = wire_cfg(max_players, &participants);
        let mut bad_data = Vec::new();
        bad_data.push(DKG_WIRE_VERSION);
        cfg.expected_ceremony_id.write(&mut bad_data);
        bad_data.push(0xFF);
        let result = DkgMessage::read_cfg(&mut bad_data.as_ref(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_buffer_rejected() {
        let max_players = NonZeroU32::new(3).unwrap();
        let (_, _, participants) = setup_dkg(3);
        let cfg = wire_cfg(max_players, &participants);
        let empty: &[u8] = &[];
        let result = DkgMessage::read_cfg(&mut &empty[..], &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_size_matches_encoded_length() {
        let (info, keys, participants) = setup_dkg(3);
        let cfg = wire_cfg(NonZeroU32::new(3).unwrap(), &participants);

        let (_, pub_msg, priv_msgs) = Dealer::<MinSig, bls12381::PrivateKey>::start::<N3f1>(
            rand_core::OsRng,
            info,
            keys[0].clone(),
            None,
        )
        .unwrap();

        let (_, priv_msg) = priv_msgs.into_iter().nth(1).unwrap();
        let msg = DkgMessage::DealerBundle {
            ceremony_id: cfg.expected_ceremony_id,
            pub_msg,
            priv_msg,
        };

        assert_eq!(msg.encode_size(), msg.encode().len());
    }

    #[test]
    fn wrong_ceremony_id_is_rejected() {
        let (info, keys, participants) = setup_dkg(3);
        let max_players = NonZeroU32::new(3).unwrap();
        let cfg = wire_cfg(max_players, &participants);
        let wrong_id = DkgCeremonyId::new(b"test", 1, None, &participants);

        let (_, pub_msg, priv_msgs) = Dealer::<MinSig, bls12381::PrivateKey>::start::<N3f1>(
            rand_core::OsRng,
            info,
            keys[0].clone(),
            None,
        )
        .unwrap();
        let (_, priv_msg) = priv_msgs.into_iter().nth(1).unwrap();
        let msg = DkgMessage::DealerBundle {
            ceremony_id: wrong_id,
            pub_msg,
            priv_msg,
        };

        let encoded = msg.encode();
        let result = DkgMessage::read_for_ceremony(&mut encoded.as_ref(), &cfg);
        assert!(matches!(
            result,
            Err(DkgMessageReadError::WrongCeremonyId { .. })
        ));
    }
}
