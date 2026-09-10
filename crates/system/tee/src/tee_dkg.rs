//! Host-side TEE DKG ceremony coordinator.
//!
//! This is the TEE-native equivalent of the consensus DKG actor
//! (`crates/blockchain/consensus/src/dkg_actor`): the public protocol - P2P
//! gossip, ceremony bookkeeping, message shaping - runs on the host, while every
//! secret-touching operation is delegated to the enclave over the Noise-IK
//! channel (the [`EnclaveChannel`] / `EnclaveClient` protocol). Unlike a literal
//! clone of the consensus actor, no `Dealer`/`Player` ever runs on the host, so
//! shares and the assembled key never appear in host memory.
//!
//! The coordinator exposes the ceremony as explicit phase methods that each (a)
//! call the enclave seam and (b) shape the resulting host wire messages. A
//! driver - the production commonware-P2P event loop, or the in-process e2e test
//! harness - routes [`DealerBundle`] / [`Ack`] / [`FinalizedLog`] messages between
//! peers and feeds them back into the matching phase method. The wire messages carry
//! only opaque bytes (the host never decodes Commonware types - the enclave does).
//!
//! Production note: the threshold/timeout/retry event loop that drives these
//! phases over real commonware P2P gossip is the remaining host-integration piece
//! (validated on the localnet); this module is the seam-routing + message-shaping
//! core that loop builds on, and is validated end-to-end over the real Noise-IK
//! transport by `bin/outbe-tee-enclave/tests/dkg_e2e.rs`.

use alloy_primitives::B256;

use crate::errors::TransportError;
use crate::protocol::{EnclaveRequest, EnclaveResponse};

/// The host's channel to its enclave: a request/response transport. Implemented
/// by [`crate::EnclaveClient`] over Noise-IK; abstracted so the coordinator is
/// testable and transport-agnostic.
pub trait EnclaveChannel {
    fn request(
        &mut self,
        req: &EnclaveRequest,
    ) -> core::result::Result<EnclaveResponse, TransportError>;
}

impl EnclaveChannel for crate::EnclaveClient {
    fn request(
        &mut self,
        req: &EnclaveRequest,
    ) -> core::result::Result<EnclaveResponse, TransportError> {
        crate::EnclaveClient::request(self, req)
    }
}

impl EnclaveChannel for crate::AuthorizedEnclaveClient {
    fn request(
        &mut self,
        req: &EnclaveRequest,
    ) -> core::result::Result<EnclaveResponse, TransportError> {
        crate::AuthorizedEnclaveClient::request(self, req)
    }
}

impl EnclaveChannel for crate::RuntimeEnclaveClient {
    fn request(
        &mut self,
        req: &EnclaveRequest,
    ) -> core::result::Result<EnclaveResponse, TransportError> {
        crate::RuntimeEnclaveClient::request(self, req)
    }
}

/// A dealer's sealed dealing to one recipient (dealer -> player).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DealerBundle {
    pub dealer_bls: Vec<u8>,
    pub pub_msg: Vec<u8>,
    pub sealed_share: Vec<u8>,
}

/// A player's acknowledgement of a verified dealing (player -> dealer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub player_bls: Vec<u8>,
    pub ack: Vec<u8>,
}

/// A dealer's signed log of its completed dealing (dealer -> all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedLog {
    pub dealer_bls: Vec<u8>,
    pub signed_log: Vec<u8>,
}

/// A TEE DKG gossip message, carried over the consensus P2P layer. All fields are
/// opaque bytes (the host never decodes Commonware types - the enclave does).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgWireMessage {
    DealerBundle(DealerBundle),
    Ack(Ack),
    FinalizedLog(FinalizedLog),
    /// Seam F: a participant's partial signature over the fixed offer message,
    /// **sealed to one recipient enclave** (`partial` is opaque ciphertext). Each
    /// signer broadcasts one of these per recipient; a recipient collects the
    /// ciphertexts addressed to it (`recipient_bls == its enclave`) and recovers
    /// the offer key in-SGX. The host cannot decrypt them.
    TributeOfferPartial {
        signer_bls: Vec<u8>,
        recipient_bls: Vec<u8>,
        partial: Vec<u8>,
    },
}

impl DkgWireMessage {
    /// Encode to the deterministic wire format `tag(1) || [u32 len || bytes]...`
    /// so the consensus P2P adapter can ship it as an opaque payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        fn put(buf: &mut Vec<u8>, field: &[u8]) {
            buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
            buf.extend_from_slice(field);
        }
        let mut buf = Vec::new();
        match self {
            DkgWireMessage::DealerBundle(b) => {
                buf.push(0);
                put(&mut buf, &b.dealer_bls);
                put(&mut buf, &b.pub_msg);
                put(&mut buf, &b.sealed_share);
            }
            DkgWireMessage::Ack(a) => {
                buf.push(1);
                put(&mut buf, &a.player_bls);
                put(&mut buf, &a.ack);
            }
            DkgWireMessage::FinalizedLog(l) => {
                buf.push(2);
                put(&mut buf, &l.dealer_bls);
                put(&mut buf, &l.signed_log);
            }
            DkgWireMessage::TributeOfferPartial {
                signer_bls,
                recipient_bls,
                partial,
            } => {
                buf.push(3);
                put(&mut buf, signer_bls);
                put(&mut buf, recipient_bls);
                put(&mut buf, partial);
            }
        }
        buf
    }

    /// Decode the wire format produced by [`DkgWireMessage::to_bytes`]. Rejects a
    /// malformed or trailing-byte payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0usize;
        let tag = *bytes
            .first()
            .ok_or(CeremonyError::MalformedWire("empty payload"))?;
        offset += 1;
        let take = |offset: &mut usize| -> Result<Vec<u8>> {
            let len_end = offset
                .checked_add(4)
                .filter(|end| *end <= bytes.len())
                .ok_or(CeremonyError::MalformedWire("truncated length"))?;
            let len = u32::from_be_bytes([
                bytes[*offset],
                bytes[*offset + 1],
                bytes[*offset + 2],
                bytes[*offset + 3],
            ]) as usize;
            let end = len_end
                .checked_add(len)
                .filter(|end| *end <= bytes.len())
                .ok_or(CeremonyError::MalformedWire("truncated field"))?;
            let field = bytes[len_end..end].to_vec();
            *offset = end;
            Ok(field)
        };
        let msg = match tag {
            0 => DkgWireMessage::DealerBundle(DealerBundle {
                dealer_bls: take(&mut offset)?,
                pub_msg: take(&mut offset)?,
                sealed_share: take(&mut offset)?,
            }),
            1 => DkgWireMessage::Ack(Ack {
                player_bls: take(&mut offset)?,
                ack: take(&mut offset)?,
            }),
            2 => DkgWireMessage::FinalizedLog(FinalizedLog {
                dealer_bls: take(&mut offset)?,
                signed_log: take(&mut offset)?,
            }),
            3 => DkgWireMessage::TributeOfferPartial {
                signer_bls: take(&mut offset)?,
                recipient_bls: take(&mut offset)?,
                partial: take(&mut offset)?,
            },
            _ => return Err(CeremonyError::MalformedWire("unknown tag")),
        };
        if offset != bytes.len() {
            return Err(CeremonyError::MalformedWire("trailing bytes"));
        }
        Ok(msg)
    }
}

/// The P2P gossip surface the ceremony driver needs. Implemented over the
/// consensus P2P channel in the node; an in-memory implementation drives the
/// end-to-end test. Async because real P2P send/recv is async.
#[allow(async_fn_in_trait)]
pub trait DkgGossip {
    /// Send a message to one peer, addressed by BLS public key bytes.
    async fn send(&mut self, to: &[u8], msg: DkgWireMessage) -> Result<()>;
    /// Broadcast a message to every peer.
    async fn broadcast(&mut self, msg: DkgWireMessage) -> Result<()>;
    /// Receive the next `(from_bls, msg)`, or `None` once the ceremony's inputs
    /// are exhausted / the channel closes.
    async fn recv(&mut self) -> Option<(Vec<u8>, DkgWireMessage)>;
}

/// Drive this node's full TEE DKG ceremony to completion over `gossip`, routing
/// every secret operation to the enclave via `enclave`. `n` is the participant
/// count. The founding ceremony intentionally requires all `n` identities, acks,
/// and finalized logs: every genesis validator must finish with a usable enclave
/// share before block 1. Although the threshold primitive can recover from
/// `2f+1`, selecting a partial founding committee is not a startup fallback;
/// operators must restore the missing participant and restart the ceremony.
///
/// Returns this node's [`CeremonyOutcome`] (public group key + share commitment).
/// Mirrors the consensus DKG actor's event loop, but no `Dealer`/`Player` runs on
/// the host - every seam crosses to the enclave.
pub async fn run_tee_dkg_ceremony<C: EnclaveChannel, G: DkgGossip>(
    coord: &CeremonyCoordinator,
    enclave: &mut C,
    gossip: &mut G,
    n: usize,
    chain_id: B256,
    tribute_offer_epoch: u64,
) -> Result<CeremonyOutcome> {
    use std::collections::{BTreeMap, BTreeSet};

    coord.open(enclave)?;

    // Seam A: deal. The bundle addressed to self is ingested locally; the rest
    // are gossiped to their recipients.
    let mut self_ack: Option<Addressed<Ack>> = None;
    for bundle in coord.deal(enclave)? {
        if bundle.to == coord.my_bls() {
            self_ack = coord.ingest(enclave, &bundle.msg)?;
        } else {
            gossip
                .send(&bundle.to, DkgWireMessage::DealerBundle(bundle.msg))
                .await?;
        }
    }

    // Acks for THIS node's dealing (incl. the self-ack), keyed by player.
    let mut my_acks: BTreeSet<Vec<u8>> = BTreeSet::new();
    if let Some(ack) = self_ack {
        coord.receive_ack(enclave, &ack.msg)?;
        my_acks.insert(ack.msg.player_bls.clone());
    }

    let mut dealer_finalized = false;
    let mut logs: BTreeMap<Vec<u8>, FinalizedLog> = BTreeMap::new();
    let mut ingested_dealers: BTreeSet<Vec<u8>> = BTreeSet::new();
    let me_bls = coord.my_bls().to_vec();
    // Seam F sealed partials ADDRESSED TO THIS ENCLAVE that arrive while we are
    // still collecting dealer logs (a fast peer can finish and broadcast its
    // sealed offer partial early); keyed by signer, buffered here and folded into
    // the Seam F phase below so none is lost. Ciphertexts for other recipients are
    // ignored (this node cannot and need not decrypt them).
    let mut sealed_for_me: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

    // Once this node has finalized its own dealer log, fold it in locally too.
    let maybe_finalize_dealer = |enclave: &mut C,
                                 my_acks: &BTreeSet<Vec<u8>>,
                                 dealer_finalized: &mut bool|
     -> Result<Option<FinalizedLog>> {
        if !*dealer_finalized && my_acks.len() >= n {
            *dealer_finalized = true;
            return Ok(Some(coord.finalize_dealer(enclave)?));
        }
        Ok(None)
    };

    if let Some(log) = maybe_finalize_dealer(enclave, &my_acks, &mut dealer_finalized)? {
        logs.insert(log.dealer_bls.clone(), log.clone());
        gossip.broadcast(DkgWireMessage::FinalizedLog(log)).await?;
    }

    // Event loop: process gossiped messages until this node has every dealer log.
    while logs.len() < n {
        let Some((_from, msg)) = gossip.recv().await else {
            return Err(CeremonyError::UnexpectedResponse(
                "gossip closed before ceremony completed",
            ));
        };
        match msg {
            DkgWireMessage::DealerBundle(bundle) => {
                if !ingested_dealers.contains(&bundle.dealer_bls) {
                    if let Some(ack) = coord.ingest(enclave, &bundle)? {
                        ingested_dealers.insert(bundle.dealer_bls.clone());
                        gossip.send(&ack.to, DkgWireMessage::Ack(ack.msg)).await?;
                    }
                }
            }
            DkgWireMessage::Ack(ack) => {
                if !my_acks.contains(&ack.player_bls) {
                    coord.receive_ack(enclave, &ack)?;
                    my_acks.insert(ack.player_bls.clone());
                }
                if let Some(log) = maybe_finalize_dealer(enclave, &my_acks, &mut dealer_finalized)?
                {
                    logs.insert(log.dealer_bls.clone(), log.clone());
                    gossip.broadcast(DkgWireMessage::FinalizedLog(log)).await?;
                }
            }
            DkgWireMessage::FinalizedLog(log) => {
                logs.insert(log.dealer_bls.clone(), log);
            }
            DkgWireMessage::TributeOfferPartial {
                signer_bls,
                recipient_bls,
                partial,
            } => {
                if recipient_bls == me_bls {
                    sealed_for_me.insert(signer_bls, partial);
                }
            }
        }
    }

    // Seam E: every dealer log collected - recover this node's threshold share.
    let ordered: Vec<FinalizedLog> = logs.into_values().collect();
    let mut outcome = coord.finalize_player(enclave, &ordered)?;

    // Seam F: derive the shared tribute offer key. Each node threshold-signs the
    // fixed offer message with its share and SEALS the partial to every recipient
    // enclave; it broadcasts one ciphertext per recipient and keeps the one
    // addressed to itself. The cryptographic recovery threshold is `2f+1`, but
    // the founding startup policy deliberately collects all `n` sealed partials
    // so every genesis validator proves participation and installs the same offer
    // key before block 1. The enclave decrypts them in-SGX, recovers the group
    // signature, and derives the offer keypair. The host only ever relays
    // ciphertext, so it cannot recover the offer key. Every honest node derives
    // the byte-identical offer public key (asserted by the unit/e2e tests and by
    // localnet state-root parity).
    let my_sealed = coord.tribute_offer_partials_sealed(enclave)?;
    for (recipient_bls, blob) in my_sealed {
        if recipient_bls == me_bls {
            // The ciphertext sealed to my own enclave - keep it locally.
            sealed_for_me.insert(me_bls.clone(), blob);
        } else {
            gossip
                .broadcast(DkgWireMessage::TributeOfferPartial {
                    signer_bls: me_bls.clone(),
                    recipient_bls,
                    partial: blob,
                })
                .await?;
        }
    }

    while sealed_for_me.len() < n {
        let Some((_from, msg)) = gossip.recv().await else {
            return Err(CeremonyError::UnexpectedResponse(
                "gossip closed before founding offer-key finalization completed",
            ));
        };
        if let DkgWireMessage::TributeOfferPartial {
            signer_bls,
            recipient_bls,
            partial,
        } = msg
        {
            if recipient_bls == me_bls {
                sealed_for_me.insert(signer_bls, partial);
            }
        }
        // Stray late DKG messages (dealer bundles / acks / logs) are ignored: the
        // ceremony already finalized, so only offer partials are still relevant.
    }

    let partials: Vec<Vec<u8>> = sealed_for_me.into_values().collect();
    let (tribute_offer_public, tribute_offer_group_public_key) =
        coord.finalize_tribute_offer(enclave, &partials, chain_id, tribute_offer_epoch)?;
    outcome.tribute_offer_public = tribute_offer_public;
    outcome.tribute_offer_group_public_key = tribute_offer_group_public_key;
    Ok(outcome)
}

/// A bundle addressed to a specific recipient by BLS pubkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addressed<T> {
    pub to: Vec<u8>,
    pub msg: T,
}

/// The completed ceremony result for this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyOutcome {
    /// Public group threshold key (encoded). Identical for all honest parties.
    pub group_public: Vec<u8>,
    /// Commitment to this node's secret threshold share (the share stays in SGX).
    pub share_commitment: B256,
    /// The shared tribute offer X25519 public key, derived from the group
    /// threshold signature over the fixed offer message (Seam F). Byte-identical
    /// for all honest parties; clients encrypt offers to it. Set by
    /// [`run_tee_dkg_ceremony`]; `[0u8; 32]` until Seam F completes.
    pub tribute_offer_public: [u8; 32],
    /// The committee's encoded DKG group public key (constant term). Set alongside
    /// `tribute_offer_public` at Seam F and carried into the founding bootstrap
    /// payload.
    pub tribute_offer_group_public_key: Vec<u8>,
}

/// Coordinator errors: a transport failure, or an unexpected enclave response.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("unexpected enclave response for {0}")]
    UnexpectedResponse(&'static str),
    #[error("malformed DKG wire message: {0}")]
    MalformedWire(&'static str),
    #[error("enclave error: {0}")]
    EnclaveError(String),
    #[error("bounded delivery error: {0}")]
    Delivery(String),
}

type Result<T> = core::result::Result<T, CeremonyError>;

/// Drives one node's participation in a TEE DKG ceremony by routing each phase to
/// the enclave and shaping the host wire messages.
pub struct CeremonyCoordinator {
    ceremony_id: B256,
    round: u64,
    my_bls: Vec<u8>,
    participants: Vec<crate::protocol::ParticipantAnnounce>,
}

impl CeremonyCoordinator {
    /// `participants` is each enclave's announced `ParticipantAnnounce` (BLS
    /// identity + X25519 enc key + the owner's binding signature), obtained from
    /// each enclave's `GetPublicKeys`, including this node.
    pub fn new(
        ceremony_id: B256,
        round: u64,
        my_bls: Vec<u8>,
        participants: Vec<crate::protocol::ParticipantAnnounce>,
    ) -> Self {
        Self {
            ceremony_id,
            round,
            my_bls,
            participants,
        }
    }

    /// This node's BLS public key bytes.
    pub fn my_bls(&self) -> &[u8] {
        &self.my_bls
    }

    /// Open the ceremony inside the enclave.
    pub fn open<C: EnclaveChannel>(&self, ch: &mut C) -> Result<()> {
        match ch.request(&EnclaveRequest::DkgOpen {
            ceremony_id: self.ceremony_id,
            round: self.round,
            participants: self.participants.clone(),
        })? {
            EnclaveResponse::Ack => Ok(()),
            _ => Err(CeremonyError::UnexpectedResponse("DkgOpen")),
        }
    }

    /// Seam A: deal and produce one [`DealerBundle`] per recipient.
    pub fn deal<C: EnclaveChannel>(&self, ch: &mut C) -> Result<Vec<Addressed<DealerBundle>>> {
        match ch.request(&EnclaveRequest::DkgStartDealer {
            ceremony_id: self.ceremony_id,
        })? {
            EnclaveResponse::DkgDealt {
                pub_msg,
                sealed_shares,
            } => Ok(sealed_shares
                .into_iter()
                .map(|(recipient_bls, sealed_share)| Addressed {
                    to: recipient_bls,
                    msg: DealerBundle {
                        dealer_bls: self.my_bls.clone(),
                        pub_msg: pub_msg.clone(),
                        sealed_share,
                    },
                })
                .collect()),
            _ => Err(CeremonyError::UnexpectedResponse("DkgStartDealer")),
        }
    }

    /// Seam B: open + verify an incoming dealing; produce an [`Ack`] addressed to
    /// the dealer (or `None` if the dealing did not verify).
    pub fn ingest<C: EnclaveChannel>(
        &self,
        ch: &mut C,
        bundle: &DealerBundle,
    ) -> Result<Option<Addressed<Ack>>> {
        match ch.request(&EnclaveRequest::DkgPlayerIngest {
            ceremony_id: self.ceremony_id,
            dealer_bls: bundle.dealer_bls.clone(),
            pub_msg: bundle.pub_msg.clone(),
            sealed_share: bundle.sealed_share.clone(),
        })? {
            EnclaveResponse::DkgPlayerAck { ack } => Ok(ack.map(|ack| Addressed {
                to: bundle.dealer_bls.clone(),
                msg: Ack {
                    player_bls: self.my_bls.clone(),
                    ack,
                },
            })),
            _ => Err(CeremonyError::UnexpectedResponse("DkgPlayerIngest")),
        }
    }

    /// Seam C: record a player's ack at this node's dealer.
    pub fn receive_ack<C: EnclaveChannel>(&self, ch: &mut C, ack: &Ack) -> Result<()> {
        match ch.request(&EnclaveRequest::DkgDealerReceiveAck {
            ceremony_id: self.ceremony_id,
            player_bls: ack.player_bls.clone(),
            ack: ack.ack.clone(),
        })? {
            EnclaveResponse::Ack => Ok(()),
            _ => Err(CeremonyError::UnexpectedResponse("DkgDealerReceiveAck")),
        }
    }

    /// Seam D: finalize this node's dealing into a broadcastable [`FinalizedLog`].
    pub fn finalize_dealer<C: EnclaveChannel>(&self, ch: &mut C) -> Result<FinalizedLog> {
        match ch.request(&EnclaveRequest::DkgDealerFinalize {
            ceremony_id: self.ceremony_id,
        })? {
            EnclaveResponse::DkgSignedLog { signed_log } => Ok(FinalizedLog {
                dealer_bls: self.my_bls.clone(),
                signed_log,
            }),
            _ => Err(CeremonyError::UnexpectedResponse("DkgDealerFinalize")),
        }
    }

    /// Seam E: verify the collected dealer logs and recover this node's threshold
    /// share inside the enclave; return the public outcome.
    pub fn finalize_player<C: EnclaveChannel>(
        &self,
        ch: &mut C,
        logs: &[FinalizedLog],
    ) -> Result<CeremonyOutcome> {
        let signed_logs = logs.iter().map(|l| l.signed_log.clone()).collect();
        match ch.request(&EnclaveRequest::DkgPlayerFinalize {
            ceremony_id: self.ceremony_id,
            signed_logs,
        })? {
            EnclaveResponse::DkgPlayerFinalized {
                group_public,
                share_commitment,
            } => Ok(CeremonyOutcome {
                group_public,
                share_commitment,
                // Filled by `run_tee_dkg_ceremony` after Seam F.
                tribute_offer_public: [0u8; 32],
                tribute_offer_group_public_key: Vec::new(),
            }),
            _ => Err(CeremonyError::UnexpectedResponse("DkgPlayerFinalize")),
        }
    }

    /// Seam F: threshold-sign the fixed offer message with this node's share, then
    /// seal the partial to each recipient enclave. Returns one
    /// `(recipient_bls, sealed_partial)` per participant; the caller gossips each
    /// sealed ciphertext to its recipient. The host never sees a plaintext partial.
    pub fn tribute_offer_partials_sealed<C: EnclaveChannel>(
        &self,
        ch: &mut C,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        match ch.request(&EnclaveRequest::DkgTributeOfferPartial {
            ceremony_id: self.ceremony_id,
        })? {
            EnclaveResponse::DkgTributeOfferPartial { sealed } => Ok(sealed),
            _ => Err(CeremonyError::UnexpectedResponse("DkgTributeOfferPartial")),
        }
    }

    /// Founding Seam F: finalize the group threshold signature from the sealed
    /// partials addressed to this enclave and install the permanent offer key.
    /// The enclave capability matrix rejects this request once the key is ready.
    pub fn finalize_tribute_offer<C: EnclaveChannel>(
        &self,
        ch: &mut C,
        sealed_partials: &[Vec<u8>],
        chain_id: B256,
        tribute_offer_epoch: u64,
    ) -> Result<([u8; 32], Vec<u8>)> {
        match ch.request(&EnclaveRequest::DkgFinalizeTributeOffer {
            ceremony_id: self.ceremony_id,
            sealed_partials: sealed_partials.to_vec(),
            chain_id,
            tribute_offer_epoch,
        })? {
            EnclaveResponse::DkgTributeOfferKey {
                tribute_offer_public,
                group_public_key,
            } => Ok((tribute_offer_public, group_public_key)),
            EnclaveResponse::Error { message } => Err(CeremonyError::EnclaveError(message)),
            _ => Err(CeremonyError::UnexpectedResponse("DkgFinalizeTributeOffer")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_messages() -> Vec<DkgWireMessage> {
        vec![
            DkgWireMessage::DealerBundle(DealerBundle {
                dealer_bls: vec![1, 2, 3],
                pub_msg: vec![4; 40],
                sealed_share: vec![5; 80],
            }),
            DkgWireMessage::Ack(Ack {
                player_bls: vec![6, 7],
                ack: vec![8; 50],
            }),
            DkgWireMessage::FinalizedLog(FinalizedLog {
                dealer_bls: vec![9],
                signed_log: vec![10; 120],
            }),
            DkgWireMessage::TributeOfferPartial {
                signer_bls: vec![11, 12, 13],
                recipient_bls: vec![21, 22, 23],
                partial: vec![14; 48],
            },
        ]
    }

    #[test]
    fn dkg_wire_message_roundtrips() {
        for msg in sample_messages() {
            let bytes = msg.to_bytes();
            assert_eq!(DkgWireMessage::from_bytes(&bytes).unwrap(), msg);
        }
    }

    #[test]
    fn dkg_wire_message_rejects_malformed() {
        assert!(DkgWireMessage::from_bytes(&[]).is_err());
        assert!(DkgWireMessage::from_bytes(&[9]).is_err()); // unknown tag
        let mut bytes = sample_messages()[0].to_bytes();
        bytes.push(0xFF); // trailing byte
        assert!(DkgWireMessage::from_bytes(&bytes).is_err());
        assert!(DkgWireMessage::from_bytes(&[0, 0, 0, 0, 255]).is_err()); // truncated field
    }
}
