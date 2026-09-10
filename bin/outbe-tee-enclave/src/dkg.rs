//! Stateful-per-ceremony DKG secret session (enclave side).
//!
//! The host-side `tee_dkg` actor (a TEE-native clone of the consensus DKG actor)
//! drives the public protocol - P2P gossip, ceremony bookkeeping, timing, wire
//! codec - and delegates the five secret-touching seams to this module over the
//! Noise-IK channel. The Commonware `Dealer` / `Player` are non-serializable
//! secret objects that live across several host<->enclave round-trips, so each
//! ceremony's state is held resident here keyed by ceremony id and never leaves
//! SGX in plaintext.
//!
//! The TEE DKG is infrastructure: the threshold key it produces serves multiple
//! use cases (tribute offers being one), so its identifiers are `tee`, not
//! `tribute`.
//!
//! Seams (mirrors `crates/blockchain/consensus/src/dkg_actor/actor.rs`):
//!  - A `start_dealer`        -> `Dealer::start`          (deal + seal per-player shares)
//!  - B `player_ingest`       -> `Player::dealer_message` (open + verify incoming share)
//!  - C `dealer_receive_ack`  -> `Dealer::receive_player_ack`
//!  - D `dealer_finalize`     -> `Dealer::finalize`       (sign dealer log)
//!  - E `player_finalize`     -> `Player::finalize`       (recover local threshold share)
//!
//! [`verify_dealer_log`] (`SignedDealerLog::check`) is public-only and therefore
//! also runnable on the host; it is provided here for the host actor and the
//! in-process ceremony test.
//!
//! ## SECURITY - share confidentiality
//!
//! Commonware's per-player share (`DealerPrivMsg`) is a protocol-secret
//! `Secret<Scalar>`, not a ciphertext: in Feldman-Desmedt the recipient
//! *verifies* the share against the dealer's public commitment. The consensus
//! DKG may transmit shares on the host; the TEE DKG must not - its premise is
//! that shares never appear on the host in plaintext.
//!
//! This module therefore seals shares **inside** the enclave: [`DkgSession::start_dealer`]
//! encrypts each per-player share to that recipient enclave's X25519 key (sealed
//! box, [`crate::crypto::encrypt_share`]) and returns only opaque
//! [`EncryptedShare`] blobs; [`DkgSession::player_ingest`] opens the blob with the
//! resident X25519 secret ([`crate::crypto::decrypt_share`]) and verifies inside
//! SGX. The host only ever relays ciphertext. Each session holds an in-enclave
//! X25519 share-decryption keypair ([`DkgSession::enc_public`] is announced so
//! dealers can seal to it).

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use alloy_primitives::{keccak256, B256};
use commonware_codec::{Encode as _, Read as _, ReadExt as _};
use commonware_cryptography::bls12381::{
    self,
    dkg::feldman_desmedt::{
        Dealer, DealerLog, DealerPrivMsg, DealerPubMsg, Info, Logs, Output, Player, PlayerAck,
        SignedDealerLog,
    },
    primitives::{
        group::Share,
        ops::threshold,
        sharing::Mode,
        variant::{MinSig, PartialSignature},
    },
    Batch,
};
use commonware_cryptography::Signer as _;
use commonware_parallel::Sequential;
use commonware_utils::{ordered::Set, N3f1, TryCollect as _};
use zeroize::Zeroizing;

use crate::crypto::{decrypt_share, encrypt_share, x25519_public, EncryptedShare};
use crate::errors::{Result, TeeError};

/// Threshold variant pinned for the TEE DKG (2f+1 fault model), matching the
/// consensus DKG so the same Commonware code paths apply.
type Variant = MinSig;
/// BLS12-381 public key (Commonware MinPk encoding).
pub type PubKey = bls12381::PublicKey;
/// BLS12-381 private key - the TEE threshold-BLS signing key, generated **inside**
/// the enclave and never exported in plaintext.
pub type PrivKey = bls12381::PrivateKey;

/// Public DKG `Info` shared by every party in a ceremony. Constructed
/// identically on every node from the same `(namespace, round, prev_output,
/// dealers, participants)` so the ceremony binds the same transcript domain.
pub type CeremonyInfo = Info<Variant, PubKey>;
/// Public per-dealer commitment broadcast to all players.
pub type CeremonyPubMsg = DealerPubMsg<Variant>;
/// Player acknowledgement of a verified dealing (public; returned to the dealer).
pub type CeremonyAck = PlayerAck<PubKey>;
/// Dealer-signed log of a completed dealing (public; gossiped to all).
pub type CeremonySignedLog = SignedDealerLog<Variant, PrivKey>;
/// Verified dealer log (output of [`verify_dealer_log`]); fed to player finalize.
pub type CeremonyLog = DealerLog<Variant, PubKey>;
/// Group threshold public polynomial - the ceremony's public output.
pub type CeremonyOutput = Output<Variant, PubKey>;
/// A validator's long-term threshold secret share. Never leaves the enclave.
pub type CeremonyShare = Share;

/// Seam F output: `(tribute_offer_secret, tribute_offer_public, encoded_group_sig)`.
/// The secret + group signature stay resident in the enclave; the public is
/// registered on-chain. Both secret values are `Zeroizing` (wiped on drop).
pub type RecoveredTributeOfferKey = (Zeroizing<[u8; 32]>, [u8; 32], Zeroizing<Vec<u8>>);

/// 32-byte opaque ceremony identifier supplied by the host actor (the
/// `DkgCeremonyId` digest). Used only as the resident-session map key; the
/// enclave never parses ceremony wire format.
pub type CeremonyKey = [u8; 32];

/// Byte-encoded dealing returned by [`DkgSession::start_dealer_encoded`]:
/// `(encoded pub_msg, [(encoded recipient BLS pubkey, sealed share bytes)])`.
pub type EncodedDealing = (Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>);

/// Domain namespace for TEE DKG ceremonies. The TEE DKG is infrastructure (the
/// threshold key it produces serves multiple use cases, tribute offers being
/// one), so the namespace is `tee`, not `tribute`. Distinct from the consensus
/// DKG namespace (`b"outbe"`) so a TEE ceremony message can never be replayed
/// into a consensus ceremony (strong domain separation).
pub const TEE_DKG_NAMESPACE: &[u8] = b"outbe-tee-dkg";

/// Seam F - the namespace + fixed message the DKG group threshold-signs to
/// derive the shared tribute offer key. Every enclave signs the SAME message
/// with its share; recovering `2f+1` partials yields the deterministic group
/// threshold signature, whose HKDF is the shared offer secret. The message is
/// fixed (no per-call/per-block data) so the offer key is stable for the epoch;
/// `chain_id`/`tribute_offer_epoch` domain separation is applied in the HKDF, never
/// in the signed message. Distinct from [`TEE_DKG_NAMESPACE`] and any consensus
/// signing domain.
pub const TEE_OFFER_NAMESPACE: &[u8] = b"outbe-tee-offer";
pub const TEE_OFFER_MESSAGE: &[u8] = b"outbe/tee/offer/v1";

fn dkg_err(context: &str, error: impl core::fmt::Debug) -> TeeError {
    TeeError::Dkg(format!("{context}: {error:?}"))
}

/// One party's resident secret state for a single TEE DKG ceremony.
///
/// Holds the in-enclave `Dealer` (this party's dealing), `Player` (this party's
/// share-collection), and the X25519 share-decryption secret. `Dealer`/`Player`
/// are `Option` because Commonware consumes them at finalize; once taken, the
/// matching seam returns [`TeeError::DkgSeamOrder`] rather than panicking.
pub struct DkgSession {
    info: CeremonyInfo,
    /// TEE threshold-BLS signing key, generated in-enclave for this ceremony.
    signing_key: PrivKey,
    /// X25519 secret used to open shares sealed to this enclave. Zeroized on drop.
    enc_secret: Zeroizing<[u8; 32]>,
    /// Each participant's announced X25519 share-encryption key (BLS pubkey ->
    /// X25519 pubkey), supplied at open. Dealers seal shares to these keys.
    recipient_enc_keys: BTreeMap<PubKey, [u8; 32]>,
    dealer: Option<Dealer<Variant, PrivKey>>,
    player: Option<Player<Variant, PrivKey>>,
    /// This party's recovered threshold share (Seam E output), retained so Seam F
    /// can threshold-sign the offer message with it. `Share` zeroizes on drop.
    recovered_share: Option<CeremonyShare>,
    /// The group output (public `Sharing`) from Seam E, retained so Seam F's
    /// `threshold::recover` can interpolate partials against it.
    group_output: Option<CeremonyOutput>,
}

impl DkgSession {
    /// Open a player session for `info` under the in-enclave `signing_key` and
    /// X25519 `enc_secret` (this enclave's stable share-decryption key). The
    /// `recipient_enc_keys` map (each participant's announced X25519 key) is
    /// captured here so [`DkgSession::start_dealer`] can seal shares to it. The
    /// party becomes a dealer only after `start_dealer`.
    pub fn new(
        info: CeremonyInfo,
        signing_key: PrivKey,
        enc_secret: &[u8; 32],
        recipient_enc_keys: BTreeMap<PubKey, [u8; 32]>,
    ) -> Result<Self> {
        let player = Player::<Variant, PrivKey>::new(info.clone(), signing_key.clone())
            .map_err(|e| dkg_err("player new", e))?;
        Ok(Self {
            info,
            signing_key,
            enc_secret: Zeroizing::new(*enc_secret),
            recipient_enc_keys,
            dealer: None,
            player: Some(player),
            recovered_share: None,
            group_output: None,
        })
    }

    /// This party's BLS public key (its identity in the ceremony).
    pub fn participant_pubkey(&self) -> PubKey {
        self.signing_key.public_key()
    }

    /// This enclave's X25519 share-decryption public key. Announced (e.g. via the
    /// `BoundaryOutcome` recipient channel) so dealers seal shares to it.
    pub fn enc_public(&self) -> [u8; 32] {
        x25519_public(&self.enc_secret)
    }

    /// Seam A - generate this party's dealing and seal each per-player share to
    /// the recipient enclave's X25519 key. Returns the public commitment and the
    /// opaque [`EncryptedShare`] blobs (one per participant); the secret
    /// polynomial and the plaintext shares never leave SGX. A participant missing
    /// from the captured `recipient_enc_keys` is a typed error. `previous_share`
    /// is `None` for the initial bootstrap and `Some` for a reshare.
    pub fn start_dealer(
        &mut self,
        previous_share: Option<CeremonyShare>,
    ) -> Result<(CeremonyPubMsg, Vec<(PubKey, EncryptedShare)>)> {
        if self.dealer.is_some() {
            return Err(TeeError::DkgSeamOrder("start_dealer called twice"));
        }
        let (dealer, pub_msg, priv_msgs) = Dealer::<Variant, PrivKey>::start::<N3f1>(
            rand_core::OsRng,
            self.info.clone(),
            self.signing_key.clone(),
            previous_share,
        )
        .map_err(|e| dkg_err("dealer start", e))?;
        self.dealer = Some(dealer);

        let mut sealed = Vec::with_capacity(priv_msgs.len());
        for (player_pk, priv_msg) in priv_msgs {
            let enc_pub = self.recipient_enc_keys.get(&player_pk).ok_or_else(|| {
                TeeError::Dkg(
                    "missing recipient share-encryption key for a participant".to_string(),
                )
            })?;
            // Serialize the protocol-secret share and seal it to the recipient.
            // The plaintext exists only in this enclave-sidecar process; the host
            // gets ciphertext. (Process isolation today, not SGX memory
            // encryption - see audit_tee_bootstrap.md `tee-not-real-sgx`.)
            let plaintext = Zeroizing::new(priv_msg.encode().to_vec());
            let blob = encrypt_share(enc_pub, plaintext.as_ref())?;
            sealed.push((player_pk, blob));
        }
        Ok((pub_msg, sealed))
    }

    /// Seam B - open a sealed incoming share with the resident X25519 secret,
    /// then verify it against the dealer's public commitment and produce an
    /// acknowledgement. The plaintext share exists only inside SGX. Returns
    /// `Ok(None)` if the dealing is invalid (host treats as no-ack).
    pub fn player_ingest(
        &mut self,
        dealer: PubKey,
        pub_msg: CeremonyPubMsg,
        encrypted_share: &EncryptedShare,
    ) -> Result<Option<CeremonyAck>> {
        let priv_bytes = Zeroizing::new(decrypt_share(&self.enc_secret, encrypted_share)?);
        let mut reader: &[u8] = priv_bytes.as_ref();
        let priv_msg =
            DealerPrivMsg::read(&mut reader).map_err(|e| dkg_err("decode sealed share", e))?;
        let player = self
            .player
            .as_mut()
            .ok_or(TeeError::DkgSeamOrder("player already finalized"))?;
        Ok(player.dealer_message::<N3f1>(dealer, pub_msg, priv_msg))
    }

    /// Seam C - record a player's acknowledgement at this party's dealer. The
    /// dealer tallies acks toward the finalize threshold.
    pub fn dealer_receive_ack(&mut self, player: PubKey, ack: CeremonyAck) -> Result<()> {
        let dealer = self.dealer.as_mut().ok_or(TeeError::DkgSeamOrder(
            "dealer not started / already finalized",
        ))?;
        dealer
            .receive_player_ack(player, ack)
            .map_err(|e| dkg_err("dealer receive ack", e))
    }

    /// Seam D - finalize this party's dealing into a signed dealer log (signed
    /// with the in-enclave signing key). Consumes the resident `Dealer`.
    pub fn dealer_finalize(&mut self) -> Result<CeremonySignedLog> {
        let dealer = self.dealer.take().ok_or(TeeError::DkgSeamOrder(
            "dealer not started / already finalized",
        ))?;
        Ok(dealer.finalize::<N3f1>())
    }

    /// Seam E - recover this party's long-term threshold share from the verified
    /// dealer logs. Consumes the resident `Player`. Returns the public group
    /// output and the secret `Share`; the share is the caller's to seal and must
    /// never leave the enclave in plaintext.
    pub fn player_finalize(
        &mut self,
        logs: Vec<(PubKey, CeremonyLog)>,
    ) -> Result<(CeremonyOutput, CeremonyShare)> {
        let player = self
            .player
            .take()
            .ok_or(TeeError::DkgSeamOrder("player already finalized"))?;
        let mut finalize_logs = Logs::<Variant, PubKey, N3f1>::new(self.info.clone());
        for (dealer_pk, log) in logs {
            finalize_logs.record(dealer_pk, log);
        }
        let (output, share) = player
            .finalize::<N3f1, Batch>(&mut rand_core::OsRng, finalize_logs, &Sequential)
            .map_err(|e| dkg_err("player finalize", e))?;
        // Retain the group output + this party's share resident so Seam F
        // (offer-key partial-sign + group-sig recovery) can run on a later
        // request without re-finalizing. Both zeroize when the session drops.
        self.group_output = Some(output.clone());
        self.recovered_share = Some(share.clone());
        Ok((output, share))
    }

    /// Seam F (offer key) - threshold-sign the fixed offer message
    /// ([`TEE_OFFER_MESSAGE`]) with this party's recovered share, then **seal the
    /// partial to every participant's X25519 share-encryption key** (one
    /// [`EncryptedShare`] per recipient). The host relays only the opaque
    /// ciphertexts, so it cannot recover the group signature - and therefore the
    /// offer key - itself; recovery happens only inside each recipient enclave
    /// ([`DkgSession::recover_tribute_offer_secret`]). Requires
    /// [`DkgSession::player_finalize`] to have run (the share must be resident).
    pub fn tribute_offer_partials_sealed(&self) -> Result<Vec<(PubKey, EncryptedShare)>> {
        let share = self.recovered_share.as_ref().ok_or(TeeError::DkgSeamOrder(
            "tribute_offer_partials_sealed before player_finalize",
        ))?;
        let partial =
            threshold::sign_message::<Variant>(share, TEE_OFFER_NAMESPACE, TEE_OFFER_MESSAGE);
        // The plaintext partial exists only in this enclave; it is sealed to each
        // recipient (including self) so the host only ever relays ciphertext.
        let partial_bytes = Zeroizing::new(partial.encode().to_vec());
        let mut out = Vec::with_capacity(self.recipient_enc_keys.len());
        for (recipient_pk, enc_pub) in &self.recipient_enc_keys {
            let blob = encrypt_share(enc_pub, partial_bytes.as_ref())?;
            out.push((recipient_pk.clone(), blob));
        }
        Ok(out)
    }

    /// Seam F (offer key) - recover the group threshold signature over the fixed
    /// offer message from the **sealed partials addressed to this enclave**
    /// (decrypted in-SGX with the resident X25519 share-decryption secret), then
    /// derive the shared offer X25519 keypair from it (`HKDF(group_sig)` bound to
    /// `chain_id` + `tribute_offer_epoch`). Returns `(tribute_offer_secret, tribute_offer_public)`; the
    /// caller stores the secret in the enclave's resident offer-key slot and never
    /// exports it. Deterministic: every honest enclave recovers the same group
    /// signature from any valid `2f+1` subset, hence the same offer key. Because
    /// the host only ever holds the ciphertexts, it cannot run this recovery.
    pub fn recover_tribute_offer_secret(
        &self,
        sealed_for_me: &[Vec<u8>],
        chain_id: B256,
        tribute_offer_epoch: u64,
    ) -> Result<RecoveredTributeOfferKey> {
        let output = self.group_output.as_ref().ok_or(TeeError::DkgSeamOrder(
            "recover_tribute_offer_secret before player_finalize",
        ))?;
        let mut partials: Vec<PartialSignature<Variant>> = Vec::with_capacity(sealed_for_me.len());
        for blob_bytes in sealed_for_me {
            let blob = EncryptedShare::from_bytes(blob_bytes)?;
            let plaintext = Zeroizing::new(decrypt_share(&self.enc_secret, &blob)?);
            let mut reader: &[u8] = plaintext.as_ref();
            let partial = PartialSignature::<Variant>::read(&mut reader)
                .map_err(|e| dkg_err("decode offer partial", e))?;
            partials.push(partial);
        }
        let group_sig =
            threshold::recover::<Variant, _, N3f1>(output.public(), partials.iter(), &Sequential)
                .map_err(|e| dkg_err("recover offer group signature", e))?;
        // `sigma` (the encoded group signature) is retained resident by the caller
        // so the exact permanent key survives restart and can be delivered through
        // the deterministic one-time registry onboarding artifact.
        let sigma = Zeroizing::new(group_sig.encode().to_vec());
        let (secret, public) = crate::crypto::derive_tribute_offer_secret_from_group_sig(
            sigma.as_ref(),
            chain_id,
            tribute_offer_epoch,
        )?;
        Ok((secret, public, sigma))
    }

    /// The encoded DKG group public KEY - the constant term of the public
    /// polynomial (`output.public().public()`), a single fixed-size point. PUBLIC:
    /// it is the verification key for this committee's threshold group signatures
    /// and matches the byte layout of
    /// the consensus VRF `vrf_group_public_key_bytes` (constant term, not the whole
    /// polynomial). Carried as signed founding bootstrap material. Requires
    /// `player_finalize`.
    pub fn group_public_key_bytes(&self) -> Result<Vec<u8>> {
        let output = self.group_output.as_ref().ok_or(TeeError::DkgSeamOrder(
            "group_public_key_bytes before player_finalize",
        ))?;
        Ok(output.public().public().encode().to_vec())
    }
}

/// Verify a signed dealer log against the ceremony `info`, yielding the dealer's
/// public key (recovered from the log signature) and the public [`CeremonyLog`]
/// used by [`DkgSession::player_finalize`]. Public-only - no secret material -
/// so the host actor runs it too; provided here for the host actor and the
/// in-process ceremony test, and to keep the seam vocabulary in one place.
pub fn verify_dealer_log(
    info: &CeremonyInfo,
    signed: CeremonySignedLog,
) -> Option<(PubKey, CeremonyLog)> {
    signed.check(info)
}

/// Decode a BLS public key from its Commonware-encoded bytes.
fn decode_pubkey(bytes: &[u8]) -> Result<PubKey> {
    let mut reader: &[u8] = bytes;
    PubKey::read(&mut reader).map_err(|e| dkg_err("decode bls pubkey", e))
}

/// Build the canonical ceremony `Info` from the participants' encoded BLS public
/// keys. Sorts the set canonically (by encoded pubkey) so every enclave that is
/// given the same participant set constructs a byte-identical `Info`. Returns the
/// `Info` and the sorted public keys. Public-only; the host actor and the enclave
/// share it.
pub fn build_ceremony_info(
    round: u64,
    participant_bls: &[Vec<u8>],
) -> Result<(CeremonyInfo, Vec<PubKey>)> {
    let mut pubkeys: Vec<PubKey> = participant_bls
        .iter()
        .map(|b| decode_pubkey(b))
        .collect::<Result<_>>()?;
    pubkeys.sort_by_key(|k| k.encode());
    let participants: Set<PubKey> = pubkeys
        .iter()
        .cloned()
        .try_collect()
        .map_err(|e| dkg_err("build participant set", e))?;
    let info = Info::<Variant, PubKey>::new::<N3f1>(
        TEE_DKG_NAMESPACE,
        round,
        None,
        Mode::NonZeroCounter,
        participants.clone(),
        participants,
    )
    .map_err(|e| dkg_err("build ceremony info", e))?;
    Ok((info, pubkeys))
}

/// Byte-level seam adapters: the enclave transport shuttles opaque bytes, and all
/// Commonware encode/decode stays here (next to the ceremony `Info` that supplies
/// the decode config). Each mirrors the typed seam of the same name.
impl DkgSession {
    fn max_players(&self) -> Result<NonZeroU32> {
        let n = u32::try_from(self.recipient_enc_keys.len())
            .map_err(|_| TeeError::Dkg("participant count exceeds u32".to_string()))?;
        NonZeroU32::new(n).ok_or_else(|| TeeError::Dkg("empty participant set".to_string()))
    }

    /// Seam A (bytes): `(encoded pub_msg, [(encoded recipient bls, sealed share)])`.
    pub fn start_dealer_encoded(&mut self) -> Result<EncodedDealing> {
        let (pub_msg, sealed) = self.start_dealer(None)?;
        let shares = sealed
            .into_iter()
            .map(|(pk, blob)| (pk.encode().to_vec(), blob.to_bytes()))
            .collect();
        Ok((pub_msg.encode().to_vec(), shares))
    }

    /// Seam B (bytes): open + verify a sealed dealing; returns the encoded ack.
    pub fn player_ingest_encoded(
        &mut self,
        dealer_bls: &[u8],
        pub_msg: &[u8],
        sealed_share: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let dealer = decode_pubkey(dealer_bls)?;
        let max = self.max_players()?;
        let mut reader: &[u8] = pub_msg;
        let pub_msg = DealerPubMsg::<Variant>::read_cfg(&mut reader, &max)
            .map_err(|e| dkg_err("decode pub_msg", e))?;
        let blob = EncryptedShare::from_bytes(sealed_share)?;
        let ack = self.player_ingest(dealer, pub_msg, &blob)?;
        Ok(ack.map(|a| a.encode().to_vec()))
    }

    /// Seam C (bytes): record a player's encoded ack at this dealer.
    pub fn dealer_receive_ack_encoded(&mut self, player_bls: &[u8], ack: &[u8]) -> Result<()> {
        let player = decode_pubkey(player_bls)?;
        let mut reader: &[u8] = ack;
        let ack = PlayerAck::<PubKey>::read(&mut reader).map_err(|e| dkg_err("decode ack", e))?;
        self.dealer_receive_ack(player, ack)
    }

    /// Seam D (bytes): finalize this dealer's log to encoded bytes.
    pub fn dealer_finalize_encoded(&mut self) -> Result<Vec<u8>> {
        Ok(self.dealer_finalize()?.encode().to_vec())
    }

    /// Seam E (bytes): verify each encoded signed dealer log, recover the local
    /// share, and return `(encoded group public, share commitment)`. The share
    /// commitment is `keccak256(share)`; the secret share stays in the enclave.
    pub fn player_finalize_encoded(&mut self, signed_logs: &[Vec<u8>]) -> Result<(Vec<u8>, B256)> {
        let max = self.max_players()?;
        let mut logs = Vec::with_capacity(signed_logs.len());
        let mut distinct_dealers = std::collections::BTreeSet::new();
        for bytes in signed_logs {
            let mut reader: &[u8] = bytes;
            let signed = SignedDealerLog::<Variant, PrivKey>::read_cfg(&mut reader, &max)
                .map_err(|e| dkg_err("decode signed log", e))?;
            let (pk, log) = verify_dealer_log(&self.info, signed)
                .ok_or_else(|| TeeError::Dkg("dealer log failed verification".to_string()))?;
            distinct_dealers.insert(commonware_codec::Encode::encode(&pk).to_vec());
            logs.push((pk, log));
        }
        // Initial DKG: the group key is the sum of EVERY dealer's contribution, so an
        // incomplete dealer set yields a DIFFERENT group key. Require the verified
        // distinct dealers to cover the full committee - otherwise an untrusted host
        // feeding different dealer subsets to different enclaves would diverge the
        // derived offer key across validators. (Each verified dealer is a committee
        // member, so a full distinct count equals full coverage. Scheduled rolling
        // reshare is a separate consensus ceremony; this founding path is all-n.)
        let expected = max.get() as usize;
        if distinct_dealers.len() != expected {
            return Err(TeeError::Dkg(format!(
                "incomplete dealer set: {} of {expected} committee dealers",
                distinct_dealers.len(),
            )));
        }
        let (output, share) = self.player_finalize(logs)?;
        Ok((output.encode().to_vec(), keccak256(share.encode())))
    }
}

/// Resident store of in-progress DKG ceremonies, keyed by ceremony id.
///
/// Bounded by the number of concurrent ceremonies a node participates in (one in
/// the PoC). Sessions are removed on completion (or on the host abandoning the
/// ceremony) so secret `Dealer`/`Player` state does not accumulate.
#[derive(Default)]
pub struct DkgSessionStore {
    sessions: BTreeMap<CeremonyKey, DkgSession>,
}

impl DkgSessionStore {
    /// New empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a fresh ceremony session. Rejects a duplicate ceremony id so a
    /// replayed `open` cannot silently reset in-progress secret state.
    pub fn open(
        &mut self,
        id: CeremonyKey,
        info: CeremonyInfo,
        signing_key: PrivKey,
        enc_secret: &[u8; 32],
        recipient_enc_keys: BTreeMap<PubKey, [u8; 32]>,
    ) -> Result<()> {
        if self.sessions.contains_key(&id) {
            return Err(TeeError::Dkg(format!(
                "ceremony {} already open",
                hex::encode(id)
            )));
        }
        self.sessions.insert(
            id,
            DkgSession::new(info, signing_key, enc_secret, recipient_enc_keys)?,
        );
        Ok(())
    }

    /// Mutable access to an open ceremony session.
    pub fn get_mut(&mut self, id: &CeremonyKey) -> Result<&mut DkgSession> {
        self.sessions
            .get_mut(id)
            .ok_or_else(|| TeeError::DkgSessionMissing(hex::encode(id)))
    }

    /// Remove and return a ceremony session (e.g. after player finalize, or when
    /// the host abandons the ceremony). When the returned value is dropped, the
    /// constituent secret scalars (`Secret<Scalar>` inside `Dealer`/`Player`, the
    /// `signing_key`, and the `Zeroizing` X25519 secret) zeroize via their `Drop`
    /// impls; note that `Dealer`/`Player` do not themselves implement
    /// `ZeroizeOnDrop`, so the session must be dropped (never cloned into a
    /// long-lived owner) to guarantee cleanup.
    pub fn remove(&mut self, id: &CeremonyKey) -> Option<DkgSession> {
        self.sessions.remove(id)
    }

    /// Number of resident ceremonies.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the store holds no ceremonies.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// n validators with deterministic keys, sorted by encoded public key (the
    /// canonical Commonware ordering), and a shared `Info`.
    fn setup(n: u32) -> (CeremonyInfo, Vec<PrivKey>, Vec<PubKey>) {
        let keys: Vec<PrivKey> = (0..n)
            .map(|i| PrivKey::from_seed(u64::from(i) + 1))
            .collect();
        let participant_bls: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| k.public_key().encode().to_vec())
            .collect();
        let (info, pubkeys) = build_ceremony_info(0, &participant_bls).unwrap();
        // Return private keys ordered to match the canonical pubkey order.
        let mut ordered_keys = keys;
        ordered_keys.sort_by_key(|k| k.public_key().encode());
        (info, ordered_keys, pubkeys)
    }

    /// Deterministic, distinct X25519 secret for party `i`. Varies byte 1, which
    /// X25519 clamping leaves untouched (clamping clears the low 3 bits of byte 0,
    /// so varying byte 0 in 1..8 would collapse to one scalar).
    fn enc_secret_for(i: usize) -> [u8; 32] {
        let mut s = [0x11u8; 32];
        s[1] = i as u8 + 1;
        s
    }

    /// Build each party's announced X25519 share-encryption pubkey, keyed by BLS
    /// pubkey: `(enc_secrets, recipient_enc_keys)`.
    fn enc_material(pubkeys: &[PubKey]) -> (Vec<[u8; 32]>, BTreeMap<PubKey, [u8; 32]>) {
        let secrets: Vec<[u8; 32]> = (0..pubkeys.len()).map(enc_secret_for).collect();
        let map = pubkeys
            .iter()
            .zip(&secrets)
            .map(|(pk, sk)| (pk.clone(), x25519_public(sk)))
            .collect();
        (secrets, map)
    }

    /// Drive a complete n-party ceremony in-process through the enclave seams,
    /// with every share sealed dealer->recipient and opened inside the recipient
    /// session, and return each party's `(group output bytes, share bytes)`.
    fn run_ceremony(n: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
        let (info, keys, pubkeys) = setup(n);
        let count = n as usize;
        let (enc_secrets, enc_keys) = enc_material(&pubkeys);

        let mut sessions: Vec<DkgSession> = keys
            .iter()
            .zip(&enc_secrets)
            .map(|(k, sk)| {
                DkgSession::new(info.clone(), k.clone(), sk, enc_keys.clone()).expect("session")
            })
            .collect();

        // Phase A: every party deals and seals shares to recipients (seam A).
        let mut pub_msgs: Vec<CeremonyPubMsg> = Vec::with_capacity(count);
        let mut sealed_shares: Vec<BTreeMap<PubKey, EncryptedShare>> = Vec::with_capacity(count);
        for session in sessions.iter_mut() {
            let (pub_msg, blobs) = session.start_dealer(None).expect("start_dealer");
            assert_eq!(blobs.len(), count, "one sealed share per participant");
            pub_msgs.push(pub_msg);
            sealed_shares.push(blobs.into_iter().collect());
        }

        // Phase B/C: deliver dealer i's sealed share to each player j (seam B
        // opens + verifies it), then the resulting acks back to dealer i (seam C).
        for i in 0..count {
            let dealer_pk = pubkeys[i].clone();
            let pub_msg = pub_msgs[i].clone();
            let mut acks: Vec<(PubKey, CeremonyAck)> = Vec::with_capacity(count);
            for (j, session) in sessions.iter_mut().enumerate() {
                let player_pk = pubkeys[j].clone();
                let blob = sealed_shares[i]
                    .remove(&player_pk)
                    .expect("sealed share for player present");
                if let Some(ack) = session
                    .player_ingest(dealer_pk.clone(), pub_msg.clone(), &blob)
                    .expect("player_ingest")
                {
                    acks.push((player_pk, ack));
                }
            }
            assert_eq!(acks.len(), count, "every player acks a valid dealing");
            for (player_pk, ack) in acks {
                sessions[i]
                    .dealer_receive_ack(player_pk, ack)
                    .expect("dealer_receive_ack");
            }
        }

        // Phase D: each dealer finalizes its log (seam D); all parties verify.
        // `verify_dealer_log` recovers the dealer pubkey from the signed log, so
        // it must match the dealer's declared identity.
        let mut dealer_logs: Vec<(PubKey, CeremonyLog)> = Vec::with_capacity(count);
        for (i, session) in sessions.iter_mut().enumerate() {
            let signed = session.dealer_finalize().expect("dealer_finalize");
            let (dealer_pk, log) = verify_dealer_log(&info, signed).expect("dealer log verifies");
            assert_eq!(
                dealer_pk, pubkeys[i],
                "recovered dealer pubkey matches dealer"
            );
            dealer_logs.push((dealer_pk, log));
        }

        // Phase E: each player recovers its threshold share (seam E).
        sessions
            .into_iter()
            .map(|mut session| {
                let (output, share) = session
                    .player_finalize(dealer_logs.clone())
                    .expect("player_finalize");
                (output.encode().to_vec(), share.encode().to_vec())
            })
            .collect()
    }

    #[test]
    fn full_in_process_ceremony_reaches_consistent_group_key() {
        let results = run_ceremony(4);
        assert_eq!(results.len(), 4);

        // Every party must derive the identical public group output - this is the
        // determinism property the consensus/execution boundary relies on.
        let group = &results[0].0;
        for (i, (output, _share)) in results.iter().enumerate() {
            assert_eq!(output, group, "party {i} diverged on the group public key");
        }

        // Each party holds a distinct, non-empty threshold share.
        let mut shares: Vec<&Vec<u8>> = results.iter().map(|(_, s)| s).collect();
        for share in &shares {
            assert!(!share.is_empty(), "share must be non-empty");
        }
        shares.sort();
        shares.dedup();
        assert_eq!(shares.len(), 4, "every party's share must be distinct");
    }

    #[test]
    fn sealed_ceremony_completes_for_several_sizes() {
        // The sealed share path must converge to a single group key for every
        // party, across ceremony sizes.
        for n in [4u32, 7] {
            let results = run_ceremony(n);
            let group = &results[0].0;
            assert!(results.iter().all(|(o, _)| o == group));
        }
    }

    #[test]
    fn player_finalize_encoded_rejects_incomplete_dealer_set() {
        // Fix A (C2): a host feeding fewer than all-n dealer logs would diverge the
        // group key across enclaves, so the byte finalize must reject an incomplete
        // set. Drive a 4-party ceremony to per-dealer encoded logs, then finalize.
        let n = 4usize;
        let (info, keys, pubkeys) = setup(n as u32);
        let (enc_secrets, enc_keys) = enc_material(&pubkeys);
        let mut sessions: Vec<DkgSession> = keys
            .iter()
            .zip(&enc_secrets)
            .map(|(k, sk)| {
                DkgSession::new(info.clone(), k.clone(), sk, enc_keys.clone()).expect("session")
            })
            .collect();

        let mut pub_msgs: Vec<CeremonyPubMsg> = Vec::with_capacity(n);
        let mut sealed_shares: Vec<BTreeMap<PubKey, EncryptedShare>> = Vec::with_capacity(n);
        for s in sessions.iter_mut() {
            let (pm, blobs) = s.start_dealer(None).expect("start_dealer");
            pub_msgs.push(pm);
            sealed_shares.push(blobs.into_iter().collect());
        }
        for i in 0..n {
            let dealer_pk = pubkeys[i].clone();
            let pm = pub_msgs[i].clone();
            let mut acks: Vec<(PubKey, CeremonyAck)> = Vec::new();
            for (j, s) in sessions.iter_mut().enumerate() {
                let blob = sealed_shares[i].remove(&pubkeys[j]).expect("sealed share");
                if let Some(ack) = s
                    .player_ingest(dealer_pk.clone(), pm.clone(), &blob)
                    .expect("player_ingest")
                {
                    acks.push((pubkeys[j].clone(), ack));
                }
            }
            for (pk, ack) in acks {
                sessions[i]
                    .dealer_receive_ack(pk, ack)
                    .expect("dealer_receive_ack");
            }
        }

        let logs: Vec<Vec<u8>> = sessions
            .iter_mut()
            .map(|s| {
                s.dealer_finalize_encoded()
                    .expect("dealer_finalize_encoded")
            })
            .collect();

        // Complete set finalizes; the incomplete subset (n-1 dealers) is rejected.
        assert!(
            sessions[1].player_finalize_encoded(&logs).is_ok(),
            "complete dealer set must finalize"
        );
        let err = sessions[0]
            .player_finalize_encoded(&logs[..n - 1])
            .unwrap_err();
        assert!(
            matches!(err, TeeError::Dkg(_)),
            "incomplete dealer set must be rejected: {err:?}"
        );
    }

    #[test]
    fn player_ingest_rejects_share_sealed_to_another_enclave() {
        // A share sealed to a DIFFERENT recipient must not open in this session.
        let (info, keys, pubkeys) = setup(4);

        // The dealer's recipient map points EVERY participant at the dealer's own
        // enc key, so the share addressed to the player is sealed to the wrong key.
        let dealer_enc = enc_secret_for(0);
        let wrong_keys: BTreeMap<PubKey, [u8; 32]> = pubkeys
            .iter()
            .map(|pk| (pk.clone(), x25519_public(&dealer_enc)))
            .collect();
        let mut dealer = DkgSession::new(info.clone(), keys[0].clone(), &dealer_enc, wrong_keys)
            .expect("dealer");

        let player_enc = enc_secret_for(1);
        let mut player =
            DkgSession::new(info, keys[1].clone(), &player_enc, BTreeMap::new()).expect("player");

        let (pub_msg, blobs) = dealer.start_dealer(None).expect("start_dealer");
        let player_pk = player.participant_pubkey();
        let blob = blobs
            .into_iter()
            .find(|(pk, _)| *pk == player_pk)
            .expect("share for player")
            .1;

        let err = player
            .player_ingest(dealer.participant_pubkey(), pub_msg, &blob)
            .unwrap_err();
        assert!(matches!(err, TeeError::DecryptFailed | TeeError::Dkg(_)));
    }

    #[test]
    fn session_store_open_get_remove_lifecycle() {
        let (info, keys, pubkeys) = setup(4);
        let (enc_secrets, enc_keys) = enc_material(&pubkeys);
        let mut store = DkgSessionStore::new();
        assert!(store.is_empty());

        let id: CeremonyKey = [0x11; 32];
        store
            .open(
                id,
                info.clone(),
                keys[0].clone(),
                &enc_secrets[0],
                enc_keys.clone(),
            )
            .expect("open");
        assert_eq!(store.len(), 1);

        // Duplicate open is rejected (no silent reset of secret state).
        assert!(store
            .open(
                id,
                info.clone(),
                keys[0].clone(),
                &enc_secrets[0],
                enc_keys.clone()
            )
            .is_err());

        // The resident session is usable: a dealer seals a share to every
        // participant (enc keys captured at open cover all four pubkeys).
        let (_pub_msg, blobs) = store
            .get_mut(&id)
            .expect("session present")
            .start_dealer(None)
            .expect("start_dealer");
        assert_eq!(blobs.len(), 4);

        // Missing ceremony id is a typed error, not a panic.
        let missing: CeremonyKey = [0x22; 32];
        assert!(store.get_mut(&missing).is_err());

        assert!(store.remove(&id).is_some());
        assert!(store.is_empty());
    }

    #[test]
    fn seam_order_violations_are_typed_errors_not_panics() {
        let (info, keys, pubkeys) = setup(4);
        let (enc_secrets, enc_keys) = enc_material(&pubkeys);
        let mut session =
            DkgSession::new(info, keys[0].clone(), &enc_secrets[0], enc_keys).expect("session");

        // dealer_finalize before start_dealer -> typed error.
        assert!(matches!(
            session.dealer_finalize(),
            Err(TeeError::DkgSeamOrder(_))
        ));

        session.start_dealer(None).expect("start_dealer");
        // Second start_dealer -> typed error.
        assert!(matches!(
            session.start_dealer(None),
            Err(TeeError::DkgSeamOrder(_))
        ));
    }

    /// Drive a complete n-party ceremony through seams A-E and return the
    /// resident sessions, each holding its recovered share + group output so
    /// Seam F (offer key) can run on them.
    fn drive_ceremony_to_shares(n: u32) -> Vec<DkgSession> {
        let (info, keys, pubkeys) = setup(n);
        let count = n as usize;
        let (enc_secrets, enc_keys) = enc_material(&pubkeys);
        let mut sessions: Vec<DkgSession> = keys
            .iter()
            .zip(&enc_secrets)
            .map(|(k, sk)| {
                DkgSession::new(info.clone(), k.clone(), sk, enc_keys.clone()).expect("session")
            })
            .collect();

        let mut pub_msgs: Vec<CeremonyPubMsg> = Vec::with_capacity(count);
        let mut sealed_shares: Vec<BTreeMap<PubKey, EncryptedShare>> = Vec::with_capacity(count);
        for session in sessions.iter_mut() {
            let (pub_msg, blobs) = session.start_dealer(None).expect("start_dealer");
            pub_msgs.push(pub_msg);
            sealed_shares.push(blobs.into_iter().collect());
        }
        for i in 0..count {
            let dealer_pk = pubkeys[i].clone();
            let pub_msg = pub_msgs[i].clone();
            let mut acks: Vec<(PubKey, CeremonyAck)> = Vec::with_capacity(count);
            for (j, session) in sessions.iter_mut().enumerate() {
                let player_pk = pubkeys[j].clone();
                let blob = sealed_shares[i].remove(&player_pk).expect("sealed share");
                if let Some(ack) = session
                    .player_ingest(dealer_pk.clone(), pub_msg.clone(), &blob)
                    .expect("player_ingest")
                {
                    acks.push((player_pk, ack));
                }
            }
            for (player_pk, ack) in acks {
                sessions[i]
                    .dealer_receive_ack(player_pk, ack)
                    .expect("dealer_receive_ack");
            }
        }
        let mut dealer_logs: Vec<(PubKey, CeremonyLog)> = Vec::with_capacity(count);
        for (i, session) in sessions.iter_mut().enumerate() {
            let signed = session.dealer_finalize().expect("dealer_finalize");
            let (dealer_pk, log) = verify_dealer_log(&info, signed).expect("dealer log verifies");
            assert_eq!(dealer_pk, pubkeys[i]);
            dealer_logs.push((dealer_pk, log));
        }
        for session in sessions.iter_mut() {
            session
                .player_finalize(dealer_logs.clone())
                .expect("player_finalize");
        }
        sessions
    }

    /// Mirror the host coordinator's SEALED Seam-F relay for unit tests: every
    /// session seals its partial to every recipient, the host holds only the
    /// ciphertexts, and each session recovers its offer key from the ciphertexts
    /// addressed to it (decrypted in-SGX). Returns each session's `(secret,public)`.
    fn sealed_tribute_offer_keys(
        sessions: &[DkgSession],
        chain_id: B256,
        epoch: u64,
    ) -> Vec<(Zeroizing<[u8; 32]>, [u8; 32])> {
        use commonware_cryptography::Signer as _;
        let pubkeys: Vec<PubKey> = sessions
            .iter()
            .map(|s| s.signing_key.public_key())
            .collect();
        let sealed: Vec<Vec<(PubKey, EncryptedShare)>> = sessions
            .iter()
            .map(|s| {
                s.tribute_offer_partials_sealed()
                    .expect("tribute_offer_partials_sealed")
            })
            .collect();
        sessions
            .iter()
            .enumerate()
            .map(|(i, s)| {
                // The ciphertexts addressed to session i (from every signer).
                let for_me: Vec<Vec<u8>> = sealed
                    .iter()
                    .flat_map(|signer| {
                        signer
                            .iter()
                            .filter(|(r, _)| *r == pubkeys[i])
                            .map(|(_, b)| b.to_bytes())
                    })
                    .collect();
                let (secret, public, _group_sig) = s
                    .recover_tribute_offer_secret(&for_me, chain_id, epoch)
                    .expect("recover_tribute_offer_secret");
                (secret, public)
            })
            .collect()
    }

    /// Seam F core property: every party recovers the SAME group threshold
    /// signature over the fixed offer message and therefore derives the
    /// byte-identical offer keypair - the determinism the on-chain offer key
    /// relies on. Also checks chain-binding.
    #[test]
    fn seam_f_derives_identical_tribute_offer_key_across_parties() {
        let sessions = drive_ceremony_to_shares(4);
        let chain_id = B256::repeat_byte(0xC1);

        let derived = sealed_tribute_offer_keys(&sessions, chain_id, 0);
        let sk0 = &derived[0].0;
        let pk0 = derived[0].1;
        for (i, (sk, pk)) in derived.iter().enumerate() {
            assert_eq!(*pk, pk0, "party {i} diverged on the offer public key");
            assert_eq!(sk, sk0, "party {i} diverged on the offer secret");
        }

        // Chain-binding: a different chain_id yields a different offer key.
        let other = sealed_tribute_offer_keys(&sessions, B256::repeat_byte(0xC2), 0);
        assert_ne!(other[0].1, pk0, "offer key must be chain-bound");
    }

    /// Below-quorum sealed partials must return a typed error, never panic.
    #[test]
    fn seam_f_below_quorum_partials_errors() {
        use commonware_cryptography::Signer as _;
        let sessions = drive_ceremony_to_shares(4);
        let my_pk = sessions[0].signing_key.public_key();
        // Only 2 ciphertexts addressed to session 0 (< quorum 3 for n=4).
        let for_me: Vec<Vec<u8>> = sessions
            .iter()
            .take(2)
            .map(|s| {
                let sealed = s.tribute_offer_partials_sealed().expect("seal");
                sealed
                    .into_iter()
                    .find(|(r, _)| *r == my_pk)
                    .map(|(_, b)| b.to_bytes())
                    .expect("blob for me")
            })
            .collect();
        assert!(sessions[0]
            .recover_tribute_offer_secret(&for_me, B256::ZERO, 0)
            .is_err());
    }

    /// Seam F before `player_finalize` (no resident share/output) is a typed
    /// seam-order error, not a panic.
    #[test]
    fn seam_f_before_finalize_is_typed_error() {
        let (info, keys, pubkeys) = setup(4);
        let (enc_secrets, enc_keys) = enc_material(&pubkeys);
        let session =
            DkgSession::new(info, keys[0].clone(), &enc_secrets[0], enc_keys).expect("session");
        assert!(matches!(
            session.tribute_offer_partials_sealed(),
            Err(TeeError::DkgSeamOrder(_))
        ));
        assert!(matches!(
            session.recover_tribute_offer_secret(&[], B256::ZERO, 0),
            Err(TeeError::DkgSeamOrder(_))
        ));
    }

    /// SECURITY - no-leak proof (sealed Seam F): the offer partial signatures are
    /// the secret that, combined by public Lagrange math (`threshold::recover`),
    /// reconstruct the group signature sigma and therefore the offer key. The fix
    /// seals each partial pairwise (X25519 + ChaCha20Poly1305) to its recipient
    /// enclave, so the HOST only ever relays **ciphertext** on gossip. This test
    /// proves: (1) a legit enclave still recovers the byte-identical offer key
    /// from the blobs addressed to it, and (2) the host, holding only the gossiped
    /// ciphertexts and the public DKG group output, CANNOT assemble a quorum of
    /// plaintext partials and therefore cannot run `threshold::recover` at all.
    #[test]
    fn tribute_offer_key_not_recoverable_by_host_from_sealed_partials() {
        let sessions = drive_ceremony_to_shares(4);
        let chain_id = B256::repeat_byte(0xC1);
        let epoch = 7u64;

        // (1) Reference: every legit enclave recovers the SAME offer key in-SGX,
        // decrypting the sealed partials addressed to it. (Confidentiality without
        // breaking correctness.)
        let keys = sealed_tribute_offer_keys(&sessions, chain_id, epoch);
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(*k, keys[0], "legit enclave {i} diverged on the offer key");
        }
        assert_ne!(keys[0].1, [0u8; 32]);

        // (2) What the host actually sees on the gossip channel: ONLY the sealed
        // ciphertexts `(recipient_bls, EncryptedShare wire)`. It has no enclave
        // X25519 secret, so it cannot decrypt them. Its strongest attack is to
        // treat the ciphertext as if it were a plaintext partial and feed it to the
        // public Lagrange recovery.
        let ciphertexts: Vec<Vec<u8>> = sessions
            .iter()
            .flat_map(|s| {
                s.tribute_offer_partials_sealed()
                    .expect("tribute_offer_partials_sealed")
                    .into_iter()
                    .map(|(_, blob)| blob.to_bytes())
            })
            .collect();

        // The sealed wire (X25519 ephemeral pub || nonce || ciphertext) does not
        // decode as a BLS `PartialSignature`. The host cannot obtain even one valid
        // plaintext partial, let alone the quorum `threshold::recover` requires.
        let decodable = ciphertexts
            .iter()
            .filter(|bytes| {
                let mut reader: &[u8] = bytes;
                PartialSignature::<Variant>::read(&mut reader).is_ok()
            })
            .count();
        assert!(
            decodable < 3,
            "host must not be able to assemble a quorum (>=3) of plaintext \
             partials from the sealed ciphertexts; decoded {decodable}"
        );
    }
}
