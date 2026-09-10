//! Neutral wire-protocol types for the node <-> enclave channel.
//!
//! These types are the message contract shared by the host (`outbe-tee`) and
//! the enclave (`outbe-tee-enclave`). They carry **no secret material** and no
//! cryptographic logic - only the shape of requests and responses.
//!
//! Transport (later slice): length-prefixed framing over UDS, wrapped in a
//! Noise-IK transport (payload layer). Production first exposes only an
//! initialization challenge. A node-signed manifest installs one persistent
//! `NodeHost` initiator; every later command, including quote generation, is
//! accepted only after that initiator is authenticated by Noise message 1.
//! `GetQuote` exists only for the separate development transport.
//!
//! Opaque byte fields (`Vec<u8>`) intentionally hide DKG wire internals: the
//! host parses only the public envelope and forwards the encrypted
//! secret-bearing parts to the enclave without decrypting them.

use alloy_primitives::{Address, B256, U256};

pub use outbe_primitives::time::WorldwideDay;

/// Hard cap for the deterministic registry onboarding artifact. The current
/// X25519/nonce/AEAD envelope is substantially smaller; this prevents a
/// malformed enclave response from creating an unbounded consensus log.
pub const MAX_ONBOARDING_ARTIFACT_BYTES: usize = 512;

/// Minimum canonical framing: the committed 32-byte offer public key plus the
/// ephemeral public key, nonce and authenticated ciphertext framing.
pub const MIN_ONBOARDING_ARTIFACT_BYTES: usize = 60;

/// A single offer handed to the enclave.
///
/// Fields mirror the part of `ITributeFactory.offerTribute` the enclave needs,
/// plus the sender and the node-resolved public Oracle inputs:
///   - `cipherText`, `nonce`, `ephemeralPubkey`, `worldwideDay`,
///     `tributeCurrency`, `referenceCurrency`, `excludeFromIntexIssuance` (ABI);
///   - `owner` - the L1 `msg.sender`; the enclave binds it into the result and
///     into the `token_id` (computed in-enclave, see `TributeOfferResult`);
///   - `issuance_wwd_vwap_minor`, `reference_wwd_vwap_minor`, and
///     `reference_scurve_minor` - resolved by the node from committed Oracle
///     state; not ABI fields.
///
/// The ZK fields (`zkProof`/`zkVerificationKey`/`zkPublicKey`/`zkMerkleRoot`)
/// are verified BEFORE the enclave call and are NOT forwarded.
///
/// Every field here is public and host-supplied, so the enclave never echoes any
/// of them back - [`TributeOfferResult`] carries only what the enclave itself
/// computed from the decrypted payload.
///
/// Price integrity: the enclave applies the rate but does not verify it against
/// chain state; integrity is enforced by deterministic re-execution (a forged
/// rate yields a state-root mismatch). See plan section "Oracle Price Determinism".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EncryptedTributeOffer {
    /// L1 `msg.sender` that owns the resulting Tribute (public, on-chain).
    pub owner: Address,
    /// ABI `cipherText`: AEAD ciphertext of the offer payload.
    pub cipher_text: Vec<u8>,
    /// ABI `nonce`: 12-byte ChaCha20Poly1305 nonce.
    pub nonce: Vec<u8>,
    /// ABI `ephemeralPubkey` (uint256): client ephemeral X25519 public key for
    /// ECDHE, big-endian.
    pub ephemeral_pubkey: U256,
    /// ABI `worldwideDay`: UTC+14 day key (`YYYYMMDD`). Calendar validity and
    /// OFFERING status are settled by the node before the call; the enclave
    /// binds the value into `token_id` without re-deriving either. The host
    /// recomputes the same `(owner, day)` identity from its own input and
    /// rejects a mismatch, and every validator re-executes the call, so the
    /// chain - not a second in-enclave calendar - is what anchors this field.
    pub worldwide_day: WorldwideDay,
    /// ABI `tributeCurrency`: ISO 4217 code the tribute amount is denominated in.
    pub tribute_currency: u16,
    /// ABI `referenceCurrency`. A separate axis from `tribute_currency` - it
    /// drives gem/intex qualification, not pricing.
    pub reference_currency: u16,
    /// ABI `excludeFromIntexIssuance`: when true, the resulting Tribute is
    /// excluded from Intex issuance.
    pub exclude_from_intex_issuance: bool,
    /// Exact WorldwideDay VWAP for `COEN/<tribute_currency>`, scale 1e6.
    pub issuance_wwd_vwap_minor: U256,
    /// Exact WorldwideDay VWAP for `COEN/<reference_currency>`, scale 1e6.
    pub reference_wwd_vwap_minor: U256,
    /// Continuous reference-currency S-curve value, scale 1e6. Zero means no
    /// active curve and is valid.
    pub reference_scurve_minor: U256,
    /// Public ZK claim context supplied only for registered L2 networks with
    /// ZK verification enabled. The owner is the first public input embedded
    /// in `zkProof`; the chain id is read from the local execution context.
    #[serde(default)]
    pub zk_context: Option<TributeZkContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TributeZkContext {
    pub derived_owner: B256,
    pub chain_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TributeZkExpectedHashes {
    pub nft_hash: B256,
    pub binding_hash: B256,
}

/// Status of a single offer after enclave processing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TributeOfferStatus {
    Created,
    Rejected { reason: String },
}

/// Public result for a single offer (Enclave Return Rule: no L2 draft owner, no
/// L2 pubkey, no raw proof witness).
///
/// `token_id` is computed **inside the enclave** via Poseidon over sensitive
/// decrypted data (it cannot be derived on the host, which never sees that
/// data). `owner` is the L1 `msg.sender`, bound by the enclave. The remaining
/// fields are the economics derived from the decrypted payload.
///
/// This carries **only what the enclave computed**. Values the host supplied in
/// [`EncryptedTributeOffer`] - day, currencies, exclusion flag, price - are not
/// echoed back: the host already holds them, so an echo would be one more thing
/// to keep in agreement for no gain. `owner` is the exception and is deliberate:
/// it is folded into `token_id`, so comparing it against `msg.sender` checks the
/// enclave's computation rather than repeating an input.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TributeOfferResult {
    /// Poseidon(token_id preimage) - computed in-enclave from sensitive data.
    pub token_id: B256,
    /// L1 `msg.sender` (public, on-chain).
    pub owner: Address,
    pub issuance_amount_minor: U256,
    pub nominal_amount_minor: U256,
    /// `max(reference_wwd_vwap_minor, reference_scurve_minor)`, computed inside
    /// the enclave and checked by the host against the public request inputs.
    pub effective_reference_price_minor: U256,
    /// SU hashes (hex) - the host marks them used (replay prevention). Public
    /// on-chain as used-markers. The privacy-preserving markers-only form (rather
    /// than raw hashes) is a later slice (see `process.rs`).
    pub su_hashes: Vec<String>,
    /// WAA wallet addresses - host routes agent rewards. Public on-chain.
    pub wallet_addresses: Vec<String>,
    /// SRA addresses - host routes agent rewards. Public on-chain.
    pub sra_addresses: Vec<String>,
    /// Expected public hashes recomputed over the decrypted TributeDraft.
    /// Present only when the matching request carried [`TributeZkContext`].
    #[serde(default)]
    pub zk_expected_hashes: Option<TributeZkExpectedHashes>,
    pub status: TributeOfferStatus,
}

/// Requests sent from the node to the enclave.
///
/// DKG secret-seam variants carry opaque bytes: the host never sees plaintext
/// shares.
/// One DKG participant's ceremony-scoped identity. `enc_sig` authenticates the
/// full network binding, ceremony id, round, exact participant-set hash and
/// X25519 share-recipient key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParticipantAnnounce {
    /// Encoded TEE-BLS public key (the participant's DKG identity).
    pub bls_pub: Vec<u8>,
    /// Announced X25519 share-encryption public key.
    pub enc_pub: [u8; 32],
    pub ceremony_id: B256,
    pub round: u64,
    pub participant_set_hash: B256,
    /// TEE-BLS signature over the complete ceremony-scoped announcement.
    pub enc_sig: Vec<u8>,
}

/// A Gratis write operation the enclave applies over encrypted per-account state.
///
/// The op determines the sign of the aggregate deltas the host applies to the
/// public `total_supply` / `pledged_total_supply` scalars, and which ciphertext
/// slots move (balance vs pledged vs pledge-lock-ticket).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GratisOp {
    /// Mint `amount` to `account` (credit balance; `total_supply += amount`).
    Mint,
    /// Burn `amount` from `account` (debit balance; `total_supply -= amount`).
    Burn,
    /// Lock the gratis that covers `amount` stablecoin minor units into a new
    /// `PledgeLockTicket` pending a credis request. `amount` is the STABLES figure
    /// the pledger signed; the gratis actually debited comes from
    /// [`GratisOpRequest::pledge_terms`] (derived host-side from the oracle rate) and
    /// is what moves the balance and `pledged_total_supply`. The gratis is parked in
    /// the ticket, NOT yet credited to the account's pledged ledger.
    Pledge,
    /// Return a still-pending pledge (e.g. credis rejected): read the ticket, credit
    /// its gratis back to `account`'s balance, and delete it
    /// (`pledged_total_supply -= ticket.gratis_amount`). `amount` is the STABLES
    /// figure, cross-checked against the ticket.
    Unpledge,
    /// Consume a `PledgeLockTicket` for a credis request: verify `spend_auth` binds
    /// it to `smart_account`, credit the ticket gratis into the EOA's own pledged
    /// ledger, and delete the ticket (no aggregate change - it stays pledged). Returns
    /// the sealed [`PledgeTerms`] so credis can size the position from the quote the
    /// pledger accepted.
    ConsumePledge,
    /// Release `amount` of collateral from the EOA's own pledged ledger back to its
    /// balance (`pledged_total_supply -= amount`). Amount-based (no ticket); the
    /// on-chain Credis position is the accounting authority.
    ReleaseToEoa,
    /// Burn `amount` of collateral from the EOA's own pledged ledger at credis void
    /// (`total_supply -= amount`; `pledged_total_supply -= amount`). Amount-based (no
    /// ticket); the on-chain Credis position's outstanding balance is the authority.
    BurnPledged,
    /// Read-only: decrypt a state-key-sealed owner blob and return the plaintext EOA.
    /// With `pledge_handle = Some(handle)` the blob in `current_pledge_record` is a live
    /// `PledgeLockTicket` (used at credis `ConsumePledge` time, before the calldata carries
    /// no EOA); with `None` it is the self-contained `eoa_ct` stored on the Credis position
    /// (used at settlement/void to recover the EOA that keys the pledged ledger).
    /// No state mutation, no authorization.
    RevealOwner,
}

/// Proof that the caller holds the account's modify key, without revealing it.
///
/// `mac = HMAC-SHA256(modify_key, "outbe/gratis/modify/v1" || account || op_tag ||
/// amount || op_nonce || chain_id)`, recomputed inside the enclave (which
/// re-derives `modify_key` from the resident state key + account). `op_nonce` is
/// the account's monotonic on-chain replay counter, so a captured tuple cannot be
/// replayed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModifyAuth {
    pub mac: [u8; 32],
    pub op_nonce: u64,
}

/// Loan terms quoted at pledge time and sealed into the `PledgeLockTicket`, so
/// `requestCredis` sizes the position from the price the pledger accepted instead of
/// re-quoting the oracle a transaction later. Supplied by the host on a `Pledge` and
/// handed back verbatim on the matching `ConsumePledge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PledgeTerms {
    /// Stablecoin minor units the pledge covers - equals `GratisOpRequest::amount` on
    /// a `Pledge` (the enclave cross-checks it, since that is the MAC-bound figure).
    pub stables_amount: U256,
    /// Gratis debited from the pledger's balance, derived host-side from the oracle
    /// rate and capped by the caller's `maxGratis`.
    pub gratis_amount: U256,
    /// The stablecoin the credis is disbursed in.
    pub asset: Address,
    /// COEN/ISO rate (scale 1e6) used for the conversion; pinned as the Credis
    /// position's `entry_price_minor` without changing the field shape.
    pub entry_rate: U256,
}

/// Inputs for a single `ApplyGratisOp`. The host reads the current ciphertext
/// blobs + versions from committed storage and forwards them verbatim; the
/// enclave decrypts, enforces invariants, and re-encrypts deterministically.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GratisOpRequest {
    pub op: GratisOp,
    pub chain_id: B256,
    /// Balance/pledged-owning account (the EOA). For `ConsumePledge`/`ReleaseToEoa`/
    /// `BurnPledged` the EOA never appears in calldata or stored plaintext: the host first
    /// recovers it with a `RevealOwner` round-trip (decrypting the pledge ticket, or the
    /// `eoa_ct` stored on the Credis position) and passes the revealed address here. For
    /// `ConsumePledge` the enclave still cross-checks it against `ticket.owner`. Ignored for
    /// `RevealOwner` itself.
    pub account: Address,
    /// The MAC-bound amount: gratis for Mint/Burn/ReleaseToEoa/BurnPledged, but
    /// STABLECOIN minor units for `Pledge`/`Unpledge` (there the gratis figure travels
    /// in [`Self::pledge_terms`] / the ticket).
    // TODO(privacy): `amount` is a plaintext write input, so per-tx amounts are
    // visible in calldata (only cumulative balances are encrypted). To also hide
    // amounts, carry a client-encrypted amount blob here (like `EncryptedTributeOffer`)
    // and decrypt it inside the enclave - heavier ABI + a client encrypt step.
    pub amount: U256,
    /// Current balance blob (`version(8 BE) || ciphertext`), self-versioning so no
    /// separate version slot is needed. Empty when the account has no state yet.
    pub current_balance: Vec<u8>,
    /// Current pledged-ledger blob (same `version || ct` shape). Empty if none.
    pub current_pledged: Vec<u8>,
    /// Existing pledge-lock-ticket blob (`version || ct`); empty for `Pledge`. Set for
    /// `Unpledge`/`ConsumePledge`.
    pub current_pledge_record: Vec<u8>,
    /// Modify-key authorization (required for Mint/Burn/Pledge/Unpledge; ignored for
    /// the credis-driven `ConsumePledge`/`ReleaseToEoa`/`BurnPledged`).
    pub modify_auth: ModifyAuth,
    /// Pledge handle identifying the ticket (set for `Unpledge`/`ConsumePledge`).
    pub pledge_handle: Option<B256>,
    /// Destination smart account (set for `ConsumePledge`).
    pub smart_account: Option<Address>,
    /// Spend authorization binding the pledge to `smart_account`
    /// (`spend_auth_mac(pledge_secret, smart_account)`), set for `ConsumePledge`.
    pub spend_auth: Option<[u8; 32]>,
    /// The oracle-derived loan terms to seal into the new ticket. Required for
    /// `Pledge`, `None` for every other op.
    #[serde(default)]
    pub pledge_terms: Option<PledgeTerms>,
    /// Optional co-located Fidelity cohort update/probe, applied atomically with
    /// the Gratis op in the SAME enclave round-trip (Mint -> `In`, Burn/BurnPledged
    /// -> `Out`, Pledge -> `Probe` for the eligibility gate). A failing section
    /// rejects the whole op - the host writes neither ledger.
    #[serde(default)]
    pub fidelity: Option<FidelityOpSection>,
}

/// The Fidelity cohort mutation carried inside a Gratis op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FidelityCohortOp {
    /// Acquisition: push a new active cohort of the Gratis op's `amount`.
    In,
    /// Sale: consume active cohorts LIFO (proportional boundary split) for the
    /// Gratis op's `amount`.
    Out,
    /// Read-only league probe (no cohort mutation, no blob rewrite): used by the
    /// pledge eligibility gate to learn the caller's league in the same trip.
    Probe,
}

/// Co-located Fidelity input riding in a [`GratisOpRequest`]. The host reads the
/// account's current cohort blob from committed storage and forwards it
/// verbatim; account + amount are the Gratis op's own fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FidelityOpSection {
    pub op: FidelityCohortOp,
    /// Block timestamp (seconds) - the cohort `acquired_at`/`sold_at` stamp and
    /// the league evaluation time.
    pub timestamp: u64,
    /// Plaintext global `first_qualified_start` scalar (league ceiling anchor);
    /// `0` before any account has qualified.
    pub first_qualified_start: u64,
    /// Current cohort-ledger blob (`version(8 BE) || ciphertext`); empty when the
    /// account has no cohort state yet.
    pub current_blob: Vec<u8>,
}

/// Plaintext receipt of a [`FidelityOpSection`], returned inside the
/// [`GratisOpResult`]. Cohort contents never appear here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FidelityOpOutcome {
    /// New cohort-ledger blob (`version || ct`) to store verbatim; EMPTY for a
    /// `Probe` (nothing to write).
    pub new_blob: Vec<u8>,
    /// `Some(ts)` when this op set the account's `qualified_start` (first
    /// acquisition) - the host updates the global plaintext
    /// `first_qualified_start` if still unset.
    pub qualified_start_initialized: Option<u64>,
    /// The account's league at the section timestamp, evaluated post-op.
    pub league: u16,
}

/// Inputs for a STANDALONE `ApplyFidelityCohortOp` - a cohort mutation applied
/// on its own enclave round-trip (used where there is no co-located Gratis op to
/// fold into, i.e. the fidelity crate's `cohort_in`/`cohort_out` before the
/// Phase-3 round-trip fold). The section carries the op/timestamp/anchor/blob;
/// `account` + `amount` are the mutation's subject. Consensus path (called from
/// precompile-driven factory flows, re-executed by every validator).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FidelityCohortRequest {
    pub chain_id: B256,
    pub account: Address,
    pub amount: U256,
    pub section: FidelityOpSection,
}

/// Public result of an `ApplyFidelityCohortOp`: the plaintext outcome plus the
/// determinism/attestation material. Cohort contents never appear here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FidelityCohortResult {
    pub outcome: FidelityOpOutcome,
    /// Diagnostic hash of the canonical request inputs; the host recomputes it to
    /// detect enclave non-determinism, then discards.
    pub inputs_canonical_hash: B256,
    /// Local-only attestation tag over `(inputs_canonical_hash || result)`; the
    /// host verifies it against the pinned enclave attestation key, then discards.
    pub attestation_tag: Vec<u8>,
}

/// Outcome of a single Gratis op.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GratisOpStatus {
    Applied,
    Rejected { reason: String },
}

/// Public result of an `ApplyGratisOp`: the new ciphertext blobs to store verbatim
/// plus the plaintext receipt the host needs (aggregate deltas, event amount,
/// pledge linkage). Per-account plaintext balances never appear here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GratisOpResult {
    pub status: GratisOpStatus,
    /// New balance blob (`version || ct`) to store verbatim.
    pub new_balance: Vec<u8>,
    /// New pledged-ledger blob (`version || ct`) to store verbatim.
    pub new_pledged: Vec<u8>,
    /// New pledge-lock-ticket blob (`version || ct`) for `Pledge`; empty on
    /// `Unpledge`/`ConsumePledge` (which the host writes back to clear/delete the
    /// ticket slot). Empty and untouched for all other ops.
    pub new_pledge_record: Vec<u8>,
    /// Deterministic pledge handle for a `Pledge` (zero otherwise).
    pub pledge_handle: B256,
    /// Pledged gratis surfaced for credis (`ConsumePledge`); zero otherwise.
    pub gratis_amount: U256,
    /// The loan terms sealed in the consumed ticket (`ConsumePledge`); `None`
    /// otherwise. Lets credis size the position from the pledge-time quote.
    #[serde(default)]
    pub pledge_terms: Option<PledgeTerms>,
    /// Plaintext EOA recovered by a `RevealOwner` op (zero otherwise). Lets the host key the
    /// per-account pledged/balance ledgers without the EOA ever appearing in calldata or state.
    pub revealed_owner: Address,
    /// Self-contained sealed EOA blob (`nonce(12) || ChaCha20Poly1305(owner 20B)` under the
    /// state key) produced by `ConsumePledge` for the host to store on the Credis position;
    /// empty for every other op. Later decrypted via `RevealOwner` (`pledge_handle = None`).
    pub eoa_ct: Vec<u8>,
    /// Amount for the emitted event (mint/burn/pledge/unpledge magnitude).
    pub event_amount: U256,
    /// The account's next modify-auth nonce (for the host to persist).
    pub next_op_nonce: u64,
    /// Receipt of the co-located Fidelity section; `Some` iff the request
    /// carried one and the op was applied.
    #[serde(default)]
    pub fidelity: Option<FidelityOpOutcome>,
    /// Diagnostic hash of the canonical request inputs; the host recomputes it to
    /// detect enclave non-determinism, then discards.
    pub inputs_canonical_hash: B256,
    /// Local-only attestation tag over `(inputs_canonical_hash || result)`; the
    /// host verifies it against the pinned enclave attestation key, then discards.
    pub attestation_tag: Vec<u8>,
}

/// The confidential ledger a key-derivation / op request targets. Selects the
/// enclave key domain (state/view/modify HKDF labels) so Gratis and Promis derive
/// cryptographically independent keys from the same resident group signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Ledger {
    Gratis,
    Promis,
    /// The encrypted per-account cohort ledger (Fidelity). View keys decrypt the
    /// cohort blob client-side; there is no user-held modify capability (cohort
    /// ops are chain-initiated inside Gratis ops).
    Fidelity,
}

/// A Promis write operation the enclave applies over the encrypted per-account
/// balance. Promis is a mint/burn-only confidential ledger (no pledge/credis
/// machinery), so its op set is a strict subset of [`GratisOp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PromisOp {
    /// Mint `amount` to `account` (credit balance; `total_supply += amount`).
    Mint,
    /// Burn `amount` from `account` (debit balance; `total_supply -= amount`).
    Burn,
}

/// Inputs for a single `ApplyPromisOp`. The host reads the current balance
/// ciphertext (`version(8 BE) || ct`, empty for a fresh account) from committed
/// storage and forwards it verbatim; the enclave decrypts, enforces the balance
/// invariant + modify-key authorization, and re-encrypts deterministically.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PromisOpRequest {
    pub op: PromisOp,
    pub chain_id: B256,
    pub account: Address,
    pub amount: U256,
    /// Current balance blob (`version(8 BE) || ciphertext`); empty when the account
    /// has no state yet.
    pub current_balance: Vec<u8>,
    /// Modify-key authorization (required for both Mint and Burn).
    pub modify_auth: ModifyAuth,
}

/// Outcome of a single Promis op.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PromisOpStatus {
    Applied,
    Rejected { reason: String },
}

/// Public result of an `ApplyPromisOp`: the new balance ciphertext to store
/// verbatim plus the plaintext receipt (event amount, next op-nonce). The
/// per-account plaintext balance never appears here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PromisOpResult {
    pub status: PromisOpStatus,
    /// New balance blob (`version || ct`) to store verbatim.
    pub new_balance: Vec<u8>,
    /// Amount for the emitted event (mint/burn magnitude).
    pub event_amount: U256,
    /// The account's next modify-auth nonce (for the host to persist).
    pub next_op_nonce: u64,
    /// Diagnostic hash of the canonical request inputs; the host recomputes it to
    /// detect enclave non-determinism, then discards.
    pub inputs_canonical_hash: B256,
    /// Local-only attestation tag over `(inputs_canonical_hash || result)`; the host
    /// verifies it against the pinned enclave attestation key, then discards.
    pub attestation_tag: Vec<u8>,
}

/// One owner's encrypted cohort blob in a [`FidelitySnapshotRequest`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FidelitySnapshotEntry {
    pub owner: Address,
    /// Current cohort-ledger blob (`version(8 BE) || ct`); empty for no state.
    pub cohort_blob: Vec<u8>,
}

/// Inputs for a `SnapshotFidelityLeagues` batch: metadosis's once-per-WWD league
/// snapshot over the day's tribute owners. The host reads each owner's cohort
/// blob from committed storage and forwards it verbatim; the enclave decrypts and
/// returns one plaintext league word per owner. Consensus path (called from the
/// OCOMP prepare step in begin-block, re-executed by every validator).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FidelitySnapshotRequest {
    /// League evaluation time (the WWD's intent-bound snapshot timestamp).
    pub timestamp: u64,
    /// Plaintext global `first_qualified_start` scalar; `0` if unset.
    pub first_qualified_start: u64,
    pub entries: Vec<FidelitySnapshotEntry>,
}

/// One owner's plaintext league in a snapshot result, in request order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FidelityLeagueEntry {
    pub owner: Address,
    pub league: u16,
}

/// Inputs for a `QueryFidelityIndex`: an owner-authorized read of one account's
/// RCFI/league over its encrypted cohorts. NOT a consensus path - served via
/// `eth_call`. `owner_sig` is the 65-byte EIP-191 `personal_sign` signature by
/// `account` over [`fidelity_query_auth_message`]; the enclave recovers it and
/// rejects unless the signer equals `account`, the message chain id equals the
/// enclave's resident chain id, and `expiry >= block_timestamp`.
///
/// Scope of the guarantees: the signature is never key material and can never
/// be forged. Chain binding IS enforced - the enclave hashes the message under
/// its own resident chain id and rejects a mismatched `chain_id`, so a signature
/// captured on another chain (same reused EOA) cannot authorize a read here.
/// The `expiry` bound is only advisory against a COMPROMISED host: the enclave
/// has no trusted clock on the `eth_call` path and checks `expiry` against the
/// host-supplied `block_timestamp`, so a malicious host can pass
/// `block_timestamp = 0` and reuse a stale genuine signature. The worst case is
/// re-reading the derived index/league the owner already chose to expose by
/// signing - never the raw cohort ledger.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FidelityQueryRequest {
    /// The chain the authorization is for; the enclave rejects unless it equals
    /// its own resident chain id (it does NOT trust this value for key
    /// derivation - that uses the resident id).
    pub chain_id: B256,
    pub account: Address,
    /// Current cohort-ledger blob (`version(8 BE) || ct`); empty for no state.
    pub cohort_blob: Vec<u8>,
    /// Timestamp to evaluate RCFI/league at (any time - the curve is pure).
    pub query_timestamp: u64,
    /// Current block timestamp, for the `expiry` freshness check (advisory
    /// against a compromised host - see the type doc).
    pub block_timestamp: u64,
    /// Plaintext global `first_qualified_start` scalar; `0` if unset.
    pub first_qualified_start: u64,
    /// Authorization deadline (seconds); the signature is valid until then.
    pub expiry: u64,
    /// 65-byte `r||s||v` signature (Vec because serde does not derive for
    /// `[u8; 65]`; the enclave validates the length).
    pub owner_sig: Vec<u8>,
}

/// Plaintext result of a `QueryFidelityIndex` (10^18-scaled fixed point, same
/// as the historical `IFidelity` values).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FidelityQueryResult {
    pub rcfi: U256,
    pub efficiency: U256,
    pub league: u16,
    /// Diagnostic hash of the canonical request inputs; the host recomputes it to
    /// detect enclave non-determinism, then discards.
    pub inputs_canonical_hash: B256,
    /// Local-only attestation tag over `(inputs_canonical_hash || result)`; the host
    /// verifies it against the pinned enclave attestation key, then discards.
    pub attestation_tag: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EnclaveRequest {
    /// Development-only pre-handshake quote. The production server
    /// rejects this variant and never routes it after initialization.
    GetQuote { nonce: [u8; 32] },
    /// Production pre-handshake discovery for an uninitialized enclave. Returns
    /// one challenge plus the persistent enclave public keys to be signed by the
    /// node identity. Rejected once initialization is committed.
    GetInitializationChallenge,
    /// Production pre-handshake initialization authorization. `manifest` is the
    /// canonical `EnclaveInitializationManifestV1`; `node_signature` is a
    /// recoverable secp256k1 signature (`r || s || v`). The following Noise IK
    /// message 1 must authenticate the exact NodeHost key in the manifest.
    Initialize {
        manifest: Vec<u8>,
        node_signature: Vec<u8>,
    },
    /// Production pre-handshake marker for an already initialized enclave. The
    /// responder returns nothing until the following Noise IK message 1 proves
    /// possession of the sealed NodeHost static key.
    OpenSession,
    /// Production pre-handshake marker for one previously authorized remote
    /// source NodeHost. The ticket is consumed before Noise message 1, which
    /// must prove the exact initiator static stored under this id.
    OpenRemoteSessionV1 { ticket_id: B256 },
    /// Noise-IK handshake message.
    SessionHandshake { noise_msg: Vec<u8> },
    /// Return the enclave's public keys (recipient X25519, attestation, Noise
    /// static, tribute-BLS).
    GetPublicKeys,
    /// Local-owner command that installs one bounded, one-use remote Noise
    /// admission previously derived from exact finalized Registry state.
    AuthorizeRemoteSessionV1 {
        ticket_id: B256,
        initiator_static_x25519: [u8; 32],
        responder_static_x25519: [u8; 32],
        deadline: u64,
        finalized_block_hash: B256,
    },
    /// Generate a fresh DCAP quote for the exact canonical registration,
    /// renewal or transition intent. Production accepts this only inside an
    /// authenticated NodeHost session and only when the intent matches the
    /// sealed identity. A transition additionally returns a purpose-bound
    /// proof that this enclave has the permanent offer key resident.
    GenerateDcapQuote { intent: Vec<u8> },
    /// Sign one exact GramineDirectDev registration intent inside the enclave.
    /// This command is accepted by the development transport, or by an
    /// authenticated production NodeHost session when the enclave itself
    /// detects SGX with remote attestation disabled. It never returns an SGX
    /// quote or hardware-attestation claim.
    SignRegistrationIntentDevV1 { intent: Vec<u8> },

    /// Start one bounded, request-committed DCAP verification upload. Evidence
    /// and policy bytes follow in strictly sequential chunks on this same
    /// authenticated Noise session.
    BeginDcapVerificationV1 {
        request_hash: B256,
        evidence_len: u32,
        policy_len: u32,
        block_timestamp: u64,
    },
    /// Start the dedicated `RegisterEnclave` verify-and-seal flow. Unlike the
    /// generic verifier, this request commits both authorization signatures and
    /// exact Registry offer-key epochs before any evidence bytes are accepted.
    BeginDcapOnboardingVerificationV1 {
        request_hash: B256,
        evidence_len: u32,
        policy_len: u32,
        block_timestamp: u64,
        node_signature: Vec<u8>,
        enclave_signature: Vec<u8>,
        expected_tribute_offer_public: [u8; 32],
        key_epoch: u64,
        tribute_offer_epoch: u64,
    },
    /// Append the next exact byte range to the active verification upload.
    DcapVerificationChunkV1 {
        request_hash: B256,
        offset: u32,
        bytes: Vec<u8>,
    },
    /// Finish the exact upload and run the full enclave-resident verifier.
    FinishDcapVerificationV1 { request_hash: B256 },

    /// Open a TEE DKG ceremony session inside the enclave. Each `participants[i]`
    /// bundles a BLS identity, its announced X25519 share-encryption key, and the
    /// owner's signature binding the two - so the untrusted host cannot mis-pair or
    /// duplicate enc keys. The enclave verifies every binding, rejects duplicate
    /// enc keys, then builds the ceremony `Info` from the BLS set and captures the
    /// enc keys so dealings can be sealed to recipients. The host only relays values
    /// it obtained from each participant's `PublicKeys`.
    DkgOpen {
        ceremony_id: B256,
        round: u64,
        participants: Vec<ParticipantAnnounce>,
    },
    /// Seam A: deal + seal per-player shares. Returns the public commitment and
    /// one opaque sealed share per participant.
    DkgStartDealer { ceremony_id: B256 },
    /// Seam B: open + verify an incoming sealed dealing inside the enclave. The
    /// host relays the opaque `sealed_share` without decrypting it.
    DkgPlayerIngest {
        ceremony_id: B256,
        dealer_bls: Vec<u8>,
        pub_msg: Vec<u8>,
        sealed_share: Vec<u8>,
    },
    /// Seam C: record a player's acknowledgement at this enclave's dealer.
    DkgDealerReceiveAck {
        ceremony_id: B256,
        player_bls: Vec<u8>,
        ack: Vec<u8>,
    },
    /// Seam D: finalize this enclave's dealing into a signed dealer log.
    DkgDealerFinalize { ceremony_id: B256 },
    /// Seam E: verify the collected signed dealer logs and recover this enclave's
    /// local threshold share (committed inside the enclave). Returns the public
    /// group key and the share commitment.
    DkgPlayerFinalize {
        ceremony_id: B256,
        signed_logs: Vec<Vec<u8>>,
    },
    /// Seam F (offer key): threshold-sign the fixed offer message with this
    /// enclave's recovered share, then **seal the partial to every recipient
    /// enclave's X25519 key** (one ciphertext per participant). The host relays
    /// only the opaque ciphertexts - it never sees a plaintext partial, so it
    /// cannot recover the group signature (and hence the offer key) itself.
    /// Requires `DkgPlayerFinalize` first.
    DkgTributeOfferPartial { ceremony_id: B256 },
    /// Founding Seam F: finalize the initial group threshold signature from the
    /// sealed partials addressed to THIS enclave (decrypted in-SGX) and install
    /// the one permanent offer X25519 keypair. The capability matrix permits
    /// this request only to a keyless Validator; it is not a lost-key recovery
    /// or post-genesis replacement surface. Releases the ceremony session.
    DkgFinalizeTributeOffer {
        ceremony_id: B256,
        /// Sealed partials addressed to this enclave (one `EncryptedShare` blob per
        /// signer); decrypted with the enclave's X25519 share-decryption secret.
        sealed_partials: Vec<Vec<u8>>,
        chain_id: B256,
        tribute_offer_epoch: u64,
    },

    /// Decrypt a batch of offers, apply each one's node-resolved price, and
    /// return the canonical Tribute results. Each `EncryptedTributeOffer` is
    /// self-contained (its own owner, day, currencies and price), so the batch is
    /// simply a list. A single transaction carries one offer today; the list
    /// future-proofs multi-offer txs. This is the sole offer-processing
    /// entrypoint (the enclave decrypts, applies the price, computes economics +
    /// Poseidon `token_id`, and returns `TributeOfferResult`).
    ProcessTributeOfferBatch { offers: Vec<EncryptedTributeOffer> },

    /// Start one streaming finalized-admission verification rooted in the
    /// measured genesis committee. The enclave retains only the current
    /// committee; transition records follow on this authenticated session.
    BeginDcapOnboardingArtifactIngestV1 {
        request_hash: B256,
        artifact: Vec<u8>,
        anchor_outcome: Vec<u8>,
        expected_intent_hash: B256,
        expected_tribute_offer_public: [u8; 32],
        expected_key_epoch: u64,
        expected_tribute_offer_epoch: u64,
    },
    /// Append bytes to the current transition or admission record.
    DcapOnboardingArtifactChunkV1 {
        request_hash: B256,
        kind: crate::finalized_admission::FinalizedAdmissionRecordKindV1,
        offset: u32,
        bytes: Vec<u8>,
    },
    /// Verify the current complete record. Transition records advance and prune
    /// the committee cursor; the admission record authenticates Registry state.
    CommitDcapOnboardingArtifactRecordV1 {
        request_hash: B256,
        kind: crate::finalized_admission::FinalizedAdmissionRecordKindV1,
    },
    /// After a verified admission record, decrypt,
    /// durably seal, and only finally activate the resident offer key.
    FinishDcapOnboardingArtifactIngestV1 { request_hash: B256 },

    /// Apply a Gratis write op over encrypted per-account state. The enclave
    /// derives the resident `gratis_state_key` from the same group signature as
    /// the offer key, decrypts the supplied blobs, enforces balance invariants +
    /// modify-key authorization, and re-encrypts deterministically. This is a
    /// consensus path (called inside precompile `dispatch`, re-executed by every
    /// validator).
    ApplyGratisOp { request: Box<GratisOpRequest> },

    /// Like [`EnclaveRequest::ApplyGratisOp`] but for the confidential Promis
    /// ledger (mint/burn over an encrypted balance). Consensus path, re-executed
    /// by every validator.
    ApplyPromisOp { request: Box<PromisOpRequest> },

    /// Off-chain key delivery: derive `account`'s view + modify keys for `ledger`
    /// from the matching resident state key and seal them to the requester's
    /// ephemeral X25519 key. NOT a consensus path - served only over RPC, never
    /// during block execution.
    ///
    /// `owner_sig` is the 65-byte (`r||s||v`) EIP-191 `personal_sign` signature by
    /// `account` over `derive_account_keys_message(ledger, account,
    /// requester_ephemeral_pubkey)`. The enclave recovers it and rejects unless the
    /// signer equals `account`, so the keys are released only to the account owner -
    /// the trust boundary is the enclave, not the (untrusted) host RPC that also
    /// checks it as a fast reject. Carried as `Vec<u8>` because serde does not derive
    /// for `[u8; 65]`; the enclave validates the length.
    DeriveAccountKeys {
        ledger: Ledger,
        account: Address,
        requester_ephemeral_pubkey: [u8; 32],
        owner_sig: Vec<u8>,
    },

    /// Apply a standalone Fidelity cohort mutation (`In`/`Out`) over encrypted
    /// per-account state, on its own round-trip. Consensus path, re-executed by
    /// every validator. See [`FidelityCohortRequest`].
    ApplyFidelityCohortOp { request: Box<FidelityCohortRequest> },

    /// Batch-decrypt cohort blobs and return one plaintext league per owner -
    /// metadosis's once-per-WWD Fidelity snapshot. Consensus path (OCOMP prepare
    /// step in begin-block, re-executed by every validator).
    SnapshotFidelityLeagues {
        request: Box<FidelitySnapshotRequest>,
    },

    /// Owner-authorized read of one account's RCFI/league over its encrypted
    /// cohorts (signed, expiring authorization - see [`FidelityQueryRequest`]).
    /// NOT a consensus path - served via `eth_call`.
    QueryFidelityIndex { request: Box<FidelityQueryRequest> },

    /// Read-only health/telemetry probe: uptime, request counters, offer-key
    /// readiness and self-observed heap usage. Never touches keys or sealed
    /// state. NOT a consensus path - served to the local NodeHost only.
    ///
    /// WIRE-COMPAT LAW: the codec encodes enums by variant declaration index
    /// (postcard), so new variants are appended ONLY at the tail of
    /// `EnclaveRequest` / `EnclaveResponse` and fields of existing wire structs
    /// are never added, removed or reordered. Deployment order for a new
    /// variant: enclave binary first, node second.
    Health,
    /// Ask this initialized enclave to produce its exact ceremony-scoped DKG
    /// participant announcement. `participant_bls` is canonicalized and bound
    /// into both the ceremony id and signature inside the enclave.
    DkgParticipantAnnounceV1 {
        ceremony_id: B256,
        round: u64,
        participant_bls: Vec<Vec<u8>>,
    },
    /// Produce a deterministic offer-key onboarding artifact for one exact
    /// GramineDirectDev registration. This is available only to an initialized
    /// local NodeHost whose sealed network binding selected GramineDirectDev and
    /// whose permanent offer key is already resident. The recipient still must
    /// prove finalized TeeRegistry admission before it can install the key.
    PrepareGramineDirectDevOnboardingArtifactV1 {
        request_hash: B256,
        context: Vec<u8>,
    },
    /// Install an exact finalized DirectDev onboarding artifact into this
    /// initialized keyless enclave. The CLI exposes this only after the exact
    /// registration transaction and TeeRegistry binding are finalized.
    IngestGramineDirectDevOnboardingArtifactV1 {
        artifact: Vec<u8>,
        expected_intent_hash: B256,
        expected_tribute_offer_public: [u8; 32],
        expected_key_epoch: u64,
        expected_tribute_offer_epoch: u64,
    },
}

impl EnclaveRequest {
    /// Stable snake_case label for this request, used as a metric/log key on
    /// both the node client and the enclave server. Never wire data.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::GetQuote { .. } => "get_quote",
            Self::GetInitializationChallenge => "get_initialization_challenge",
            Self::Initialize { .. } => "initialize",
            Self::OpenSession => "open_session",
            Self::OpenRemoteSessionV1 { .. } => "open_remote_session_v1",
            Self::SessionHandshake { .. } => "session_handshake",
            Self::GetPublicKeys => "get_public_keys",
            Self::AuthorizeRemoteSessionV1 { .. } => "authorize_remote_session_v1",
            Self::GenerateDcapQuote { .. } => "generate_dcap_quote",
            Self::SignRegistrationIntentDevV1 { .. } => "sign_registration_intent_dev_v1",
            Self::BeginDcapVerificationV1 { .. } => "begin_dcap_verification_v1",
            Self::BeginDcapOnboardingVerificationV1 { .. } => {
                "begin_dcap_onboarding_verification_v1"
            }
            Self::DcapVerificationChunkV1 { .. } => "dcap_verification_chunk_v1",
            Self::FinishDcapVerificationV1 { .. } => "finish_dcap_verification_v1",
            Self::DkgOpen { .. } => "dkg_open",
            Self::DkgParticipantAnnounceV1 { .. } => "dkg_participant_announce_v1",
            Self::DkgStartDealer { .. } => "dkg_start_dealer",
            Self::DkgPlayerIngest { .. } => "dkg_player_ingest",
            Self::DkgDealerReceiveAck { .. } => "dkg_dealer_receive_ack",
            Self::DkgDealerFinalize { .. } => "dkg_dealer_finalize",
            Self::DkgPlayerFinalize { .. } => "dkg_player_finalize",
            Self::DkgTributeOfferPartial { .. } => "dkg_tribute_offer_partial",
            Self::DkgFinalizeTributeOffer { .. } => "dkg_finalize_tribute_offer",
            Self::ProcessTributeOfferBatch { .. } => "process_tribute_offer_batch",
            Self::BeginDcapOnboardingArtifactIngestV1 { .. } => {
                "begin_dcap_onboarding_artifact_ingest_v1"
            }
            Self::DcapOnboardingArtifactChunkV1 { .. } => "dcap_onboarding_artifact_chunk_v1",
            Self::CommitDcapOnboardingArtifactRecordV1 { .. } => {
                "commit_dcap_onboarding_artifact_record_v1"
            }
            Self::FinishDcapOnboardingArtifactIngestV1 { .. } => {
                "finish_dcap_onboarding_artifact_ingest_v1"
            }
            Self::ApplyGratisOp { .. } => "apply_gratis_op",
            Self::ApplyPromisOp { .. } => "apply_promis_op",
            Self::DeriveAccountKeys { .. } => "derive_account_keys",
            Self::ApplyFidelityCohortOp { .. } => "apply_fidelity_cohort_op",
            Self::SnapshotFidelityLeagues { .. } => "snapshot_fidelity_leagues",
            Self::QueryFidelityIndex { .. } => "query_fidelity_index",
            Self::Health => "health",
            Self::PrepareGramineDirectDevOnboardingArtifactV1 { .. } => {
                "prepare_gramine_direct_dev_onboarding_artifact_v1"
            }
            Self::IngestGramineDirectDevOnboardingArtifactV1 { .. } => {
                "ingest_gramine_direct_dev_onboarding_artifact_v1"
            }
        }
    }

    /// True when re-sending this request after a lost response cannot
    /// double-apply enclave state: the request is pure or deterministic, so the
    /// reconnect-and-retry path may re-send it once. State-mutating requests
    /// (initialization, DKG seams, artifact ingestion, session admission and
    /// the multi-frame DCAP upload) must never be re-sent implicitly - the
    /// exhaustive match forces every future variant to make this choice.
    pub const fn is_idempotent(&self) -> bool {
        match self {
            Self::GetQuote { .. }
            | Self::GetPublicKeys
            | Self::GenerateDcapQuote { .. }
            | Self::SignRegistrationIntentDevV1 { .. }
            | Self::ProcessTributeOfferBatch { .. }
            | Self::ApplyGratisOp { .. }
            | Self::ApplyPromisOp { .. }
            | Self::DeriveAccountKeys { .. }
            | Self::ApplyFidelityCohortOp { .. }
            | Self::SnapshotFidelityLeagues { .. }
            | Self::QueryFidelityIndex { .. }
            | Self::Health
            | Self::PrepareGramineDirectDevOnboardingArtifactV1 { .. } => true,
            Self::GetInitializationChallenge
            | Self::Initialize { .. }
            | Self::OpenSession
            | Self::OpenRemoteSessionV1 { .. }
            | Self::SessionHandshake { .. }
            | Self::AuthorizeRemoteSessionV1 { .. }
            | Self::BeginDcapVerificationV1 { .. }
            | Self::BeginDcapOnboardingVerificationV1 { .. }
            | Self::DcapVerificationChunkV1 { .. }
            | Self::FinishDcapVerificationV1 { .. }
            | Self::DkgParticipantAnnounceV1 { .. }
            | Self::DkgOpen { .. }
            | Self::DkgStartDealer { .. }
            | Self::DkgPlayerIngest { .. }
            | Self::DkgDealerReceiveAck { .. }
            | Self::DkgDealerFinalize { .. }
            | Self::DkgPlayerFinalize { .. }
            | Self::DkgTributeOfferPartial { .. }
            | Self::DkgFinalizeTributeOffer { .. }
            | Self::BeginDcapOnboardingArtifactIngestV1 { .. }
            | Self::DcapOnboardingArtifactChunkV1 { .. }
            | Self::CommitDcapOnboardingArtifactRecordV1 { .. }
            | Self::FinishDcapOnboardingArtifactIngestV1 { .. }
            | Self::IngestGramineDirectDevOnboardingArtifactV1 { .. } => false,
        }
    }
}

/// Self-observed enclave health snapshot returned by [`EnclaveRequest::Health`].
///
/// Heap fields come from the enclave binary's counting global allocator and are
/// a proxy for EPC pressure (they exclude thread stacks, allocator overhead and
/// direct mmaps); `0` means allocator accounting is not installed. Per-class
/// counters are fixed fields, not maps, so the wire shape stays stable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnclaveHealthStatusV1 {
    pub uptime_s: u64,
    pub offer_key_ready: bool,
    pub heap_current_bytes: u64,
    pub heap_peak_bytes: u64,
    pub requests_total: u64,
    pub requests_errored: u64,
    pub requests_denied: u64,
    pub class_initialized: u64,
    pub class_founding_keyless: u64,
    pub class_keyless_onboarding: u64,
    pub class_ready: u64,
    pub class_dev_source_seal: u64,
    pub class_dev_recipient_ingest: u64,
}

/// Domain-tagged message an account owner personal-signs to authorize Fidelity
/// index queries until `expiry`:
/// `"outbe/fidelity/query-auth/v1" || chain_id(32) || account(20) || expiry_be(8)`.
///
/// SHARED by the host precompile (fast reject) and the enclave (the trust
/// boundary) so the two hash an identical preimage. Deliberately scoped: a
/// leaked signature authorizes index reads until `expiry` - it is never key
/// material and cannot decrypt state.
pub fn fidelity_query_auth_message(chain_id: B256, account: Address, expiry: u64) -> Vec<u8> {
    let tag: &[u8] = b"outbe/fidelity/query-auth/v1";
    let mut m = Vec::with_capacity(tag.len() + 32 + 20 + 8);
    m.extend_from_slice(tag);
    m.extend_from_slice(chain_id.as_slice());
    m.extend_from_slice(account.as_slice());
    m.extend_from_slice(&expiry.to_be_bytes());
    m
}

/// Deterministic hash over the canonical batch inputs - every field of every
/// offer. Length-prefixed to be unambiguous.
///
/// Every field of `ProcessTributeOfferBatch` must be covered here: an input the
/// hash skips is silently unattested, since the host's recompute and the
/// enclave's would agree on ignoring it.
///
/// SHARED by the enclave (which returns it in `TributeOfferBatch`) and the host (which
/// recomputes it from the request it sent and compares - a mismatch is enclave
/// non-determinism). Defining it once here keeps the two byte layouts from
/// drifting. Diagnostic only - never written to chain state.
pub fn inputs_canonical_hash(offers: &[EncryptedTributeOffer]) -> B256 {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(offers.len() as u32).to_be_bytes());
    for offer in offers {
        buf.extend_from_slice(offer.owner.as_slice());
        buf.extend_from_slice(&(offer.cipher_text.len() as u32).to_be_bytes());
        buf.extend_from_slice(&offer.cipher_text);
        buf.extend_from_slice(&(offer.nonce.len() as u32).to_be_bytes());
        buf.extend_from_slice(&offer.nonce);
        buf.extend_from_slice(&offer.ephemeral_pubkey.to_be_bytes::<32>());
        buf.extend_from_slice(&offer.worldwide_day.value().to_be_bytes());
        buf.extend_from_slice(&offer.tribute_currency.to_be_bytes());
        buf.extend_from_slice(&offer.reference_currency.to_be_bytes());
        buf.push(u8::from(offer.exclude_from_intex_issuance));
        buf.extend_from_slice(&offer.issuance_wwd_vwap_minor.to_be_bytes::<32>());
        buf.extend_from_slice(&offer.reference_wwd_vwap_minor.to_be_bytes::<32>());
        buf.extend_from_slice(&offer.reference_scurve_minor.to_be_bytes::<32>());
        match &offer.zk_context {
            Some(context) => {
                buf.push(1);
                buf.extend_from_slice(context.derived_owner.as_slice());
                buf.extend_from_slice(&context.chain_id.to_be_bytes());
            }
            None => buf.push(0),
        }
    }
    alloy_primitives::keccak256(buf)
}

/// Domain-tagged message a caller personal-signs to prove control of `account`
/// before `DeriveAccountKeys` reveals its keys, bound to the target `ledger`:
/// `"outbe/<ledger>/derive-keys/v1" || account(20) || ephemeralPubkey(32)`.
///
/// SHARED by the host RPC (fast reject) and the enclave (the trust boundary) so
/// the two hash an identical preimage - a divergence would let one accept a
/// signature the other rejects. The Gratis tag byte-matches the historical
/// [`derive_gratis_keys_message`], so existing Gratis clients are unaffected.
pub fn derive_account_keys_message(
    ledger: Ledger,
    account: Address,
    ephemeral_pubkey: B256,
) -> Vec<u8> {
    let tag: &[u8] = match ledger {
        Ledger::Gratis => b"outbe/gratis/derive-keys/v1",
        Ledger::Promis => b"outbe/promis/derive-keys/v1",
        Ledger::Fidelity => b"outbe/fidelity/derive-keys/v1",
    };
    let mut m = Vec::with_capacity(tag.len() + 20 + 32);
    m.extend_from_slice(tag);
    m.extend_from_slice(account.as_slice());
    m.extend_from_slice(ephemeral_pubkey.as_slice());
    m
}

/// Backward-compatible alias for the Gratis key-derivation message
/// (`derive_account_keys_message(Ledger::Gratis, ...)`).
pub fn derive_gratis_keys_message(account: Address, ephemeral_pubkey: B256) -> Vec<u8> {
    derive_account_keys_message(Ledger::Gratis, account, ephemeral_pubkey)
}

/// EIP-191 `personal_sign` digest of `message` - matches ethers `signMessage`.
pub fn eip191_hash(message: &[u8]) -> B256 {
    let mut buf = Vec::with_capacity(message.len() + 40);
    buf.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    buf.extend_from_slice(message.len().to_string().as_bytes());
    buf.extend_from_slice(message);
    alloy_primitives::keccak256(buf)
}

/// Domain-separated preimage the enclave signs (with its Ed25519 attestation key)
/// and the host verifies - it binds the canonical inputs hash to the produced
/// results, so the host can prove the results were computed inside the attested
/// enclave (not substituted by the host). SHARED so the two byte layouts cannot
/// drift: `serde_json` of a fixed-field struct list is deterministic (struct
/// field order is declaration order; there are no maps or floats). Local-only -
/// never written to chain state.
pub fn tribute_offer_attestation_preimage(
    inputs_canonical_hash: B256,
    results: &[TributeOfferResult],
) -> Vec<u8> {
    let results_json = serde_json::to_vec(results).unwrap_or_default();
    let mut buf = Vec::with_capacity(30 + 32 + 4 + results_json.len());
    buf.extend_from_slice(b"outbe/tee/offer-attestation/v1");
    buf.extend_from_slice(inputs_canonical_hash.as_slice());
    buf.extend_from_slice(&(results_json.len() as u32).to_be_bytes());
    buf.extend_from_slice(&results_json);
    buf
}

/// Responses returned from the enclave to the node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EnclaveResponse {
    /// SGX quote bundle. Carries the enclave public keys in cleartext plus the
    /// `report_data` that binds them: the host recomputes
    /// `keccak256(noise_static_pub || recipient_x25519_pub || attestation_pub)`
    /// and checks it equals `report_data`, proving the cleartext keys are the
    /// attested ones. `noise_static_pub` is then used as the Noise-IK remote
    /// static key. Callable before the handshake (unauthenticated).
    Quote {
        mrenclave: B256,
        mrsigner: B256,
        isv_svn: u16,
        report_data: B256,
        recipient_x25519_pub: [u8; 32],
        attestation_pub: [u8; 32],
        noise_static_pub: [u8; 32],
        quote_body: Vec<u8>,
        /// Human-readable attestation environment the enclave detected (e.g.
        /// `dcap (gramine-sgx)` or `none (gramine-direct / no SGX)`), so the host
        /// can log the exact mode instead of guessing direct-vs-bare.
        attestation: String,
    },
    /// Public first-boot material. This is not attestation and carries no
    /// authority; the node identity must sign all fields in the canonical
    /// initialization manifest before the enclave accepts a Noise initiator.
    InitializationChallenge {
        challenge: [u8; 32],
        recipient_x25519_pub: [u8; 32],
        attestation_pub: [u8; 32],
        noise_static_pub: [u8; 32],
    },
    /// Intent-bound real quote generated only for an authenticated NodeHost.
    /// The canonical intent is echoed byte-for-byte so callers cannot associate
    /// the returned quote with another request.
    DcapQuote {
        intent: Vec<u8>,
        quote_body: Vec<u8>,
        /// Ed25519 proof of possession by the persistent quote-bound
        /// attestation key over `RegistrationIntentV1::intent_hash()`.
        enclave_signature: Vec<u8>,
        /// Canonical `TransitionKeyReadyProofV1` for a transition intent;
        /// empty for every other operation.
        transition_key_ready_proof: Vec<u8>,
    },
    /// Development-only proof of possession over the exact canonical intent.
    /// The echoed bytes prevent a host from associating the signature with a
    /// different registration.
    RegistrationIntentSignedDevV1 {
        intent: Vec<u8>,
        enclave_signature: Vec<u8>,
    },
    DcapVerificationStartedV1 {
        request_hash: B256,
    },
    DcapVerificationChunkAcceptedV1 {
        request_hash: B256,
        next_offset: u32,
    },
    DcapOnboardingArtifactIngestStartedV1 {
        request_hash: B256,
    },
    DcapOnboardingArtifactChunkAcceptedV1 {
        request_hash: B256,
        next_offset: u32,
    },
    DcapOnboardingArtifactRecordAcceptedV1 {
        request_hash: B256,
        kind: crate::finalized_admission::FinalizedAdmissionRecordKindV1,
    },
    /// Canonical accepted verdict or stable reject code, authenticated by the
    /// persistent quote-bound Ed25519 key over the exact request commitment.
    DcapVerificationFinishedV1 {
        request_hash: B256,
        outcome: Vec<u8>,
        attestation_tag: Vec<u8>,
    },
    /// Purpose-bound onboarding verdict plus its deterministic Registry
    /// artifact. Rejected verdicts carry an empty artifact.
    DcapOnboardingVerificationFinishedV1 {
        request_hash: B256,
        outcome: Vec<u8>,
        onboarding_artifact: Vec<u8>,
        attestation_tag: Vec<u8>,
    },
    Handshake {
        noise_msg: Vec<u8>,
    },
    PublicKeys {
        /// True only after the permanent tribute-offer key has been installed.
        /// Before that point `recipient_x25519_pub` is the one-time onboarding
        /// recipient key and must never be treated as permanent chain state.
        offer_key_ready: bool,
        recipient_x25519_pub: [u8; 32],
        attestation_pub: [u8; 32],
        noise_static_pub: [u8; 32],
        /// TEE threshold-BLS public key (the enclave's DKG participant identity).
        tee_bls_pub: Vec<u8>,
        /// X25519 share-encryption public key; dealers seal DKG shares to it.
        dkg_enc_pub: [u8; 32],
        /// TEE-BLS signature over the `(chain_id, dkg_enc_pub)` binding, proving
        /// this enc key belongs to `tee_bls_pub`. Relayed by the host into peers'
        /// `DkgOpen` and verified there before the enc key is trusted.
        dkg_enc_sig: Vec<u8>,
    },
    Initialized {
        enclave_id: B256,
        node_host_authorization_hash: B256,
        sealed_loaded: bool,
    },
    RemoteSessionAuthorizedV1 {
        ticket_id: B256,
    },
    /// Generic acknowledgement (e.g. `DkgOpen` / `DkgDealerReceiveAck`).
    Ack,
    /// Seam A result: public commitment + one opaque sealed share per recipient
    /// `(recipient_bls, sealed_share)`.
    DkgDealt {
        pub_msg: Vec<u8>,
        sealed_shares: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Seam B result: the player's acknowledgement bytes, or `None` if the dealing
    /// did not verify.
    DkgPlayerAck {
        ack: Option<Vec<u8>>,
    },
    /// Seam D result: this enclave's signed dealer log.
    DkgSignedLog {
        signed_log: Vec<u8>,
    },
    /// Seam E result: the public group key and this enclave's share commitment.
    DkgPlayerFinalized {
        group_public: Vec<u8>,
        share_commitment: B256,
    },
    /// Seam F result: this enclave's partial signature over the offer message,
    /// **sealed to each recipient enclave** - one opaque ciphertext per
    /// participant `(recipient_bls, sealed_partial)`. The host relays the
    /// ciphertexts but cannot decrypt them, so it cannot recover the group
    /// signature / offer key.
    DkgTributeOfferPartial {
        sealed: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Seam F result: the shared offer public key derived from the recovered
    /// group signature (the secret stays resident in the enclave).
    DkgTributeOfferKey {
        tribute_offer_public: [u8; 32],
        /// The committee's DKG group public key (constant term), carried into the
        /// founding bootstrap payload with the derived tribute offer key.
        group_public_key: Vec<u8>,
    },
    /// One-time onboarding result: the installed offer public key matched the
    /// on-chain commitment.
    FinalizedAdmissionIngestedV1 {
        request_hash: B256,
        tribute_offer_public: [u8; 32],
    },
    TributeOfferBatch {
        results: Vec<TributeOfferResult>,
        /// Diagnostic hash of canonical inputs (incl. price/day/currency);
        /// host compares it to detect enclave non-determinism, then discards.
        inputs_canonical_hash: B256,
        /// Local-only attestation tag; host verifies against its enclave's
        /// attestation key, then discards. Never written to state.
        attestation_tag: Vec<u8>,
    },
    /// Result of an `ApplyGratisOp`: new ciphertexts + plaintext receipt.
    GratisOpApplied {
        result: Box<GratisOpResult>,
    },
    /// Result of an `ApplyPromisOp`: new balance ciphertext + plaintext receipt.
    PromisOpApplied {
        result: Box<PromisOpResult>,
    },
    /// Result of an `ApplyFidelityCohortOp`: the plaintext cohort outcome.
    FidelityCohortApplied {
        result: Box<FidelityCohortResult>,
    },
    /// Result of a `SnapshotFidelityLeagues`: one plaintext league per owner, in
    /// request order.
    FidelityLeaguesSnapshotted {
        leagues: Vec<FidelityLeagueEntry>,
        /// Diagnostic hash of canonical inputs; host compares to detect enclave
        /// non-determinism, then discards.
        inputs_canonical_hash: B256,
        /// Local-only attestation tag; host verifies, then discards.
        attestation_tag: Vec<u8>,
    },
    /// Result of a `QueryFidelityIndex`.
    FidelityIndexQueried {
        result: Box<FidelityQueryResult>,
    },
    /// Result of `DeriveAccountKeys`: `AEAD(ECDHE(enclave, requester_ephemeral),
    /// view_key || modify_key)` sealed to the requester. Opaque to the host.
    AccountKeysSealed {
        account: Address,
        sealed: Vec<u8>,
        nonce: [u8; 12],
        enclave_ephemeral_pubkey: [u8; 32],
    },
    Error {
        message: String,
    },
    /// Result of [`EnclaveRequest::Health`]. Appended at the tail per the
    /// wire-compat law on [`EnclaveRequest`].
    HealthStatus {
        status: Box<EnclaveHealthStatusV1>,
    },
    /// Ceremony-scoped DKG participant identity created by the enclave after it
    /// validates the exact participant set and derived ceremony id.
    DkgParticipantAnnounceV1 {
        participant: ParticipantAnnounce,
    },
    /// Exact purpose-bound artifact produced by the resident source enclave for
    /// a GramineDirectDev registration. The attestation tag authenticates the
    /// request commitment and artifact to the local NodeHost.
    GramineDirectDevOnboardingArtifactPreparedV1 {
        request_hash: B256,
        onboarding_artifact: Vec<u8>,
    },
    GramineDirectDevOnboardingArtifactIngestedV1 {
        tribute_offer_public: [u8; 32],
    },
}

/// Deterministic hash over the canonical inputs of a single Gratis op. SHARED by
/// the enclave (returned in `GratisOpResult`) and the host (recomputed from the
/// request it sent and compared - a mismatch is enclave non-determinism).
/// Length-prefixed to be unambiguous. Diagnostic only - never written to state.
pub fn gratis_op_canonical_hash(req: &GratisOpRequest) -> B256 {
    fn push_bytes(buf: &mut Vec<u8>, b: &[u8]) {
        buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
        buf.extend_from_slice(b);
    }
    let mut buf: Vec<u8> = Vec::new();
    buf.push(req.op as u8);
    buf.extend_from_slice(req.chain_id.as_slice());
    buf.extend_from_slice(req.account.as_slice());
    buf.extend_from_slice(&req.amount.to_be_bytes::<32>());
    push_bytes(&mut buf, &req.current_balance);
    push_bytes(&mut buf, &req.current_pledged);
    push_bytes(&mut buf, &req.current_pledge_record);
    buf.extend_from_slice(&req.modify_auth.mac);
    buf.extend_from_slice(&req.modify_auth.op_nonce.to_be_bytes());
    // Optional linkage fields: length/flag-prefixed so presence is unambiguous.
    match req.pledge_handle {
        Some(h) => {
            buf.push(1);
            buf.extend_from_slice(h.as_slice());
        }
        None => buf.push(0),
    }
    match req.smart_account {
        Some(a) => {
            buf.push(1);
            buf.extend_from_slice(a.as_slice());
        }
        None => buf.push(0),
    }
    match req.spend_auth {
        Some(s) => {
            buf.push(1);
            buf.extend_from_slice(&s);
        }
        None => buf.push(0),
    }
    match req.pledge_terms {
        Some(t) => {
            buf.push(1);
            buf.extend_from_slice(&t.stables_amount.to_be_bytes::<32>());
            buf.extend_from_slice(&t.gratis_amount.to_be_bytes::<32>());
            buf.extend_from_slice(t.asset.as_slice());
            buf.extend_from_slice(&t.entry_rate.to_be_bytes::<32>());
        }
        None => buf.push(0),
    }
    match &req.fidelity {
        Some(f) => {
            buf.push(1);
            buf.push(f.op as u8);
            buf.extend_from_slice(&f.timestamp.to_be_bytes());
            buf.extend_from_slice(&f.first_qualified_start.to_be_bytes());
            push_bytes(&mut buf, &f.current_blob);
        }
        None => buf.push(0),
    }
    alloy_primitives::keccak256(buf)
}

/// Domain-separated preimage the enclave signs (Ed25519 attestation key) and the
/// host verifies, binding the canonical inputs hash to the produced result so the
/// host can prove the result came from the attested enclave. SHARED so the byte
/// layouts cannot drift. Local-only - never written to chain state.
pub fn gratis_op_attestation_preimage(
    inputs_canonical_hash: B256,
    result: &GratisOpResult,
) -> Vec<u8> {
    // Hash the ciphertext-bearing result fields deterministically. serde_json of a
    // fixed-field struct is deterministic (declaration order, no maps/floats); we
    // exclude the tag itself to avoid self-reference.
    let mut probe = result.clone();
    probe.attestation_tag = Vec::new();
    let result_json = serde_json::to_vec(&probe).unwrap_or_default();
    // v2: the result JSON now carries the optional Fidelity section outcome.
    let mut buf = Vec::with_capacity(31 + 32 + 4 + result_json.len());
    buf.extend_from_slice(b"outbe/tee/gratis-attestation/v2");
    buf.extend_from_slice(inputs_canonical_hash.as_slice());
    buf.extend_from_slice(&(result_json.len() as u32).to_be_bytes());
    buf.extend_from_slice(&result_json);
    buf
}

/// Deterministic hash over the canonical inputs of a single Promis op (the
/// [`promis_op_canonical_hash`] analogue of [`gratis_op_canonical_hash`]). SHARED
/// by the enclave (returned in `PromisOpResult`) and the host (recomputed and
/// compared - a mismatch is enclave non-determinism). Length-prefixed;
/// diagnostic only - never written to state.
pub fn promis_op_canonical_hash(req: &PromisOpRequest) -> B256 {
    let mut buf: Vec<u8> = Vec::new();
    buf.push(req.op as u8);
    buf.extend_from_slice(req.chain_id.as_slice());
    buf.extend_from_slice(req.account.as_slice());
    buf.extend_from_slice(&req.amount.to_be_bytes::<32>());
    buf.extend_from_slice(&(req.current_balance.len() as u32).to_be_bytes());
    buf.extend_from_slice(&req.current_balance);
    buf.extend_from_slice(&req.modify_auth.mac);
    buf.extend_from_slice(&req.modify_auth.op_nonce.to_be_bytes());
    alloy_primitives::keccak256(buf)
}

/// Domain-separated preimage the enclave signs (Ed25519 attestation key) and the
/// host verifies for a Promis op - the [`gratis_op_attestation_preimage`]
/// analogue, with its own domain tag so a Gratis attestation can never be replayed
/// as a Promis one. Local-only - never written to chain state.
pub fn promis_op_attestation_preimage(
    inputs_canonical_hash: B256,
    result: &PromisOpResult,
) -> Vec<u8> {
    let mut probe = result.clone();
    probe.attestation_tag = Vec::new();
    let result_json = serde_json::to_vec(&probe).unwrap_or_default();
    let mut buf = Vec::with_capacity(31 + 32 + 4 + result_json.len());
    buf.extend_from_slice(b"outbe/tee/promis-attestation/v1");
    buf.extend_from_slice(inputs_canonical_hash.as_slice());
    buf.extend_from_slice(&(result_json.len() as u32).to_be_bytes());
    buf.extend_from_slice(&result_json);
    buf
}

/// Deterministic hash over the canonical inputs of a standalone Fidelity cohort
/// op. SHARED by the enclave (returned in `FidelityCohortApplied`) and the host
/// (recomputed and compared). Length-prefixed; diagnostic only.
pub fn fidelity_cohort_canonical_hash(req: &FidelityCohortRequest) -> B256 {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(req.chain_id.as_slice());
    buf.extend_from_slice(req.account.as_slice());
    buf.extend_from_slice(&req.amount.to_be_bytes::<32>());
    buf.push(req.section.op as u8);
    buf.extend_from_slice(&req.section.timestamp.to_be_bytes());
    buf.extend_from_slice(&req.section.first_qualified_start.to_be_bytes());
    buf.extend_from_slice(&(req.section.current_blob.len() as u32).to_be_bytes());
    buf.extend_from_slice(&req.section.current_blob);
    alloy_primitives::keccak256(buf)
}

/// Domain-separated attestation preimage for a standalone Fidelity cohort op -
/// its own tag so no other attestation can be replayed as one. Local-only.
pub fn fidelity_cohort_attestation_preimage(
    inputs_canonical_hash: B256,
    result: &FidelityCohortResult,
) -> Vec<u8> {
    let mut probe = result.clone();
    probe.attestation_tag = Vec::new();
    let result_json = serde_json::to_vec(&probe).unwrap_or_default();
    let mut buf = Vec::with_capacity(39 + 32 + 4 + result_json.len());
    buf.extend_from_slice(b"outbe/tee/fidelity-cohort-attestation/v1");
    buf.extend_from_slice(inputs_canonical_hash.as_slice());
    buf.extend_from_slice(&(result_json.len() as u32).to_be_bytes());
    buf.extend_from_slice(&result_json);
    buf
}

/// Deterministic hash over the canonical inputs of a Fidelity league snapshot
/// batch. SHARED by the enclave (returned in `FidelityLeaguesSnapshotted`) and
/// the host (recomputed and compared - a mismatch is enclave non-determinism).
/// Length-prefixed; diagnostic only - never written to state.
pub fn fidelity_snapshot_canonical_hash(req: &FidelitySnapshotRequest) -> B256 {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&req.timestamp.to_be_bytes());
    buf.extend_from_slice(&req.first_qualified_start.to_be_bytes());
    buf.extend_from_slice(&(req.entries.len() as u32).to_be_bytes());
    for entry in &req.entries {
        buf.extend_from_slice(entry.owner.as_slice());
        buf.extend_from_slice(&(entry.cohort_blob.len() as u32).to_be_bytes());
        buf.extend_from_slice(&entry.cohort_blob);
    }
    alloy_primitives::keccak256(buf)
}

/// Domain-separated attestation preimage for a Fidelity snapshot batch - the
/// [`gratis_op_attestation_preimage`] analogue with its own tag. Local-only.
pub fn fidelity_snapshot_attestation_preimage(
    inputs_canonical_hash: B256,
    leagues: &[FidelityLeagueEntry],
) -> Vec<u8> {
    let leagues_json = serde_json::to_vec(leagues).unwrap_or_default();
    let mut buf = Vec::with_capacity(41 + 32 + 4 + leagues_json.len());
    buf.extend_from_slice(b"outbe/tee/fidelity-snapshot-attestation/v1");
    buf.extend_from_slice(inputs_canonical_hash.as_slice());
    buf.extend_from_slice(&(leagues_json.len() as u32).to_be_bytes());
    buf.extend_from_slice(&leagues_json);
    buf
}

/// Deterministic hash over the canonical inputs of a single Fidelity index
/// query. SHARED by the enclave (returned in `FidelityQueryResult`) and the host
/// (recomputed and compared). Length-prefixed; diagnostic only.
pub fn fidelity_query_canonical_hash(req: &FidelityQueryRequest) -> B256 {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(req.chain_id.as_slice());
    buf.extend_from_slice(req.account.as_slice());
    buf.extend_from_slice(&(req.cohort_blob.len() as u32).to_be_bytes());
    buf.extend_from_slice(&req.cohort_blob);
    buf.extend_from_slice(&req.query_timestamp.to_be_bytes());
    buf.extend_from_slice(&req.block_timestamp.to_be_bytes());
    buf.extend_from_slice(&req.first_qualified_start.to_be_bytes());
    buf.extend_from_slice(&req.expiry.to_be_bytes());
    buf.extend_from_slice(&(req.owner_sig.len() as u32).to_be_bytes());
    buf.extend_from_slice(&req.owner_sig);
    alloy_primitives::keccak256(buf)
}

/// Domain-separated attestation preimage for a Fidelity index query - its own
/// tag so no other attestation can be replayed as one. Local-only.
pub fn fidelity_query_attestation_preimage(
    inputs_canonical_hash: B256,
    result: &FidelityQueryResult,
) -> Vec<u8> {
    let mut probe = result.clone();
    probe.attestation_tag = Vec::new();
    let result_json = serde_json::to_vec(&probe).unwrap_or_default();
    let mut buf = Vec::with_capacity(38 + 32 + 4 + result_json.len());
    buf.extend_from_slice(b"outbe/tee/fidelity-query-attestation/v1");
    buf.extend_from_slice(inputs_canonical_hash.as_slice());
    buf.extend_from_slice(&(result_json.len() as u32).to_be_bytes());
    buf.extend_from_slice(&result_json);
    buf
}
