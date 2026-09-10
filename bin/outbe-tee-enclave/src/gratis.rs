//! Enclave-side Gratis confidential state engine (secret-bearing).
//!
//! Derives per-account view/modify keys and the resident `gratis_state_key` from
//! the DKG group signature, and applies Gratis write ops over deterministically
//! encrypted balances. Every function here is a pure transform of its inputs +
//! the resident state key, so every validator's enclave produces byte-identical
//! ciphertext (consensus determinism) - the same property `encrypt_share_deterministic`
//! provides for the on-chain offer-key seal.
//!
//! Blob format for every stored ciphertext: `version(8, big-endian) || AEAD-ct`.
//! The monotonic `version` is folded into the AEAD nonce so overwriting a slot
//! never reuses a `(key, nonce)` pair; it is also what lets the client derive the
//! nonce to decrypt (balance/pledged use the account's view key as the AEAD key).

use alloy_primitives::{Address, B256, U256};
use ring::hmac;

use outbe_tee::protocol::{GratisOp, GratisOpRequest, GratisOpResult, GratisOpStatus, PledgeTerms};

use crate::confidential::{FIELD_BALANCE, GRATIS};
use crate::crypto::{chacha20poly1305_decrypt, chacha20poly1305_encrypt, hkdf_sha256};
use crate::errors::{Result, TeeError};

/// AEAD-slot field tags folded into the nonce derivation so a ciphertext cannot be
/// lifted between an account's balance and pledged slots. `FIELD_BALANCE` (tag 0)
/// is shared and imported from [`crate::confidential`]; pledged/eoa are Gratis-local.
const FIELD_PLEDGED: u8 = 1;
/// Folded into the sealed-EOA nonce IKM so its nonce can never collide with an amount
/// blob or a pledge ticket sealed under the same state key + handle.
const FIELD_EOA: u8 = 2;

/// Sealed-EOA blob: `nonce(12) || ChaCha20Poly1305(Address 20B)` = 48 bytes.
const EOA_CT_LEN: usize = 12 + 20 + 16;

/// PledgeLockTicket plaintext:
/// `stables(32) || owner(20) || gratis(32) || asset(20) || entry_rate(32)` = 136 bytes.
const RECORD_PLAINTEXT_LEN: usize = 32 + 20 + 32 + 20 + 32;

const SPEND_BIND_TAG: &[u8] = b"outbe/gratis/credis-bind/v1";

// --- Key derivation (delegates to the shared confidential core) ------------------

/// Derive the resident Gratis state key from the DKG group signature. See
/// [`crate::confidential::Domain::derive_state_key`].
pub fn derive_gratis_state_key(group_sig: &[u8], chain_id: B256, epoch: u64) -> Result<[u8; 32]> {
    GRATIS.derive_state_key(group_sig, chain_id, epoch)
}

/// Per-account view key: read capability AND the AEAD key for the account's
/// balance/pledged blobs, so a holder can decrypt its own state client-side.
pub fn derive_view_key(state_key: &[u8; 32], account: Address) -> Result<[u8; 32]> {
    GRATIS.derive_view_key(state_key, account)
}

/// Per-account modify key: authorizes writes (via HMAC); never decrypts state.
pub fn derive_modify_key(state_key: &[u8; 32], account: Address) -> Result<[u8; 32]> {
    GRATIS.derive_modify_key(state_key, account)
}

/// HKDF `info` for the deterministic per-pledge handle:
/// `HKDF(salt = gratis_state_key, ikm = account || amount || op_nonce,
/// info = GRATIS_PLEDGE_HANDLE_INFO)`.
pub const GRATIS_PLEDGE_HANDLE_INFO: &[u8] = b"outbe/gratis/pledge-handle/v1";

/// Deterministic pledge handle (public record id) that replaces the old ZK
/// commitment. Unique per `(account, amount, op_nonce)`.
pub fn derive_pledge_handle(
    state_key: &[u8; 32],
    account: Address,
    amount: U256,
    op_nonce: u64,
) -> Result<B256> {
    let mut ikm = account.as_slice().to_vec();
    ikm.extend_from_slice(&amount.to_be_bytes::<32>());
    ikm.extend_from_slice(&op_nonce.to_be_bytes());
    Ok(B256::from(hkdf_sha256(
        state_key,
        &ikm,
        GRATIS_PLEDGE_HANDLE_INFO,
    )?))
}

// --- Authorization MACs (also used by clients/tests to produce the auth) --------

/// `HMAC-SHA256(modify_key, preimage)` - the write authorization the client sends
/// and the enclave re-checks. See [`crate::confidential::Domain::modify_mac`].
pub fn modify_mac(
    modify_key: &[u8; 32],
    account: Address,
    op: GratisOp,
    amount: U256,
    op_nonce: u64,
    chain_id: B256,
) -> [u8; 32] {
    GRATIS.modify_mac(modify_key, account, op as u8, amount, op_nonce, chain_id)
}

fn verify_modify_auth(
    modify_key: &[u8; 32],
    account: Address,
    op: GratisOp,
    amount: U256,
    op_nonce: u64,
    chain_id: B256,
    mac: &[u8; 32],
) -> bool {
    GRATIS.verify_modify_auth(
        modify_key, account, op as u8, amount, op_nonce, chain_id, mac,
    )
}

/// Per-pledge spend secret the EOA derives locally from its modify key + the
/// public handle, then hands to the CCA off-chain. `HMAC(modify_key, handle)`.
pub fn pledge_secret(modify_key: &[u8; 32], handle: B256) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, modify_key);
    let tag = hmac::sign(&key, handle.as_slice());
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Spend authorization binding a pledge to a destination smart account, so a
/// mempool observer of `requestCredis(handle, spend_auth)` cannot redirect it.
/// `HMAC(pledge_secret, "credis-bind" || bundle)`.
pub fn spend_auth_mac(pledge_secret: &[u8; 32], bundle: Address) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, pledge_secret);
    let mut msg = SPEND_BIND_TAG.to_vec();
    msg.extend_from_slice(bundle.as_slice());
    let tag = hmac::sign(&key, &msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

// --- Versioned deterministic AEAD over per-account amounts (shared core) ---------

fn slot_nonce(key: &[u8; 32], ikm: &[u8], version: u64) -> Result<[u8; 12]> {
    GRATIS.slot_nonce(key, ikm, version)
}

/// Decrypt a `version || ct` amount blob; an empty blob is a fresh slot (`0`).
fn read_amount(
    view_key: &[u8; 32],
    account: Address,
    field: u8,
    blob: &[u8],
) -> Result<(u64, U256)> {
    GRATIS.read_amount(view_key, account, field, blob)
}

/// Encrypt `amount` into a fresh `version+1 || ct` blob.
fn write_amount(
    view_key: &[u8; 32],
    account: Address,
    field: u8,
    prev_version: u64,
    amount: U256,
) -> Result<Vec<u8>> {
    GRATIS.write_amount(view_key, account, field, prev_version, amount)
}

/// Client-side helper: decrypt an account's balance blob with its view key (the
/// key delivered by `DeriveAccountKeys`). Same primitive the enclave uses, so a
/// client reproduces the plaintext without ever touching the state key.
pub fn decrypt_balance(view_key: &[u8; 32], account: Address, blob: &[u8]) -> Result<U256> {
    read_amount(view_key, account, FIELD_BALANCE, blob).map(|(_, v)| v)
}

/// Client-side helper: decrypt an account's pledged-ledger blob with its view key.
pub fn decrypt_pledged(view_key: &[u8; 32], account: Address, blob: &[u8]) -> Result<U256> {
    read_amount(view_key, account, FIELD_PLEDGED, blob).map(|(_, v)| v)
}

// --- Pledge record --------------------------------------------------------------

/// The parked pledge: its owner plus the loan terms quoted at pledge time.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PledgeLockTicket {
    stables_amount: U256,
    owner: Address,
    gratis_amount: U256,
    asset: Address,
    entry_rate: U256,
}

impl PledgeLockTicket {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(RECORD_PLAINTEXT_LEN);
        b.extend_from_slice(&self.stables_amount.to_be_bytes::<32>());
        b.extend_from_slice(self.owner.as_slice());
        b.extend_from_slice(&self.gratis_amount.to_be_bytes::<32>());
        b.extend_from_slice(self.asset.as_slice());
        b.extend_from_slice(&self.entry_rate.to_be_bytes::<32>());
        b
    }

    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != RECORD_PLAINTEXT_LEN {
            return Err(TeeError::DecryptFailed);
        }
        Ok(Self {
            stables_amount: U256::from_be_slice(&b[0..32]),
            owner: Address::from_slice(&b[32..52]),
            gratis_amount: U256::from_be_slice(&b[52..84]),
            asset: Address::from_slice(&b[84..104]),
            entry_rate: U256::from_be_slice(&b[104..136]),
        })
    }

    fn terms(&self) -> PledgeTerms {
        PledgeTerms {
            stables_amount: self.stables_amount,
            gratis_amount: self.gratis_amount,
            asset: self.asset,
            entry_rate: self.entry_rate,
        }
    }
}

fn read_ticket(state_key: &[u8; 32], handle: B256, blob: &[u8]) -> Result<(u64, PledgeLockTicket)> {
    if blob.len() < 8 {
        return Err(TeeError::DecryptFailed);
    }
    let mut vbytes = [0u8; 8];
    vbytes.copy_from_slice(&blob[..8]);
    let version = u64::from_be_bytes(vbytes);
    let nonce = slot_nonce(state_key, handle.as_slice(), version)?;
    let pt = chacha20poly1305_decrypt(state_key, &nonce, &blob[8..])?;
    Ok((version, PledgeLockTicket::decode(&pt)?))
}

fn write_ticket(
    state_key: &[u8; 32],
    handle: B256,
    prev_version: u64,
    ticket: &PledgeLockTicket,
) -> Result<Vec<u8>> {
    let version = prev_version.saturating_add(1);
    let nonce = slot_nonce(state_key, handle.as_slice(), version)?;
    let ct = chacha20poly1305_encrypt(state_key, &nonce, &ticket.encode())?;
    let mut blob = version.to_be_bytes().to_vec();
    blob.extend_from_slice(&ct);
    Ok(blob)
}

// --- Sealed EOA (hide the pledger<->bundle linkage from external observers) ---------

/// Seal an EOA under the global state key into a self-contained blob the host stores on
/// the Credis position (`nonce(12) || ct`). The nonce is derived from the unique pledge
/// `handle` + an EOA domain tag - so it is unique per position and can never collide with
/// that handle's ticket nonce - and stored in the blob so `open_eoa_ct` needs no handle.
/// Written once (the position's EOA is immutable), so a fixed version is fine.
fn seal_eoa_ct(state_key: &[u8; 32], handle: B256, owner: Address) -> Result<Vec<u8>> {
    let mut ikm = handle.as_slice().to_vec();
    ikm.push(FIELD_EOA);
    let nonce = slot_nonce(state_key, &ikm, 1)?;
    let ct = chacha20poly1305_encrypt(state_key, &nonce, owner.as_slice())?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    debug_assert_eq!(
        blob.len(),
        EOA_CT_LEN,
        "eoa_ct blob must be {EOA_CT_LEN} bytes"
    );
    Ok(blob)
}

/// Open a [`seal_eoa_ct`] blob back to the plaintext EOA.
fn open_eoa_ct(state_key: &[u8; 32], blob: &[u8]) -> Result<Address> {
    if blob.len() != EOA_CT_LEN {
        return Err(TeeError::DecryptFailed);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let pt = chacha20poly1305_decrypt(state_key, &nonce, &blob[12..])?;
    if pt.len() != 20 {
        return Err(TeeError::DecryptFailed);
    }
    Ok(Address::from_slice(&pt))
}

// --- The op engine --------------------------------------------------------------

fn base_result() -> GratisOpResult {
    GratisOpResult {
        status: GratisOpStatus::Applied,
        new_balance: Vec::new(),
        new_pledged: Vec::new(),
        new_pledge_record: Vec::new(),
        pledge_handle: B256::ZERO,
        gratis_amount: U256::ZERO,
        pledge_terms: None,
        revealed_owner: Address::ZERO,
        eoa_ct: Vec::new(),
        event_amount: U256::ZERO,
        next_op_nonce: 0,
        fidelity: None,
        inputs_canonical_hash: B256::ZERO,
        attestation_tag: Vec::new(),
    }
}

/// A fresh `Rejected` result carrying only the diagnostic inputs hash. Used by
/// the dispatch when the co-located Fidelity section fails AFTER the Gratis op
/// itself succeeded: the whole combined op must reject, and no ciphertext from
/// the successful half may leak into the rejected result.
pub fn rejected_result(reason: String, inputs_canonical_hash: B256) -> GratisOpResult {
    let mut r = base_result();
    r.status = GratisOpStatus::Rejected { reason };
    r.inputs_canonical_hash = inputs_canonical_hash;
    r
}

fn reject(reason: impl Into<String>) -> GratisOpResult {
    let mut r = base_result();
    r.status = GratisOpStatus::Rejected {
        reason: reason.into(),
    };
    r
}

/// Apply a Gratis op over encrypted state. Pure and deterministic given
/// `state_key` + `req`. Sets `inputs_canonical_hash`; the caller (dispatch) signs
/// and fills `attestation_tag`. Business rejections come back as
/// `GratisOpStatus::Rejected` (-> precompile revert), never a panic.
pub fn apply_op(state_key: &[u8; 32], req: &GratisOpRequest) -> GratisOpResult {
    let inputs_canonical_hash = outbe_tee::protocol::gratis_op_canonical_hash(req);
    let mut result = match apply_op_inner(state_key, req) {
        Ok(r) => r,
        Err(e) => reject(e.to_string()),
    };
    result.inputs_canonical_hash = inputs_canonical_hash;
    result
}

fn apply_op_inner(state_key: &[u8; 32], req: &GratisOpRequest) -> Result<GratisOpResult> {
    match req.op {
        GratisOp::Mint | GratisOp::Burn | GratisOp::Pledge | GratisOp::Unpledge => {
            apply_owner_op(state_key, req)
        }
        GratisOp::ConsumePledge => apply_consume_pledge(state_key, req),
        GratisOp::ReleaseToEoa => apply_release_to_eoa(state_key, req),
        GratisOp::BurnPledged => apply_burn_pledged(state_key, req),
        GratisOp::RevealOwner => apply_reveal_owner(state_key, req),
    }
}

/// Read-only: recover the plaintext EOA that keys the confidential pledged/balance ledgers,
/// without the EOA ever appearing in calldata or stored plaintext. `pledge_handle = Some`
/// -> the blob in `current_pledge_record` is a live `PledgeLockTicket` (credis
/// `ConsumePledge` time, when calldata no longer carries the EOA); `None` -> the
/// self-contained `eoa_ct` stored on the Credis position (settlement / void). No state
/// mutation, no authorization - the on-chain Credis position is the accounting authority.
fn apply_reveal_owner(state_key: &[u8; 32], req: &GratisOpRequest) -> Result<GratisOpResult> {
    let owner = match req.pledge_handle {
        Some(handle) => {
            read_ticket(state_key, handle, &req.current_pledge_record)?
                .1
                .owner
        }
        None => open_eoa_ct(state_key, &req.current_pledge_record)?,
    };
    if owner.is_zero() {
        return Ok(reject("revealed owner is zero"));
    }
    let mut r = base_result();
    r.revealed_owner = owner;
    Ok(r)
}

/// Mine/Burn/Pledge/Unpledge - all modify-key gated and keyed by `req.account`.
fn apply_owner_op(state_key: &[u8; 32], req: &GratisOpRequest) -> Result<GratisOpResult> {
    if req.amount.is_zero() {
        return Ok(reject("amount must be positive"));
    }
    if req.account.is_zero() {
        return Ok(reject("invalid address"));
    }
    let modify_key = derive_modify_key(state_key, req.account)?;
    if !verify_modify_auth(
        &modify_key,
        req.account,
        req.op,
        req.amount,
        req.modify_auth.op_nonce,
        req.chain_id,
        &req.modify_auth.mac,
    ) {
        return Ok(reject("invalid modify authorization"));
    }

    let view_key = derive_view_key(state_key, req.account)?;
    let (bver, balance) = read_amount(&view_key, req.account, FIELD_BALANCE, &req.current_balance)?;

    let mut r = base_result();
    r.event_amount = req.amount;
    r.next_op_nonce = req.modify_auth.op_nonce.saturating_add(1);

    match req.op {
        GratisOp::Mint => {
            let new_balance = match balance.checked_add(req.amount) {
                Some(v) => v,
                None => return Ok(reject("gratis balance overflow")),
            };
            r.new_balance = write_amount(&view_key, req.account, FIELD_BALANCE, bver, new_balance)?;
        }
        GratisOp::Burn => {
            if balance < req.amount {
                return Ok(reject("insufficient balance"));
            }
            r.new_balance = write_amount(
                &view_key,
                req.account,
                FIELD_BALANCE,
                bver,
                balance - req.amount,
            )?;
        }
        GratisOp::Pledge => {
            // Two-phase pledge: debit the liquid balance and PARK the gratis in a new
            // PledgeLockTicket together with the loan terms it was quoted against. The
            // pledged ledger is credited only later, when `ConsumePledge` consumes the
            // ticket at requestCredis.
            let Some(terms) = req.pledge_terms else {
                return Ok(reject("pledge requires loan terms"));
            };
            // `req.amount` is the MAC-bound figure, so the terms must agree with it or
            // the pledger's authorization would cover a different loan than the ticket.
            if terms.stables_amount != req.amount {
                return Ok(reject("pledge terms do not match the authorized amount"));
            }
            if terms.gratis_amount.is_zero() {
                return Ok(reject("pledge gratis amount must be positive"));
            }
            if terms.asset.is_zero() {
                return Ok(reject("pledge asset must not be zero"));
            }
            if balance < terms.gratis_amount {
                return Ok(reject("insufficient balance"));
            }
            let handle =
                derive_pledge_handle(state_key, req.account, req.amount, req.modify_auth.op_nonce)?;
            let ticket = PledgeLockTicket {
                stables_amount: terms.stables_amount,
                owner: req.account,
                gratis_amount: terms.gratis_amount,
                asset: terms.asset,
                entry_rate: terms.entry_rate,
            };
            r.new_balance = write_amount(
                &view_key,
                req.account,
                FIELD_BALANCE,
                bver,
                balance - terms.gratis_amount,
            )?;
            r.new_pledge_record = write_ticket(state_key, handle, 0, &ticket)?;
            r.pledge_handle = handle;
            // The aggregates and the GratisPledged event are gratis-denominated.
            r.event_amount = terms.gratis_amount;
        }
        GratisOp::Unpledge => {
            // Return a still-pending pledge (e.g. credis rejected): credit the ticket
            // gratis back to the balance and DELETE the ticket (host writes back the
            // empty `new_pledge_record`) so it can never be consumed later.
            let Some(handle) = req.pledge_handle else {
                return Ok(reject("unpledge requires a pledge handle"));
            };
            let (_rver, ticket) = read_ticket(state_key, handle, &req.current_pledge_record)?;
            if ticket.owner != req.account {
                return Ok(reject("unpledge account does not match pledge ticket"));
            }
            if ticket.stables_amount != req.amount {
                return Ok(reject("unpledge amount does not match pledge ticket"));
            }
            let new_balance = match balance.checked_add(ticket.gratis_amount) {
                Some(v) => v,
                None => return Ok(reject("gratis balance overflow")),
            };
            r.new_balance = write_amount(&view_key, req.account, FIELD_BALANCE, bver, new_balance)?;
            // `new_pledge_record` stays empty -> host clears (deletes) the ticket slot.
            r.event_amount = ticket.gratis_amount;
        }
        _ => unreachable!("apply_owner_op only handles owner ops"),
    }
    Ok(r)
}

/// requestCredis: consume a `PledgeLockTicket`, verify the spend binding to the
/// smart account, credit the ticket amount into the EOA's OWN pledged ledger, and
/// delete the ticket. No escrow account is involved - the collateral stays with the
/// pledger for the whole credis term. The EOA no longer travels in calldata: the host
/// recovers it with a prior `RevealOwner` round-trip and passes it as `req.account`; the
/// enclave still checks it matches the ticket owner so the caller cannot consume a
/// different account's ticket. The result carries `eoa_ct` - the ticket owner sealed under
/// the state key - for the host to store on the Credis position (hiding the EOA<->bundle link).
fn apply_consume_pledge(state_key: &[u8; 32], req: &GratisOpRequest) -> Result<GratisOpResult> {
    let (Some(handle), Some(bundle), Some(spend_auth)) =
        (req.pledge_handle, req.smart_account, req.spend_auth)
    else {
        return Ok(reject(
            "consume_pledge requires handle, bundle, and spend_auth",
        ));
    };
    let (_tver, ticket) = read_ticket(state_key, handle, &req.current_pledge_record)?;
    if ticket.owner != req.account {
        return Ok(reject(
            "consume_pledge account does not match pledge ticket",
        ));
    }
    let modify_key = derive_modify_key(state_key, ticket.owner)?;
    let secret = pledge_secret(&modify_key, handle);
    let expected = spend_auth_mac(&secret, bundle);
    if !constant_time_eq(&expected, &spend_auth) {
        return Ok(reject("invalid spend authorization"));
    }

    // Credit the EOA's OWN pledged ledger (pending -> active); no escrow move.
    let eoa_view = derive_view_key(state_key, ticket.owner)?;
    let (pver, pledged) =
        read_amount(&eoa_view, ticket.owner, FIELD_PLEDGED, &req.current_pledged)?;
    let new_pledged = match pledged.checked_add(ticket.gratis_amount) {
        Some(v) => v,
        None => return Ok(reject("gratis pledged overflow")),
    };

    let mut r = base_result();
    r.new_pledged = write_amount(&eoa_view, ticket.owner, FIELD_PLEDGED, pver, new_pledged)?;
    // `new_pledge_record` stays empty -> host clears (deletes) the ticket slot, so it
    // can never be consumed twice (double-spend).
    r.eoa_ct = seal_eoa_ct(state_key, handle, ticket.owner)?;
    r.gratis_amount = ticket.gratis_amount;
    r.event_amount = ticket.gratis_amount;
    // Hand credis the quote the pledger accepted so it never re-prices the loan.
    r.pledge_terms = Some(ticket.terms());
    Ok(r)
}

/// Settlement: release `amount` of collateral from the EOA's OWN pledged ledger back
/// to its balance (`EOA.pledged -= amount; EOA.balance += amount`). Amount-based (no
/// ticket): the on-chain Credis position schedule is the accounting authority for the
/// per-settlement amount; the enclave only enforces pledged-ledger sufficiency.
/// `req.account` is the EOA the host recovered from the position's `eoa_ct` via a prior
/// `RevealOwner` round-trip - it never appears in calldata or stored plaintext.
fn apply_release_to_eoa(state_key: &[u8; 32], req: &GratisOpRequest) -> Result<GratisOpResult> {
    if req.amount.is_zero() {
        return Ok(reject("amount must be positive"));
    }
    if req.account.is_zero() {
        return Ok(reject("invalid address"));
    }
    let eoa_view = derive_view_key(state_key, req.account)?;
    let (pver, pledged) = read_amount(&eoa_view, req.account, FIELD_PLEDGED, &req.current_pledged)?;
    if pledged < req.amount {
        return Ok(reject("insufficient pledged balance"));
    }
    let (bver, balance) = read_amount(&eoa_view, req.account, FIELD_BALANCE, &req.current_balance)?;
    let new_balance = match balance.checked_add(req.amount) {
        Some(v) => v,
        None => return Ok(reject("gratis balance overflow")),
    };

    let mut r = base_result();
    r.new_pledged = write_amount(
        &eoa_view,
        req.account,
        FIELD_PLEDGED,
        pver,
        pledged - req.amount,
    )?;
    r.new_balance = write_amount(&eoa_view, req.account, FIELD_BALANCE, bver, new_balance)?;
    r.gratis_amount = req.amount;
    r.event_amount = req.amount;
    Ok(r)
}

/// Credis expiry: burn `amount` of collateral from the EOA's OWN pledged ledger
/// (`EOA.pledged -= amount`; the host then reduces `total_supply`). Amount-based (no
/// ticket): the on-chain Credis position's outstanding collateral is the authority;
/// the enclave only enforces pledged-ledger sufficiency.
fn apply_burn_pledged(state_key: &[u8; 32], req: &GratisOpRequest) -> Result<GratisOpResult> {
    if req.amount.is_zero() {
        return Ok(reject("amount must be positive"));
    }
    if req.account.is_zero() {
        return Ok(reject("invalid address"));
    }
    let eoa_view = derive_view_key(state_key, req.account)?;
    let (pver, pledged) = read_amount(&eoa_view, req.account, FIELD_PLEDGED, &req.current_pledged)?;
    if pledged < req.amount {
        return Ok(reject("insufficient pledged balance"));
    }

    let mut r = base_result();
    r.new_pledged = write_amount(
        &eoa_view,
        req.account,
        FIELD_PLEDGED,
        pver,
        pledged - req.amount,
    )?;
    r.gratis_amount = req.amount;
    r.event_amount = req.amount;
    Ok(r)
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbe_primitives::units::SCALE_1E6_U256;
    use outbe_tee::protocol::ModifyAuth;

    const CHAIN: B256 = B256::repeat_byte(0xC1);
    fn state_key() -> [u8; 32] {
        derive_gratis_state_key(b"a-group-threshold-signature-~48-bytes-long!!", CHAIN, 0).unwrap()
    }
    fn alice() -> Address {
        Address::repeat_byte(0x11)
    }
    fn bundle() -> Address {
        Address::repeat_byte(0xBB)
    }

    fn auth(sk: &[u8; 32], acct: Address, op: GratisOp, amount: U256, nonce: u64) -> ModifyAuth {
        let mk = derive_modify_key(sk, acct).unwrap();
        ModifyAuth {
            mac: modify_mac(&mk, acct, op, amount, nonce, CHAIN),
            op_nonce: nonce,
        }
    }

    fn req(op: GratisOp, acct: Address, amount: U256, nonce: u64) -> GratisOpRequest {
        GratisOpRequest {
            op,
            chain_id: CHAIN,
            account: acct,
            amount,
            current_balance: Vec::new(),
            current_pledged: Vec::new(),
            current_pledge_record: Vec::new(),
            modify_auth: ModifyAuth {
                mac: [0u8; 32],
                op_nonce: nonce,
            },
            pledge_handle: None,
            smart_account: None,
            spend_auth: None,
            pledge_terms: None,
            fidelity: None,
        }
    }

    fn asset() -> Address {
        Address::repeat_byte(0xA5)
    }

    /// The oracle-derived terms the host seals into a pledge ticket. `gratis` is what
    /// leaves the balance; `stables` is what the pledger signed.
    fn terms(stables: U256, gratis: U256) -> PledgeTerms {
        PledgeTerms {
            stables_amount: stables,
            gratis_amount: gratis,
            asset: asset(),
            entry_rate: U256::from(2u64) * SCALE_1E6_U256,
        }
    }

    /// Known-answer vectors pinning the Gratis key-derivation / amount-AEAD /
    /// modify-MAC byte layouts to literal hex. These guard the shared
    /// [`crate::confidential`] core against silent format drift: any change to an
    /// HKDF label, nonce IKM, blob layout, or MAC preimage would make persisted
    /// on-chain Gratis ciphertext undecryptable and split the DKG-derived state key
    /// across validators - a break the round-trip tests below cannot catch because
    /// they start from empty storage. Regenerate ONLY on an intentional, reviewed
    /// format change (bump the on-chain layout version accordingly).
    #[test]
    fn gratis_known_answer_vectors() {
        const KAT_GROUP_SIG: &[u8] = b"kat-fixed-gratis-group-signature-48b-padding";
        let sk = derive_gratis_state_key(KAT_GROUP_SIG, CHAIN, 0).unwrap();
        assert_eq!(
            alloy_primitives::hex::encode(sk),
            "ee0bcead11e31dbafbf16c5b7fb2aa659045c38a7259db9002aa66bc9d9b08b3"
        );
        let vk = derive_view_key(&sk, alice()).unwrap();
        let blob = write_amount(&vk, alice(), FIELD_BALANCE, 0, U256::from(1000u64)).unwrap();
        assert_eq!(
            alloy_primitives::hex::encode(&blob),
            "0000000000000001186436dfe4774b400beaa3115d0ab9abae57d6defa6f80943ec703ede5ea855d8823cdeb05b2de5491aaf6829c5b213b"
        );
        let mk = derive_modify_key(&sk, alice()).unwrap();
        let mac = modify_mac(&mk, alice(), GratisOp::Mint, U256::from(1000u64), 0, CHAIN);
        assert_eq!(
            alloy_primitives::hex::encode(mac),
            "688879e6e80acafeb78b7804de6edbd1032d95b2b654a049824c269c4aace152"
        );
    }

    #[test]
    fn mine_is_deterministic_across_calls() {
        let sk = state_key();
        let mut r = req(GratisOp::Mint, alice(), U256::from(1000u64), 0);
        r.modify_auth = auth(&sk, alice(), GratisOp::Mint, r.amount, 0);
        let a = apply_op(&sk, &r);
        let b = apply_op(&sk, &r);
        assert_eq!(a, b, "same state key + request -> byte-identical result");
        assert!(matches!(a.status, GratisOpStatus::Applied));
        assert!(!a.new_balance.is_empty());
    }

    #[test]
    fn view_key_decrypts_minted_balance() {
        let sk = state_key();
        let mut r = req(GratisOp::Mint, alice(), U256::from(4242u64), 0);
        r.modify_auth = auth(&sk, alice(), GratisOp::Mint, r.amount, 0);
        let res = apply_op(&sk, &r);
        // A holder with only the view key can decrypt the balance blob.
        let vk = derive_view_key(&sk, alice()).unwrap();
        let (_v, bal) = read_amount(&vk, alice(), FIELD_BALANCE, &res.new_balance).unwrap();
        assert_eq!(bal, U256::from(4242u64));
        assert_eq!(res.next_op_nonce, 1);
    }

    #[test]
    fn mine_rejects_forged_modify_auth() {
        let sk = state_key();
        let mut r = req(GratisOp::Mint, alice(), U256::from(1u64), 0);
        r.modify_auth = auth(&sk, alice(), GratisOp::Mint, r.amount, 0);
        r.modify_auth.mac[0] ^= 0xff;
        assert!(matches!(
            apply_op(&sk, &r).status,
            GratisOpStatus::Rejected { .. }
        ));
    }

    #[test]
    fn burn_requires_sufficient_balance() {
        let sk = state_key();
        // mint 100
        let mut m = req(GratisOp::Mint, alice(), U256::from(100u64), 0);
        m.modify_auth = auth(&sk, alice(), GratisOp::Mint, m.amount, 0);
        let minted = apply_op(&sk, &m);
        // burn 200 -> reject
        let mut b = req(GratisOp::Burn, alice(), U256::from(200u64), 1);
        b.current_balance = minted.new_balance.clone();
        b.modify_auth = auth(&sk, alice(), GratisOp::Burn, b.amount, 1);
        assert!(matches!(
            apply_op(&sk, &b).status,
            GratisOpStatus::Rejected { .. }
        ));
    }

    /// requestCredis consume: the pledge ticket credits the EOA's OWN pledged ledger
    /// (no escrow), the ticket is deleted, and settlements release from that same
    /// ledger back to the EOA's balance.
    #[test]
    fn pledge_consume_and_release_flow() {
        let sk = state_key();
        // mint 1000 to alice
        let mut m = req(GratisOp::Mint, alice(), U256::from(1000u64), 0);
        m.modify_auth = auth(&sk, alice(), GratisOp::Mint, m.amount, 0);
        let minted = apply_op(&sk, &m);

        // pledge $500 of credit, which the oracle quote covers with 1000 gratis: the
        // balance is drained by the GRATIS figure and parked in the ticket (pledged
        // still 0). The two units are deliberately different so a mix-up shows up.
        let mut p = req(GratisOp::Pledge, alice(), U256::from(500u64), 1);
        p.current_balance = minted.new_balance.clone();
        p.pledge_terms = Some(terms(U256::from(500u64), U256::from(1000u64)));
        p.modify_auth = auth(&sk, alice(), GratisOp::Pledge, p.amount, 1);
        let pledged = apply_op(&sk, &p);
        assert!(matches!(pledged.status, GratisOpStatus::Applied));
        assert_eq!(
            pledged.event_amount,
            U256::from(1000u64),
            "pledged_total_supply is gratis-denominated"
        );
        let handle = pledged.pledge_handle;
        assert_ne!(handle, B256::ZERO);
        assert!(!pledged.new_pledge_record.is_empty(), "ticket written");
        assert!(
            pledged.new_pledged.is_empty(),
            "pledge does not touch pledged_ct"
        );
        let vk = derive_view_key(&sk, alice()).unwrap();
        let (_v, bal) = read_amount(&vk, alice(), FIELD_BALANCE, &pledged.new_balance).unwrap();
        assert_eq!(bal, U256::ZERO);

        // requestCredis: alice derives the pledge secret and binds to the bundle. The
        // collateral is credited into alice's OWN pledged ledger and the ticket is
        // deleted (empty new_pledge_record).
        let mk = derive_modify_key(&sk, alice()).unwrap();
        let secret = pledge_secret(&mk, handle);
        let spend = spend_auth_mac(&secret, bundle());
        let mut rc = req(GratisOp::ConsumePledge, alice(), U256::ZERO, 0);
        rc.current_pledge_record = pledged.new_pledge_record.clone();
        rc.current_pledged = Vec::new();
        rc.pledge_handle = Some(handle);
        rc.smart_account = Some(bundle());
        rc.spend_auth = Some(spend);
        let credis_res = apply_op(&sk, &rc);
        assert!(matches!(credis_res.status, GratisOpStatus::Applied));
        assert_eq!(credis_res.gratis_amount, U256::from(1000u64));
        assert_eq!(
            credis_res.pledge_terms,
            Some(terms(U256::from(500u64), U256::from(1000u64))),
            "credis sizes the loan from the pledge-time quote"
        );
        assert!(
            credis_res.new_pledge_record.is_empty(),
            "ticket deleted on consume"
        );
        let (_v, alice_pledged) =
            read_amount(&vk, alice(), FIELD_PLEDGED, &credis_res.new_pledged).unwrap();
        assert_eq!(alice_pledged, U256::from(1000u64));

        // A wrong bundle binding is rejected (front-running defense).
        let mut bad = rc.clone();
        bad.smart_account = Some(Address::repeat_byte(0xEE));
        assert!(matches!(
            apply_op(&sk, &bad).status,
            GratisOpStatus::Rejected { .. }
        ));

        // Re-consuming the (now deleted) ticket is rejected - no double-spend.
        let mut again = rc.clone();
        again.current_pledge_record = credis_res.new_pledge_record.clone();
        assert!(matches!(
            apply_op(&sk, &again).status,
            GratisOpStatus::Rejected { .. }
        ));

        // Ten settlements (amount-based release, 100 each) -> drains pledged back
        // to balance.
        let mut pledged_blob = credis_res.new_pledged.clone();
        let mut bal_blob = pledged.new_balance.clone();
        let mut total_released = U256::ZERO;
        for _ in 0..10 {
            let mut u = req(GratisOp::ReleaseToEoa, alice(), U256::from(100u64), 0);
            u.current_pledged = pledged_blob.clone();
            u.current_balance = bal_blob.clone();
            let un = apply_op(&sk, &u);
            assert!(
                matches!(un.status, GratisOpStatus::Applied),
                "{:?}",
                un.status
            );
            total_released += un.gratis_amount;
            pledged_blob = un.new_pledged.clone();
            bal_blob = un.new_balance.clone();
        }
        assert_eq!(total_released, U256::from(1000u64));
        let (_v, final_bal) = read_amount(&vk, alice(), FIELD_BALANCE, &bal_blob).unwrap();
        assert_eq!(final_bal, U256::from(1000u64));
        let (_v, final_pledged) = read_amount(&vk, alice(), FIELD_PLEDGED, &pledged_blob).unwrap();
        assert_eq!(final_pledged, U256::ZERO);
        // An 11th release rejected - pledged ledger is empty.
        let mut u = req(GratisOp::ReleaseToEoa, alice(), U256::from(100u64), 0);
        u.current_pledged = pledged_blob;
        u.current_balance = bal_blob;
        assert!(matches!(
            apply_op(&sk, &u).status,
            GratisOpStatus::Rejected { .. }
        ));
    }

    /// Helper: mine `gratis` then pledge `stables` worth of credit against exactly that
    /// gratis, returning `(handle, pledge_result)`.
    fn mine_and_pledge(sk: &[u8; 32], stables: U256, gratis: U256) -> (B256, GratisOpResult) {
        let mut m = req(GratisOp::Mint, alice(), gratis, 0);
        m.modify_auth = auth(sk, alice(), GratisOp::Mint, gratis, 0);
        let minted = apply_op(sk, &m);
        let mut p = req(GratisOp::Pledge, alice(), stables, 1);
        p.current_balance = minted.new_balance.clone();
        p.pledge_terms = Some(terms(stables, gratis));
        p.modify_auth = auth(sk, alice(), GratisOp::Pledge, stables, 1);
        let pledged = apply_op(sk, &p);
        (pledged.pledge_handle, pledged)
    }

    /// The ticket carries every field the credis needs; a byte more or less must not
    /// silently decode (the exact-length check is what stops a stale-format blob from
    /// being reinterpreted).
    #[test]
    fn pledge_ticket_roundtrips_all_terms() {
        let ticket = PledgeLockTicket {
            stables_amount: U256::from(500u64),
            owner: alice(),
            gratis_amount: U256::from(1000u64),
            asset: asset(),
            entry_rate: U256::from(2u64) * SCALE_1E6_U256,
        };
        let encoded = ticket.encode();
        assert_eq!(encoded.len(), RECORD_PLAINTEXT_LEN);
        assert_eq!(PledgeLockTicket::decode(&encoded).unwrap(), ticket);
        assert!(PledgeLockTicket::decode(&encoded[..RECORD_PLAINTEXT_LEN - 1]).is_err());

        let sk = state_key();
        let handle = derive_pledge_handle(&sk, alice(), U256::from(500u64), 1).unwrap();
        let blob = write_ticket(&sk, handle, 0, &ticket).unwrap();
        assert_eq!(read_ticket(&sk, handle, &blob).unwrap().1, ticket);
    }

    /// The MAC only covers `amount` (the stables figure), so the terms the host
    /// supplies must agree with it - otherwise the pledger's authorization would
    /// cover a different loan than the one sealed in the ticket.
    #[test]
    fn pledge_rejects_terms_that_contradict_the_authorized_amount() {
        let sk = state_key();
        let mut m = req(GratisOp::Mint, alice(), U256::from(1000u64), 0);
        m.modify_auth = auth(&sk, alice(), GratisOp::Mint, m.amount, 0);
        let minted = apply_op(&sk, &m);

        let mut p = req(GratisOp::Pledge, alice(), U256::from(500u64), 1);
        p.current_balance = minted.new_balance.clone();
        // Signed for $500, terms claim $900.
        p.pledge_terms = Some(terms(U256::from(900u64), U256::from(1000u64)));
        p.modify_auth = auth(&sk, alice(), GratisOp::Pledge, U256::from(500u64), 1);
        assert!(matches!(
            apply_op(&sk, &p).status,
            GratisOpStatus::Rejected { .. }
        ));

        // Terms are mandatory on a pledge at all.
        let mut missing = p.clone();
        missing.pledge_terms = None;
        assert!(matches!(
            apply_op(&sk, &missing).status,
            GratisOpStatus::Rejected { .. }
        ));
    }

    /// Consume the collateral, then at expiry burn the remaining from the EOA's own
    /// pledged ledger. `total_supply` is reduced host-side from `event_amount`.
    #[test]
    fn burn_pledged_debits_remaining_collateral() {
        let sk = state_key();
        let (handle, pledged) = mine_and_pledge(&sk, U256::from(500u64), U256::from(1000u64));

        let mk = derive_modify_key(&sk, alice()).unwrap();
        let spend = spend_auth_mac(&pledge_secret(&mk, handle), bundle());
        let mut rc = req(GratisOp::ConsumePledge, alice(), U256::ZERO, 0);
        rc.current_pledge_record = pledged.new_pledge_record.clone();
        rc.pledge_handle = Some(handle);
        rc.smart_account = Some(bundle());
        rc.spend_auth = Some(spend);
        let consumed = apply_op(&sk, &rc);
        assert!(matches!(consumed.status, GratisOpStatus::Applied));

        // Release across 3 settlements (300), leaving 700 outstanding.
        let mut pledged_blob = consumed.new_pledged.clone();
        let mut bal_blob = pledged.new_balance.clone();
        for _ in 0..3 {
            let mut u = req(GratisOp::ReleaseToEoa, alice(), U256::from(100u64), 0);
            u.current_pledged = pledged_blob.clone();
            u.current_balance = bal_blob.clone();
            let un = apply_op(&sk, &u);
            pledged_blob = un.new_pledged.clone();
            bal_blob = un.new_balance.clone();
        }

        // Burn the outstanding 700.
        let mut b = req(GratisOp::BurnPledged, alice(), U256::from(700u64), 0);
        b.current_pledged = pledged_blob.clone();
        let burned = apply_op(&sk, &b);
        assert!(matches!(burned.status, GratisOpStatus::Applied));
        assert_eq!(burned.event_amount, U256::from(700u64));
        let vk = derive_view_key(&sk, alice()).unwrap();
        let (_v, remaining) =
            read_amount(&vk, alice(), FIELD_PLEDGED, &burned.new_pledged).unwrap();
        assert_eq!(remaining, U256::ZERO);

        // A second burn of the now-empty pledged ledger is rejected.
        let mut b2 = req(GratisOp::BurnPledged, alice(), U256::from(700u64), 0);
        b2.current_pledged = burned.new_pledged.clone();
        assert!(matches!(
            apply_op(&sk, &b2).status,
            GratisOpStatus::Rejected { .. }
        ));
    }

    /// A direct unpledge returns the pending collateral and deletes the ticket so it
    /// can no longer be consumed for credis (no double-spend).
    #[test]
    fn unpledge_returns_pending_and_blocks_credis() {
        let sk = state_key();
        let stables = U256::from(500u64);
        let gratis = U256::from(1000u64);
        let (handle, pledged) = mine_and_pledge(&sk, stables, gratis);

        // Unpledge is quoted in the same unit the pledge was: stables in, gratis back.
        let mut up = req(GratisOp::Unpledge, alice(), stables, 2);
        up.pledge_handle = Some(handle);
        up.current_pledge_record = pledged.new_pledge_record.clone();
        up.current_balance = pledged.new_balance.clone();
        up.modify_auth = auth(&sk, alice(), GratisOp::Unpledge, stables, 2);
        let un = apply_op(&sk, &up);
        assert!(
            matches!(un.status, GratisOpStatus::Applied),
            "{:?}",
            un.status
        );
        assert_eq!(un.event_amount, gratis, "aggregate delta is gratis");
        let vk = derive_view_key(&sk, alice()).unwrap();
        let (_v, bal) = read_amount(&vk, alice(), FIELD_BALANCE, &un.new_balance).unwrap();
        assert_eq!(bal, gratis, "collateral returned to alice");
        assert!(
            un.new_pledge_record.is_empty(),
            "ticket deleted on unpledge"
        );

        let mk = derive_modify_key(&sk, alice()).unwrap();
        let spend = spend_auth_mac(&pledge_secret(&mk, handle), bundle());
        let mut rc = req(GratisOp::ConsumePledge, alice(), U256::ZERO, 0);
        rc.current_pledge_record = un.new_pledge_record.clone();
        rc.pledge_handle = Some(handle);
        rc.smart_account = Some(bundle());
        rc.spend_auth = Some(spend);
        assert!(
            matches!(apply_op(&sk, &rc).status, GratisOpStatus::Rejected { .. }),
            "deleted ticket must not be spendable for credis"
        );
    }

    /// The EOA is recovered through the enclave both at consume (from the live ticket) and
    /// at settlement/void (from the sealed `eoa_ct`), never from calldata.
    #[test]
    fn reveal_owner_roundtrips_ticket_and_eoa_ct() {
        let sk = state_key();
        let (handle, pledged) = mine_and_pledge(&sk, U256::from(500u64), U256::from(1000u64));

        // RevealOwner on the live ticket (Some(handle)) -> the pledger EOA.
        let mut rt = req(GratisOp::RevealOwner, Address::ZERO, U256::ZERO, 0);
        rt.pledge_handle = Some(handle);
        rt.current_pledge_record = pledged.new_pledge_record.clone();
        let revealed = apply_op(&sk, &rt);
        assert!(matches!(revealed.status, GratisOpStatus::Applied));
        assert_eq!(revealed.revealed_owner, alice());

        // ConsumePledge seals the owner into a self-contained eoa_ct blob.
        let mk = derive_modify_key(&sk, alice()).unwrap();
        let spend = spend_auth_mac(&pledge_secret(&mk, handle), bundle());
        let mut rc = req(GratisOp::ConsumePledge, alice(), U256::ZERO, 0);
        rc.current_pledge_record = pledged.new_pledge_record.clone();
        rc.pledge_handle = Some(handle);
        rc.smart_account = Some(bundle());
        rc.spend_auth = Some(spend);
        let consumed = apply_op(&sk, &rc);
        assert!(matches!(consumed.status, GratisOpStatus::Applied));
        assert_eq!(consumed.eoa_ct.len(), EOA_CT_LEN);

        // RevealOwner on the stored eoa_ct (None) -> the same EOA, with no handle needed.
        let mut re = req(GratisOp::RevealOwner, Address::ZERO, U256::ZERO, 0);
        re.pledge_handle = None;
        re.current_pledge_record = consumed.eoa_ct.clone();
        let opened = apply_op(&sk, &re);
        assert!(matches!(opened.status, GratisOpStatus::Applied));
        assert_eq!(opened.revealed_owner, alice());
    }

    /// Same owner + different pledge handle -> different sealed ciphertext (nonce
    /// uniqueness), and a tampered blob fails AEAD integrity.
    #[test]
    fn eoa_ct_differs_across_positions() {
        let sk = state_key();
        let h1 = derive_pledge_handle(&sk, alice(), U256::from(10u64), 1).unwrap();
        let h2 = derive_pledge_handle(&sk, alice(), U256::from(20u64), 2).unwrap();
        assert_ne!(h1, h2);
        let c1 = seal_eoa_ct(&sk, h1, alice()).unwrap();
        let c2 = seal_eoa_ct(&sk, h2, alice()).unwrap();
        assert_ne!(
            c1, c2,
            "same owner, different handle -> different ciphertext"
        );
        assert_eq!(open_eoa_ct(&sk, &c1).unwrap(), alice());
        assert_eq!(open_eoa_ct(&sk, &c2).unwrap(), alice());

        let mut bad = c1.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(open_eoa_ct(&sk, &bad).is_err());
    }
}
