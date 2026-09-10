//! Domain-parameterized confidential-amount core, shared by the Gratis and Promis
//! enclave engines.
//!
//! Every ledger that stores per-account amounts as ciphertext
//! (`version(8, big-endian) || AEAD-ct`) and gates writes with a modify-key HMAC
//! reuses these primitives. A [`Domain`] supplies the HKDF `info` labels + the
//! modify-preimage tag, so two ledgers derive **cryptographically independent**
//! keys from the same resident group signature. Every function is a pure transform
//! of its inputs + the resident state key, so every validator's enclave produces
//! byte-identical ciphertext (consensus determinism).
//!
//! This is pure code-motion of the key-derivation / amount-AEAD / modify-MAC
//! primitives that previously lived inline in `gratis.rs`; the `GRATIS` domain
//! reproduces those byte layouts exactly (guarded by the `gratis.rs` known-answer
//! vectors).

use alloy_primitives::{Address, B256, U256};
use ring::hmac;

use outbe_tee::protocol::Ledger;

use crate::crypto::{chacha20poly1305_decrypt, chacha20poly1305_encrypt, hkdf_sha256};
use crate::errors::{Result, TeeError};

/// Balance amount-slot field tag folded into the nonce derivation. Shared: every
/// ledger's primary balance uses tag `0` (higher tags - e.g. Gratis pledged/eoa -
/// are ledger-local).
pub const FIELD_BALANCE: u8 = 0;

/// Amount blob length: `version(8, BE) || ChaCha20Poly1305(U256 32B) (+16B tag)` =
/// 56 bytes. Constant for every amount, so ciphertext size never leaks magnitude.
pub const AMOUNT_BLOB_LEN: usize = 8 + 32 + 16;

/// The domain-separation labels for one confidential ledger.
pub struct Domain {
    /// HKDF `info` prefix for the resident state key (epoch string is appended).
    pub state_info: &'static [u8],
    /// HKDF `info` for a per-account view (AEAD) key.
    pub view_info: &'static [u8],
    /// HKDF `info` for a per-account modify (HMAC) key.
    pub modify_info: &'static [u8],
    /// HKDF `info` for the per-slot deterministic AEAD nonce.
    pub nonce_info: &'static [u8],
    /// Domain tag prefixing the modify-auth HMAC preimage.
    pub modify_tag: &'static [u8],
}

/// Gratis domain separators - byte-identical to the historical inline labels.
pub const GRATIS: Domain = Domain {
    state_info: b"outbe/gratis/state-key/v1/",
    view_info: b"outbe/gratis/view-key/v1",
    modify_info: b"outbe/gratis/modify-key/v1",
    nonce_info: b"outbe/gratis/nonce/v1",
    modify_tag: b"outbe/gratis/modify/v1",
};

/// Promis domain separators - keys are independent from Gratis's.
pub const PROMIS: Domain = Domain {
    state_info: b"outbe/promis/state-key/v1/",
    view_info: b"outbe/promis/view-key/v1",
    modify_info: b"outbe/promis/modify-key/v1",
    nonce_info: b"outbe/promis/nonce/v1",
    modify_tag: b"outbe/promis/modify/v1",
};

/// Fidelity domain separators - keys are independent from Gratis's and
/// Promis's. Encrypts the per-account cohort ledger (a variable-length record
/// blob, see [`Domain::write_blob`]), not a single amount. The modify labels
/// are reserved but unused: cohort ops are chain-initiated (they ride inside
/// the co-located Gratis op), so there is no user-held modify capability.
pub const FIDELITY: Domain = Domain {
    state_info: b"outbe/fidelity/state-key/v1/",
    view_info: b"outbe/fidelity/view-key/v1",
    modify_info: b"outbe/fidelity/modify-key/v1",
    nonce_info: b"outbe/fidelity/nonce/v1",
    modify_tag: b"outbe/fidelity/modify/v1",
};

/// The confidential domain for a wire-level [`Ledger`] (used by the off-chain
/// `DeriveAccountKeys` dispatch to pick view/modify key derivation by ledger).
pub fn domain_for(ledger: Ledger) -> &'static Domain {
    match ledger {
        Ledger::Gratis => &GRATIS,
        Ledger::Promis => &PROMIS,
        Ledger::Fidelity => &FIDELITY,
    }
}

impl Domain {
    /// Resident state key from the DKG group signature: `salt = chain_id`,
    /// `ikm = group_sig`, `info = state_info || epoch_string`. Identical across
    /// every committee enclave, so encrypted state is byte-identical.
    pub fn derive_state_key(
        &self,
        group_sig: &[u8],
        chain_id: B256,
        epoch: u64,
    ) -> Result<[u8; 32]> {
        let mut info = self.state_info.to_vec();
        info.extend_from_slice(epoch.to_string().as_bytes());
        hkdf_sha256(chain_id.as_slice(), group_sig, &info)
    }

    /// Per-account view key: read capability AND the AEAD key for the account's
    /// amount blobs, so a holder can decrypt its own state client-side.
    pub fn derive_view_key(&self, state_key: &[u8; 32], account: Address) -> Result<[u8; 32]> {
        hkdf_sha256(state_key, account.as_slice(), self.view_info)
    }

    /// Per-account modify key: authorizes writes (via HMAC); never decrypts state.
    pub fn derive_modify_key(&self, state_key: &[u8; 32], account: Address) -> Result<[u8; 32]> {
        hkdf_sha256(state_key, account.as_slice(), self.modify_info)
    }

    /// Deterministic per-slot AEAD nonce: `HKDF(key, ikm || version_be, nonce_info)[..12]`.
    pub fn slot_nonce(&self, key: &[u8; 32], ikm: &[u8], version: u64) -> Result<[u8; 12]> {
        let mut buf = ikm.to_vec();
        buf.extend_from_slice(&version.to_be_bytes());
        let okm = hkdf_sha256(key, &buf, self.nonce_info)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&okm[..12]);
        Ok(nonce)
    }

    /// Decrypt a `version || ct` amount blob; an empty blob is a fresh slot (`0`).
    pub fn read_amount(
        &self,
        view_key: &[u8; 32],
        account: Address,
        field: u8,
        blob: &[u8],
    ) -> Result<(u64, U256)> {
        if blob.is_empty() {
            return Ok((0, U256::ZERO));
        }
        if blob.len() < 8 {
            return Err(TeeError::DecryptFailed);
        }
        let mut vbytes = [0u8; 8];
        vbytes.copy_from_slice(&blob[..8]);
        let version = u64::from_be_bytes(vbytes);
        let mut ikm = account.as_slice().to_vec();
        ikm.push(field);
        let nonce = self.slot_nonce(view_key, &ikm, version)?;
        let pt = chacha20poly1305_decrypt(view_key, &nonce, &blob[8..])?;
        if pt.len() != 32 {
            return Err(TeeError::DecryptFailed);
        }
        Ok((version, U256::from_be_slice(&pt)))
    }

    /// Encrypt `amount` into a fresh `version+1 || ct` blob.
    pub fn write_amount(
        &self,
        view_key: &[u8; 32],
        account: Address,
        field: u8,
        prev_version: u64,
        amount: U256,
    ) -> Result<Vec<u8>> {
        let version = prev_version.saturating_add(1);
        let mut ikm = account.as_slice().to_vec();
        ikm.push(field);
        let nonce = self.slot_nonce(view_key, &ikm, version)?;
        let ct = chacha20poly1305_encrypt(view_key, &nonce, &amount.to_be_bytes::<32>())?;
        let mut blob = version.to_be_bytes().to_vec();
        blob.extend_from_slice(&ct);
        debug_assert_eq!(
            blob.len(),
            AMOUNT_BLOB_LEN,
            "amount blob must be a fixed {AMOUNT_BLOB_LEN} bytes"
        );
        Ok(blob)
    }

    /// Decrypt a `version || ct` variable-length record blob (the
    /// [`Domain::read_amount`] analogue for non-amount payloads, e.g. the
    /// Fidelity cohort ledger). An empty blob is a fresh slot (version 0,
    /// empty plaintext). The caller owns the plaintext layout.
    pub fn read_blob(
        &self,
        view_key: &[u8; 32],
        account: Address,
        field: u8,
        blob: &[u8],
    ) -> Result<(u64, Vec<u8>)> {
        if blob.is_empty() {
            return Ok((0, Vec::new()));
        }
        if blob.len() < 8 {
            return Err(TeeError::DecryptFailed);
        }
        let mut vbytes = [0u8; 8];
        vbytes.copy_from_slice(&blob[..8]);
        let version = u64::from_be_bytes(vbytes);
        let mut ikm = account.as_slice().to_vec();
        ikm.push(field);
        let nonce = self.slot_nonce(view_key, &ikm, version)?;
        let pt = chacha20poly1305_decrypt(view_key, &nonce, &blob[8..])?;
        Ok((version, pt))
    }

    /// Encrypt a variable-length record plaintext into a fresh `version+1 || ct`
    /// blob (the [`Domain::write_amount`] analogue for non-amount payloads).
    /// Unlike amounts, the ciphertext length follows the plaintext length -
    /// callers that must not leak record cardinality pad the plaintext to a
    /// deterministic bucket before calling.
    pub fn write_blob(
        &self,
        view_key: &[u8; 32],
        account: Address,
        field: u8,
        prev_version: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let version = prev_version.saturating_add(1);
        let mut ikm = account.as_slice().to_vec();
        ikm.push(field);
        let nonce = self.slot_nonce(view_key, &ikm, version)?;
        let ct = chacha20poly1305_encrypt(view_key, &nonce, plaintext)?;
        let mut blob = version.to_be_bytes().to_vec();
        blob.extend_from_slice(&ct);
        Ok(blob)
    }

    fn modify_preimage(
        &self,
        account: Address,
        op_tag: u8,
        amount: U256,
        op_nonce: u64,
        chain_id: B256,
    ) -> Vec<u8> {
        let mut b = self.modify_tag.to_vec();
        b.extend_from_slice(account.as_slice());
        b.push(op_tag);
        b.extend_from_slice(&amount.to_be_bytes::<32>());
        b.extend_from_slice(&op_nonce.to_be_bytes());
        b.extend_from_slice(chain_id.as_slice());
        b
    }

    /// `HMAC-SHA256(modify_key, preimage)` - the write authorization the client
    /// sends and the enclave re-checks. `op_tag` is the ledger op's `as u8` value.
    pub fn modify_mac(
        &self,
        modify_key: &[u8; 32],
        account: Address,
        op_tag: u8,
        amount: U256,
        op_nonce: u64,
        chain_id: B256,
    ) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, modify_key);
        let tag = hmac::sign(
            &key,
            &self.modify_preimage(account, op_tag, amount, op_nonce, chain_id),
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        out
    }

    /// Constant-time verify of a [`Domain::modify_mac`].
    #[allow(clippy::too_many_arguments)] // mirrors the MAC preimage inputs + the tag
    pub fn verify_modify_auth(
        &self,
        modify_key: &[u8; 32],
        account: Address,
        op_tag: u8,
        amount: U256,
        op_nonce: u64,
        chain_id: B256,
        mac: &[u8; 32],
    ) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA256, modify_key);
        hmac::verify(
            &key,
            &self.modify_preimage(account, op_tag, amount, op_nonce, chain_id),
            mac,
        )
        .is_ok()
    }
}
