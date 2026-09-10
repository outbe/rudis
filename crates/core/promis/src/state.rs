//! Low-level storage access for the confidential Promis token.
//!
//! CRUD over the encrypted balance blob, the plaintext supply aggregate, and the
//! modify-auth replay counter. Ciphertext is read/written verbatim - this layer
//! never decrypts. Business orchestration (building enclave requests, applying the
//! returned receipt, emitting events) lives in [`crate::runtime`]; the cross-crate
//! surface is [`crate::api`].

use alloy_primitives::{Address, U256};
use outbe_primitives::error::Result;

use crate::schema::Promis;

impl Promis<'_> {
    // --- Metadata ---

    pub fn name(&self) -> &str {
        "promis"
    }

    pub fn symbol(&self) -> &str {
        "PROMIS"
    }

    pub fn decimals(&self) -> u8 {
        6
    }

    // --- Plaintext aggregate (non-attributable) ---

    pub fn total_supply(&self) -> Result<U256> {
        self.total_supply.read()
    }

    // --- Ciphertext reads (returned verbatim; the view-key holder decrypts) ---

    /// Encrypted balance blob for `account` (`version(8) || AEAD-ct`); empty if the
    /// account has never held a balance.
    pub fn balance_ct_of(&self, account: Address) -> Result<Vec<u8>> {
        self.balance_ct.get_bytes(&account).read()
    }

    /// The account's current modify-auth replay counter (the value a client must
    /// bind into its next write authorization).
    pub fn op_nonce_of(&self, account: Address) -> Result<u64> {
        self.op_nonce.read(&account)
    }

    // --- Writers (all `&self`; storage mutates through interior mutability) ---

    pub(crate) fn write_balance_ct(&self, account: Address, blob: &[u8]) -> Result<()> {
        self.balance_ct.get_bytes(&account).write(blob)
    }

    pub(crate) fn set_op_nonce(&self, account: Address, nonce: u64) -> Result<()> {
        self.op_nonce.write(&account, nonce)
    }

    pub(crate) fn set_total_supply(&self, value: U256) -> Result<()> {
        self.total_supply.write(value)
    }
}
