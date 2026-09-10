//! Low-level storage access for the confidential Gratis token.
//!
//! CRUD over the encrypted blob slots, the plaintext aggregates, and the
//! modify-auth replay counter. Ciphertext is read/written verbatim - this layer
//! never decrypts. Business orchestration (building enclave requests, applying
//! the returned receipt, emitting events) lives in [`crate::runtime`]; the
//! cross-crate surface is [`crate::api`].

use alloy_primitives::{Address, B256, U256};
use outbe_primitives::error::Result;

use crate::schema::Gratis;

impl Gratis<'_> {
    // --- Metadata ---

    pub fn name(&self) -> &str {
        "gratis"
    }

    pub fn symbol(&self) -> &str {
        "GRATIS"
    }

    pub fn decimals(&self) -> u8 {
        6
    }

    // --- Plaintext aggregates (non-attributable) ---

    pub fn total_supply(&self) -> Result<U256> {
        self.total_supply.read()
    }

    pub fn pledged_total_supply(&self) -> Result<U256> {
        self.pledged_total_supply.read()
    }

    // --- Ciphertext reads (returned verbatim; the view-key holder decrypts) ---

    /// Encrypted balance blob for `account` (`version(8) || AEAD-ct`); empty if
    /// the account has never held a balance.
    pub fn balance_ct_of(&self, account: Address) -> Result<Vec<u8>> {
        self.balance_ct.get_bytes(&account).read()
    }

    /// Encrypted pledged-ledger blob for `account`.
    pub fn pledged_ct_of(&self, account: Address) -> Result<Vec<u8>> {
        self.pledged_ct.get_bytes(&account).read()
    }

    /// The account's current modify-auth replay counter (the value a client must
    /// bind into its next write authorization).
    pub fn op_nonce_of(&self, account: Address) -> Result<u64> {
        self.op_nonce.read(&account)
    }

    pub(crate) fn pledge_ticket_ct_of(&self, handle: B256) -> Result<Vec<u8>> {
        self.pledge_lock_tickets.get_bytes(&handle).read()
    }

    // --- Writers (all `&self`; storage mutates through interior mutability) ---

    pub(crate) fn write_balance_ct(&self, account: Address, blob: &[u8]) -> Result<()> {
        self.balance_ct.get_bytes(&account).write(blob)
    }

    pub(crate) fn write_pledged_ct(&self, account: Address, blob: &[u8]) -> Result<()> {
        self.pledged_ct.get_bytes(&account).write(blob)
    }

    /// Write (or, with an empty `blob`, clear/delete) the encrypted pledge-lock-ticket
    /// under `handle`.
    pub(crate) fn write_pledge_ticket_ct(&self, handle: B256, blob: &[u8]) -> Result<()> {
        self.pledge_lock_tickets.get_bytes(&handle).write(blob)
    }

    pub(crate) fn set_op_nonce(&self, account: Address, nonce: u64) -> Result<()> {
        self.op_nonce.write(&account, nonce)
    }

    pub(crate) fn set_total_supply(&self, value: U256) -> Result<()> {
        self.total_supply.write(value)
    }

    pub(crate) fn set_pledged_total_supply(&self, value: U256) -> Result<()> {
        self.pledged_total_supply.write(value)
    }
}
