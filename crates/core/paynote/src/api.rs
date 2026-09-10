//! Cross-module API for the PayNote pool.
//!
//! In-process Rust surface for other precompile modules (gem, nod, …). This is
//! deliberately **not** a Solidity ABI: spending a note is a privileged
//! in-runtime transition, not something an EOA calls directly, so `consume`
//! never appears in `IPayNote.sol` and never routes through dispatch.
//!
//! Callers depend on this module, not on [`crate::runtime`] or
//! [`crate::state`]-level internals.

use alloy_primitives::B256;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::runtime;
use crate::schema::PayNoteContract;

pub use crate::runtime::PayNoteClaim;

/// Verify a `outbe.paynote@1.1.0` spend proof, nullify the note, append any
/// change commitment, and return the validated claim.
///
/// **Moves no tokens.** PayNote owns the tree, the nullifier set and the root
/// window; the caller decides what `claim.spend_amount` of `claim.asset` buys
/// and is responsible for paying `claim.spender`.
///
/// The claim comes from the proof itself, so the caller must check that
/// `claim.asset` and `claim.spend_amount` are what it expected before acting
/// on them — a valid proof for the *wrong* asset is still a valid proof.
///
/// Reverts if the tree is uninitialized, the chain ID does not match, the root
/// is outside the acceptance window, the nullifier is already spent, or the
/// proof fails verification. The nullifier write and the change append are one
/// rollback unit with the caller's own effects.
pub fn consume(storage: &StorageHandle<'_>, proof: &[u8]) -> Result<PayNoteClaim> {
    runtime::consume(storage, proof)
}

/// Whether `root` is inside the acceptance window. Useful for pre-flighting a
/// spend before committing to the gas of full verification.
pub fn is_known_root(storage: &StorageHandle<'_>, root: B256) -> Result<bool> {
    let paynote: PayNoteContract<'_> = storage.contract();
    Ok(paynote.recent_roots.read_all()?.contains(&root))
}

/// Whether `nullifier` has already been spent.
pub fn is_spent(storage: &StorageHandle<'_>, nullifier: B256) -> Result<bool> {
    let paynote: PayNoteContract<'_> = storage.contract();
    paynote.spent_nullifiers.read(&nullifier)
}
