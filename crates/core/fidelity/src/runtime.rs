//! Fidelity runtime orchestration.
//!
//! RCFI/league are no longer computed on-chain: cohorts are encrypted and the
//! enclave is the sole evaluator. This layer reads/writes the cohort ciphertext
//! from committed storage and drives the enclave for the three flows -
//! cohort mutations ([`FidelityContract::cohort_in`]/[`FidelityContract::cohort_out`]),
//! the per-owner league snapshot ([`FidelityContract::snapshot_leagues`],
//! [`FidelityContract::league_at`]), and owner-authorized index queries
//! ([`FidelityContract::query_index_at`]). Only `max_rcfi_at` stays on-chain, as
//! a pure function of the plaintext `first_qualified_start` anchor.

use alloy_primitives::{Address, B256, U256};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_tee::protocol::{
    FidelityCohortOp, FidelityCohortRequest, FidelityOpOutcome, FidelityOpSection,
    FidelityQueryRequest, FidelityQueryResult, FidelitySnapshotEntry, FidelitySnapshotRequest,
};

use crate::enclave_client;
use crate::math::t_dec;
use crate::schema::FidelityContract;

fn chain_id_b256(storage: &StorageHandle<'_>) -> Result<B256> {
    Ok(B256::from(U256::from(storage.chain_id()?)))
}

impl FidelityContract<'_> {
    fn now(&self) -> Result<u64> {
        Ok(self.storage.timestamp()?.to::<u64>())
    }

    /// Build the cohort op section from committed storage (current blob + the
    /// plaintext global anchor), for folding into a co-located gratis op.
    pub fn cohort_section(
        &self,
        account: Address,
        op: FidelityCohortOp,
        timestamp: u64,
    ) -> Result<FidelityOpSection> {
        Ok(FidelityOpSection {
            op,
            timestamp,
            first_qualified_start: self.first_qualified_start()?,
            current_blob: self.cohorts_ct_of(account)?,
        })
    }

    /// Persist a cohort outcome (from a folded gratis op or the standalone
    /// path): store the new ciphertext and, on the account's first acquisition,
    /// anchor the global `first_qualified_start` (set-once). A probe outcome
    /// (empty blob, no init) is a no-op.
    pub fn apply_outcome(&self, account: Address, outcome: &FidelityOpOutcome) -> Result<()> {
        if !outcome.new_blob.is_empty() {
            self.write_cohorts_ct(account, &outcome.new_blob)?;
        }
        if let Some(ts) = outcome.qualified_start_initialized {
            self.init_first_qualified_start(ts)?;
        }
        Ok(())
    }

    fn run_cohort_op(
        &self,
        account: Address,
        amount: U256,
        op: FidelityCohortOp,
        timestamp: u64,
    ) -> Result<()> {
        // Zero-amount In/Out are no-ops (the enclave would also no-op); skip the
        // round-trip entirely so a zero mint/burn never touches the enclave.
        if amount.is_zero() {
            return Ok(());
        }
        let section = self.cohort_section(account, op, timestamp)?;
        let req = FidelityCohortRequest {
            chain_id: chain_id_b256(&self.storage)?,
            account,
            amount,
            section,
        };
        let result = enclave_client::apply_cohort_op(req)?;
        self.apply_outcome(account, &result.outcome)
    }

    /// ACQUISITION hook: record a new active gratis cohort for `account` at block
    /// time `timestamp` (seconds). No-op on a zero amount.
    pub fn cohort_in(&self, account: Address, amount: U256, timestamp: u64) -> Result<()> {
        self.run_cohort_op(account, amount, FidelityCohortOp::In, timestamp)
    }

    /// SALE hook: destroy `account`'s active cohorts LIFO at block time
    /// `timestamp` (seconds), logging the sold slices. No-op on a zero amount.
    pub fn cohort_out(&self, account: Address, amount: U256, timestamp: u64) -> Result<()> {
        self.run_cohort_op(account, amount, FidelityCohortOp::Out, timestamp)
    }

    /// Batch league snapshot: read each owner's cohort blob and ask the enclave
    /// for one plaintext league per owner (in `owners` order).
    pub fn snapshot_leagues(
        &self,
        timestamp: u64,
        owners: &[Address],
    ) -> Result<Vec<(Address, u16)>> {
        if owners.is_empty() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::with_capacity(owners.len());
        for owner in owners {
            entries.push(FidelitySnapshotEntry {
                owner: *owner,
                cohort_blob: self.cohorts_ct_of(*owner)?,
            });
        }
        let req = FidelitySnapshotRequest {
            timestamp,
            first_qualified_start: self.first_qualified_start()?,
            entries,
        };
        Ok(enclave_client::snapshot_leagues(req)?
            .into_iter()
            .map(|e| (e.owner, e.league))
            .collect())
    }

    /// League for `account` at `timestamp` (a single-owner snapshot).
    pub fn league_at(&self, account: Address, timestamp: u64) -> Result<u16> {
        self.snapshot_leagues(timestamp, &[account])?
            .first()
            .map(|(_, league)| *league)
            .ok_or_else(|| {
                PrecompileError::Fatal("fidelity snapshot returned no league".to_string())
            })
    }

    /// League for `account` at the current block time.
    pub fn league(&self, account: Address) -> Result<u16> {
        self.league_at(account, self.now()?)
    }

    /// Synthetic-max RCFI at `timestamp`: `t_dec(timestamp - first_qualified_start)`.
    /// Pure function of the plaintext anchor - computed on-chain, no enclave.
    /// Zero before any account has qualified.
    pub fn max_rcfi_at(&self, timestamp: u64) -> Result<U256> {
        let first = self.first_qualified_start()?;
        if first == 0 {
            return Ok(U256::ZERO);
        }
        Ok(t_dec(timestamp.saturating_sub(first)))
    }

    /// Owner-authorized RCFI/league query at `query_timestamp` (the eth_call
    /// path). The enclave verifies the signed, expiring, chain-scoped
    /// authorization before decrypting.
    pub fn query_index_at(
        &self,
        account: Address,
        query_timestamp: u64,
        expiry: u64,
        owner_sig: Vec<u8>,
    ) -> Result<FidelityQueryResult> {
        let req = FidelityQueryRequest {
            chain_id: chain_id_b256(&self.storage)?,
            account,
            cohort_blob: self.cohorts_ct_of(account)?,
            query_timestamp,
            block_timestamp: self.now()?,
            first_qualified_start: self.first_qualified_start()?,
            expiry,
            owner_sig,
        };
        enclave_client::query_index(req)
    }

    /// Owner-authorized RCFI/league query at the current block time.
    pub fn query_index_now(
        &self,
        account: Address,
        expiry: u64,
        owner_sig: Vec<u8>,
    ) -> Result<FidelityQueryResult> {
        self.query_index_at(account, self.now()?, expiry, owner_sig)
    }
}
