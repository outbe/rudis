//! Enclave-side Fidelity cohort engine (secret-bearing).
//!
//! The Fidelity cohort ledger (the Gratis movement history) lives on-chain as
//! one AEAD blob per account under the [`crate::confidential::FIDELITY`]
//! domain, so its keys are cryptographically independent from Gratis's and
//! Promis's. This module is the only place cohorts exist in plaintext:
//!
//! - cohort mutations ride inside the co-located Gratis op
//!   ([`apply_cohort_section`], from the `ApplyGratisOp` dispatch);
//! - the once-per-WWD metadosis league snapshot batch-decrypts the day's
//!   owners ([`snapshot_leagues`]);
//! - owner-authorized `eth_call` queries evaluate RCFI in place
//!   ([`query_index`], gated by a signed, expiring authorization - never a raw
//!   view key).
//!
//! The RCFI arithmetic is `outbe_fidelity_math` - the exact accumulator the
//! chain historically ran over plaintext cohorts - so the two evaluation paths
//! cannot drift. Every function is a pure transform of its inputs + the
//! resident state key (consensus determinism); business failures return
//! structured errors, never panics.

use alloy_primitives::{Address, B256, U256};

use outbe_fidelity_math::{league_from_rcfi, t_dec, RcfiAccumulator};
use outbe_tee::protocol::{
    eip191_hash, fidelity_cohort_canonical_hash, fidelity_query_auth_message,
    fidelity_query_canonical_hash, FidelityCohortOp, FidelityCohortRequest, FidelityCohortResult,
    FidelityLeagueEntry, FidelityOpOutcome, FidelityOpSection, FidelityQueryRequest,
    FidelityQueryResult, FidelitySnapshotRequest,
};

use crate::confidential::FIDELITY;
use crate::errors::{Result, TeeError};

/// Cohort-ledger blob field tag folded into the nonce derivation. Tag 0 is safe
/// here despite Gratis also using 0 for balances: the FIDELITY domain derives
/// independent keys.
pub const FIELD_COHORTS: u8 = 0;

/// Interior header: `qualified_start(8) || active_count(4) || sold_count(4)`.
const HEADER_LEN: usize = 16;
/// `size(32) || acquired_at(8)`.
const ACTIVE_ENTRY_LEN: usize = 40;
/// `size(32) || acquired_at(8) || sold_at(8)`.
const SOLD_ENTRY_LEN: usize = 48;
/// Smallest padding bucket (in combined cohort count).
const MIN_BUCKET: usize = 8;

/// Derive the resident Fidelity state key from the DKG group signature. See
/// [`crate::confidential::Domain::derive_state_key`].
pub fn derive_fidelity_state_key(group_sig: &[u8], chain_id: B256, epoch: u64) -> Result<[u8; 32]> {
    FIDELITY.derive_state_key(group_sig, chain_id, epoch)
}

fn err(msg: impl Into<String>) -> TeeError {
    TeeError::Fidelity(msg.into())
}

/// Plaintext cohort ledger of one account - the decrypted blob interior.
///
/// `active` is a LIFO stack of acquisitions `(size, acquired_at)`; `sold` an
/// append-only log `(size, acquired_at, sold_at)`. Semantics are a 1:1 port of
/// the historical on-chain `FidelityContract::cohort_in/cohort_out`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct CohortState {
    qualified_start: u64,
    active: Vec<(U256, u64)>,
    sold: Vec<(U256, u64, u64)>,
}

impl CohortState {
    /// Decode a blob interior. Empty interior = fresh account. Trailing bytes
    /// beyond the declared entries are padding and ignored.
    fn decode(interior: &[u8]) -> Result<Self> {
        if interior.is_empty() {
            return Ok(Self::default());
        }
        if interior.len() < HEADER_LEN {
            return Err(err("cohort interior shorter than header"));
        }
        let mut u64buf = [0u8; 8];
        u64buf.copy_from_slice(&interior[..8]);
        let qualified_start = u64::from_be_bytes(u64buf);
        let mut u32buf = [0u8; 4];
        u32buf.copy_from_slice(&interior[8..12]);
        let active_count = u32::from_be_bytes(u32buf) as usize;
        u32buf.copy_from_slice(&interior[12..16]);
        let sold_count = u32::from_be_bytes(u32buf) as usize;

        let need = active_count
            .checked_mul(ACTIVE_ENTRY_LEN)
            .zip(sold_count.checked_mul(SOLD_ENTRY_LEN))
            .and_then(|(a, s)| a.checked_add(s))
            .and_then(|e| e.checked_add(HEADER_LEN))
            .ok_or_else(|| err("cohort counts overflow"))?;
        if interior.len() < need {
            return Err(err("cohort interior truncated"));
        }

        let mut offset = HEADER_LEN;
        let mut active = Vec::with_capacity(active_count);
        for _ in 0..active_count {
            let size = U256::from_be_slice(&interior[offset..offset + 32]);
            u64buf.copy_from_slice(&interior[offset + 32..offset + 40]);
            active.push((size, u64::from_be_bytes(u64buf)));
            offset += ACTIVE_ENTRY_LEN;
        }
        let mut sold = Vec::with_capacity(sold_count);
        for _ in 0..sold_count {
            let size = U256::from_be_slice(&interior[offset..offset + 32]);
            u64buf.copy_from_slice(&interior[offset + 32..offset + 40]);
            let acquired_at = u64::from_be_bytes(u64buf);
            u64buf.copy_from_slice(&interior[offset + 40..offset + 48]);
            sold.push((size, acquired_at, u64::from_be_bytes(u64buf)));
            offset += SOLD_ENTRY_LEN;
        }
        Ok(Self {
            qualified_start,
            active,
            sold,
        })
    }

    /// Encode, zero-padded to the next combined-count bucket (8, 16, 32, ...) so
    /// the ciphertext length leaks only a coarse cohort-count bucket. The
    /// combined count never decreases (a full-consume moves active -> sold), so
    /// the blob length is monotone and changes only at bucket crossings.
    fn encode_padded(&self) -> Result<Vec<u8>> {
        let active_count =
            u32::try_from(self.active.len()).map_err(|_| err("active cohort count overflow"))?;
        let sold_count =
            u32::try_from(self.sold.len()).map_err(|_| err("sold cohort count overflow"))?;
        let total = self.active.len() + self.sold.len();
        let bucket = total.max(MIN_BUCKET).next_power_of_two();
        let target = HEADER_LEN + bucket * SOLD_ENTRY_LEN;

        let mut out = Vec::with_capacity(target);
        out.extend_from_slice(&self.qualified_start.to_be_bytes());
        out.extend_from_slice(&active_count.to_be_bytes());
        out.extend_from_slice(&sold_count.to_be_bytes());
        for (size, acquired_at) in &self.active {
            out.extend_from_slice(&size.to_be_bytes::<32>());
            out.extend_from_slice(&acquired_at.to_be_bytes());
        }
        for (size, acquired_at, sold_at) in &self.sold {
            out.extend_from_slice(&size.to_be_bytes::<32>());
            out.extend_from_slice(&acquired_at.to_be_bytes());
            out.extend_from_slice(&sold_at.to_be_bytes());
        }
        out.resize(target.max(out.len()), 0);
        Ok(out)
    }

    /// ACQUISITION: push a new active cohort. Returns `Some(timestamp)` when
    /// this is the account's first qualified acquisition.
    fn cohort_in(&mut self, amount: U256, timestamp: u64) -> Option<u64> {
        if amount.is_zero() {
            return None;
        }
        let initialized = if self.qualified_start == 0 {
            self.qualified_start = timestamp;
            Some(timestamp)
        } else {
            None
        };
        self.active.push((amount, timestamp));
        initialized
    }

    /// SALE: consume active cohorts LIFO (youngest first). The boundary cohort
    /// is split proportionally - the sold slice keeps the ORIGINAL
    /// `acquired_at`, the remainder stays active. Clamps when the stack runs
    /// out (mirrors the on-chain defensive clamp).
    fn cohort_out(&mut self, amount: U256, timestamp: u64) {
        let mut remaining = amount;
        while !remaining.is_zero() {
            let Some((size, acquired_at)) = self.active.last().copied() else {
                break;
            };
            if size <= remaining {
                self.active.pop();
                self.sold.push((size, acquired_at, timestamp));
                remaining -= size;
            } else {
                self.sold.push((remaining, acquired_at, timestamp));
                if let Some(last) = self.active.last_mut() {
                    last.0 = size - remaining;
                }
                remaining = U256::ZERO;
            }
        }
    }

    /// `(rcfi, efficiency, league)` at `timestamp` - the same
    /// `RcfiAccumulator` + `league_from_rcfi` pipeline the chain historically
    /// ran over plaintext cohort slots.
    fn rcfi_triple(&self, timestamp: u64) -> Result<(U256, U256, U256)> {
        let mut acc = RcfiAccumulator::default();
        for (size, acquired_at) in &self.active {
            acc.add_active(*size, *acquired_at, timestamp)
                .ok_or_else(|| err("rcfi arithmetic overflow"))?;
        }
        for (size, acquired_at, sold_at) in &self.sold {
            acc.add_sold(*size, *acquired_at, *sold_at, timestamp)
                .ok_or_else(|| err("rcfi arithmetic overflow"))?;
        }
        acc.finish(self.qualified_start, timestamp)
            .ok_or_else(|| err("rcfi arithmetic overflow"))
    }

    /// `(rcfi, efficiency, league)` at `timestamp`. `first_qualified_start = 0`
    /// means no account has qualified (league floor).
    fn evaluate(&self, timestamp: u64, first_qualified_start: u64) -> Result<(U256, U256, u16)> {
        let (rcfi, efficiency, _) = self.rcfi_triple(timestamp)?;
        let max = if first_qualified_start == 0 {
            U256::ZERO
        } else {
            t_dec(timestamp.saturating_sub(first_qualified_start))
        };
        let league =
            league_from_rcfi(rcfi, max).ok_or_else(|| err("league arithmetic overflow"))?;
        Ok((rcfi, efficiency, league))
    }
}

fn read_state(view_key: &[u8; 32], account: Address, blob: &[u8]) -> Result<(u64, CohortState)> {
    let (version, interior) = FIDELITY.read_blob(view_key, account, FIELD_COHORTS, blob)?;
    Ok((version, CohortState::decode(&interior)?))
}

/// Apply the Fidelity section of a Gratis op: decrypt the account's cohort
/// blob, mutate (or just probe), re-encrypt, and report the plaintext receipt.
/// `amount` is the Gratis op's own amount. Errors reject the whole combined op.
pub fn apply_cohort_section(
    state_key: &[u8; 32],
    account: Address,
    amount: U256,
    section: &FidelityOpSection,
) -> Result<FidelityOpOutcome> {
    let view_key = FIDELITY.derive_view_key(state_key, account)?;
    let (version, mut state) = read_state(&view_key, account, &section.current_blob)?;

    let mut qualified_start_initialized = None;
    match section.op {
        FidelityCohortOp::In => {
            qualified_start_initialized = state.cohort_in(amount, section.timestamp);
        }
        FidelityCohortOp::Out => state.cohort_out(amount, section.timestamp),
        FidelityCohortOp::Probe => {}
    }

    // If this very op qualified the account first on the whole chain, the host
    // will set the global scalar to the section timestamp - evaluate the league
    // against that same anchor.
    let effective_first = if section.first_qualified_start != 0 {
        section.first_qualified_start
    } else {
        qualified_start_initialized.unwrap_or(0)
    };
    let (_, _, league) = state.evaluate(section.timestamp, effective_first)?;

    let new_blob = match section.op {
        // Probe never rewrites the ledger - empty means "nothing to write".
        FidelityCohortOp::Probe => Vec::new(),
        FidelityCohortOp::In | FidelityCohortOp::Out => FIDELITY.write_blob(
            &view_key,
            account,
            FIELD_COHORTS,
            version,
            &state.encode_padded()?,
        )?,
    };
    Ok(FidelityOpOutcome {
        new_blob,
        qualified_start_initialized,
        league,
    })
}

/// Apply a STANDALONE cohort op (its own round-trip). Thin wrapper over
/// [`apply_cohort_section`] that sets the canonical inputs hash; the caller
/// (dispatch) signs `attestation_tag`. Errors surface as an enclave error ->
/// host `Fatal`.
pub fn apply_cohort_op(
    state_key: &[u8; 32],
    req: &FidelityCohortRequest,
) -> Result<FidelityCohortResult> {
    let outcome = apply_cohort_section(state_key, req.account, req.amount, &req.section)?;
    Ok(FidelityCohortResult {
        outcome,
        inputs_canonical_hash: fidelity_cohort_canonical_hash(req),
        attestation_tag: Vec::new(),
    })
}

/// Batch-decrypt the day's owners and return one plaintext league per owner, in
/// request order - metadosis's once-per-WWD snapshot. A single undecryptable
/// blob fails the whole batch (state corruption must be loud and deterministic,
/// not silently skipped).
pub fn snapshot_leagues(
    state_key: &[u8; 32],
    req: &FidelitySnapshotRequest,
) -> Result<Vec<FidelityLeagueEntry>> {
    let mut leagues = Vec::with_capacity(req.entries.len());
    for entry in &req.entries {
        let view_key = FIDELITY.derive_view_key(state_key, entry.owner)?;
        let (_, state) = read_state(&view_key, entry.owner, &entry.cohort_blob)?;
        let (_, _, league) = state.evaluate(req.timestamp, req.first_qualified_start)?;
        leagues.push(FidelityLeagueEntry {
            owner: entry.owner,
            league,
        });
    }
    Ok(leagues)
}

/// Owner-authorized RCFI/league read. Verifies the signed authorization INSIDE
/// the enclave (the trust boundary - a compromised host reaches this transport
/// directly), then decrypts and evaluates. `resident_chain_id` is the enclave's
/// own boot-bound chain id, passed by the dispatch - NOT taken from the
/// host-controlled request.
///
/// Chain binding: the auth message embeds a chain id, but the state key is
/// derived from `resident_chain_id`, so a signature made for a different chain
/// (same reused EOA on devnet/testnet) must not authorize a read here. We reject
/// unless `req.chain_id == resident_chain_id` and only then hash the signed
/// message - otherwise the host could set `req.chain_id` to whatever the
/// captured signature covered and defeat the scoping.
///
/// Freshness caveat: `expiry` is checked against the host-supplied
/// `block_timestamp`. The enclave has no trusted clock on this non-consensus
/// `eth_call` path, so expiry only bounds a leaked signature for requests
/// forwarded by an HONEST host; a fully compromised host can pass
/// `block_timestamp = 0` and reuse a stale (but genuine) signature indefinitely.
/// It can still never forge a signature or decrypt raw cohorts - only re-read
/// the derived index/league the owner already exposed by signing.
pub fn query_index(
    state_key: &[u8; 32],
    resident_chain_id: B256,
    req: &FidelityQueryRequest,
) -> Result<FidelityQueryResult> {
    if req.chain_id != resident_chain_id {
        return Err(err("query authorization is for a different chain"));
    }
    if req.expiry < req.block_timestamp {
        return Err(err("query authorization expired"));
    }
    let Ok(sig65) = <[u8; 65]>::try_from(req.owner_sig.as_slice()) else {
        return Err(err("owner signature must be 65 bytes"));
    };
    let prehash = eip191_hash(&fidelity_query_auth_message(
        resident_chain_id,
        req.account,
        req.expiry,
    ));
    match outbe_primitives::tee_signatures::recover_signer(&prehash, &sig65) {
        Ok(signer) if signer == req.account => {}
        _ => return Err(err("owner signature does not control account")),
    }

    let view_key = FIDELITY.derive_view_key(state_key, req.account)?;
    let (_, state) = read_state(&view_key, req.account, &req.cohort_blob)?;
    let (rcfi, efficiency, league) =
        state.evaluate(req.query_timestamp, req.first_qualified_start)?;
    Ok(FidelityQueryResult {
        rcfi,
        efficiency,
        league,
        inputs_canonical_hash: fidelity_query_canonical_hash(req),
        attestation_tag: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbe_fidelity_math::{MAX_LEAGUE, MIN_LEAGUE};

    const CHAIN: B256 = B256::repeat_byte(0xC2);
    const DAY: u64 = 86_400;

    fn state_key() -> [u8; 32] {
        derive_fidelity_state_key(b"a-group-threshold-signature-~48-bytes-long!!", CHAIN, 0)
            .unwrap()
    }
    fn alice() -> Address {
        Address::repeat_byte(0x11)
    }
    fn section(
        op: FidelityCohortOp,
        timestamp: u64,
        first: u64,
        blob: Vec<u8>,
    ) -> FidelityOpSection {
        FidelityOpSection {
            op,
            timestamp,
            first_qualified_start: first,
            current_blob: blob,
        }
    }

    /// Known-answer vectors pinning the FIDELITY domain byte layout: the state
    /// key derivation, one cohort blob, and the query-auth preimage hash. Any
    /// change to an HKDF label, the interior/padding layout, or the auth
    /// message would make persisted on-chain cohort ciphertext undecryptable or
    /// split query auth between host and enclave. Regenerate only on an
    /// intentional, reviewed format change.
    #[test]
    fn fidelity_known_answer_vectors() {
        let sk = state_key();
        let sk_hex = hex::encode(sk);

        let mut state = CohortState::default();
        assert_eq!(
            state.cohort_in(U256::from(1_000u64), 1_000_000),
            Some(1_000_000)
        );
        state.cohort_out(U256::from(400u64), 1_000_000 + 30 * DAY);
        let vk = FIDELITY.derive_view_key(&sk, alice()).unwrap();
        let blob = FIDELITY
            .write_blob(
                &vk,
                alice(),
                FIELD_COHORTS,
                0,
                &state.encode_padded().unwrap(),
            )
            .unwrap();
        let blob_hex = hex::encode(&blob);

        let auth_hash = hex::encode(eip191_hash(&fidelity_query_auth_message(
            CHAIN,
            alice(),
            2_000_000,
        )));

        // To regenerate: `cargo test -p outbe-tee-enclave fidelity_known_answer -- --nocapture`
        // with the asserts commented out, then paste.
        assert_eq!(
            sk_hex,
            "445d55ec5e634dcf92522bc31a29b3e6f83696ab70796158b42c06f6dac47b62"
        );
        assert_eq!(
            blob_hex,
            concat!(
                "0000000000000001bab8f027ea4c23fb2647e47a7b4c083f629c78edda01c85f",
                "e843b5587fb6e44aed5bed96352c60681344985aaf0e97514903bc7c79e7b5bc",
                "6d63f981f94440125954e08368b42f97227dc1b813ba02097de37864f1fa62e9",
                "7dbbeac17ef19a6525b0ee10d4679359cfdd8020e557708ea0e4f1be1a78a979",
                "dee60f7d476544a2c89ae0ed54adb2df4eeb447ca8cfe0e42a2b495038e30f27",
                "a75924e982d4dd0c9a7829cb5e0e6b420b551099bb30c65d34694ede1da2d742",
                "267eb65747ec2cb880377706faf005ab70dce63121528904a7bbbed3b74f91be",
                "a62c94d792311aa1b2003dd8ffd0d733e947db6e1b1672a6caf5bebaf418d658",
                "2f8a90efa82a7d77a92f3b378f2b5847a068f1f5310837580794834a51954a1f",
                "e658c8c17ccf4a81f46401fbe1af7aa53915f60cfb8ab55c3da57e0a513c53ec",
                "51bbabb4f08bc6459d13f92ff92174847ae2ad41af456d5103e6b980acd80896",
                "ac8aad54a3cdb727d02bab5baea1428f9b5bcc97573f378a2c8d7f0b462bbdff",
                "6559059dae38dfe5af446f1d8b6d073f4753417547095e62ac1fd8f22913509b",
                "c0332ac01ae25ff9"
            )
        );
        assert_eq!(
            auth_hash,
            "ec33700aff11e6138f687c7b5c76c10df507673f9a56a4d3e4676d171166fe45"
        );
    }

    #[test]
    fn blob_roundtrip_and_padding_bucket() {
        let mut state = CohortState::default();
        state.cohort_in(U256::from(500u64), 100);
        state.cohort_in(U256::from(700u64), 200);
        state.cohort_out(U256::from(600u64), 300);
        let encoded = state.encode_padded().unwrap();
        // 3 active+sold cohorts -> bucket 8.
        assert_eq!(encoded.len(), HEADER_LEN + 8 * SOLD_ENTRY_LEN);
        assert_eq!(CohortState::decode(&encoded).unwrap(), state);

        // 9 combined -> bucket 16.
        for i in 0..7 {
            state.cohort_in(U256::from(1u64), 400 + i);
        }
        let bigger = state.encode_padded().unwrap();
        assert_eq!(bigger.len(), HEADER_LEN + 16 * SOLD_ENTRY_LEN);
        assert_eq!(CohortState::decode(&bigger).unwrap(), state);
    }

    #[test]
    fn lifo_split_preserves_original_acquired_at() {
        let mut state = CohortState::default();
        state.cohort_in(U256::from(1_000u64), 100);
        state.cohort_in(U256::from(500u64), 200);
        // Consume 700: full-consume the youngest (500 @200), split 200 off the
        // older (1000 @100) - sold slice keeps acquired_at 100.
        state.cohort_out(U256::from(700u64), 300);
        assert_eq!(state.active, vec![(U256::from(800u64), 100)]);
        assert_eq!(
            state.sold,
            vec![
                (U256::from(500u64), 200, 300),
                (U256::from(200u64), 100, 300)
            ]
        );
        // Over-consume clamps at an empty stack, mirroring the on-chain guard.
        state.cohort_out(U256::from(10_000u64), 400);
        assert!(state.active.is_empty());
        assert_eq!(state.sold.len(), 3);
    }

    #[test]
    fn evaluate_matches_direct_accumulator() {
        let mut state = CohortState::default();
        state.cohort_in(U256::from(1_000u64), 1_000_000);
        state.cohort_in(U256::from(500u64), 1_000_000 + 100 * DAY);
        state.cohort_out(U256::from(700u64), 1_000_000 + 200 * DAY);
        let now = 1_000_000 + 400 * DAY;

        let mut acc = RcfiAccumulator::default();
        for (s, a) in &state.active {
            acc.add_active(*s, *a, now).unwrap();
        }
        for (s, a, so) in &state.sold {
            acc.add_sold(*s, *a, *so, now).unwrap();
        }
        let (rcfi, eff, _) = acc.finish(state.qualified_start, now).unwrap();
        let max = t_dec(now - 1_000_000);
        let expected_league = league_from_rcfi(rcfi, max).unwrap();

        let (got_rcfi, got_eff, got_league) = state.evaluate(now, 1_000_000).unwrap();
        assert_eq!(got_rcfi, rcfi);
        assert_eq!(got_eff, eff);
        assert_eq!(got_league, expected_league);
        assert!((MIN_LEAGUE..=MAX_LEAGUE).contains(&got_league));
    }

    #[test]
    fn apply_section_roundtrips_through_encryption() {
        let sk = state_key();
        let s_in = section(FidelityCohortOp::In, 1_000_000, 0, Vec::new());
        let out_in = apply_cohort_section(&sk, alice(), U256::from(1_000u64), &s_in).unwrap();
        assert_eq!(out_in.qualified_start_initialized, Some(1_000_000));
        assert!(!out_in.new_blob.is_empty());
        // Global anchor was just set by this op -> league floor.
        assert_eq!(out_in.league, MIN_LEAGUE);

        // Second acquisition: existing qualified_start, global anchor known.
        let s_in2 = section(
            FidelityCohortOp::In,
            1_000_000 + 100 * DAY,
            1_000_000,
            out_in.new_blob.clone(),
        );
        let out_in2 = apply_cohort_section(&sk, alice(), U256::from(500u64), &s_in2).unwrap();
        assert_eq!(out_in2.qualified_start_initialized, None);
        // Sole holder, no sales -> top league.
        assert_eq!(out_in2.league, MAX_LEAGUE);

        // Probe: no rewrite, same league as the state it probed.
        let s_probe = section(
            FidelityCohortOp::Probe,
            1_000_000 + 100 * DAY,
            1_000_000,
            out_in2.new_blob.clone(),
        );
        let probe = apply_cohort_section(&sk, alice(), U256::ZERO, &s_probe).unwrap();
        assert!(probe.new_blob.is_empty());
        assert_eq!(probe.league, MAX_LEAGUE);

        // Sale drops efficiency below 1 -> league falls under the ceiling.
        let s_out = section(
            FidelityCohortOp::Out,
            1_000_000 + 200 * DAY,
            1_000_000,
            out_in2.new_blob.clone(),
        );
        let out_out = apply_cohort_section(&sk, alice(), U256::from(1_200u64), &s_out).unwrap();
        assert!(out_out.league < MAX_LEAGUE);

        // Determinism: identical inputs -> identical outcome (byte-identical blob).
        let again = apply_cohort_section(&sk, alice(), U256::from(1_200u64), &s_out).unwrap();
        assert_eq!(again, out_out);
    }

    #[test]
    fn snapshot_orders_and_defaults() {
        let sk = state_key();
        let bob = Address::repeat_byte(0x22);
        let s_in = section(FidelityCohortOp::In, 1_000_000, 0, Vec::new());
        let minted = apply_cohort_section(&sk, alice(), U256::from(1_000u64), &s_in).unwrap();

        let req = FidelitySnapshotRequest {
            timestamp: 1_000_000 + 50 * DAY,
            first_qualified_start: 1_000_000,
            entries: vec![
                outbe_tee::protocol::FidelitySnapshotEntry {
                    owner: alice(),
                    cohort_blob: minted.new_blob,
                },
                // Bob has no cohort state - league floor, not an error.
                outbe_tee::protocol::FidelitySnapshotEntry {
                    owner: bob,
                    cohort_blob: Vec::new(),
                },
            ],
        };
        let leagues = snapshot_leagues(&sk, &req).unwrap();
        assert_eq!(leagues.len(), 2);
        assert_eq!(leagues[0].owner, alice());
        assert_eq!(leagues[0].league, MAX_LEAGUE);
        assert_eq!(leagues[1].owner, bob);
        assert_eq!(leagues[1].league, MIN_LEAGUE);

        // Tampered ciphertext fails the whole batch, loudly.
        let mut bad = req.clone();
        if let Some(b) = bad.entries[0].cohort_blob.last_mut() {
            *b ^= 1;
        }
        assert!(snapshot_leagues(&sk, &bad).is_err());
    }

    /// 1e18-scaled fixed point -> f64 (via micro-units to avoid precision loss).
    fn fp_to_f64(fp: U256) -> f64 {
        let micros: u128 = (fp / U256::from(1_000_000_000_000u128)).to::<u128>();
        micros as f64 / 1_000_000.0
    }

    /// Golden replay of the PDF `reference/decay.py` scenario through the enclave
    /// `CohortState` port - the on-chain math moved here, so this is where the
    /// float-model agreement is pinned (+/-1 decayed day, +/-1e-3 efficiency). The
    /// fixture lives in the fidelity crate (regenerated from `decay.py`); we read
    /// it across the workspace rather than duplicate the generated artifact.
    #[test]
    fn golden_matches_decay_py_reference() {
        let raw = include_str!("../../../crates/core/fidelity/tests/fixtures/rcfi_golden.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let txs: Vec<(u64, bool, U256)> = v["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["ts"].as_u64().unwrap(),
                    t["kind"].as_str().unwrap() == "deposit",
                    t["amount_units"].as_str().unwrap().parse::<U256>().unwrap(),
                )
            })
            .collect();
        let samples = v["samples"].as_array().unwrap();
        assert!(!samples.is_empty());

        for s in samples {
            let ts = s["ts"].as_u64().unwrap();
            let want_rcfi = s["rcfi"].as_f64().unwrap();
            let want_eff = s["efficiency"].as_f64().unwrap();
            let want_dage = s["d_age"].as_f64().unwrap();

            // Rebuild state from every tx up to and including the sample instant,
            // mirroring the reference's `tx.date <= current_date` loop.
            let mut state = CohortState::default();
            for (t_ts, deposit, amount) in &txs {
                if *t_ts <= ts {
                    if *deposit {
                        state.cohort_in(*amount, *t_ts);
                    } else {
                        state.cohort_out(*amount, *t_ts);
                    }
                }
            }
            let (rcfi_fp, eff_fp, dage_fp) = state.rcfi_triple(ts).unwrap();
            assert!(
                (fp_to_f64(rcfi_fp) - want_rcfi).abs() <= 1.0,
                "rcfi at ts={ts}: got {}, want {want_rcfi}",
                fp_to_f64(rcfi_fp)
            );
            assert!(
                (fp_to_f64(eff_fp) - want_eff).abs() <= 1e-3,
                "efficiency at ts={ts}: got {}, want {want_eff}",
                fp_to_f64(eff_fp)
            );
            assert!(
                (fp_to_f64(dage_fp) - want_dage).abs() <= 1.0,
                "d_age at ts={ts}: got {}, want {want_dage}",
                fp_to_f64(dage_fp)
            );
        }
    }

    /// Deterministic secp256k1 signer and its EVM address (mirrors the
    /// transport tests' helper).
    fn evm_signer(seed: u8) -> (k256::ecdsa::SigningKey, Address) {
        let sk = k256::ecdsa::SigningKey::from_slice(&outbe_primitives::test_keys::secret(
            (seed) as u64,
        ))
        .unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let addr = Address::from_slice(&alloy_primitives::keccak256(&point.as_bytes()[1..])[12..]);
        (sk, addr)
    }

    /// EIP-191 owner signature over the query-auth message for `chain_id`.
    fn query_sig(
        signer: &k256::ecdsa::SigningKey,
        chain_id: B256,
        account: Address,
        expiry: u64,
    ) -> Vec<u8> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let prehash = eip191_hash(&fidelity_query_auth_message(chain_id, account, expiry));
        let (sig, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            signer.sign_prehash(prehash.as_slice()).unwrap();
        let mut sig65 = [0u8; 65];
        sig65[..64].copy_from_slice(sig.to_bytes().as_slice());
        sig65[64] = recid.to_byte();
        sig65.to_vec()
    }

    fn query_req(
        chain_id: B256,
        account: Address,
        blob: Vec<u8>,
        expiry: u64,
        block_ts: u64,
        sig: Vec<u8>,
    ) -> FidelityQueryRequest {
        FidelityQueryRequest {
            chain_id,
            account,
            cohort_blob: blob,
            query_timestamp: 1_000_000 + 100 * DAY,
            block_timestamp: block_ts,
            first_qualified_start: 1_000_000,
            expiry,
            owner_sig: sig,
        }
    }

    #[test]
    fn query_happy_path_matches_snapshot_evaluation() {
        let sk = state_key();
        let (signer, account) = evm_signer(0x33);
        let minted = apply_cohort_section(
            &sk,
            account,
            U256::from(1_000u64),
            &section(FidelityCohortOp::In, 1_000_000, 0, Vec::new()),
        )
        .unwrap();

        let sig = query_sig(&signer, CHAIN, account, 2_000_000);
        let req = query_req(CHAIN, account, minted.new_blob, 2_000_000, 1_500_000, sig);
        let out = query_index(&sk, CHAIN, &req).unwrap();
        // Sole holder, no sales -> top league; rcfi > 0.
        assert_eq!(out.league, MAX_LEAGUE);
        assert!(out.rcfi > U256::ZERO);
    }

    #[test]
    fn query_rejects_foreign_chain_signature() {
        // The core regression: a signature made for a DIFFERENT chain (same
        // reused EOA) must not authorize a read on this enclave's chain, even
        // though the host sets req.chain_id to the foreign value.
        let sk = state_key();
        let (signer, account) = evm_signer(0x44);
        let minted = apply_cohort_section(
            &sk,
            account,
            U256::from(1_000u64),
            &section(FidelityCohortOp::In, 1_000_000, 0, Vec::new()),
        )
        .unwrap();

        let foreign_chain = B256::repeat_byte(0xEE);
        let sig = query_sig(&signer, foreign_chain, account, 2_000_000);
        // Host forwards the foreign chain_id it matches the signature to.
        let req = query_req(
            foreign_chain,
            account,
            minted.new_blob,
            2_000_000,
            1_500_000,
            sig,
        );
        // Resident chain is CHAIN, not foreign_chain -> rejected before decrypt.
        assert!(query_index(&sk, CHAIN, &req).is_err());
    }

    #[test]
    fn query_rejects_wrong_signer_expiry_and_bad_length() {
        let sk = state_key();
        let (signer, account) = evm_signer(0x55);
        let (other, _) = evm_signer(0x56);
        let minted = apply_cohort_section(
            &sk,
            account,
            U256::from(1_000u64),
            &section(FidelityCohortOp::In, 1_000_000, 0, Vec::new()),
        )
        .unwrap();

        // Wrong signer (other's key over account's message).
        let bad_signer = query_sig(&other, CHAIN, account, 2_000_000);
        let req = query_req(
            CHAIN,
            account,
            minted.new_blob.clone(),
            2_000_000,
            1_500_000,
            bad_signer,
        );
        assert!(query_index(&sk, CHAIN, &req).is_err());

        // Expired: expiry < block_timestamp.
        let good = query_sig(&signer, CHAIN, account, 1_000);
        let req = query_req(
            CHAIN,
            account,
            minted.new_blob.clone(),
            1_000,
            1_500_000,
            good,
        );
        assert!(query_index(&sk, CHAIN, &req).is_err());

        // Malformed signature length.
        let req = query_req(
            CHAIN,
            account,
            minted.new_blob,
            2_000_000,
            1_500_000,
            vec![0u8; 10],
        );
        assert!(query_index(&sk, CHAIN, &req).is_err());
    }
}
