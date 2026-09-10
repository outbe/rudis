//! Enclave-side Promis confidential balance engine (secret-bearing).
//!
//! The Promis analogue of [`crate::gratis`], restricted to Mint/Burn over an
//! encrypted per-account balance - Promis has no pledge/credis machinery. All key
//! derivation, amount AEAD, and modify-auth verification is the shared
//! [`crate::confidential`] core under the [`crate::confidential::PROMIS`] domain,
//! so Promis keys are cryptographically independent from Gratis's. Every function
//! is a pure transform of its inputs + the resident state key (consensus
//! determinism).

use alloy_primitives::{Address, B256, U256};

use outbe_tee::protocol::{PromisOp, PromisOpRequest, PromisOpResult, PromisOpStatus};

use crate::confidential::{FIELD_BALANCE, PROMIS};
use crate::errors::Result;

/// Derive the resident Promis state key from the DKG group signature. See
/// [`crate::confidential::Domain::derive_state_key`].
pub fn derive_promis_state_key(group_sig: &[u8], chain_id: B256, epoch: u64) -> Result<[u8; 32]> {
    PROMIS.derive_state_key(group_sig, chain_id, epoch)
}

/// Per-account view key: read capability AND the AEAD key for the account's
/// balance blob. See [`crate::confidential::Domain::derive_view_key`].
pub fn derive_view_key(state_key: &[u8; 32], account: Address) -> Result<[u8; 32]> {
    PROMIS.derive_view_key(state_key, account)
}

/// Per-account modify key: authorizes writes (via HMAC); never decrypts state.
/// See [`crate::confidential::Domain::derive_modify_key`].
pub fn derive_modify_key(state_key: &[u8; 32], account: Address) -> Result<[u8; 32]> {
    PROMIS.derive_modify_key(state_key, account)
}

/// `HMAC-SHA256(modify_key, preimage)` - the write authorization the client sends
/// and the enclave re-checks. See [`crate::confidential::Domain::modify_mac`].
pub fn modify_mac(
    modify_key: &[u8; 32],
    account: Address,
    op: PromisOp,
    amount: U256,
    op_nonce: u64,
    chain_id: B256,
) -> [u8; 32] {
    PROMIS.modify_mac(modify_key, account, op as u8, amount, op_nonce, chain_id)
}

/// Client-side helper: decrypt an account's Promis balance blob with its view key
/// (the key delivered by `DeriveAccountKeys`). Same primitive the enclave uses, so
/// a client reproduces the plaintext without ever touching the state key.
pub fn decrypt_balance(view_key: &[u8; 32], account: Address, blob: &[u8]) -> Result<U256> {
    PROMIS
        .read_amount(view_key, account, FIELD_BALANCE, blob)
        .map(|(_, v)| v)
}

fn base_result() -> PromisOpResult {
    PromisOpResult {
        status: PromisOpStatus::Applied,
        new_balance: Vec::new(),
        event_amount: U256::ZERO,
        next_op_nonce: 0,
        inputs_canonical_hash: B256::ZERO,
        attestation_tag: Vec::new(),
    }
}

fn reject(reason: impl Into<String>) -> PromisOpResult {
    let mut r = base_result();
    r.status = PromisOpStatus::Rejected {
        reason: reason.into(),
    };
    r
}

/// Apply a Promis op over encrypted state. Pure and deterministic given
/// `state_key` + `req`. Sets `inputs_canonical_hash`; the caller (dispatch) signs
/// and fills `attestation_tag`. Business rejections come back as
/// `PromisOpStatus::Rejected` (-> precompile revert), never a panic.
pub fn apply_op(state_key: &[u8; 32], req: &PromisOpRequest) -> PromisOpResult {
    let inputs_canonical_hash = outbe_tee::protocol::promis_op_canonical_hash(req);
    let mut result = match apply_op_inner(state_key, req) {
        Ok(r) => r,
        Err(e) => reject(e.to_string()),
    };
    result.inputs_canonical_hash = inputs_canonical_hash;
    result
}

/// Mint/Burn - modify-key gated and keyed by `req.account`.
fn apply_op_inner(state_key: &[u8; 32], req: &PromisOpRequest) -> Result<PromisOpResult> {
    if req.amount.is_zero() {
        return Ok(reject("amount must be positive"));
    }
    if req.account.is_zero() {
        return Ok(reject("invalid address"));
    }
    let modify_key = PROMIS.derive_modify_key(state_key, req.account)?;
    if !PROMIS.verify_modify_auth(
        &modify_key,
        req.account,
        req.op as u8,
        req.amount,
        req.modify_auth.op_nonce,
        req.chain_id,
        &req.modify_auth.mac,
    ) {
        return Ok(reject("invalid modify authorization"));
    }

    let view_key = PROMIS.derive_view_key(state_key, req.account)?;
    let (bver, balance) =
        PROMIS.read_amount(&view_key, req.account, FIELD_BALANCE, &req.current_balance)?;

    let mut r = base_result();
    r.event_amount = req.amount;
    r.next_op_nonce = req.modify_auth.op_nonce.saturating_add(1);

    match req.op {
        PromisOp::Mint => {
            let new_balance = match balance.checked_add(req.amount) {
                Some(v) => v,
                None => return Ok(reject("promis balance overflow")),
            };
            r.new_balance =
                PROMIS.write_amount(&view_key, req.account, FIELD_BALANCE, bver, new_balance)?;
        }
        PromisOp::Burn => {
            if balance < req.amount {
                return Ok(reject("insufficient balance"));
            }
            r.new_balance = PROMIS.write_amount(
                &view_key,
                req.account,
                FIELD_BALANCE,
                bver,
                balance - req.amount,
            )?;
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbe_tee::protocol::ModifyAuth;

    const CHAIN: B256 = B256::repeat_byte(0xC2);

    fn state_key() -> [u8; 32] {
        derive_promis_state_key(b"a-group-threshold-signature-~48-bytes-long!!", CHAIN, 0).unwrap()
    }
    fn alice() -> Address {
        Address::repeat_byte(0x11)
    }
    fn auth(sk: &[u8; 32], acct: Address, op: PromisOp, amount: U256, nonce: u64) -> ModifyAuth {
        let mk = PROMIS.derive_modify_key(sk, acct).unwrap();
        ModifyAuth {
            mac: PROMIS.modify_mac(&mk, acct, op as u8, amount, nonce, CHAIN),
            op_nonce: nonce,
        }
    }
    fn req(op: PromisOp, acct: Address, amount: U256, nonce: u64) -> PromisOpRequest {
        PromisOpRequest {
            op,
            chain_id: CHAIN,
            account: acct,
            amount,
            current_balance: Vec::new(),
            modify_auth: ModifyAuth {
                mac: [0u8; 32],
                op_nonce: nonce,
            },
        }
    }

    #[test]
    fn mint_is_deterministic_across_calls() {
        let sk = state_key();
        let mut r = req(PromisOp::Mint, alice(), U256::from(1000u64), 0);
        r.modify_auth = auth(&sk, alice(), PromisOp::Mint, r.amount, 0);
        let a = apply_op(&sk, &r);
        let b = apply_op(&sk, &r);
        assert_eq!(a, b);
        assert_eq!(a.status, PromisOpStatus::Applied);
    }

    #[test]
    fn view_key_decrypts_minted_balance() {
        let sk = state_key();
        let mut r = req(PromisOp::Mint, alice(), U256::from(4242u64), 0);
        r.modify_auth = auth(&sk, alice(), PromisOp::Mint, r.amount, 0);
        let res = apply_op(&sk, &r);
        let vk = PROMIS.derive_view_key(&sk, alice()).unwrap();
        assert_eq!(
            decrypt_balance(&vk, alice(), &res.new_balance).unwrap(),
            U256::from(4242u64)
        );
    }

    #[test]
    fn mint_rejects_forged_modify_auth() {
        let sk = state_key();
        let mut r = req(PromisOp::Mint, alice(), U256::from(1u64), 0);
        r.modify_auth = ModifyAuth {
            mac: [7u8; 32],
            op_nonce: 0,
        };
        assert!(matches!(
            apply_op(&sk, &r).status,
            PromisOpStatus::Rejected { .. }
        ));
    }

    #[test]
    fn burn_requires_sufficient_balance() {
        let sk = state_key();
        let mut m = req(PromisOp::Mint, alice(), U256::from(100u64), 0);
        m.modify_auth = auth(&sk, alice(), PromisOp::Mint, m.amount, 0);
        let minted = apply_op(&sk, &m);
        let mut b = req(PromisOp::Burn, alice(), U256::from(200u64), 1);
        b.current_balance = minted.new_balance.clone();
        b.modify_auth = auth(&sk, alice(), PromisOp::Burn, b.amount, 1);
        assert!(matches!(
            apply_op(&sk, &b).status,
            PromisOpStatus::Rejected { .. }
        ));
    }

    #[test]
    fn burn_reduces_balance() {
        let sk = state_key();
        let mut m = req(PromisOp::Mint, alice(), U256::from(1000u64), 0);
        m.modify_auth = auth(&sk, alice(), PromisOp::Mint, m.amount, 0);
        let minted = apply_op(&sk, &m);
        let mut b = req(PromisOp::Burn, alice(), U256::from(300u64), 1);
        b.current_balance = minted.new_balance.clone();
        b.modify_auth = auth(&sk, alice(), PromisOp::Burn, b.amount, 1);
        let burned = apply_op(&sk, &b);
        assert_eq!(burned.status, PromisOpStatus::Applied);
        let vk = PROMIS.derive_view_key(&sk, alice()).unwrap();
        assert_eq!(
            decrypt_balance(&vk, alice(), &burned.new_balance).unwrap(),
            U256::from(700u64)
        );
    }
}
