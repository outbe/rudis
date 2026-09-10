//! Canonical TributeDraft public-input derivation inside the enclave.
//!
//! The claim is folded from the encrypted payload (draft id, amount, su ids),
//! the cleartext offer (`worldwide_day`, `tribute_currency`) and
//! `derived_owner`, which is public input zero of the submitted full proof.
//! Keeping the fold here binds the proof claim to the plaintext the enclave
//! actually decrypted without exposing the draft id or amount fields to the
//! host.
//!
//! Because the day and currency are folded in, a caller who declares cleartext
//! values that disagree with their L2-attested draft produces an `nft_hash` that
//! does not match the proof's public input, and the offer is rejected. That is
//! what keeps those two fields bound now that they no longer travel encrypted.

use alloy_primitives::B256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_protocol::protocol::entity::Entity as EntityTrait;
use outbe_protocol::{OutbeV1, Suite};
use outbe_protocol_derive::Entity;
use outbe_tee::protocol::{EncryptedTributeOffer, TributeZkExpectedHashes};

use crate::compute::CanonicalAmount;
use crate::payload::TributeInputPayload;

#[derive(Entity)]
struct TributeDraftClaim {
    #[outbe(id_seed)]
    id: B256,
    #[outbe(body, owner, pos = 0)]
    derived_owner: B256,
    #[outbe(body, pos = 1)]
    worldwide_day: u64,
    #[outbe(body, pos = 2)]
    currency: u16,
    #[outbe(body, pos = 3)]
    base: u64,
    #[outbe(body, pos = 4)]
    atto: u64,
    #[outbe(body, pos = 5)]
    su_ids: Vec<B256>,
}

pub(crate) fn derive_expected_hashes(
    offer: &EncryptedTributeOffer,
    payload: &TributeInputPayload,
    amount: &CanonicalAmount,
) -> Result<Option<TributeZkExpectedHashes>, String> {
    let Some(context) = &offer.zk_context else {
        return Ok(None);
    };

    let id = parse_b256(&payload.tribute_draft_id, "tribute_draft_id")?;
    let su_ids = payload
        .su_hashes
        .iter()
        .map(|value| parse_b256(value, "su_hash"))
        .collect::<Result<Vec<_>, _>>()?;
    let su_ids = outbe_protocol::codec::sort_set::<Fr, B256>(&su_ids)
        .map_err(|error| format!("invalid canonical su_ids: {error}"))?;

    let draft = TributeDraftClaim {
        id,
        derived_owner: context.derived_owner,
        worldwide_day: offer.worldwide_day.into(),
        currency: offer.tribute_currency,
        base: amount.base,
        atto: amount.atto,
        su_ids,
    };
    let nft_hash = <TributeDraftClaim as EntityTrait<OutbeV1>>::entity_hash(&draft)
        .map_err(|error| format!("invalid canonical TributeDraft: {error}"))?;
    let binding_hash = OutbeV1::binding(&offer.owner.into_array(), id.as_ref(), context.chain_id)
        .map_err(|error| format!("failed to derive binding_hash: {error}"))?;

    Ok(Some(TributeZkExpectedHashes {
        nft_hash: field_to_b256(nft_hash),
        binding_hash: field_to_b256(binding_hash),
    }))
}

fn parse_b256(value: &str, what: &'static str) -> Result<B256, String> {
    value
        .parse::<B256>()
        .map_err(|_| format!("{what} must be 0x-prefixed 32-byte hex"))
}

fn field_to_b256(field: Fr) -> B256 {
    let bytes = field.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    B256::from(out)
}
