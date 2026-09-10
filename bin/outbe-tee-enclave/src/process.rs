//! Offer-batch processing: decrypt -> validate -> apply the node-resolved oracle
//! price -> compute the canonical public `TributeOfferResult` (incl. in-enclave
//! Poseidon `token_id`) for each offer.
//!
//! The result carries only what is computed here. Day, currencies, exclusion flag
//! and price are host-supplied request fields, so echoing them back would just be
//! one more thing for the two sides to keep in agreement.
//!
//! What the enclave does NOT do (stays on the host):
//!   - worldwide-day calendar validity and OFFERING status (one `WorldwideDay`
//!     check on the node, whose `(owner, day)` identity recompute then rejects
//!     any day the enclave was fed that disagrees with it);
//!   - tribute-already-exists check;
//!   - SU-hash used-marking (replay prevention);
//!   - agent-reward (wallet/SRA) increments.
//!
//! The host applies those after receiving the public results. SU-hash markers
//! and agent-reward routing in a privacy-preserving form are a later slice.
//!
//! Determinism: each offer's price is supplied by the node from committed Oracle
//! state (identical on every validator), and every step here is pure integer/hash
//! math, so all validators produce byte-identical results. A forged price
//! surfaces as a state-root mismatch on re-execution.

use alloy_primitives::{Address, B256, U256};

use outbe_tee::protocol::{EncryptedTributeOffer, TributeOfferResult, TributeOfferStatus};

use crate::compute::{compute_nominal, compute_token_id, parse_canonical_amount};
use crate::crypto::ecdhe_tribute_offer_decrypt;
use crate::payload::parse_and_validate;
use crate::zk_claim::derive_expected_hashes;

/// The enclave-resident offer decryption key material (derived from the sealed
/// root seed via the HKDF chain). Borrowed for the duration of a batch call.
pub struct TributeOfferKeyMaterial<'a> {
    pub tribute_offer_private_key: &'a [u8; 32],
    pub salt: &'a [u8; 32],
}

/// Process a batch of encrypted offers, each carrying its own node-resolved
/// price. Per-offer failures become `Rejected{reason}` (never abort the whole
/// batch). Returns the results plus a canonical-inputs hash used by the host to
/// detect enclave non-determinism.
pub fn process_tribute_offer_batch(
    key: &TributeOfferKeyMaterial<'_>,
    offers: &[EncryptedTributeOffer],
) -> (Vec<TributeOfferResult>, B256) {
    let mut results = Vec::with_capacity(offers.len());
    for offer in offers {
        let result = match process_one(key, offer) {
            Ok(result) => result,
            Err(reason) => rejected(reason),
        };
        results.push(result);
    }
    let hash = outbe_tee::protocol::inputs_canonical_hash(offers);
    (results, hash)
}

fn process_one(
    key: &TributeOfferKeyMaterial<'_>,
    offer: &EncryptedTributeOffer,
) -> Result<TributeOfferResult, String> {
    let ephemeral = offer.ephemeral_pubkey.to_be_bytes::<32>();
    let plaintext = ecdhe_tribute_offer_decrypt(
        key.tribute_offer_private_key,
        key.salt,
        &ephemeral,
        &offer.nonce,
        &offer.cipher_text,
    )
    .map_err(|e| format!("decryption failed: {e}"))?;

    let payload = parse_and_validate(&plaintext)?;
    let amount = parse_canonical_amount(&payload.amount_base, &payload.amount_atto)?;
    let zk_expected_hashes = derive_expected_hashes(offer, &payload, &amount)?;
    let amount_minor = amount.amount_minor;
    if amount_minor.is_zero() {
        return Err("amount must be positive".to_string());
    }

    if offer.issuance_wwd_vwap_minor.is_zero() || offer.reference_wwd_vwap_minor.is_zero() {
        return Err(format!(
            "required WorldwideDay VWAP unavailable for worldwide_day {}",
            offer.worldwide_day
        ));
    }

    let (nominal_amount_minor, effective_reference_price_minor) = compute_nominal(
        amount_minor,
        offer.issuance_wwd_vwap_minor,
        offer.reference_wwd_vwap_minor,
        offer.reference_scurve_minor,
    )?;

    // token_id is Poseidon over owner + day. It is deterministic in
    // (owner, worldwide_day) so a duplicate offer for the same owner and day
    // collides and is rejected downstream (TributeAlreadyExists).
    // draft_id is still validated by compute_token_id but not bound into the id.
    // TODO refactor this to correctly validate tribute_draft_id
    let token_id = compute_token_id(offer.owner, offer.worldwide_day, &payload.tribute_draft_id)?;

    Ok(TributeOfferResult {
        token_id,
        owner: offer.owner,
        issuance_amount_minor: amount_minor,
        nominal_amount_minor,
        effective_reference_price_minor,
        // Returned for the host's SU-hash used-marking + agent-reward routing
        // (public on-chain). Privacy-preserving markers-only form is a later
        // slice (see module doc / Enclave Return Rule).
        su_hashes: payload.su_hashes,
        wallet_addresses: payload.wallet_addresses,
        sra_addresses: payload.sra_addresses,
        zk_expected_hashes,
        status: TributeOfferStatus::Created,
    })
}

/// Build a `Rejected` result. Nothing is known beyond the reason - every field
/// the host sent stays on the host, and everything else needed decryption to
/// have succeeded. `owner` is zero rather than echoed for the same reason.
fn rejected(reason: String) -> TributeOfferResult {
    TributeOfferResult {
        token_id: B256::ZERO,
        owner: Address::ZERO,
        issuance_amount_minor: U256::ZERO,
        nominal_amount_minor: U256::ZERO,
        effective_reference_price_minor: U256::ZERO,
        su_hashes: Vec::new(),
        wallet_addresses: Vec::new(),
        sra_addresses: Vec::new(),
        zk_expected_hashes: None,
        status: TributeOfferStatus::Rejected { reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::compute_token_id;
    use crate::crypto::{chacha20poly1305_encrypt, hkdf_sha256};
    use outbe_primitives::units::SCALE_1E6_U256;
    use outbe_tee::protocol::{TributeZkContext, WorldwideDay};
    use x25519_dalek::{PublicKey, StaticSecret};

    static OFFER_SK: std::sync::LazyLock<[u8; 32]> =
        std::sync::LazyLock::new(|| outbe_primitives::test_keys::secret(7));
    const SALT: [u8; 32] = [3u8; 32];
    const NONCE: [u8; 12] = [1u8; 12];
    const DRAFT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const DAY: WorldwideDay = WorldwideDay::new(20250115);
    const NEXT_DAY: WorldwideDay = WorldwideDay::new(20250116);
    /// Encrypt a payload the way a client would (ephemeral_secret x tribute_offer_pub).
    /// Day, currencies and price are cleartext offer fields; tests that care mutate
    /// them on the returned struct.
    fn make_tribute_offer(owner: Address, json: &str) -> EncryptedTributeOffer {
        let tribute_offer_pub = PublicKey::from(&StaticSecret::from(*OFFER_SK)).to_bytes();
        let eph_sk = outbe_primitives::test_keys::secret(9);
        let eph_pub = PublicKey::from(&StaticSecret::from(eph_sk)).to_bytes();
        let shared = StaticSecret::from(eph_sk).diffie_hellman(&PublicKey::from(tribute_offer_pub));
        let key = hkdf_sha256(&SALT, shared.as_bytes(), b"tribute-factory-encryption").unwrap();
        let ciphertext = chacha20poly1305_encrypt(&key, &NONCE, json.as_bytes()).unwrap();
        EncryptedTributeOffer {
            owner,
            cipher_text: ciphertext,
            nonce: NONCE.to_vec(),
            ephemeral_pubkey: U256::from_be_bytes(eph_pub),
            worldwide_day: DAY,
            tribute_currency: 840,
            reference_currency: 840,
            exclude_from_intex_issuance: false,
            issuance_wwd_vwap_minor: SCALE_1E6_U256,
            reference_wwd_vwap_minor: SCALE_1E6_U256,
            reference_scurve_minor: U256::ZERO,
            zk_context: None,
        }
    }

    fn key() -> TributeOfferKeyMaterial<'static> {
        TributeOfferKeyMaterial {
            tribute_offer_private_key: &OFFER_SK,
            salt: &SALT,
        }
    }

    /// The encrypted payload carries only the confidential fields - the day and
    /// the issuance currency are cleartext ABI arguments.
    const GOOD_JSON: &str = r#"{
        "creator": "alice",
        "tribute_draft_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "amount_base": "100",
        "amount_atto": "0",
        "su_hashes": ["0x2222222222222222222222222222222222222222222222222222222222222222"]
    }"#;

    const BASE_AND_ATTO_JSON: &str = r#"{
        "creator": "alice",
        "tribute_draft_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "amount_base": "1",
        "amount_atto": "500000",
        "su_hashes": ["0x2222222222222222222222222222222222222222222222222222222222222222"]
    }"#;

    fn zk_context() -> TributeZkContext {
        TributeZkContext {
            derived_owner: B256::from([0x01; 32]),
            chain_id: 19_280_501,
        }
    }

    #[test]
    fn batch_creates_tribute_with_correct_economics() {
        let owner = Address::repeat_byte(0xAB);
        let mut offer = make_tribute_offer(owner, GOOD_JSON);
        offer.issuance_wwd_vwap_minor = U256::from(2u64) * SCALE_1E6_U256;
        offer.reference_wwd_vwap_minor = offer.issuance_wwd_vwap_minor;

        let (results, hash) = process_tribute_offer_batch(&key(), &[offer]);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.status, TributeOfferStatus::Created);
        assert_eq!(r.owner, owner);
        assert_eq!(r.issuance_amount_minor, U256::from(100u64) * SCALE_1E6_U256);
        assert_eq!(r.nominal_amount_minor, U256::from(50u64) * SCALE_1E6_U256);
        assert_eq!(
            r.effective_reference_price_minor,
            U256::from(2u64) * SCALE_1E6_U256
        );
        assert_eq!(r.token_id, compute_token_id(owner, DAY, DRAFT).unwrap());
        assert_ne!(hash, B256::ZERO);
    }

    /// Regression for the removed USD pin: the enclave applies whatever price the
    /// node resolved, whatever currency it names.
    #[test]
    fn non_usd_currency_prices_from_the_offer() {
        let owner = Address::repeat_byte(0xE7);
        let mut offer = make_tribute_offer(owner, GOOD_JSON);
        offer.tribute_currency = 978;
        // Every stablecoin-backed COEN/ISO rate uses the six-decimal contract.
        offer.issuance_wwd_vwap_minor = U256::from(4u64) * SCALE_1E6_U256;
        offer.reference_wwd_vwap_minor = offer.issuance_wwd_vwap_minor;

        let (results, _) = process_tribute_offer_batch(&key(), &[offer]);
        assert_eq!(results[0].status, TributeOfferStatus::Created);
        assert_eq!(
            results[0].nominal_amount_minor,
            U256::from(25u64) * SCALE_1E6_U256
        );
    }

    /// Each offer carries its own price, so one batch can mix currencies.
    #[test]
    fn one_batch_prices_each_offer_from_its_own_field() {
        let mut usd = make_tribute_offer(Address::repeat_byte(0x01), GOOD_JSON);
        usd.issuance_wwd_vwap_minor = U256::from(2u64) * SCALE_1E6_U256;
        usd.reference_wwd_vwap_minor = usd.issuance_wwd_vwap_minor;
        let mut eur = make_tribute_offer(Address::repeat_byte(0x0B), GOOD_JSON);
        eur.tribute_currency = 978;
        eur.issuance_wwd_vwap_minor = U256::from(5u64) * SCALE_1E6_U256;
        eur.reference_wwd_vwap_minor = eur.issuance_wwd_vwap_minor;

        let (results, _) = process_tribute_offer_batch(&key(), &[usd, eur]);
        assert_eq!(results[0].status, TributeOfferStatus::Created);
        assert_eq!(
            results[0].nominal_amount_minor,
            U256::from(50u64) * SCALE_1E6_U256
        );
        assert_eq!(results[1].status, TributeOfferStatus::Created);
        assert_eq!(
            results[1].nominal_amount_minor,
            U256::from(20u64) * SCALE_1E6_U256
        );
    }

    #[test]
    fn zk_and_non_zk_share_one_canonical_base_atto_contract() {
        let plain = make_tribute_offer(Address::repeat_byte(0x31), BASE_AND_ATTO_JSON);
        let mut zk = make_tribute_offer(Address::repeat_byte(0x32), BASE_AND_ATTO_JSON);
        zk.zk_context = Some(zk_context());

        let (results, _) = process_tribute_offer_batch(&key(), &[plain, zk]);
        assert_eq!(results.len(), 2);
        for result in results {
            assert_eq!(result.status, TributeOfferStatus::Created);
            assert_eq!(result.issuance_amount_minor, U256::from(1_500_000u64));
            assert_eq!(result.nominal_amount_minor, U256::from(1_500_000u64));
        }
    }

    #[test]
    fn cross_currency_golden_returns_effective_reference_price() {
        let mut offer = make_tribute_offer(Address::repeat_byte(0x55), BASE_AND_ATTO_JSON);
        offer.issuance_wwd_vwap_minor = U256::from(10_250_000u64);
        offer.reference_wwd_vwap_minor = U256::from(250_000u64);
        offer.reference_scurve_minor = U256::from(320_000u64);
        let json = BASE_AND_ATTO_JSON
            .replace(r#""amount_base": "1""#, r#""amount_base": "0""#)
            .replace(r#""amount_atto": "500000""#, r#""amount_atto": "410000""#);
        offer = make_tribute_offer(offer.owner, &json);
        offer.issuance_wwd_vwap_minor = U256::from(10_250_000u64);
        offer.reference_wwd_vwap_minor = U256::from(250_000u64);
        offer.reference_scurve_minor = U256::from(320_000u64);

        let (results, _) = process_tribute_offer_batch(&key(), &[offer]);
        assert_eq!(results[0].status, TributeOfferStatus::Created);
        assert_eq!(results[0].nominal_amount_minor, U256::from(31_250u64));
        assert_eq!(
            results[0].effective_reference_price_minor,
            U256::from(320_000u64)
        );
    }

    #[test]
    fn zk_enabled_offer_returns_expected_hashes_bound_to_owner_and_sender() {
        let sender = Address::repeat_byte(0xAB);
        let mut offer = make_tribute_offer(sender, GOOD_JSON);
        offer.zk_context = Some(zk_context());

        let (results, _) = process_tribute_offer_batch(&key(), &[offer.clone()]);
        let expected = results[0]
            .zk_expected_hashes
            .as_ref()
            .expect("ZK context must produce expected hashes");
        assert_ne!(expected.nft_hash, B256::ZERO);
        assert_ne!(expected.binding_hash, B256::ZERO);

        offer.zk_context.as_mut().unwrap().derived_owner = B256::from([0x02; 32]);
        let (different_owner, _) = process_tribute_offer_batch(&key(), &[offer.clone()]);
        assert_ne!(
            different_owner[0]
                .zk_expected_hashes
                .as_ref()
                .unwrap()
                .nft_hash,
            expected.nft_hash
        );

        offer.owner = Address::repeat_byte(0xCD);
        let (different_sender, _) = process_tribute_offer_batch(&key(), &[offer]);
        assert_ne!(
            different_sender[0]
                .zk_expected_hashes
                .as_ref()
                .unwrap()
                .binding_hash,
            expected.binding_hash
        );
    }

    /// `worldwide_day` and `tribute_currency` are folded into the ZK claim, so a
    /// caller who declares them in cleartext still cannot disagree with the draft
    /// the proof commits to: the recomputed `nft_hash` moves and the host's
    /// comparison against the proof's public input fails. This is what replaces
    /// the binding those two fields used to get from being encrypted.
    #[test]
    fn zk_nft_hash_binds_the_cleartext_day_and_currency() {
        let owner = Address::repeat_byte(0xAB);
        let mut base = make_tribute_offer(owner, GOOD_JSON);
        base.zk_context = Some(zk_context());

        let nft_hash = |offer: EncryptedTributeOffer| {
            let (results, _) = process_tribute_offer_batch(&key(), &[offer]);
            results[0]
                .zk_expected_hashes
                .as_ref()
                .expect("ZK context must produce expected hashes")
                .nft_hash
        };

        let original = nft_hash(base.clone());

        let mut other_day = base.clone();
        other_day.worldwide_day = NEXT_DAY;
        assert_ne!(original, nft_hash(other_day));

        let mut other_currency = base;
        other_currency.tribute_currency = 978;
        assert_ne!(original, nft_hash(other_currency));
    }

    #[test]
    fn zk_nft_hash_uses_canonical_su_id_set_order() {
        let first = GOOD_JSON.replace(
            r#""su_hashes": ["0x2222222222222222222222222222222222222222222222222222222222222222"]"#,
            r#""su_hashes": [
                "0x2323232323232323232323232323232323232323232323232323232323232323",
                "0x2222222222222222222222222222222222222222222222222222222222222222"
            ]"#,
        );
        let second = GOOD_JSON.replace(
            r#""su_hashes": ["0x2222222222222222222222222222222222222222222222222222222222222222"]"#,
            r#""su_hashes": [
                "0x2222222222222222222222222222222222222222222222222222222222222222",
                "0x2323232323232323232323232323232323232323232323232323232323232323"
            ]"#,
        );
        let mut first = make_tribute_offer(Address::repeat_byte(0xAB), &first);
        let mut second = make_tribute_offer(Address::repeat_byte(0xAB), &second);
        first.zk_context = Some(zk_context());
        second.zk_context = Some(zk_context());

        let (results, _) = process_tribute_offer_batch(&key(), &[first, second]);
        assert_eq!(
            results[0].zk_expected_hashes.as_ref().unwrap().nft_hash,
            results[1].zk_expected_hashes.as_ref().unwrap().nft_hash
        );
    }

    #[test]
    fn zk_and_non_zk_reject_the_same_noncanonical_amounts() {
        for (needle, replacement) in [
            (r#""amount_base": "100""#, r#""amount_base": "1.5""#),
            (r#""amount_base": "100""#, r#""amount_base": "01""#),
            (r#""amount_atto": "0""#, r#""amount_atto": "1000000""#),
        ] {
            let json = GOOD_JSON.replace(needle, replacement);
            let plain = make_tribute_offer(Address::repeat_byte(0x41), &json);
            let mut zk = make_tribute_offer(Address::repeat_byte(0x42), &json);
            zk.zk_context = Some(zk_context());

            let (results, _) = process_tribute_offer_batch(&key(), &[plain, zk]);
            assert_eq!(results.len(), 2);
            assert!(results
                .iter()
                .all(|result| matches!(result.status, TributeOfferStatus::Rejected { .. })));
        }
    }

    #[test]
    fn inputs_hash_binds_zk_owner_and_chain_id() {
        let mut offer = make_tribute_offer(Address::repeat_byte(0xAB), GOOD_JSON);
        offer.zk_context = Some(zk_context());
        let original = outbe_tee::protocol::inputs_canonical_hash(&[offer.clone()]);

        offer.zk_context.as_mut().unwrap().derived_owner = B256::from([0x02; 32]);
        let different_owner = outbe_tee::protocol::inputs_canonical_hash(&[offer.clone()]);
        assert_ne!(original, different_owner);

        offer.zk_context.as_mut().unwrap().chain_id += 1;
        let different_chain = outbe_tee::protocol::inputs_canonical_hash(&[offer]);
        assert_ne!(different_owner, different_chain);
    }

    /// A host that hands over a zero price must not reach the division in
    /// `compute_nominal`.
    #[test]
    fn zero_price_is_rejected_not_aborted() {
        // Distinct owners so both offers are independent (one owner = at most one
        // Tribute per day); only the zero-price one is rejected.
        let mut bad = make_tribute_offer(Address::repeat_byte(0x01), GOOD_JSON);
        bad.issuance_wwd_vwap_minor = U256::ZERO;
        let good = make_tribute_offer(Address::repeat_byte(0x0B), GOOD_JSON);

        let (results, _) = process_tribute_offer_batch(&key(), &[bad, good]);
        assert!(matches!(
            results[0].status,
            TributeOfferStatus::Rejected { .. }
        ));
        assert_eq!(results[1].status, TributeOfferStatus::Created);
    }

    #[test]
    fn garbage_ciphertext_is_rejected() {
        let mut offer = make_tribute_offer(Address::repeat_byte(0x02), GOOD_JSON);
        offer.cipher_text = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let (results, _) = process_tribute_offer_batch(&key(), &[offer]);
        assert!(matches!(
            results[0].status,
            TributeOfferStatus::Rejected { .. }
        ));
    }

    #[test]
    fn bad_draft_id_is_rejected() {
        let bad_json = r#"{
            "creator": "alice",
            "tribute_draft_id": "not-a-32-byte-hex",
            "amount_base": "100",
            "amount_atto": "0",
            "su_hashes": ["0x2222222222222222222222222222222222222222222222222222222222222222"]
        }"#;
        let offers = vec![make_tribute_offer(Address::repeat_byte(0x04), bad_json)];

        let (results, _) = process_tribute_offer_batch(&key(), &offers);
        assert!(matches!(
            results[0].status,
            TributeOfferStatus::Rejected { .. }
        ));
    }

    #[test]
    fn inputs_hash_is_deterministic_and_input_bound() {
        let owner = Address::repeat_byte(0x03);
        let offers = vec![make_tribute_offer(owner, GOOD_JSON)];
        let h1 = outbe_tee::protocol::inputs_canonical_hash(&offers);
        let h2 = outbe_tee::protocol::inputs_canonical_hash(&offers);
        assert_eq!(h1, h2);
        // different reference currency -> different hash
        let mut other = offers.clone();
        other[0].reference_currency = 978;
        assert_ne!(h1, outbe_tee::protocol::inputs_canonical_hash(&other));
    }

    /// The day, currency and price are node-resolved request inputs, so each has
    /// to move the canonical hash. A field the hash skips rides to the enclave
    /// unattested and no other test would notice.
    #[test]
    fn inputs_hash_binds_the_priced_request_fields() {
        let offers = vec![make_tribute_offer(Address::repeat_byte(0x05), GOOD_JSON)];
        let base = outbe_tee::protocol::inputs_canonical_hash(&offers);

        for mutate in [
            (|o: &mut EncryptedTributeOffer| o.worldwide_day = NEXT_DAY) as fn(&mut _),
            |o: &mut EncryptedTributeOffer| o.tribute_currency = 978,
            |o: &mut EncryptedTributeOffer| o.exclude_from_intex_issuance = true,
            |o: &mut EncryptedTributeOffer| o.issuance_wwd_vwap_minor = U256::from(2u64),
            |o: &mut EncryptedTributeOffer| o.reference_wwd_vwap_minor = U256::from(2u64),
            |o: &mut EncryptedTributeOffer| o.reference_scurve_minor = U256::from(2u64),
        ] {
            let mut other = offers.clone();
            mutate(&mut other[0]);
            assert_ne!(
                base,
                outbe_tee::protocol::inputs_canonical_hash(&other),
                "a request field is missing from the canonical hash"
            );
        }
    }
}
