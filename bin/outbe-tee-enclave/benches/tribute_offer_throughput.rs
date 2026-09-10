//! Throughput benchmark for the in-enclave tribute-offer processing path.
//!
//! Measures the **pure CPU cost** the enclave pays per offer during block
//! execution - the ceiling on how many tribute offers the network can settle:
//!   X25519 ECDHE -> HKDF-SHA256 -> ChaCha20Poly1305 decrypt -> JSON parse ->
//!   U256 economics -> Poseidon-BN254 `token_id`.
//!
//! What is NOT here: the Noise/UDS transport round-trip and SGX enter/exit +
//! gramine syscall-emulation overhead. Those bound the *transport* cost, not the
//! compute; measure them with the `transport_throughput_offers_per_sec` ignored
//! test (run it under gramine-sgx on real hardware for the production figure).
//! The compute below runs at near-native speed inside SGX2, so this is a tight
//! upper bound on per-offer enclave CPU time.
//!
//! Run: `cargo bench -p outbe-tee-enclave`
//! The `batch/*` group reports elements/sec == offers/sec.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use alloy_primitives::{Address, U256};
use x25519_dalek::{PublicKey, StaticSecret};

use outbe_tee::offer_encrypt::encrypt_tribute_offer_with;
use outbe_tee::protocol::{EncryptedTributeOffer, WorldwideDay};
use outbe_tee::OFFER_HKDF_SALT;
use outbe_tee_enclave::compute::compute_token_id;
use outbe_tee_enclave::crypto::ecdhe_tribute_offer_decrypt;
use outbe_tee_enclave::process::{process_tribute_offer_batch, TributeOfferKeyMaterial};

/// Enclave-resident offer secret (the DKG-derived key in production; a fixed test
/// scalar here - derivation cost is one-time at bootstrap, not per offer).
static OFFER_SK: std::sync::LazyLock<[u8; 32]> =
    std::sync::LazyLock::new(|| outbe_primitives::test_keys::secret(7));
const NONCE: [u8; 12] = [1u8; 12];
const DRAFT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

/// A representative offer payload (1 SU hash, USD). Realistic size for the
/// decrypt + JSON-parse cost; more SU hashes scale the parse, not the crypto.
const GOOD_JSON: &str = r#"{
    "creator": "alice",
    "tribute_draft_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "worldwide_day": 20250115,
    "currency": 840,
    "amount_base": "100",
    "amount_atto": "0",
    "su_hashes": ["0x2222222222222222222222222222222222222222222222222222222222222222"]
}"#;

fn offer_public() -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*OFFER_SK)).to_bytes()
}

fn key_material() -> TributeOfferKeyMaterial<'static> {
    TributeOfferKeyMaterial {
        tribute_offer_private_key: &OFFER_SK,
        salt: &OFFER_HKDF_SALT,
    }
}

/// Encrypt one offer exactly as a client would, via the shared recipe in
/// `outbe_tee::offer_encrypt` (also used by `outbe-cli` and the node's canary).
/// This is the client's cost, done outside the timed region.
fn make_offer(owner: Address) -> EncryptedTributeOffer {
    let eph_sk = outbe_primitives::test_keys::secret(9);
    let eph_pub = PublicKey::from(&StaticSecret::from(eph_sk)).to_bytes();
    let cipher_text =
        encrypt_tribute_offer_with(&offer_public(), eph_sk, NONCE, GOOD_JSON.as_bytes()).unwrap();
    EncryptedTributeOffer {
        owner,
        cipher_text,
        nonce: NONCE.to_vec(),
        ephemeral_pubkey: U256::from_be_bytes(eph_pub),
        worldwide_day: WorldwideDay::new(20250115),
        tribute_currency: 840,
        reference_currency: 840,
        exclude_from_intex_issuance: false,
        issuance_wwd_vwap_minor: U256::from(2_000_000u64),
        reference_wwd_vwap_minor: U256::from(2_000_000u64),
        reference_scurve_minor: U256::ZERO,
        zk_context: None,
    }
}

/// Distinct owners so each offer yields a distinct `token_id` (realistic batch).
fn make_batch(n: usize) -> Vec<EncryptedTributeOffer> {
    (0..n)
        .map(|i| {
            let mut owner = [0u8; 20];
            owner[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            make_offer(Address::from(owner))
        })
        .collect()
}

/// Component costs: isolate the two heavy primitives so the batch number can be
/// attributed (decrypt vs Poseidon vs the rest).
fn bench_components(c: &mut Criterion) {
    let offer = make_offer(Address::repeat_byte(0xAB));
    let ephemeral = offer.ephemeral_pubkey.to_be_bytes::<32>();
    let owner = Address::repeat_byte(0xAB);

    let mut g = c.benchmark_group("component");

    // X25519 ECDHE + HKDF + ChaCha20Poly1305 decrypt of one offer.
    g.bench_function("decrypt", |b| {
        b.iter(|| {
            ecdhe_tribute_offer_decrypt(
                &OFFER_SK,
                &OFFER_HKDF_SALT,
                std::hint::black_box(&ephemeral),
                std::hint::black_box(&offer.nonce),
                std::hint::black_box(&offer.cipher_text),
            )
            .unwrap()
        })
    });

    // Poseidon-BN254 token_id over (owner, day, draft id).
    g.bench_function("poseidon_token_id", |b| {
        b.iter(|| {
            compute_token_id(
                std::hint::black_box(owner),
                WorldwideDay::new(20250115),
                std::hint::black_box(DRAFT),
            )
            .unwrap()
        })
    });

    // Full single-offer path (decrypt + parse + economics + Poseidon).
    let one = vec![offer.clone()];
    let key = key_material();
    g.bench_function("process_one_full", |b| {
        b.iter(|| {
            process_tribute_offer_batch(std::hint::black_box(&key), std::hint::black_box(&one))
        })
    });

    g.finish();
}

/// Batch throughput: elements/sec == offers/sec the enclave can settle, ignoring
/// transport. The per-block on-chain budget divided by this gives offers/block.
fn bench_batch_throughput(c: &mut Criterion) {
    let key = key_material();
    let mut g = c.benchmark_group("batch");
    for &n in &[1usize, 10, 100, 500] {
        let batch = make_batch(n);
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &batch, |b, batch| {
            b.iter(|| {
                process_tribute_offer_batch(std::hint::black_box(&key), std::hint::black_box(batch))
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench_components, bench_batch_throughput);
criterion_main!(benches);
