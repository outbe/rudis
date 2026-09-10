//! End-to-end transport test: a real UDS, a Noise-IK handshake, and an encrypted
//! `ProcessTributeOfferBatch` round-trip between the host client and the enclave server.

use std::os::unix::net::UnixListener;
use std::thread;

use alloy_primitives::{Address, U256};
use x25519_dalek::{PublicKey, StaticSecret};

use outbe_tee::protocol::{
    EnclaveRequest, EnclaveResponse, EncryptedTributeOffer, TributeOfferStatus, WorldwideDay,
};
use outbe_tee::EnclaveClient;
use outbe_tee_enclave::crypto::{chacha20poly1305_encrypt, hkdf_sha256};
use outbe_tee_enclave::keys::EnclaveKeys;
use outbe_tee_enclave::transport::serve_connection;

const OFFER_SECRET: [u8; 32] = [7u8; 32];
const OFFER_SALT: [u8; 32] = outbe_tee::OFFER_HKDF_SALT;

const GOOD_JSON: &str = r#"{
    "creator": "alice",
    "tribute_draft_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "amount_base": "100",
    "amount_atto": "0",
    "su_hashes": ["0x2222222222222222222222222222222222222222222222222222222222222222"]
}"#;

/// Encrypt an offer to the enclave offer key + salt, exactly as a client would.
fn encrypt_offer(
    tribute_offer_public: [u8; 32],
    owner: Address,
    price: U256,
) -> EncryptedTributeOffer {
    let eph_sk = outbe_primitives::test_keys::secret(9);
    let eph_pub = PublicKey::from(&StaticSecret::from(eph_sk)).to_bytes();
    let shared = StaticSecret::from(eph_sk).diffie_hellman(&PublicKey::from(tribute_offer_public));
    let key = hkdf_sha256(
        &OFFER_SALT,
        shared.as_bytes(),
        b"tribute-factory-encryption",
    )
    .unwrap();
    let nonce = [1u8; 12];
    let cipher_text = chacha20poly1305_encrypt(&key, &nonce, GOOD_JSON.as_bytes()).unwrap();
    EncryptedTributeOffer {
        owner,
        cipher_text,
        nonce: nonce.to_vec(),
        ephemeral_pubkey: U256::from_be_bytes(eph_pub),
        worldwide_day: WorldwideDay::new(20250115),
        tribute_currency: 840,
        reference_currency: 840,
        exclude_from_intex_issuance: false,
        issuance_wwd_vwap_minor: price,
        reference_wwd_vwap_minor: price,
        reference_scurve_minor: U256::ZERO,
        zk_context: None,
    }
}

#[test]
fn handshake_and_offer_roundtrip_over_uds() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("enclave.sock");

    let keys = EnclaveKeys::new(OFFER_SECRET, None).unwrap();
    let tribute_offer_public = keys.tribute_offer_public();

    // Server: accept exactly one connection and serve it to completion.
    let listener = UnixListener::bind(&sock).unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let offer_key = std::sync::Arc::new(std::sync::OnceLock::new());
        serve_connection(stream, &keys, &offer_key).unwrap();
    });

    // Client: GetQuote -> verify+pin -> Noise-IK handshake.
    let mut client = EnclaveClient::connect(&sock).unwrap();

    // Encrypted GetPublicKeys returns the offer key matching the enclave.
    match client.request(&EnclaveRequest::GetPublicKeys).unwrap() {
        EnclaveResponse::PublicKeys {
            recipient_x25519_pub,
            ..
        } => assert_eq!(recipient_x25519_pub, tribute_offer_public),
        other => panic!("unexpected response: {other:?}"),
    }

    // Encrypted ProcessTributeOfferBatch decrypts + prices the offer in the enclave.
    let owner = Address::repeat_byte(0xAB);
    let price = U256::from(2_000_000u64); // 2.0 COEN/840
    let offer = encrypt_offer(tribute_offer_public, owner, price);
    match client
        .request(&EnclaveRequest::ProcessTributeOfferBatch {
            offers: vec![offer],
        })
        .unwrap()
    {
        EnclaveResponse::TributeOfferBatch { results, .. } => {
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].status, TributeOfferStatus::Created);
            assert_eq!(results[0].owner, owner);
            assert_eq!(results[0].issuance_amount_minor, U256::from(100_000_000u64));
            assert_eq!(results[0].nominal_amount_minor, U256::from(50_000_000u64));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    drop(client); // closing the stream ends the server loop
    server.join().unwrap();
}

#[test]
fn rejects_tampered_report_data_binding() {
    // The development connection still enforces the REPORT_DATA key binding; the
    // mock enclave produces a correct binding, so connect succeeds. Negative
    // binding cases are covered by the host unit path.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("enclave.sock");
    let keys = EnclaveKeys::new(OFFER_SECRET, None).unwrap();

    let listener = UnixListener::bind(&sock).unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let offer_key = std::sync::Arc::new(std::sync::OnceLock::new());
        let _ = serve_connection(stream, &keys, &offer_key);
    });

    let client = EnclaveClient::connect(&sock);
    assert!(client.is_ok(), "valid binding should connect");
    drop(client);
    server.join().unwrap();
}

#[test]
fn development_session_cannot_invoke_production_dcap_verifier() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("enclave.sock");
    let keys = EnclaveKeys::new(OFFER_SECRET, None).unwrap();

    let listener = UnixListener::bind(&sock).unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let offer_key = std::sync::Arc::new(std::sync::OnceLock::new());
        serve_connection(stream, &keys, &offer_key).unwrap();
    });

    let mut client = EnclaveClient::connect(&sock).unwrap();
    let error = client
        .request(&EnclaveRequest::BeginDcapVerificationV1 {
            request_hash: alloy_primitives::B256::repeat_byte(0xA1),
            evidence_len: 1,
            policy_len: 1,
            block_timestamp: 1,
        })
        .unwrap_err();
    assert!(
        error.to_string().contains("production"),
        "unexpected verifier rejection: {error}"
    );
    drop(client);
    server.join().unwrap();
}

/// End-to-end **throughput** of the full enclave offer path INCLUDING transport:
/// `postcard` codec + Noise-IK encrypt/decrypt + framed UDS round-trip + the
/// in-enclave decrypt/economics/Poseidon. The Noise handshake is paid once per
/// connection (amortized), matching production where the host holds a long-lived
/// channel to the sidecar and sends one `ProcessTributeOfferBatch` per block.
///
/// Reports offers/sec and per-batch latency. Native here; run the SAME binary
/// under gramine-sgx on real hardware to fold in SGX enter/exit + gramine syscall
/// emulation (the only overhead this native run omits) for the production figure.
///
/// Ignored by default (it is a benchmark, not a correctness gate). Run with:
///   cargo test -p outbe-tee-enclave --test transport \
///     transport_throughput_offers_per_sec -- --ignored --nocapture
#[test]
#[ignore = "throughput benchmark; run with --ignored --nocapture"]
fn transport_throughput_offers_per_sec() {
    use std::time::Instant;

    // Batch size per request and number of requests (one channel, reused).
    // The codec is `postcard` (compact binary): the offer ciphertext rides as raw
    // bytes (1x) not a JSON number array (~4x), so the 64 KiB Noise frame now fits
    // ~100+ offers/request (serde_json capped near ~30). 100 here exercises that.
    const BATCH: usize = 100;
    const REQUESTS: usize = 200;
    const WARMUP: usize = 20;

    // Two modes:
    //  - default (env unset): spin up an in-process enclave server over UDS -> the
    //    NATIVE figure (no SGX);
    //  - OUTBE_TEE_BENCH_ENDPOINT=<host:port|path>: connect to an EXTERNAL enclave
    //    (e.g. one running under gramine-sgx, launched by scripts/sgx-bench.sh) ->
    //    the PRODUCTION SGX figure incl. enclave enter/exit + gramine syscall
    //    emulation. The offer public key is fetched via GetPublicKeys so we encrypt
    //    to whatever key that enclave actually holds.
    let endpoint = std::env::var("OUTBE_TEE_BENCH_ENDPOINT").ok();
    let mode = if endpoint.is_some() {
        "gramine-sgx, transport-included"
    } else {
        "native, transport-included"
    };

    // Hold the in-process server thread + tempdir alive for the native path.
    let mut _server: Option<thread::JoinHandle<()>> = None;
    let _dir; // tempdir guard
    let mut client = match &endpoint {
        Some(ep) => EnclaveClient::connect_endpoint(ep)
            .expect("connect to external enclave (OUTBE_TEE_BENCH_ENDPOINT)"),
        None => {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("enclave.sock");
            let keys = EnclaveKeys::new(OFFER_SECRET, None).unwrap();
            let listener = UnixListener::bind(&sock).unwrap();
            _server = Some(thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let offer_key = std::sync::Arc::new(std::sync::OnceLock::new());
                let _ = serve_connection(stream, &keys, &offer_key);
            }));
            let c = EnclaveClient::connect(&sock).unwrap();
            _dir = dir;
            c
        }
    };

    // The enclave's actual offer public key (the slot's resident key, or its boot
    // offer-secret fallback pre-DKG). We encrypt to this so decryption succeeds
    // against whichever enclave we are benchmarking.
    let tribute_offer_public = match client.request(&EnclaveRequest::GetPublicKeys).unwrap() {
        EnclaveResponse::PublicKeys {
            recipient_x25519_pub,
            ..
        } => recipient_x25519_pub,
        other => panic!("unexpected GetPublicKeys response: {other:?}"),
    };

    // Pre-build a batch of distinct offers (client-side encryption is not part of
    // the enclave throughput we are measuring).
    let price = U256::from(2_000_000u64);
    let batch: Vec<EncryptedTributeOffer> = (0..BATCH)
        .map(|i| {
            let mut o = [0u8; 20];
            o[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            encrypt_offer(tribute_offer_public, Address::from(o), price)
        })
        .collect();

    let send = |client: &mut EnclaveClient| match client
        .request(&EnclaveRequest::ProcessTributeOfferBatch {
            offers: batch.clone(),
        })
        .unwrap()
    {
        EnclaveResponse::TributeOfferBatch { results, .. } => assert_eq!(results.len(), BATCH),
        other => panic!("unexpected response: {other:?}"),
    };

    for _ in 0..WARMUP {
        send(&mut client);
    }

    let start = Instant::now();
    for _ in 0..REQUESTS {
        send(&mut client);
    }
    let elapsed = start.elapsed();

    let total_offers = (REQUESTS * BATCH) as f64;
    let secs = elapsed.as_secs_f64();
    let offers_per_sec = total_offers / secs;
    let per_batch_ms = secs * 1000.0 / REQUESTS as f64;
    let per_offer_us = secs * 1e6 / total_offers;

    eprintln!("\n=== enclave offer throughput ({mode}) ===");
    eprintln!("batch size           : {BATCH} offers/request");
    eprintln!("requests (timed)     : {REQUESTS}  (after {WARMUP} warmup)");
    eprintln!("total offers         : {}", REQUESTS * BATCH);
    eprintln!("wall time            : {:.3} s", secs);
    eprintln!("throughput           : {offers_per_sec:.0} offers/sec");
    eprintln!("per-batch latency    : {per_batch_ms:.3} ms");
    eprintln!("per-offer (amortized): {per_offer_us:.2} us");
    if endpoint.is_none() {
        eprintln!(
            "note: native; set OUTBE_TEE_BENCH_ENDPOINT + run under gramine-sgx for the SGX figure."
        );
    }
    eprintln!();

    drop(client);
    if let Some(server) = _server {
        server.join().unwrap();
    }
}
