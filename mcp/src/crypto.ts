import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "node:crypto";
import { bytesToBigInt } from "viem";

/**
 * Tribute offer encryption - byte-identical to the enclave decrypt path
 * (outbe_tee_enclave::crypto::ecdhe_offer_decrypt) and the verified Python port
 * in scripts/tribute_offer.py:
 *
 *   ephemeral X25519 ECDHE
 *   -> HKDF-SHA256(salt = OFFER_HKDF_SALT, info = "tribute-factory-encryption")
 *   -> ChaCha20Poly1305 (empty AAD), 12-byte nonce.
 *
 * OFFER_HKDF_SALT is the fixed protocol constant outbe_tee::OFFER_HKDF_SALT:
 * ASCII "outbe/tribute/offer-salt/v1", zero-padded to 32 bytes (see
 * crates/system/tee/src/lib.rs and bin/outbe-tee-enclave/src/keys.rs).
 */

const OFFER_SALT = (() => {
  const s = new Uint8Array(32);
  s.set(new TextEncoder().encode("outbe/tribute/offer-salt/v1"));
  return s;
})();
const HKDF_INFO = new TextEncoder().encode("tribute-factory-encryption");

export interface EncryptedOffer {
  /** ChaCha20Poly1305 ciphertext with the 16-byte tag appended. */
  cipherText: Uint8Array;
  /** 12-byte nonce. */
  nonce: Uint8Array;
  /** Ephemeral X25519 public key as a big-endian uint256 (for `ephemeralPubkey`). */
  ephemeralPubkey: bigint;
}

/** Encrypt an offer payload to the registry's DKG-derived offer public key. */
export function encryptOffer(offerPub: Uint8Array, plaintext: Uint8Array): EncryptedOffer {
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, offerPub);

  const key = hkdf(sha256, shared, OFFER_SALT, HKDF_INFO, 32);

  const nonce = new Uint8Array(randomBytes(12));
  const cipherText = chacha20poly1305(key, nonce).encrypt(plaintext);

  return { cipherText, nonce, ephemeralPubkey: bytesToBigInt(ephPub) };
}

export interface OfferPayload {
  creator: string;
  amount_base: string;
}

const U64_MAX = 18_446_744_073_709_551_615n;

/** Return one canonical lexical u64 suitable for Tribute `amount_base`. */
export function canonicalAmountBase(value: string): string {
  if (!/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) > U64_MAX) {
    throw new Error("amount_base must be a canonical unsigned u64");
  }
  return value;
}

/**
 * Build the plaintext JSON payload (fresh draft id + su hash per offer).
 * `worldwide_day` and `currency` are cleartext `offerTribute` arguments, not
 * payload fields - the node needs them to admit and price the offer.
 */
export function buildPayload(p: OfferPayload): Uint8Array {
  const hex32 = () => `0x${Buffer.from(randomBytes(32)).toString("hex")}`;
  const obj = {
    creator: p.creator,
    tribute_draft_id: hex32(),
    amount_base: canonicalAmountBase(p.amount_base),
    amount_atto: "0",
    su_hashes: [hex32()],
    wallet_addresses: [] as string[],
    sra_addresses: [] as string[],
  };
  return new TextEncoder().encode(JSON.stringify(obj));
}
