// Client-side crypto for the confidential (TEE-encrypted) Gratis token.
//
// Byte-for-byte mirror of the enclave engine
// (`bin/outbe-tee-enclave/src/{gratis.rs,crypto.rs}` + the HKDF/label constants
// in `crates/system/tee/src/lib.rs`). Any divergence means a balance won't
// decrypt or a write authorization is rejected, so keep these in lockstep.
//
// Crypto primitives use Node's built-in `crypto` (HKDF-SHA256, HMAC-SHA256,
// ChaCha20-Poly1305) plus `@noble/curves` for raw-byte X25519 ECDH.

import { createHash, createHmac, hkdfSync, createDecipheriv } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519";
import { ethers } from "ethers";

// GratisOp discriminants - MUST match `outbe_tee::protocol::GratisOp` order.
// Only Mint/Burn/Pledge/Unpledge are client-authorized; the rest are chain-driven
// (credis) and listed so the discriminants stay aligned with the Rust enum.
export enum GratisOp {
  Mint = 0,
  Burn = 1,
  Pledge = 2,
  Unpledge = 3,
  ConsumePledge = 4,
  ReleaseToEoa = 5,
  BurnPledged = 6,
  RevealOwner = 7,
}

// PromisOp discriminants - MUST match `outbe_tee::protocol::PromisOp` order.
export enum PromisOp {
  Mint = 0,
  Burn = 1,
}

// The two TEE-confidential ledgers. Selects the enclave key domain, so Gratis and
// Promis derive cryptographically independent keys - matches `outbe_tee::protocol::Ledger`.
export type Ledger = "Gratis" | "Promis";

// Per-ledger domain-separation labels - MUST match the Rust constants
// (crates/system/tee/src/lib.rs + bin/outbe-tee-enclave/src/confidential.rs).
// Note: the modify-key HKDF label (".../modify-key/v1") differs from the MAC
// preimage tag (".../modify/v1"); only the latter appears here (the enclave applies
// the former server-side when deriving the modify key).
interface LedgerLabels {
  deriveKeysTag: Uint8Array; // personal_sign domain for rudis_deriveKeys
  nonceInfo: Uint8Array; // per-slot AEAD nonce HKDF info
  modifyTag: Uint8Array; // modify-MAC preimage tag
}
const LEDGER_LABELS: Record<Ledger, LedgerLabels> = {
  Gratis: {
    deriveKeysTag: utf8("outbe/gratis/derive-keys/v1"),
    nonceInfo: utf8("outbe/gratis/nonce/v1"),
    modifyTag: utf8("outbe/gratis/modify/v1"),
  },
  Promis: {
    deriveKeysTag: utf8("outbe/promis/derive-keys/v1"),
    nonceInfo: utf8("outbe/promis/nonce/v1"),
    modifyTag: utf8("outbe/promis/modify/v1"),
  },
};

// Domain-separation labels - MUST match the Rust constants.
const DKG_SHARE_INFO = utf8("outbe/tee/dkg-share/v1"); // crypto.rs
const SPEND_BIND_TAG = utf8("outbe/gratis/credis-bind/v1"); // gratis.rs SPEND_BIND_TAG

const FIELD_BALANCE = 0;
const FIELD_PLEDGED = 1;

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Big-endian encode `n` into exactly `bytes` bytes. */
function be(n: bigint, bytes: number): Uint8Array {
  const out = new Uint8Array(bytes);
  let x = n;
  for (let i = bytes - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error(`be: ${n} does not fit in ${bytes} bytes`);
  return out;
}

function bytesToBigIntBE(b: Uint8Array): bigint {
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return x;
}

/** The 20 raw bytes of an address. */
function addressBytes(addr: string): Uint8Array {
  return ethers.getBytes(ethers.getAddress(addr));
}

// ---------------------------------------------------------------------------
// Primitives (Node built-ins)
// ---------------------------------------------------------------------------

/** HKDF-SHA256 extract+expand to 32 bytes - matches `crypto.rs::hkdf_sha256`. */
function hkdf32(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array): Uint8Array {
  return new Uint8Array(hkdfSync("sha256", ikm, salt, info, 32));
}

function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("sha256", Buffer.from(key)).update(Buffer.from(msg)).digest());
}

/**
 * ChaCha20-Poly1305 decrypt with empty AAD. Ring appends the 16-byte tag to the
 * ciphertext (`seal_in_place_append_tag`), so we split it off for Node's API.
 */
function chachaDecrypt(key: Uint8Array, nonce: Uint8Array, ctWithTag: Uint8Array): Uint8Array {
  const tag = ctWithTag.slice(ctWithTag.length - 16);
  const ct = ctWithTag.slice(0, ctWithTag.length - 16);
  const d = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  d.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([d.update(ct), d.final()]));
}

// ---------------------------------------------------------------------------
// Key delivery - rudis_deriveGratisKeys RPC
// ---------------------------------------------------------------------------

export interface GratisKeys {
  viewKey: Uint8Array; // decrypts this account's balance/pledged ciphertext
  modifyKey: Uint8Array; // authorizes writes (never decrypts)
}

/**
 * Fetch the signer's own enclave-derived view + modify keys for `ledger` via the
 * unified `rudis_deriveKeys(ledger, ...)` RPC. The enclave seals them to a fresh
 * client ephemeral X25519 key (the `decrypt_share` scheme in `crypto.rs`).
 *
 * The RPC authenticates control of the account: we prove it with an EIP-191
 * `personal_sign` over `"outbe/<ledger>/derive-keys/v1" || account || ephemeralPubkey`
 * (recovered + matched server-side), so only the account's key holder can obtain
 * its keys.
 */
export async function deriveKeys(signer: ethers.Wallet, ledger: Ledger): Promise<GratisKeys> {
  const provider = signer.provider as ethers.JsonRpcProvider | null;
  if (!provider) throw new Error("deriveKeys: signer must be connected to a JsonRpcProvider");
  const account = ethers.getAddress(await signer.getAddress());
  const labels = LEDGER_LABELS[ledger];

  const ephSecret = x25519.utils.randomPrivateKey();
  const ephPublic = x25519.getPublicKey(ephSecret);

  // Ownership proof: personal_sign over the domain-tagged message (raw bytes).
  const message = ethers.getBytes(
    ethers.concat([labels.deriveKeysTag, ethers.getBytes(account), ephPublic]),
  );
  const signature = await signer.signMessage(message);

  const resp: { sealed: string; nonce: string; enclaveEphemeralPubkey: string } =
    await provider.send("rudis_deriveKeys", [
      ledger,
      account,
      ethers.hexlify(ephPublic),
      signature,
    ]);

  const sealed = ethers.getBytes(resp.sealed);
  const nonce = ethers.getBytes(resp.nonce);
  const enclaveEph = ethers.getBytes(resp.enclaveEphemeralPubkey);

  // decrypt_share: shared = ephSecret * enclaveEph; key = HKDF(salt=ephPublic, ikm=shared).
  const shared = x25519.getSharedSecret(ephSecret, enclaveEph);
  const key = hkdf32(ephPublic, shared, DKG_SHARE_INFO);
  const plaintext = chachaDecrypt(key, nonce, sealed);
  if (plaintext.length !== 64) {
    throw new Error(`deriveKeys: expected 64 bytes (view||modify), got ${plaintext.length}`);
  }
  return { viewKey: plaintext.slice(0, 32), modifyKey: plaintext.slice(32, 64) };
}

/** Backward-compatible alias for the Gratis ledger. */
export function deriveGratisKeys(signer: ethers.Wallet): Promise<GratisKeys> {
  return deriveKeys(signer, "Gratis");
}

// ---------------------------------------------------------------------------
// Fidelity index query authorization (owner-signed, expiring)
// ---------------------------------------------------------------------------

/**
 * Owner-signed authorization for a Fidelity index query (`getFidelityIndex[At]`).
 * The Fidelity precompile forwards it to the enclave, which recovers the signer
 * and rejects the read unless it equals `account`, the chain matches, and
 * `expiry >= block timestamp`. Unlike a view key, this only authorizes index
 * reads until `expiry` - never decryption of the raw cohort ledger.
 *
 * Message = "outbe/fidelity/query-auth/v1" || chainId(32 BE) || account(20) || expiry(8 BE),
 * signed as EIP-191 personal_sign - mirrors `outbe_tee::protocol::fidelity_query_auth_message`
 * (chainId is `B256::from(U256::from(chain_id))`, i.e. the numeric chain id big-endian).
 */
export async function signFidelityQueryAuth(
  signer: ethers.Wallet,
  chainId: bigint,
  account: string,
  expiry: bigint,
): Promise<string> {
  const message = concat(
    utf8("outbe/fidelity/query-auth/v1"),
    be(chainId, 32),
    addressBytes(account),
    be(expiry, 8),
  );
  return signer.signMessage(message);
}

// ---------------------------------------------------------------------------
// Balance / pledged decryption (view key, client-side)
// ---------------------------------------------------------------------------

function decryptField(
  viewKey: Uint8Array,
  account: string,
  field: number,
  blobHex: string,
  ledger: Ledger,
): bigint {
  const blob = ethers.getBytes(blobHex);
  if (blob.length === 0) return 0n; // fresh slot
  const version = blob.slice(0, 8); // version(8 BE)
  const ct = blob.slice(8);
  // slot nonce = HKDF(salt=view_key, ikm=account||field||version)[..12]
  const ikm = concat(addressBytes(account), Uint8Array.of(field), version);
  const nonce = hkdf32(viewKey, ikm, LEDGER_LABELS[ledger].nonceInfo).slice(0, 12);
  const pt = chachaDecrypt(viewKey, nonce, ct);
  return bytesToBigIntBE(pt);
}

/** Decrypt an account's `balanceOf(...)` ciphertext blob into a bigint. */
export function decryptBalance(
  viewKey: Uint8Array,
  account: string,
  blobHex: string,
  ledger: Ledger = "Gratis",
): bigint {
  return decryptField(viewKey, account, FIELD_BALANCE, blobHex, ledger);
}

/** Decrypt a Gratis account's `pledgedOf(...)` ciphertext blob into a bigint. */
export function decryptPledged(viewKey: Uint8Array, account: string, blobHex: string): bigint {
  return decryptField(viewKey, account, FIELD_PLEDGED, blobHex, "Gratis");
}

// ---------------------------------------------------------------------------
// Write authorization (modify key, client-side)
// ---------------------------------------------------------------------------

/**
 * The modify-key MAC a write must carry:
 * `HMAC(modify_key, "<ledger>/modify/v1" || account || op || amount || opNonce || chainId)`.
 * `opNonce` MUST equal the account's current on-chain `op_nonce` for that ledger.
 * `op` is the ledger op discriminant (`GratisOp` or `PromisOp`).
 */
export function modifyMac(
  modifyKey: Uint8Array,
  account: string,
  op: GratisOp | PromisOp,
  amount: bigint,
  opNonce: bigint,
  chainId: bigint,
  ledger: Ledger = "Gratis",
): string {
  const preimage = concat(
    LEDGER_LABELS[ledger].modifyTag,
    addressBytes(account),
    Uint8Array.of(op),
    be(amount, 32),
    be(opNonce, 8),
    be(chainId, 32),
  );
  return ethers.hexlify(hmacSha256(modifyKey, preimage));
}

/**
 * Find a proof-of-work nonce for an entity id (Gem / Nod), matching
 * `outbe_common::pow`: SHA256(id_be32 || nonce_be8) must have
 * `POW_DIFFICULTY` (= 1) leading zero bytes. Difficulty 1 needs ~256 tries.
 */
export function findPowNonce(id: bigint): bigint {
  const idBytes = be(id, 32);
  for (let n = 0n; n < 1_000_000n; n++) {
    const hash = createHash("sha256").update(Buffer.from(concat(idBytes, be(n, 8)))).digest();
    if (hash[0] === 0) return n;
  }
  throw new Error("findPowNonce: no valid nonce found in 1e6 attempts");
}

/**
 * The per-pledge spend secret the EOA derives from its modify key + the public
 * pledge handle, then hands to the CCA off-chain: `HMAC(modify_key, handle)`.
 */
export function pledgeSecret(modifyKey: Uint8Array, handleHex: string): Uint8Array {
  const handle = ethers.getBytes(handleHex);
  if (handle.length !== 32) throw new Error("pledgeSecret: handle must be 32 bytes");
  return hmacSha256(modifyKey, handle);
}

/**
 * The spend authorization binding a pledge to a destination smart account:
 * `HMAC(pledge_secret, "credis-bind" || bundle)`. Prevents a mempool observer of
 * `requestCredis(handle, spendAuth)` from redirecting the loan.
 */
export function spendAuth(secret: Uint8Array, bundle: string): string {
  return ethers.hexlify(hmacSha256(secret, concat(SPEND_BIND_TAG, addressBytes(bundle))));
}

// ---------------------------------------------------------------------------
// Position id - keccak256(handle || smartAccount), matches CredisContract
// ---------------------------------------------------------------------------

/** `position_id = keccak256(pledge_handle(32) || smart_account(20))` as uint256. */
export function positionId(handleHex: string, smartAccount: string): bigint {
  const handle = ethers.getBytes(handleHex);
  if (handle.length !== 32) throw new Error("positionId: handle must be 32 bytes");
  return BigInt(ethers.keccak256(concat(handle, addressBytes(smartAccount))));
}
