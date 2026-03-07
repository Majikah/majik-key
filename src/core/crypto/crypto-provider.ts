// crypto-provider.ts from @majikah/majik-key
import * as ed25519 from "@stablelib/ed25519";
import ed2curve from "ed2curve";
import { AES } from "@stablelib/aes";
import { GCM } from "@stablelib/gcm";
import { deriveKey } from "@stablelib/pbkdf2";
import { hash, SHA256 } from "@stablelib/sha256";
import * as x25519 from "@stablelib/x25519";
import { arrayToBase64 } from "../utils";
import { argon2id as nobleArgon2id } from "@noble/hashes/argon2.js";
import { ARGON2_PARAMS } from "./constants";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

export const IV_LENGTH = 12;

export function generateRandomBytes(len: number): Uint8Array {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

export function generateEd25519Keypair() {
  const ed = ed25519.generateKeyPair();
  const pkCurve = ed2curve.convertPublicKey(ed.publicKey);
  const skCurve = ed2curve.convertSecretKey(ed.secretKey);
  return {
    edPublic: ed.publicKey,
    edSecret: ed.secretKey,
    xPublic: pkCurve ? new Uint8Array(pkCurve) : null,
    xSecret: skCurve ? new Uint8Array(skCurve) : null,
  };
}

export function deriveEd25519FromSeed(seed32: Uint8Array) {
  const ed = ed25519.generateKeyPairFromSeed(seed32);
  const pkCurve = ed2curve.convertPublicKey(ed.publicKey);
  const skCurve = ed2curve.convertSecretKey(ed.secretKey);
  return {
    edPublic: ed.publicKey,
    edSecret: ed.secretKey,
    xPublic: pkCurve ? new Uint8Array(pkCurve) : null,
    xSecret: skCurve ? new Uint8Array(skCurve) : null,
  };
}

export function fingerprintFromPublicRaw(rawPublic: Uint8Array): string {
  const digest = hash(rawPublic);
  return arrayToBase64(digest);
}

export function aesGcmEncrypt(
  keyBytes: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const aes = new AES(keyBytes);
  const gcm = new GCM(aes);
  return gcm.seal(iv, plaintext);
}

export function aesGcmDecrypt(
  keyBytes: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array | null {
  const aes = new AES(keyBytes);
  const gcm = new GCM(aes);
  return gcm.open(iv, ciphertext);
}

// ─── WASM-first Argon2id with @noble/hashes fallback ─────────────────────────

/**
 * null  = not yet probed
 * true  = hash-wasm loaded and verified
 * false = hash-wasm unavailable or broken — use noble fallback
 */
let _wasmAvailable: boolean | null = null;

async function _probeWasm(): Promise<boolean> {
  try {
    const { argon2id } = await import("hash-wasm");
    // Cheap smoke-test: tiny params, just proves the WASM module loads & runs
    await argon2id({
      password: new Uint8Array(4),
      salt: new Uint8Array(8),
      memorySize: 8,
      iterations: 1,
      parallelism: 1,
      hashLength: 4,
      outputType: "binary",
    });
    return true;
  } catch {
    return false;
  }
}

async function _argon2idWasm(
  input: Uint8Array,
  salt: Uint8Array,
  params: { m: number; t: number; p: number; dkLen: number },
): Promise<Uint8Array> {
  const { argon2id } = await import("hash-wasm");
  return argon2id({
    password: input,
    salt,
    memorySize: params.m, // KB — same unit as noble's m ✓
    iterations: params.t, // hash-wasm calls it iterations, not t
    parallelism: params.p, // hash-wasm calls it parallelism, not p
    hashLength: params.dkLen, // hash-wasm calls it hashLength, not dkLen
    outputType: "binary",
  });
}

function _argon2idNoble(
  input: Uint8Array,
  salt: Uint8Array,
  params: { m: number; t: number; p: number; dkLen: number },
): Uint8Array {
  return nobleArgon2id(input, salt, params);
}

/**
 * Internal: WASM-first argon2id with automatic noble fallback.
 * Probes WASM once per session and caches the result.
 * Falls back silently on any failure — output is always identical.
 */
async function _argon2id(
  input: Uint8Array,
  salt: Uint8Array,
  params: { m: number; t: number; p: number; dkLen: number },
): Promise<Uint8Array> {
  // First call: probe WASM availability
  if (_wasmAvailable === null) {
    _wasmAvailable = await _probeWasm();
    if (!_wasmAvailable) {
      console.warn(
        "[majikah/crypto] hash-wasm unavailable, using @noble/hashes argon2id fallback",
      );
    }
  }

  if (_wasmAvailable) {
    try {
      return await _argon2idWasm(input, salt, params);
    } catch (err) {
      // WASM loaded but failed at runtime (e.g. OOM, corrupted module)
      // Flip flag so we stop trying for the rest of this session
      _wasmAvailable = false;
      console.warn(
        "[majikah/crypto] hash-wasm runtime failure, falling back to @noble/hashes",
        err,
      );
    }
  }

  return _argon2idNoble(input, salt, params);
}

// ─── KDF v2: Argon2id (current) ───────────────────────────────────────────────

/**
 * Derive a 32-byte AES key from a user passphrase using Argon2id.
 * WASM-accelerated via hash-wasm when available, falls back to @noble/hashes.
 *
 * @param passphrase - The user's passphrase (plaintext string)
 * @param salt       - Per-identity random salt (32 bytes recommended)
 * @returns          - 32-byte key suitable for AES-256-GCM
 */
export async function deriveKeyFromPassphraseArgon2(
  passphrase: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const pw = new TextEncoder().encode(passphrase);
  return _argon2id(pw, salt, ARGON2_PARAMS.PASSPHRASE);
}

/**
 * Derive a 32-byte AES key from a BIP-39 mnemonic using Argon2id.
 * WASM-accelerated via hash-wasm when available, falls back to @noble/hashes.
 *
 * @param mnemonic - The 12-word BIP-39 mnemonic (plaintext string)
 * @param salt     - Domain-separator salt (can be a fixed constant)
 * @returns        - 32-byte key suitable for AES-256-GCM
 */
export async function deriveKeyFromMnemonicArgon2(
  mnemonic: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const m = new TextEncoder().encode(mnemonic);
  return _argon2id(m, salt, ARGON2_PARAMS.MNEMONIC);
}

// ─── KDF v1: PBKDF2-SHA256 (legacy — do not use for new operations) ───────────

/**
 * @deprecated KDF v1. Kept for reading existing accounts created before the
 * Argon2id migration. Do NOT use this for new key derivation or re-encryption.
 * When an existing account's passphrase is changed, it will automatically
 * be re-encrypted with Argon2id (kdfVersion: 2).
 */
export function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  iterations = 250000,
  keyLen = 32,
): Uint8Array {
  const pw = new TextEncoder().encode(passphrase);
  return deriveKey(SHA256, pw, salt, iterations, keyLen);
}

/**
 * @deprecated KDF v1. Kept for importing mnemonic backups created before the
 * Argon2id migration. Do NOT use this for new backup exports.
 */
export function deriveKeyFromMnemonic(
  mnemonic: string,
  salt: Uint8Array,
  iterations = 200000,
  keyLen = 32,
): Uint8Array {
  const m = new TextEncoder().encode(mnemonic);
  return deriveKey(SHA256, m, salt, iterations, keyLen);
}

export function x25519SharedSecret(
  privRaw: Uint8Array,
  pubRaw: Uint8Array,
): Uint8Array {
  // Use @stablelib/x25519 for scalar multiplication / shared secret
  const priv = new Uint8Array(privRaw);
  const pub = new Uint8Array(pubRaw);
  if ((x25519 as any).scalarMult) {
    return (x25519 as any).scalarMult(priv, pub) as Uint8Array;
  }
  if ((x25519 as any).sharedKey) {
    return (x25519 as any).sharedKey(priv, pub) as Uint8Array;
  }
  throw new Error("@stablelib/x25519: compatible API not found");
}

export function sha256(input: string): string {
  const hashed = hash(new TextEncoder().encode(input));
  return arrayToBase64(hashed);
}

// ─── ML-KEM-768: Post-Quantum Key Encapsulation ───────────────────────────────

/**
 * Derive a deterministic ML-KEM-768 keypair from a BIP-39 mnemonic seed.
 *
 * How the seed mapping works (from the noble source):
 *   ml_kem768.keygen(seed) where seed = 64 bytes
 *   └── seed.subarray(0, 32) → KPKE key generation (lattice matrix expansion)
 *   └── seed.subarray(32)    → stored as `z` in secret key (implicit rejection)
 *
 * BIP-39 seed mapping:
 *   mnemonicToSeedSync(mnemonic) → 64 bytes (PBKDF2-SHA512 of mnemonic)
 *   ├── seed[0..32]  → Ed25519 keypair → X25519 via ed2curve  (existing)
 *   └── seed[0..64]  → ML-KEM-768 keypair                     (new, uses full 64 bytes)
 *
 * IMPORTANT: ML-KEM gets the FULL 64-byte BIP-39 seed, not just the first 32.
 * This gives ML-KEM its own 64 bits of additional entropy (seed[32..64]) for
 * the implicit rejection parameter `z`, completely independent of the X25519 key.
 *
 * Both keypairs are deterministically derived from the same mnemonic — so
 * recovering the mnemonic recovers both X25519 and ML-KEM keys automatically.
 *
 * @param bip39Seed - Full 64-byte BIP-39 seed from mnemonicToSeedSync()
 * @returns ML-KEM-768 keypair
 */
export function deriveMlKemKeypairFromSeed(bip39Seed: Uint8Array): {
  publicKey: Uint8Array; // 1184 bytes
  secretKey: Uint8Array; // 2400 bytes
} {
  if (bip39Seed.length !== 64) {
    throw new Error(
      `ML-KEM seed must be 64 bytes (got ${bip39Seed.length}). ` +
        `Pass the full output of mnemonicToSeedSync(), not a truncated slice.`,
    );
  }

  return ml_kem768.keygen(bip39Seed);
}

/**
 * Generate a random ML-KEM-768 keypair.
 * Use this for testing only — production identities should use
 * deriveMlKemKeypairFromSeed() for deterministic derivation from mnemonic.
 */
export function generateMlKemKeypair(): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  return ml_kem768.keygen(); // uses crypto.getRandomValues() internally
}

/**
 * ML-KEM encapsulation: generate a shared secret and ciphertext.
 *
 * The post-quantum replacement for X25519 ephemeral key exchange.
 * The sender calls this with the recipient's ML-KEM public key.
 * Only the holder of the corresponding ML-KEM secret key can decapsulate.
 *
 * @param recipientPublicKey - ML-KEM-768 public key (1184 bytes)
 * @returns { sharedSecret: 32 bytes, cipherText: 1088 bytes }
 *
 * Note: The noble library uses `cipherText` (camelCase T) — not `ciphertext`.
 */
export function mlKemEncapsulate(recipientPublicKey: Uint8Array): {
  sharedSecret: Uint8Array; // 32 bytes → use as AES-256-GCM key after hashing
  cipherText: Uint8Array; // 1088 bytes → send to recipient alongside encrypted message
} {
  return ml_kem768.encapsulate(recipientPublicKey);
}

/**
 * ML-KEM decapsulation: recover the shared secret from ciphertext.
 *
 * IMPORTANT: ML-KEM decapsulation NEVER throws on wrong key — it returns
 * a different (useless) shared secret instead. AES-GCM authentication will
 * catch this: decryption will fail with an auth tag mismatch.
 *
 * @param cipherText         - ML-KEM-768 ciphertext (1088 bytes)
 * @param recipientSecretKey - ML-KEM-768 secret key (2400 bytes)
 * @returns sharedSecret (32 bytes)
 */
export function mlKemDecapsulate(
  cipherText: Uint8Array,
  recipientSecretKey: Uint8Array,
): Uint8Array {
  return ml_kem768.decapsulate(cipherText, recipientSecretKey);
}
