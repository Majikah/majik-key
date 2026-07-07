/**
 * solana.ts
 *
 * ⚠️ EXPERIMENTAL — Solana keypair utilities for MajikKey.
 * This module's API may change or be removed without notice in a minor version.
 *
 * Design:
 *   - Solana accounts are plain Ed25519 keypairs — no new key material or
 *     wallet standard is needed, just bytes in the right shape.
 *   - `secretKey` is always the 64-byte nacl/tweetnacl-compatible format
 *     (32-byte seed || 32-byte public key) — exactly what
 *     `@solana/web3.js`'s `Keypair.fromSecretKey()` expects, and exactly
 *     what `@stablelib/ed25519` already produces.
 *   - `@solana/web3.js` is NOT a dependency of this package. It is lazily
 *     `import()`-ed only when a caller needs an actual `Keypair`/`PublicKey`
 *     instance (e.g. to build a transaction). If it isn't installed, we
 *     throw a clear, actionable MajikKeyError instead of failing module
 *     load. Base58 address derivation does NOT require the library at all.
 *
 * Two ways to obtain a Solana identity from a MajikKey:
 *   1. deriveSolanaKeypairFromEdSecretKey() — RECOMMENDED. Domain-separates
 *      a brand-new Ed25519 keypair from the MajikKey's message-signing
 *      Ed25519 secret key, so the Solana key is never reused elsewhere.
 *   2. solanaMaterialFromEd25519SecretKey() — reuses the MajikKey's message
 *      signing Ed25519 keypair AS-IS. Simpler, but means the same private
 *      key secures two different protocols. Opt-in only.
 */

import * as ed25519 from "@stablelib/ed25519";
import { hash } from "@stablelib/sha256";
import { MAJIK_SOLANA_SEED } from "./constants";
import { MajikKeyError } from "../error";

const ED25519_SECRET_KEY_LENGTH = 64;
const ED25519_SEED_LENGTH = 32;

export interface SolanaKeypairMaterial {
  /** 32-byte Ed25519 / Solana public key. */
  publicKey: Uint8Array;
  /** 64-byte nacl-format secret key (32-byte seed || 32-byte public key). */
  secretKey: Uint8Array;
}

// ─── Derivation ─────────────────────────────────────────────────────────────

/**
 * Derive a Solana keypair domain-separated from the MajikKey's
 * message-signing Ed25519 key, but fully deterministic from it (and
 * therefore ultimately from the mnemonic).
 *
 *   seed' = SHA256(edSecretKey[0..32] || "MajikMessageSolanaSeed")
 */
export function deriveSolanaKeypairFromEdSecretKey(
  edSecretKey: Uint8Array,
): SolanaKeypairMaterial {
  if (edSecretKey.length !== ED25519_SECRET_KEY_LENGTH) {
    throw new MajikKeyError(
      `Expected a 64-byte Ed25519 secret key, got ${edSecretKey.length} bytes`,
    );
  }
  const edSeed = edSecretKey.slice(0, ED25519_SEED_LENGTH);
  const domain = new TextEncoder().encode(MAJIK_SOLANA_SEED);
  const combined = new Uint8Array(edSeed.length + domain.length);
  combined.set(edSeed, 0);
  combined.set(domain, edSeed.length);

  const solanaSeed = hash(combined); // 32 bytes
  const kp = ed25519.generateKeyPairFromSeed(solanaSeed);
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

/**
 * Reuse the MajikKey's existing message-signing Ed25519 keypair directly
 * as a Solana keypair (no re-derivation).
 *
 * ⚠️ Not recommended: the same private key would secure both Majik message
 * signing AND any Solana transactions. Prefer
 * `deriveSolanaKeypairFromEdSecretKey()` unless you specifically want the
 * identical key on both.
 */
export function solanaMaterialFromEd25519SecretKey(
  edSecretKey: Uint8Array,
): SolanaKeypairMaterial {
  if (edSecretKey.length !== ED25519_SECRET_KEY_LENGTH) {
    throw new MajikKeyError(
      `Expected a 64-byte Ed25519 secret key, got ${edSecretKey.length} bytes`,
    );
  }
  return {
    publicKey: edSecretKey.slice(ED25519_SEED_LENGTH),
    secretKey: edSecretKey.slice(),
  };
}

// ─── Base58 (Solana address encoding) — no external dependency ─────────────

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  const digits: number[] = [0];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let leadingZeros = 0;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) leadingZeros++;

  let result = "1".repeat(leadingZeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

/**
 * Solana address for a given Solana/Ed25519 public key — just its base58
 * encoding. Does NOT require @solana/web3.js.
 */
export function solanaAddressFromPublicKey(publicKey: Uint8Array): string {
  return base58Encode(publicKey);
}

// ─── Lazy @solana/web3.js loader ────────────────────────────────────────────

// core/web3/solana.ts

type SolanaKitModule = typeof import("@solana/kit");

let _kitModule: SolanaKitModule | null = null;

export async function loadSolanaKit(): Promise<SolanaKitModule> {
  if (_kitModule) return _kitModule;
  try {
    _kitModule = (await import(
      /* webpackIgnore: true */
      /* @vite-ignore */
      "@solana/kit"
    )) as SolanaKitModule;
    return _kitModule;
  } catch (err) {
    throw new MajikKeyError(
      "@solana/kit is required for this operation but is not installed. " +
        "Install it in your project with `npm install @solana/kit` " +
        "(or the yarn/pnpm equivalent) and try again.",
      err,
    );
  }
}

/**
 * Real @solana/kit KeyPairSigner backed by a genuine CryptoKeyPair.
 * Requires @solana/kit — see loadSolanaKit().
 */
export async function toSolanaKeyPairSigner(
  material: SolanaKeypairMaterial,
): Promise<Awaited<ReturnType<SolanaKitModule["createKeyPairSignerFromBytes"]>>> {
  const kit = await loadSolanaKit();
  return kit.createKeyPairSignerFromBytes(material.secretKey);
}

/**
 * Real @solana/kit Address (branded string) for this material's public key.
 */
export async function toSolanaAddress(
  material: SolanaKeypairMaterial,
): Promise<Awaited<ReturnType<SolanaKitModule["getAddressFromPublicKey"]>>> {
  const kit = await loadSolanaKit();
  const signer = await toSolanaKeyPairSigner(material);
  return signer.address;
}
/**
 * Sign an arbitrary message with a Solana keypair's Ed25519 secret key.
 * Uses @stablelib/ed25519 directly — does NOT require @solana/web3.js.
 */
export function signWithSolanaMaterial(
  material: SolanaKeypairMaterial,
  message: Uint8Array,
): Uint8Array {
  return ed25519.sign(material.secretKey, message);
}
