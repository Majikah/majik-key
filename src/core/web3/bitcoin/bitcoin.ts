/**
 * bitcoin.ts
 *
 * ⚠️ EXPERIMENTAL — Bitcoin keypair utilities for MajikKey.
 * This module's API may change or be removed without notice in a minor version.
 *
 * Design:
 *   - Real BIP-32/BIP-84 HD derivation directly off the raw 64-byte BIP-39
 *     seed — NOT a hash-based domain separation like Solana. This matters:
 *     BIP-32's tree structure lets us get privacy AND portability from the
 *     exact same standard, auditable derivation, just by choosing the path:
 *
 *       MAJIK_BITCOIN_DOMAIN_PATH   (default) — effectively private to Majik;
 *         not the path any generic wallet would derive by default.
 *       MAJIK_BITCOIN_STANDARD_PATH (opt-in)  — the REAL BIP-84 mainnet path;
 *         recoverable in any standard wallet using nothing but the mnemonic.
 *
 *   - `privateKey` is the raw 32-byte secp256k1 scalar. `toWIF()` encodes it
 *     into Wallet Import Format — the universal paste-in-import string every
 *     Bitcoin wallet accepts (base58check, versioned, deterministic).
 *   - `@scure/btc-signer` is NOT a hard dependency. It is lazily `import()`-ed
 *     only for bech32 address encoding / PSBT construction. If it isn't
 *     installed, we throw a clear, actionable MajikKeyError instead of
 *     failing module load.
 */

import { HDKey } from "@scure/bip32";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";

import {
  MAJIK_BITCOIN_STANDARD_PATH,
  MAJIK_BITCOIN_DOMAIN_PATH,
} from "./constants";
import { hash } from "@stablelib/sha256";
import { base58Encode } from "../utils";
import { MajikKeyError } from "../../error";
import { randomBytes } from "@noble/hashes/utils.js";

export interface BitcoinKeypairMaterial {
  /** 32-byte secp256k1 private key. */
  privateKey: Uint8Array;
  /** 33-byte compressed secp256k1 public key. */
  publicKey: Uint8Array;
}

export interface BitcoinDerivationOptions {
  /**
   * If true, derive the REAL BIP-84 mainnet path (SLIP-44 coin type 0) —
   * the address any standard wallet would show for this mnemonic.
   * Defaults to false (Majik's domain-separated path).
   */
  standard?: boolean;
  /** Explicit derivation path — overrides `standard` if provided. */
  path?: string;
}

// ─── Derivation ─────────────────────────────────────────────────────────────

/**
 * Derive a Bitcoin keypair via standard BIP-32/BIP-84 from the raw 64-byte
 * BIP-39 seed. Call this once at account creation/import time (mirrors
 * ML-KEM/Ed25519/ML-DSA derivation) — the seed itself is never stored, only
 * the resulting key, encrypted at rest like the others.
 */
export function deriveBitcoinKeypairFromSeed(
  seed: Uint8Array,
  options?: BitcoinDerivationOptions,
): BitcoinKeypairMaterial {
  const path =
    options?.path ??
    (options?.standard
      ? MAJIK_BITCOIN_STANDARD_PATH
      : MAJIK_BITCOIN_DOMAIN_PATH);

  const child = HDKey.fromMasterSeed(seed).derive(path);
  if (!child.privateKey || !child.publicKey) {
    throw new MajikKeyError("Failed to derive Bitcoin keypair from seed");
  }
  return {
    privateKey: child.privateKey,
    publicKey: child.publicKey,
  };
}

/**
 * Re-derive the public key from a raw private key. Used when unlocking —
 * we only encrypt/store the private key, so the public key is recomputed
 * on unlock rather than stored redundantly encrypted.
 */
export function bitcoinPublicKeyFromPrivateKey(
  privateKey: Uint8Array,
): Uint8Array {
  return secp256k1.getPublicKey(privateKey, true); // compressed
}

/** Sign a 32-byte message hash (already hashed — e.g. a Bitcoin sighash). */
export function signWithBitcoinMaterial(
  material: BitcoinKeypairMaterial,
  messageHash: Uint8Array,
  scheme: "ecdsa" | "schnorr" = "ecdsa",
): Uint8Array {
  if (scheme === "schnorr") {
    return schnorr.sign(messageHash, material.privateKey, randomBytes(32));
  }

  const signature = secp256k1.sign(messageHash, material.privateKey, {
    prehash: false,
    lowS: true, // Note: lowS is technically default in v2 for secp256k1, but it's good practice to be explicit!
  });

  return signature;
}

// ─── WIF export (Wallet Import Format) — no external lib needed ────────────

const WIF_VERSION_MAINNET = 0x80;

function doubleSha256(data: Uint8Array): Uint8Array {
  return hash(hash(data));
}

function base58checkEncode(payload: Uint8Array): string {
  const checksum = doubleSha256(payload).slice(0, 4);
  const full = new Uint8Array(payload.length + 4);
  full.set(payload, 0);
  full.set(checksum, payload.length);
  return base58Encode(full);
}

/**
 * Encode a private key as WIF — the universal paste-in-import string every
 * Bitcoin wallet accepts. Deterministic: same private key → same WIF, always.
 */
export function toWIF(
  material: BitcoinKeypairMaterial,
  options?: { compressed?: boolean },
): string {
  const compressed = options?.compressed ?? true;
  const payload = new Uint8Array(compressed ? 34 : 33);
  payload[0] = WIF_VERSION_MAINNET;
  payload.set(material.privateKey, 1);
  if (compressed) payload[33] = 0x01;
  return base58checkEncode(payload);
}

// ─── Lazy @scure/btc-signer loader (address encoding, PSBTs) ───────────────

type BtcSignerModule = typeof import("@scure/btc-signer");

let _btcModule: BtcSignerModule | null = null;

export async function loadBtcSigner(): Promise<BtcSignerModule> {
  if (_btcModule) return _btcModule;
  try {
    _btcModule = (await import(
      /* webpackIgnore: true */
      /* @vite-ignore */
      "@scure/btc-signer"
    )) as BtcSignerModule;
    return _btcModule;
  } catch (err) {
    throw new MajikKeyError(
      "@scure/btc-signer is required for this operation but is not installed. " +
        "Install it in your project with `npm install @scure/btc-signer` " +
        "(or the yarn/pnpm equivalent) and try again.",
      err,
    );
  }
}

/**
 * Native SegWit (bech32, "bc1...") mainnet address for this material's
 * public key. Requires @scure/btc-signer — see loadBtcSigner().
 */
export async function toBitcoinAddress(
  material: BitcoinKeypairMaterial,
): Promise<string> {
  const btc = await loadBtcSigner();
  const p2wpkh = btc.p2wpkh(material.publicKey);
  if (!p2wpkh.address) {
    throw new MajikKeyError("Failed to derive Bitcoin address");
  }
  return p2wpkh.address;
}
