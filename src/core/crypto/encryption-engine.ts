import { mnemonicToSeedSync } from "@scure/bip39";
import * as ed25519 from "@stablelib/ed25519";
import ed2curve from "ed2curve";

import {
  deriveMlKemKeypairFromSeed,
  fingerprintFromPublicRaw,
} from "./crypto-provider";

export interface EncryptionIdentity {
  publicKey: CryptoKey | { raw: Uint8Array }; // X25519 public key
  privateKey: CryptoKey | { raw: Uint8Array }; // X25519 private key
  fingerprint: string; // SHA-256 of X25519 public key
  mlKemPublicKey: Uint8Array; // ML-KEM-768 public key (1184 bytes)
  mlKemSecretKey?: Uint8Array; // ML-KEM-768 secret key (2400 bytes)
}

/**
 * EncryptionEngine
 * ----------------
 * Core cryptographic engine.
 */

export class EncryptionEngine {
  /* ================================
   * Identity
   * ================================ */

  // /**
  //  * Generates a random long-term identity keypair (X25519 only).
  //  * ML-KEM keys are not generated here since random identities
  //  * cannot be deterministically recovered from a mnemonic.
  //  */
  // static async generateIdentity(): Promise<EncryptionIdentity> {
  //   try {
  //     const ed = ed25519.generateKeyPair();
  //     const skCurve = ed2curve.convertSecretKey(ed.secretKey);
  //     const pkCurve = ed2curve.convertPublicKey(ed.publicKey);

  //     if (!skCurve || !pkCurve) {
  //       throw new CryptoError("Failed to convert Ed25519 keys to Curve25519");
  //     }

  //     const pkBytes = new Uint8Array(pkCurve as Uint8Array);
  //     const skBytes = new Uint8Array(skCurve as Uint8Array);

  //     const publicKey = { type: "public", raw: pkBytes } as any;
  //     const privateKey = { type: "private", raw: skBytes } as any;
  //     const fingerprint = fingerprintFromPublicRaw(pkBytes);

  //     return { publicKey, privateKey, fingerprint };
  //   } catch (err) {
  //     throw new CryptoError("Failed to generate identity", err);
  //   }
  // }

  /**
   * Derive a complete identity from a BIP-39 mnemonic.
   *
   * Seed derivation:
   *   mnemonicToSeedSync(mnemonic) → 64-byte BIP-39 seed
   *
   * X25519 derivation (unchanged from before):
   *   seed[0..32] → Ed25519 keypair via generateKeyPairFromSeed
   *              → X25519 via ed2curve conversion
   *
   * ML-KEM-768 derivation (new):
   *   seed[0..64] → ml_kem768.keygen(seed)
   *              → { publicKey: 1184 bytes, secretKey: 2400 bytes }
   *
   * The noble library accepts the full 64-byte BIP-39 seed directly.
   * Internally it uses seed[0..32] for the lattice key matrix and
   * seed[32..64] for the implicit rejection parameter `z`.
   */
  static async deriveIdentityFromMnemonic(
    mnemonic: string,
  ): Promise<EncryptionIdentity> {
    try {
      if (typeof mnemonic !== "string" || mnemonic.trim().length === 0) {
        throw new CryptoError("Mnemonic must be a non-empty string");
      }

      // Step 1: BIP-39 seed → 64 bytes
      const seed = mnemonicToSeedSync(mnemonic); // returns Buffer (Node) or Uint8Array
      const seed64 = new Uint8Array(seed); // normalize to Uint8Array

      // Step 2: X25519 identity from first 32 bytes (existing path)
      const seed32 = seed64.subarray(0, 32);
      const ed = ed25519.generateKeyPairFromSeed(seed32);
      const skCurve = ed2curve.convertSecretKey(ed.secretKey);
      const pkCurve = ed2curve.convertPublicKey(ed.publicKey);

      if (!skCurve || !pkCurve) {
        throw new CryptoError(
          "Failed to convert derived Ed25519 keys to Curve25519",
        );
      }

      const pkCurveBytes = new Uint8Array(pkCurve as Uint8Array);
      const skCurveBytes = new Uint8Array(skCurve as Uint8Array);

      const publicKey = { type: "public", raw: pkCurveBytes } as any;
      const privateKey = { type: "private", raw: skCurveBytes } as any;
      const fingerprint = fingerprintFromPublicRaw(pkCurveBytes);

      // Step 3: ML-KEM-768 keypair from FULL 64-byte seed (new)
      // ml_kem768.keygen() accepts a 64-byte seed directly.
      // seed[0..32] → lattice key matrix expansion (K-PKE keygen)
      // seed[32..64] → implicit rejection parameter z (stored in secretKey)
      const mlKemKeypair = deriveMlKemKeypairFromSeed(seed64);

      return {
        publicKey,
        privateKey,
        fingerprint,
        mlKemPublicKey: mlKemKeypair.publicKey, // 1184 bytes
        mlKemSecretKey: mlKemKeypair.secretKey, // 2400 bytes
      };
    } catch (err) {
      throw new CryptoError("Failed to derive identity from mnemonic", err);
    }
  }

  /* ================================
   * Fingerprinting
   * ================================ */

  /**
   * Generates a SHA-256 fingerprint from a public key.
   */
  static async fingerprintFromPublicKey(
    publicKey: CryptoKey | { raw: Uint8Array },
  ): Promise<string> {
    // Accept both CryptoKey and raw wrappers; use stablelib sha256 via provider
    const anyKey: any = publicKey as any;
    let rawBytes: Uint8Array;
    if (anyKey && anyKey.raw instanceof Uint8Array) {
      rawBytes = anyKey.raw;
    } else {
      this.assertPublicKey(publicKey);
      const exported = await crypto.subtle.exportKey(
        "raw",
        publicKey as CryptoKey,
      );
      rawBytes = new Uint8Array(exported);
    }

    return fingerprintFromPublicRaw(rawBytes);
  }

  /* ================================
   * Validation Helpers
   * ================================ */

  private static assertPublicKey(key: CryptoKey | { raw: Uint8Array }): void {
    const anyKey: any = key as any;
    if (!key) throw new CryptoError("Invalid public key");
    if (anyKey.raw instanceof Uint8Array) return; // raw wrapper
    if ((key as CryptoKey).type !== "public") {
      throw new CryptoError("Invalid public key");
    }
  }
}

/* ================================
 * Errors
 * ================================ */

export class CryptoError extends Error {
  cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "CryptoError";
    this.cause = cause;
  }
}
