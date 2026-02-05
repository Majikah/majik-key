
import { mnemonicToSeedSync } from "@scure/bip39";
import * as ed25519 from "@stablelib/ed25519";
import ed2curve from "ed2curve";

import {
  fingerprintFromPublicRaw,
} from "./crypto-provider";


export interface EncryptionIdentity {
  publicKey: CryptoKey | { raw: Uint8Array };
  privateKey: CryptoKey | { raw: Uint8Array };
  fingerprint: string;
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

  /**
   * Generates a long-term X25519 identity keypair.
   */
  static async generateIdentity(): Promise<EncryptionIdentity> {
    try {
      // Generate an Ed25519 keypair (stablelib) and convert to Curve25519
      const ed = ed25519.generateKeyPair();

      const skCurve = ed2curve.convertSecretKey(ed.secretKey);
      const pkCurve = ed2curve.convertPublicKey(ed.publicKey);

      if (!skCurve || !pkCurve) {
        throw new CryptoError("Failed to convert Ed25519 keys to Curve25519");
      }

      const pkBytes = new Uint8Array(pkCurve as Uint8Array);
      const skBytes = new Uint8Array(skCurve as Uint8Array);

      // Use raw key wrappers (Stablelib-backed) to avoid WebCrypto import variability
      const publicKey = { type: "public", raw: pkBytes } as any;
      const privateKey = { type: "private", raw: skBytes } as any;

      const fingerprint = fingerprintFromPublicRaw(pkBytes);

      return { publicKey, privateKey, fingerprint };
    } catch (err) {
      throw new CryptoError("Failed to generate identity", err);
    }
  }

  /**
   * Derive an identity deterministically from a BIP39 mnemonic.
   * Uses Stablelib Ed25519 to derive a keypair from seed and converts to X25519.
   */
  static async deriveIdentityFromMnemonic(
    mnemonic: string
  ): Promise<EncryptionIdentity> {
    try {
      if (typeof mnemonic !== "string" || mnemonic.trim().length === 0) {
        throw new CryptoError("Mnemonic must be a non-empty string");
      }

      // Convert mnemonic to seed (64 bytes) then reduce to 32 bytes
      const seed = mnemonicToSeedSync(mnemonic); // Buffer
      const seed32 = new Uint8Array(seed.slice(0, 32));

      // Derive Ed25519 keypair from seed (stablelib)
      const ed = ed25519.generateKeyPairFromSeed(seed32);

      // Convert Ed25519 keys to X25519 (curve25519)
      const skCurve = ed2curve.convertSecretKey(ed.secretKey);
      const pkCurve = ed2curve.convertPublicKey(ed.publicKey);

      if (!skCurve || !pkCurve) {
        throw new CryptoError(
          "Failed to convert derived Ed25519 keys to Curve25519"
        );
      }

      // Ensure plain Uint8Array
      const pkCurveBytes = new Uint8Array(pkCurve as Uint8Array);
      const skCurveBytes = new Uint8Array(skCurve as Uint8Array);

      const publicKey = { type: "public", raw: pkCurveBytes } as any;
      const privateKey = { type: "private", raw: skCurveBytes } as any;

      const fingerprint = fingerprintFromPublicRaw(pkCurveBytes);

      return { publicKey, privateKey, fingerprint };
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
    publicKey: CryptoKey | { raw: Uint8Array }
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
        publicKey as CryptoKey
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
