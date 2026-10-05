// encryption-engine.ts from @majikah/majik-key
import { mnemonicToSeedSync } from "@scure/bip39";
import { fingerprintFromPublicRaw } from "./crypto-provider.js";
import { deriveKeys } from "../keys/key-impls.js";
import { KeyId } from "../keys/key-id.js";
import type {
  ED25519RawPublicKey,
  MajikKeyFingerprint,
  MLDSA87RawPublicKey,
  MLKEM768RawPublicKey,
  X25519RawKey,
} from "../types.js";

const secureFill = Uint8Array.prototype.fill;

export interface EncryptionIdentity {
  publicKey: X25519RawKey; // X25519 public key
  privateKey: X25519RawKey; // X25519 private key
  fingerprint: MajikKeyFingerprint; // SHA-256 of X25519 public key
  mlKemPublicKey: MLKEM768RawPublicKey; // ML-KEM-768 public key (1184 bytes)
  mlKemSecretKey?: Uint8Array; // ML-KEM-768 secret key (2400 bytes)
  edPublicKey: ED25519RawPublicKey; // Ed25519, 32 bytes — for signing
  edSecretKey: Uint8Array; // Ed25519, 64 bytes — for signing
  mlDsaPublicKey: MLDSA87RawPublicKey; // ML-DSA-87, 2592 bytes
  mlDsaSecretKey: Uint8Array; // ML-DSA-87, 4896 bytes
}

/**
 * EncryptionEngine
 * ----------------
 * Core cryptographic engine.
 */
export class EncryptionEngine {
  /**
   * Derive the core identity (X25519, Ed25519, ML-KEM-768, ML-DSA-87) from a
   * BIP-39 mnemonic.
   *
   * Since 0.8 this DELEGATES to the key registry (core/keys/key-impls.ts),
   * which is the single source of truth for every derivation recipe. Output is
   * byte-for-byte identical to the previous implementation (pinned by
   * vectors/legacy-v1.vectors.json).
   */
  static async deriveIdentityFromMnemonic(
    mnemonic: string,
  ): Promise<EncryptionIdentity> {
    if (typeof mnemonic !== "string" || mnemonic.trim().length === 0) {
      throw new CryptoError("Mnemonic must be a non-empty string");
    }
    const seed64 = new Uint8Array(mnemonicToSeedSync(mnemonic));
    try {
      const k = deriveKeys(seed64, [
        KeyId.X25519,
        KeyId.ED25519,
        KeyId.ML_KEM_768,
        KeyId.ML_DSA_87,
      ]);
      const x = k.get(KeyId.X25519)!;
      const ed = k.get(KeyId.ED25519)!;
      const kem = k.get(KeyId.ML_KEM_768)!;
      const dsa = k.get(KeyId.ML_DSA_87)!;

      return {
        publicKey: { type: "public", raw: x.publicKey } as any,
        privateKey: { type: "private", raw: x.secretKey } as any,
        fingerprint: fingerprintFromPublicRaw(x.publicKey),
        mlKemPublicKey: kem.publicKey, // 1184 bytes
        mlKemSecretKey: kem.secretKey, // 2400 bytes
        edPublicKey: ed.publicKey, // 32 bytes
        edSecretKey: ed.secretKey, // 64 bytes
        mlDsaPublicKey: dsa.publicKey, // 2592 bytes
        mlDsaSecretKey: dsa.secretKey, // 4896 bytes
      };
    } catch (err) {
      throw new CryptoError("Failed to derive identity from mnemonic", err);
    } finally {
      secureFill.call(seed64, 0);
    }
  }

  /* ================================
   * Fingerprinting
   * ================================ */

  /**
   * Generates a SHA-256 fingerprint from a public key.
   */
  static async fingerprintFromPublicKey(
    publicKey: CryptoKey | X25519RawKey,
  ): Promise<string> {
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

  private static assertPublicKey(key: CryptoKey | X25519RawKey): void {
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

Object.freeze(EncryptionEngine);
Object.freeze(EncryptionEngine.prototype);
