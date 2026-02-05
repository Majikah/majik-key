import * as ed25519 from "@stablelib/ed25519";
import ed2curve from "ed2curve";
import { AES } from "@stablelib/aes";
import { GCM } from "@stablelib/gcm";
import { deriveKey } from "@stablelib/pbkdf2";
import { hash, SHA256 } from "@stablelib/sha256";
import * as x25519 from "@stablelib/x25519";
import { arrayToBase64 } from "../utils";



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
  plaintext: Uint8Array
): Uint8Array {
  const aes = new AES(keyBytes);
  const gcm = new GCM(aes);
  return gcm.seal(iv, plaintext);
}

export function aesGcmDecrypt(
  keyBytes: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array | null {
  const aes = new AES(keyBytes);
  const gcm = new GCM(aes);
  return gcm.open(iv, ciphertext);
}

export function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  iterations = 250000,
  keyLen = 32
): Uint8Array {
  const pw = new TextEncoder().encode(passphrase);
  return deriveKey(SHA256, pw, salt, iterations, keyLen);
}

export function deriveKeyFromMnemonic(
  mnemonic: string,
  salt: Uint8Array,
  iterations = 200000,
  keyLen = 32
): Uint8Array {
  const m = new TextEncoder().encode(mnemonic);
  return deriveKey(SHA256, m, salt, iterations, keyLen);
}

export function x25519SharedSecret(
  privRaw: Uint8Array,
  pubRaw: Uint8Array
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