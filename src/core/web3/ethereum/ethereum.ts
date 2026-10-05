/**
 * ethereum.ts
 *
 * ⚠️ EXPERIMENTAL — Ethereum keypair utilities for MajikKey.
 *
 * Design (mirrors bitcoin.ts):
 *   - Real BIP-32/BIP-44 derivation off the raw 64-byte BIP-39 seed at the
 *     STANDARD path m/44'/60'/0'/0/0 (see ./constants), so the account is
 *     recoverable in any Ethereum wallet from the mnemonic alone.
 *   - Everything here is pure @noble — address derivation (keccak-256 +
 *     EIP-55), EIP-191 message hashing, recoverable signing — so NO optional
 *     peer dependency is needed for the common operations. Transaction
 *     building / EIP-712 typed data should lazy-load viem or ethers
 *     (not included here).
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { MajikKeyError } from "../../error.js";
import type { EthereumSignature } from "./types.js";

export interface EthereumKeypairMaterial {
  /** 32-byte secp256k1 private key. */
  privateKey: Uint8Array;
  /** 33-byte compressed secp256k1 public key. */
  publicKey: Uint8Array;
}

const enc = (s: string) => new TextEncoder().encode(s);
const hex0x = (u: Uint8Array) => "0x" + bytesToHex(u);

/** Uncompressed (65-byte, 0x04-prefixed) form of a compressed or uncompressed public key. */
export function ethereumUncompressedPublicKey(
  publicKey: Uint8Array,
): Uint8Array {
  if (publicKey.length === 65 && publicKey[0] === 0x04) return publicKey;
  if (publicKey.length !== 33)
    throw new MajikKeyError(
      `Expected a 33-byte compressed secp256k1 public key, got ${publicKey.length} bytes`,
    );
  return secp256k1.Point.fromBytes(publicKey).toBytes(false);
}

/** EIP-55 mixed-case checksum of a lowercase 40-char hex address (no 0x). */
export function toChecksumAddress(lowerHex: string): string {
  const h = bytesToHex(keccak_256(enc(lowerHex)));
  let out = "0x";
  for (let i = 0; i < lowerHex.length; i++)
    out += parseInt(h[i], 16) >= 8 ? lowerHex[i].toUpperCase() : lowerHex[i];
  return out;
}

/** EIP-55 address: last 20 bytes of keccak256(uncompressed pubkey without the 0x04 prefix). */
export function ethereumAddressFromPublicKey(publicKey: Uint8Array): string {
  const uncompressed = ethereumUncompressedPublicKey(publicKey);
  return toChecksumAddress(
    bytesToHex(keccak_256(uncompressed.slice(1)).slice(-20)),
  );
}

export function toEthereumPrivateKeyHex(
  material: EthereumKeypairMaterial,
): string {
  return hex0x(material.privateKey);
}

/** keccak256("\x19Ethereum Signed Message:\n" + byteLength + message) — EIP-191 version 0x45. */
export function hashEthereumMessage(message: string | Uint8Array): Uint8Array {
  const body = typeof message === "string" ? enc(message) : message;
  const prefix = enc(`\x19Ethereum Signed Message:\n${body.length}`);
  const buf = new Uint8Array(prefix.length + body.length);
  buf.set(prefix, 0);
  buf.set(body, prefix.length);
  return keccak_256(buf);
}

/** Sign a 32-byte hash. Deterministic (RFC 6979), low-s, with recovery id. */
export function signEthereumHash(
  material: EthereumKeypairMaterial,
  hash32: Uint8Array,
): EthereumSignature {
  if (hash32.length !== 32)
    throw new MajikKeyError(
      `Expected a 32-byte hash, got ${hash32.length} bytes`,
    );
  // noble v2 "recovered" format = [recovery(1) | r(32) | s(32)]
  const sig = secp256k1.sign(hash32, material.privateKey, {
    prehash: false,
    lowS: true,
    format: "recovered",
  } as any) as Uint8Array;
  const recovery = sig[0] as 0 | 1;
  const r = sig.slice(1, 33);
  const s = sig.slice(33, 65);
  const v = (27 + recovery) as 27 | 28;
  return {
    r: hex0x(r),
    s: hex0x(s),
    v,
    recovery,
    serialized: hex0x(r) + bytesToHex(s) + v.toString(16),
  };
}

export function signEthereumMessage(
  material: EthereumKeypairMaterial,
  message: string | Uint8Array,
): EthereumSignature {
  return signEthereumHash(material, hashEthereumMessage(message));
}

/** Recover the signer's EIP-55 address from a hash and signature (ecrecover). */
export function recoverEthereumAddress(
  hash32: Uint8Array,
  sig: Pick<EthereumSignature, "r" | "s" | "recovery">,
): string {
  const fromHex = (h: string) =>
    Uint8Array.from(Buffer.from(h.slice(2), "hex"));
  const raw = new Uint8Array(65);
  raw[0] = sig.recovery;
  raw.set(fromHex(sig.r), 1);
  raw.set(fromHex(sig.s), 33);
  const pub = secp256k1.recoverPublicKey(raw, hash32, {
    prehash: false,
  } as any);
  return ethereumAddressFromPublicKey(pub);
}
