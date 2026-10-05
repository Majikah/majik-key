/** Fast (no Argon2): derive(seed) must reproduce the frozen legacy-v1 vectors. */
import { describe, it, expect } from "vitest";
import { mnemonicToSeedSync } from "@scure/bip39";
import { hash } from "@stablelib/sha256";
import { KeyId } from "../../src/core/keys/key-id";
import { deriveKeys, KEY_IMPLS } from "../../src/core/keys/key-impls";
import V from "../../vectors/legacy-v1.vectors.json";

const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
const sha = (u: Uint8Array) => b64(hash(u));
const seed = () => new Uint8Array(mnemonicToSeedSync(V.mnemonic));

describe("registry implementations reproduce legacy-v1 vectors", () => {
  const all = deriveKeys(seed(), [
    KeyId.X25519,
    KeyId.ED25519,
    KeyId.ML_KEM_768,
    KeyId.ML_DSA_87,
    KeyId.BTC,
  ]);

  it("x25519", () => {
    expect(b64(all.get(KeyId.X25519)!.publicKey)).toBe(
      V[KeyId.X25519].publicKey,
    );
    expect(sha(all.get(KeyId.X25519)!.secretKey)).toBe(
      V[KeyId.X25519].secretKeySha256,
    );
  });
  it("ed25519", () => {
    expect(b64(all.get(KeyId.ED25519)!.publicKey)).toBe(
      V[KeyId.ED25519].publicKey,
    );
    expect(sha(all.get(KeyId.ED25519)!.secretKey)).toBe(
      V[KeyId.ED25519].secretKeySha256,
    );
  });
  it("ml-kem-768", () => {
    expect(sha(all.get(KeyId.ML_KEM_768)!.publicKey)).toBe(
      V[KeyId.ML_KEM_768].publicKeySha256,
    );
    expect(sha(all.get(KeyId.ML_KEM_768)!.secretKey)).toBe(
      V[KeyId.ML_KEM_768].secretKeySha256,
    );
  });
  it("ml-dsa-87", () => {
    expect(sha(all.get(KeyId.ML_DSA_87)!.publicKey)).toBe(
      V[KeyId.ML_DSA_87].publicKeySha256,
    );
    expect(sha(all.get(KeyId.ML_DSA_87)!.secretKey)).toBe(
      V[KeyId.ML_DSA_87].secretKeySha256,
    );
  });
  it("btc (domain path)", () => {
    expect(b64(all.get(KeyId.BTC)!.publicKey)).toBe(V[KeyId.BTC].publicKey);
    expect(sha(all.get(KeyId.BTC)!.secretKey)).toBe(
      V[KeyId.BTC].secretKeySha256,
    );
  });
  it("does not mutate the seed and rejects wrong seed length", () => {
    const s = seed();
    const copy = s.slice();
    deriveKeys(s, [KeyId.X25519]);
    expect(s).toEqual(copy);
    expect(() => KEY_IMPLS[KeyId.ED25519]!.derive(new Uint8Array(32))).toThrow(
      /64-byte/,
    );
  });
  it("throws for ids with no implementation yet", () => {
    expect(() => deriveKeys(seed(), [KeyId.HQC_128])).toThrow(
      /No derivation implementation/,
    );
  });
});
