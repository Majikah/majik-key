/**
 * Phase 1 safety net — run BEFORE and AFTER every registry refactor step.
 * Pins the exact keys that the legacy (pre-`keys`) derivation produced for a
 * fixed public test mnemonic. If any of these fail, deterministic recovery
 * from mnemonic is broken for existing users: fix the code, never the vectors.
 *
 * Adjust the MajikKey import path / passphrase to match your validators.
 */
import { describe, it, expect } from "vitest";
import { hash } from "@stablelib/sha256";
import { MajikKey } from "../src/majik-key";
import { KeyId } from "../src/core/keys/key-id";
import { resolveRequestedKeys } from "../src/core/keys/registry";
import V from "../vectors/legacy-v1.vectors.json";

const PASS = "Vector-Test-Passphrase-123!";
const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
const sha = (u: Uint8Array) => b64(hash(u));

async function fresh() {
  return MajikKey.create(V.mnemonic, PASS, "vector", {
    deriveBitcoin: true,
    mnemonicLanguage: "en",
  });
}

function assertAll(key: MajikKey) {
  expect(key.fingerprint).toBe(V.fingerprint);
  expect(key.publicKeyBase64).toBe(V[KeyId.X25519].publicKey);
  expect(b64(key.edPublicKey!)).toBe(V[KeyId.ED25519].publicKey);
  expect(sha(key.mlKemPublicKey)).toBe(V[KeyId.ML_KEM_768].publicKeySha256);
  expect(sha(key.mlDsaPublicKey!)).toBe(V[KeyId.ML_DSA_87].publicKeySha256);
  expect(b64(key.btcPublicKey!)).toBe(V[KeyId.BTC].publicKey);
  expect(b64(key.getSolanaKeypairMaterial().publicKey)).toBe(
    V[KeyId.SOL].publicKey,
  );

  expect(sha(key.getPrivateKey().raw)).toBe(V[KeyId.X25519].secretKeySha256);
  expect(sha(key.getEdSecretKey())).toBe(V[KeyId.ED25519].secretKeySha256);
  expect(sha(key.getMlKemSecretKey())).toBe(
    V[KeyId.ML_KEM_768].secretKeySha256,
  );
  expect(sha(key.getMlDsaSecretKey())).toBe(V[KeyId.ML_DSA_87].secretKeySha256);
  expect(sha(key.getBtcSecretKey())).toBe(V[KeyId.BTC].secretKeySha256);
  expect(sha(key.getSolanaKeypairMaterial().secretKey)).toBe(
    V[KeyId.SOL].secretKeySha256,
  );
}

describe("legacy-v1 derivation is frozen", () => {
  it("create() from mnemonic reproduces pinned keys", async () => {
    assertAll(await fresh());
  }, 60_000);

  it("toJSON → fromJSON → unlock reproduces the same secrets (decrypt path)", async () => {
    const k = await fresh();
    const restored = MajikKey.fromJSON(k.toJSON());
    await restored.unlock(PASS);
    assertAll(restored);
  }, 60_000);

  it("importFromMnemonicBackup reproduces pinned keys", async () => {
    const k = await fresh();
    const imported = await MajikKey.importFromMnemonicBackup(
      k.backup,
      V.mnemonic,
      PASS,
      "vector",
    );
    assertAll(imported);
  }, 60_000);
});

describe("resolveRequestedKeys", () => {
  it("defaults to the core four", () => {
    expect(resolveRequestedKeys()).toEqual([
      KeyId.X25519,
      KeyId.ED25519,
      KeyId.ML_KEM_768,
      KeyId.ML_DSA_87,
    ]);
  });
  it("always includes core and de-duplicates", () => {
    const r = resolveRequestedKeys([KeyId.ED25519, KeyId.BTC, KeyId.BTC]);
    expect(r).toContain(KeyId.ML_DSA_87);
    expect(r.filter((x) => x === KeyId.BTC)).toHaveLength(1);
  });
  it("derived views are no-ops that need no extra stored key", () => {
    expect(resolveRequestedKeys([KeyId.SOL])).toEqual(resolveRequestedKeys());
  });
  it("rejects unknown, reserved and unsupported ids", () => {
    expect(() => resolveRequestedKeys(["pq:nope"])).toThrow(/Unknown/);
    expect(() => resolveRequestedKeys([KeyId.HQC_128])).toThrow(/reserved/);
    expect(() => resolveRequestedKeys([KeyId.LMS])).toThrow(/not supported/);
  });
  it("rejects defined-but-unimplemented ids until their phase lands", () => {
    expect(() => resolveRequestedKeys([KeyId.ML_KEM_1024])).toThrow(
      /not implemented/,
    );
  });
});
