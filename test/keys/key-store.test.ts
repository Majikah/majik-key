import { describe, it, expect } from "vitest";
import { mnemonicToSeedSync } from "@scure/bip39";
import { hash } from "@stablelib/sha256";
import { KeyId } from "../../src/core/keys/key-id";
import { deriveKeys } from "../../src/core/keys/key-impls";
import { KeyStore } from "../../src/core/keys/key-store";
import V from "../../vectors/legacy-v1.vectors.json";

const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
const sha = (u: Uint8Array) => b64(hash(u));
const IDS = [
  KeyId.X25519,
  KeyId.ED25519,
  KeyId.ML_KEM_768,
  KeyId.ML_DSA_87,
  KeyId.BTC,
];
const rnd = () => crypto.getRandomValues(new Uint8Array(32));

function fresh(aes: Uint8Array) {
  return KeyStore.fromDerived(
    deriveKeys(new Uint8Array(mnemonicToSeedSync(V.mnemonic)), IDS),
    aes,
  );
}

describe("KeyStore", () => {
  it("fromDerived is unlocked and entries → fromEntries → unlock reproduces pinned secrets", () => {
    const aes = rnd();
    const a = fresh(aes);
    expect(a.isUnlocked).toBe(true);
    const b = KeyStore.fromEntries(JSON.parse(JSON.stringify(a.toEntries())));
    expect(b.isUnlocked).toBe(false);
    expect(() => b.getSecretKey(KeyId.ED25519)).toThrow(/locked/);
    b.unlock(() => aes);
    expect(sha(b.getSecretKey(KeyId.X25519))).toBe(
      V[KeyId.X25519].secretKeySha256,
    );
    expect(sha(b.getSecretKey(KeyId.ED25519))).toBe(
      V[KeyId.ED25519].secretKeySha256,
    );
    expect(sha(b.getSecretKey(KeyId.ML_KEM_768))).toBe(
      V[KeyId.ML_KEM_768].secretKeySha256,
    );
    expect(sha(b.getSecretKey(KeyId.ML_DSA_87))).toBe(
      V[KeyId.ML_DSA_87].secretKeySha256,
    );
    expect(sha(b.getSecretKey(KeyId.BTC))).toBe(V[KeyId.BTC].secretKeySha256);
  });

  it("unlock is atomic: a wrong key leaves the store fully locked", () => {
    const aes = rnd();
    const b = KeyStore.fromEntries(fresh(aes).toEntries());
    const good = aes,
      bad = rnd();
    // right key for X25519, wrong key for the rest → must fail and stay locked
    expect(() => b.unlock((s) => (s.id === KeyId.X25519 ? good : bad))).toThrow(
      /Failed to decrypt/,
    );
    expect(b.isUnlocked).toBe(false);
    for (const id of IDS) expect(() => b.getSecretKey(id)).toThrow(/locked/);
  });

  it("lock() zeroizes secrets in place", () => {
    const s = fresh(rnd());
    const ref = s.getSecretKey(KeyId.ML_DSA_87);
    s.lock();
    expect(ref.every((x) => x === 0)).toBe(true);
    expect(s.isUnlocked).toBe(false);
  });

  it("ids() is canonical order; has/missing/hasAll work", () => {
    const s = fresh(rnd());
    expect(s.ids()).toEqual([
      KeyId.X25519,
      KeyId.ED25519,
      KeyId.ML_KEM_768,
      KeyId.ML_DSA_87,
      KeyId.BTC,
    ]);
    expect(s.has(KeyId.BTC)).toBe(true);
    expect(s.has(KeyId.ML_KEM_1024)).toBe(false);
    expect(s.missing([KeyId.ED25519, KeyId.ML_KEM_1024])).toEqual([
      KeyId.ML_KEM_1024,
    ]);
    expect(s.hasAll([KeyId.ED25519, "pq:nope"])).toBe(false);
  });

  it("legacy JSON ⇄ store round trip (Tier 1 migration + legacy export)", () => {
    const a = fresh(rnd());
    const legacy = a.toLegacyJSON();
    expect(Object.keys(legacy).sort()).toEqual([
      "btcPublicKey",
      "edPublicKey",
      "encryptedBtcSecretKey",
      "encryptedEdSecretKey",
      "encryptedMlDsaSecretKey",
      "encryptedMlKemSecretKey",
      "encryptedPrivateKey",
      "mlDsaPublicKey",
      "mlKemPublicKey",
      "publicKey",
    ]);
    expect(legacy.publicKey).toBe(V[KeyId.X25519].publicKey);
    const migrated = KeyStore.fromLegacyJSON(legacy);
    expect(migrated.toEntries()).toEqual(
      a
        .toEntries()
        .map((e) => ({ ...e, createdAt: undefined }))
        .map(({ createdAt, ...r }) => r),
    );
    expect(migrated.toLegacyJSON()).toEqual(legacy);
  });

  it("legacy account missing optional keys migrates; missing X25519 is rejected", () => {
    const a = fresh(rnd()).toLegacyJSON();
    const minimal = KeyStore.fromLegacyJSON({
      publicKey: a.publicKey,
      encryptedPrivateKey: a.encryptedPrivateKey,
    });
    expect(minimal.ids()).toEqual([KeyId.X25519]);
    expect(
      minimal.missing([KeyId.ED25519, KeyId.ML_DSA_87, KeyId.ML_KEM_768]),
    ).toHaveLength(3);
    expect(() => KeyStore.fromLegacyJSON({ publicKey: "" } as any)).toThrow(
      /X25519/,
    );
  });

  it("re-seal: new blobs open only with the new key, nothing mutated until commit", () => {
    const oldK = rnd(),
      newK = rnd();
    const s = KeyStore.fromEntries(fresh(oldK).toEntries());
    const before = JSON.stringify(s.toEntries());
    const blobs = s.prepareReseal(() => oldK, newK);
    expect(JSON.stringify(s.toEntries())).toBe(before);
    s.commitReseal(blobs);
    expect(() => s.unlock(() => oldK)).toThrow();
    s.unlock(() => newK);
    expect(sha(s.getSecretKey(KeyId.ED25519))).toBe(
      V[KeyId.ED25519].secretKeySha256,
    );
  });

  it("unknown (newer-version) entries round-trip untouched and block re-seal", () => {
    const aes = rnd();
    const entries = fresh(aes).toEntries();
    const future = {
      id: "pq:future-kem-9000",
      publicKey: "AAAA",
      encryptedSecretKey: "BBBB",
      derivation: { scheme: "x", version: 9 },
    } as any;
    const s = KeyStore.fromEntries([...entries, future]);
    expect(s.toEntries().at(-1)).toEqual(future);
    expect(s.ids()).not.toContain("pq:future-kem-9000" as any);
    expect(() => s.prepareReseal(() => aes, rnd())).toThrow(
      /newer library version/,
    );
    s.unlock(() => aes); // known keys still unlock fine
    expect(s.isUnlocked).toBe(true);
  });

  it("rejects duplicate and malformed entries", () => {
    const e = fresh(rnd()).toEntries();
    expect(() => KeyStore.fromEntries([e[0], e[0]])).toThrow(/Duplicate/);
    expect(() => KeyStore.fromEntries([{ id: 5 } as any])).toThrow(
      /Invalid key entry/,
    );
  });
});
