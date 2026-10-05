/**
 * Phase 2c-wire/2d — MajikKey on top of the KeyStore registry.
 * Gate: every pinned legacy-v1 vector must still reproduce through the NEW API,
 * and legacy (pre-`keys`) JSON must auto-migrate.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { mnemonicToSeedSync } from "@scure/bip39";
import { hash } from "@stablelib/sha256";
import { MajikKey, KeyId, CORE_KEYS } from "../src/majik-key";
import { KeyStore } from "../src/core/keys/key-store";
import { deriveKeys } from "../src/core/keys/key-impls";
import { deriveKeyFromPassphrase } from "../src/core/crypto/crypto-provider";
import { arrayToBase64 } from "../src/core/utils";
import V from "../vectors/legacy-v1.vectors.json";

const PASS = "Vector-Test-Passphrase-123!";
const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
const sha = (u: Uint8Array) => b64(hash(u));
const OTHER =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";

function assertCoreAndBtc(k: MajikKey) {
  expect(k.fingerprint).toBe(V.fingerprint);
  expect(b64(k.getPublicKey(KeyId.X25519))).toBe(V[KeyId.X25519].publicKey);
  expect(b64(k.getPublicKey(KeyId.ED25519))).toBe(V[KeyId.ED25519].publicKey);
  expect(sha(k.getPublicKey(KeyId.ML_KEM_768))).toBe(
    V[KeyId.ML_KEM_768].publicKeySha256,
  );
  expect(sha(k.getPublicKey(KeyId.ML_DSA_87))).toBe(
    V[KeyId.ML_DSA_87].publicKeySha256,
  );
  expect(sha(k.getPrivateKey(KeyId.X25519))).toBe(
    V[KeyId.X25519].secretKeySha256,
  );
  expect(sha(k.getPrivateKey(KeyId.ED25519))).toBe(
    V[KeyId.ED25519].secretKeySha256,
  );
  expect(sha(k.getPrivateKey(KeyId.ML_KEM_768))).toBe(
    V[KeyId.ML_KEM_768].secretKeySha256,
  );
  expect(sha(k.getPrivateKey(KeyId.ML_DSA_87))).toBe(
    V[KeyId.ML_DSA_87].secretKeySha256,
  );
}
function assertBtc(k: MajikKey) {
  expect(b64(k.getPublicKey(KeyId.BTC))).toBe(V[KeyId.BTC].publicKey);
  expect(sha(k.getPrivateKey(KeyId.BTC))).toBe(V[KeyId.BTC].secretKeySha256);
}

let base: MajikKey; // core + BTC, unlocked
beforeAll(async () => {
  base = await MajikKey.create(V.mnemonic, PASS, "t", { keys: [KeyId.BTC] });
});

describe("create()", () => {
  it("defaults to the core four (+ derived web3:sol view); no BTC unless asked", async () => {
    const k = await MajikKey.create(V.mnemonic, PASS);
    expect(k.availableKeys()).toEqual([...CORE_KEYS, KeyId.SOL]);
    expect(k.hasKey(KeyId.BTC)).toBe(false);
    expect(k.isCoreComplete).toBe(true);
    expect(k.hasBitcoin).toBe(false);
    assertCoreAndBtc(k);
  });
  it("legacy deriveBitcoin:true still adds BTC", async () => {
    const k = await MajikKey.create(V.mnemonic, PASS, "x", {
      deriveBitcoin: true,
      mnemonicLanguage: "en",
    });
    expect(k.hasKey(KeyId.BTC)).toBe(true);
    assertBtc(k);
  });
  it("rejects reserved / unsupported / unknown ids", async () => {
    await expect(
      MajikKey.create(V.mnemonic, PASS, "", { keys: [KeyId.HQC_128] }),
    ).rejects.toThrow(/reserved/);
    await expect(
      MajikKey.create(V.mnemonic, PASS, "", { keys: [KeyId.LMS] }),
    ).rejects.toThrow(/not supported/);
    await expect(
      MajikKey.create(V.mnemonic, PASS, "", { keys: ["pq:nope" as any] }),
    ).rejects.toThrow(/Unknown/);
  });
});

describe("registry accessors", () => {
  it("new API reproduces pinned vectors, incl. BTC and the Solana view", () => {
    assertCoreAndBtc(base);
    assertBtc(base);
    expect(b64(base.getPublicKey(KeyId.SOL))).toBe(V[KeyId.SOL].publicKey);
    expect(sha(base.getPrivateKey(KeyId.SOL))).toBe(
      V[KeyId.SOL].secretKeySha256,
    );
    expect(sha(base.getKeypair(KeyId.ML_DSA_87).private)).toBe(
      V[KeyId.ML_DSA_87].secretKeySha256,
    );
    expect(base.getKeypair(KeyId.ED25519).publicBase64).toBe(
      V[KeyId.ED25519].publicKey,
    );
  });
  it("deprecated getters are wrappers returning identical bytes", () => {
    expect(base.getEdSecretKey()).toBe(base.getPrivateKey(KeyId.ED25519));
    expect(base.getMlKemSecretKey()).toBe(base.getPrivateKey(KeyId.ML_KEM_768));
    expect(base.getMlDsaSecretKey()).toBe(base.getPrivateKey(KeyId.ML_DSA_87));
    expect(base.getBtcSecretKey()).toBe(base.getPrivateKey(KeyId.BTC));
    expect(base.getPrivateKey().raw).toBe(base.getPrivateKey(KeyId.X25519));
    expect(base.getPrivateKeyBase64()).toBe(
      b64(base.getPrivateKey(KeyId.X25519)),
    );
    expect(b64(base.mlKemPublicKey)).toBe(
      b64(base.getPublicKey(KeyId.ML_KEM_768)),
    );
    expect(
      base.hasMlKem &&
        base.hasSigningKeys &&
        base.hasBitcoin &&
        base.hasSolanaKeypair,
    ).toBe(true);
    expect(base.isFullyUpgraded).toBe(true);
  });
  it("availableKeys / family filter / listKeys / missingKeys / supportedKeys", () => {
    expect(base.availableKeys({ family: "pq" })).toEqual([
      KeyId.ML_KEM_768,
      KeyId.ML_DSA_87,
    ]);
    expect(base.availableKeys({ family: "web3" })).toEqual([
      KeyId.BTC,
      KeyId.SOL,
    ]);
    expect(base.missingKeys()).toEqual([]);
    expect(base.missingKeys([KeyId.ED25519, KeyId.ML_KEM_1024])).toEqual([
      KeyId.ML_KEM_1024,
    ]);
    expect(base.hasKeys([KeyId.ED25519, KeyId.SOL])).toBe(true);
    const info = base.listKeys().find((i) => i.id === KeyId.ML_DSA_87)!;
    expect(info).toMatchObject({
      family: "pq",
      purpose: "signature",
      kind: "stored",
      status: "stable",
    });
    expect(base.listKeys().find((i) => i.id === KeyId.SOL)!.kind).toBe(
      "derived",
    );
    expect(MajikKey.supportedKeys()).toContain(KeyId.BTC);
    expect(base.metadata.keys).toEqual(base.availableKeys());
  });
  it("unknown ids throw; handle stays live across lock()", async () => {
    expect(() => base.getPublicKey(KeyId.ML_KEM_1024)).toThrow(
      /No "pq:ml-kem-1024"/,
    );
    expect(() => base.getKeypair(KeyId.ETH)).toThrow(/No "web3:eth"/);
    const j = base.toJSON();
    const k = MajikKey.fromJSON(j);
    await k.unlock(PASS);
    const h = k.getKeypair(KeyId.ML_DSA_87);
    expect(h.isUnlocked).toBe(true);
    k.lock();
    expect(h.isUnlocked).toBe(false);
    expect(() => h.private).toThrow(/locked/);
    expect(h.public.length).toBeGreaterThan(0);
    expect(k.mlKemSecretKey).toBeUndefined();
    expect(() => k.getEdSecretKey()).toThrow(/locked/);
    expect(() => k.getPublicKey(KeyId.SOL)).toThrow(/locked/);
  });
});

describe("serialization + migration", () => {
  it("toJSON dual-writes by default; { legacy:false } is registry-only; JSON.stringify works", () => {
    const j: any = base.toJSON();
    expect(j.keysVersion).toBe(1);
    expect(j.keys.map((e: any) => e.id)).toEqual(
      base.availableKeys().filter((i) => i !== KeyId.SOL),
    );
    expect(j.encryptedMlKemSecretKey).toBeTruthy();
    expect(j.encryptedPrivateKey).toBeTruthy();
    const lean: any = base.toJSON({ legacy: false });
    expect(lean.encryptedMlKemSecretKey).toBeUndefined();
    expect(lean.encryptedPrivateKey).toBeUndefined();
    expect(lean.publicKey).toBe(V[KeyId.X25519].publicKey);
    expect(JSON.parse(JSON.stringify(base)).keys).toBeDefined();
    expect(JSON.stringify(j)).not.toMatch(/secretKeys|privateKeyBase64/);
  });

  it("registry-only JSON → fromJSON → unlock reproduces vectors", async () => {
    const k = MajikKey.fromJSON(
      base.toString(false) && base.toJSON({ legacy: false }),
    );
    expect(k.isLocked).toBe(true);
    await k.unlock(PASS);
    assertCoreAndBtc(k);
    assertBtc(k);
  });

  it("legacy flat JSON (no `keys`) auto-migrates, unlocks, and re-serializes upgraded", async () => {
    const legacy: any = JSON.parse(JSON.stringify(base.toJSON()));
    delete legacy.keys;
    delete legacy.keysVersion;
    const k = MajikKey.fromJSON(legacy);
    expect(k.availableKeys()).toEqual(base.availableKeys());
    expect(k.isCoreComplete).toBe(true);
    await k.unlock(PASS);
    assertCoreAndBtc(k);
    assertBtc(k);
    expect((k.toJSON() as any).keys).toHaveLength(5);
  });

  it("REAL legacy fixture (vectors/legacy-account.json), if present, migrates and matches vectors", async () => {
    const f = new URL("../vectors/legacy-account.json", import.meta.url);
    if (!existsSync(f)) return; // generate it with the pre-registry code, then commit it
    const k = MajikKey.fromJSON(readFileSync(f, "utf8"));
    await k.unlock(PASS);
    assertCoreAndBtc(k);
  });

  it("conflicting flat publicKey vs keys entry is rejected; newer keysVersion is rejected", () => {
    const j: any = JSON.parse(JSON.stringify(base.toJSON()));
    expect(() => MajikKey.fromJSON({ ...j, publicKey: "AAAA" })).toThrow(
      /does not match/,
    );
    expect(() => MajikKey.fromJSON({ ...j, keysVersion: 99 })).toThrow(
      /Upgrade the library/,
    );
  });

  it("dangerous JSON round-trips, includes secretKeys for every stored key", () => {
    const d: any = base.toDangerousJSON();
    expect(Object.keys(d.secretKeys).sort()).toEqual(
      [
        KeyId.BTC,
        KeyId.ED25519,
        KeyId.ML_DSA_87,
        KeyId.ML_KEM_768,
        KeyId.X25519,
      ].sort(),
    );
    const k = MajikKey.fromDangerousJSON(JSON.stringify(d));
    expect(k.isUnlocked).toBe(true);
    assertCoreAndBtc(k);
    assertBtc(k);
    // legacy-shaped dangerous JSON (no keys / secretKeys) still loads
    const old: any = { ...d };
    delete old.keys;
    delete old.keysVersion;
    delete old.secretKeys;
    assertCoreAndBtc(MajikKey.fromDangerousJSON(old));
  });
});

describe("passphrase + KDF + addKeys", () => {
  it("updatePassphrase re-encrypts every key atomically", async () => {
    const k = MajikKey.fromJSON(base.toJSON());
    await k.unlock(PASS);
    await expect(
      k.updatePassphrase("wrong-pass", "New-Passphrase-456!"),
    ).rejects.toThrow();
    expect(await k.verify(PASS)).toBe(true); // failed attempt changed nothing
    await k.updatePassphrase(PASS, "New-Passphrase-456!");
    expect(await k.verify(PASS)).toBe(false);
    expect(await k.verify("New-Passphrase-456!")).toBe(true);
    const re = MajikKey.fromJSON(k.toJSON());
    await re.unlock("New-Passphrase-456!");
    assertCoreAndBtc(re);
    assertBtc(re);
  });

  it("legacy PBKDF2 account: unlock → incomplete → migrate → addKeys(core) completes it", async () => {
    // Hand-built pre-ML-KEM, kdfVersion-1 account (only X25519, encrypted with PBKDF2)
    const seed = new Uint8Array(mnemonicToSeedSync(V.mnemonic));
    const x = deriveKeys(seed, [KeyId.X25519]).get(KeyId.X25519)!;
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const enc = KeyStore.seal(deriveKeyFromPassphrase(PASS, salt), x.secretKey);
    const old = {
      id: V.fingerprint,
      label: "old",
      fingerprint: V.fingerprint,
      publicKey: arrayToBase64(x.publicKey),
      encryptedPrivateKey: arrayToBase64(enc),
      salt: arrayToBase64(salt),
      backup: base.backup,
      timestamp: new Date().toISOString(),
    } as any;
    const k = MajikKey.fromJSON(old);
    expect(k.kdfVersion).toBe(1);
    expect(k.availableKeys()).toEqual([KeyId.X25519]);
    expect(k.missingKeys()).toEqual([
      KeyId.ED25519,
      KeyId.ML_KEM_768,
      KeyId.ML_DSA_87,
    ]);
    expect(k.isCoreComplete).toBe(false);
    await k.unlock(PASS);
    expect(sha(k.getPrivateKey(KeyId.X25519))).toBe(
      V[KeyId.X25519].secretKeySha256,
    );

    await expect(k.addKeys(CORE_KEYS, V.mnemonic, PASS)).rejects.toThrow(
      /migrate/,
    );
    await k.migrate(PASS);
    expect(k.isArgon2id).toBe(true);
    await expect(k.addKeys(CORE_KEYS, OTHER, PASS)).rejects.toThrow(
      /does not belong/,
    );
    await expect(
      k.addKeys(CORE_KEYS, V.mnemonic, "wrong-passphrase"),
    ).rejects.toThrow();
    expect(k.isCoreComplete).toBe(false); // failed attempts added nothing

    const added = await k.addKeys(CORE_KEYS, V.mnemonic, PASS);
    expect(added).toEqual([KeyId.ED25519, KeyId.ML_KEM_768, KeyId.ML_DSA_87]);
    expect(k.isCoreComplete).toBe(true);
    assertCoreAndBtc(k); // already usable while unlocked
    k.lock();
    await k.unlock(PASS);
    assertCoreAndBtc(k);
    const re = MajikKey.fromJSON(k.toJSON());
    await re.unlock(PASS);
    assertCoreAndBtc(re);
  });

  it("addKeys: adds BTC to a core-only account, is idempotent, skips derived views, rejects reserved", async () => {
    const k = await MajikKey.create(V.mnemonic, PASS);
    expect(
      await k.addKeys([KeyId.BTC, KeyId.SOL, KeyId.ED25519], V.mnemonic, PASS),
    ).toEqual([KeyId.BTC]);
    assertBtc(k);
    expect(await k.addKeys([KeyId.BTC], V.mnemonic, PASS)).toEqual([]);
    await expect(k.addKeys([KeyId.HQC_128], V.mnemonic, PASS)).rejects.toThrow(
      /reserved/,
    );
    const re = MajikKey.fromJSON(k.toJSON());
    await re.unlock(PASS);
    assertBtc(re);
  });
});
