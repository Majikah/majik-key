// majik-key.test.ts — main MajikKey suite (registry era, v0.8)
//
// Layout
//   1. Creation                      6. Serialization & migration
//   2. Registry accessors            7. Dangerous JSON
//   3. Capability flags & metadata   8. MnemonicJSON
//   4. Multi-language mnemonics      9. State updates (label / passphrase / KDF)
//   5. Lock / unlock / auto-lock    10. Backup & restoration (incl. salt generations)
//                                   11. addKeys
//                                   12. Deprecated API (still supported)
//
// Pinned-vector, KeyStore, derivation, Ethereum and HKDF coverage live in their
// own files; this suite exercises the public MajikKey surface end to end.

import { describe, it, expect, beforeAll } from "vitest";
import { MajikKey, KeyId, CORE_KEYS } from "../src/majik-key";
import { KDF_VERSION } from "../src/core/crypto/constants";
import { KEY_ALGORITHMS } from "../src/core/keys/registry";
import { base64ToUtf8, utf8ToBase64, arrayToBase64 } from "../src/core/utils";
import { MajikContact } from "@majikah/majik-contact";
import type { MnemonicLanguage } from "../src/core/crypto/wordlist";
import type { MnemonicJSON } from "../src/core/types";

const CRYPTO_TIMEOUT = 360_000;
const PASSPHRASE = "TestPassphrase123!";
const NEW_PASSPHRASE = "NewSecurePassphrase456!";
const LABEL = "My Test Key";

/** Public/secret sizes (bytes) of every key this suite creates. */
const SIZES: Partial<Record<KeyId, { pk: number; sk: number }>> = {
  [KeyId.X25519]: { pk: 32, sk: 32 },
  [KeyId.ED25519]: { pk: 32, sk: 64 },
  [KeyId.ML_KEM_768]: { pk: 1184, sk: 2400 },
  [KeyId.ML_KEM_1024]: { pk: 1568, sk: 3168 },
  [KeyId.ML_DSA_65]: { pk: 1952, sk: 4032 },
  [KeyId.ML_DSA_87]: { pk: 2592, sk: 4896 },
  [KeyId.BTC]: { pk: 33, sk: 32 },
  [KeyId.ETH]: { pk: 33, sk: 32 },
};

/** Extra keys used wherever a test needs "more than the core four". */
const EXTRA_KEYS = [KeyId.BTC, KeyId.ETH, KeyId.ML_KEM_1024, KeyId.ML_DSA_65];

const storedIds = (k: MajikKey): KeyId[] =>
  k
    .listKeys()
    .filter((i) => i.kind === "stored")
    .map((i) => i.id);

/** base64 of every stored secret — used to prove nothing changed across an operation. */
const snapshot = (k: MajikKey): Record<string, string> =>
  Object.fromEntries(
    storedIds(k).map((id) => [id, arrayToBase64(k.getPrivateKey(id))]),
  );

const newMnemonic = (lang: MnemonicLanguage = "en") =>
  MajikKey.generateMnemonic(128, lang);

describe("MajikKey", () => {
  let validMnemonic: string;
  /** Shared, mutated by the lock / update / backup sections (in order). Core four only. */
  let majikKey: MajikKey;
  /** Shared, READ-ONLY full-featured account (core + EXTRA_KEYS). Never locked or rotated. */
  let fullKey: MajikKey;
  let fullMnemonic: string;

  beforeAll(async () => {
    validMnemonic = await newMnemonic();
    fullMnemonic = await newMnemonic();
    fullKey = await MajikKey.create(fullMnemonic, PASSPHRASE, "Full", {
      keys: EXTRA_KEYS,
    });
  }, CRYPTO_TIMEOUT);

  // ── 1. CREATION ───────────────────────────────────────────────────────────
  describe("Key Creation (.create)", () => {
    it(
      "creates an unlocked core-four account from a real mnemonic",
      async () => {
        majikKey = await MajikKey.create(validMnemonic, PASSPHRASE, LABEL, {
          mnemonicLanguage: "en",
        });

        expect(majikKey).toBeInstanceOf(MajikKey);
        expect(majikKey.id).toBeTruthy();
        expect(majikKey.id).toBe(majikKey.fingerprint);
        expect(majikKey.label).toBe(LABEL);
        expect(majikKey.mnemonicLanguage).toBe("en");
        expect(majikKey.timestamp).toBeInstanceOf(Date);
        expect(majikKey.isLocked).toBe(false);
        expect(majikKey.isArgon2id).toBe(true);
        expect(majikKey.kdfVersion).toBe(KDF_VERSION.ARGON2ID);
        expect(majikKey.isCoreComplete).toBe(true);
        expect(majikKey.isFullyUpgraded).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it("defaults to EXACTLY the core four (+ the derived Solana view); Bitcoin/Ethereum are opt-in", () => {
      expect(majikKey.availableKeys()).toEqual([...CORE_KEYS, KeyId.SOL]);
      expect(storedIds(majikKey)).toEqual([...CORE_KEYS]);
      expect(majikKey.hasBitcoin).toBe(false);
      expect(majikKey.hasEthereum).toBe(false);
      expect(majikKey.missingKeys()).toEqual([]);
    });

    it("derives real keys of the correct sizes (FIPS-203/204, Ed25519, X25519)", () => {
      for (const id of CORE_KEYS) {
        const { pk, sk } = SIZES[id]!;
        expect(majikKey.getPublicKey(id)).toBeInstanceOf(Uint8Array);
        expect(majikKey.getPublicKey(id).length).toBe(pk);
        expect(majikKey.getPrivateKey(id).length).toBe(sk);
      }
    });

    it("honours `keys` for extra algorithms (core is always included, duplicates collapse)", () => {
      expect(storedIds(fullKey)).toEqual(
        expect.arrayContaining([...CORE_KEYS, ...EXTRA_KEYS]),
      );
      expect(storedIds(fullKey)).toHaveLength(
        CORE_KEYS.length + EXTRA_KEYS.length,
      );
      for (const id of EXTRA_KEYS) {
        const { pk, sk } = SIZES[id]!;
        expect(fullKey.getPublicKey(id).length).toBe(pk);
        expect(fullKey.getPrivateKey(id).length).toBe(sk);
      }
    });

    it(
      "creating with duplicate/overlapping `keys` yields one entry each",
      async () => {
        const k = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "dup",
          {
            keys: [
              KeyId.ED25519,
              KeyId.ML_KEM_512,
              KeyId.ML_KEM_512,
              KeyId.SOL,
            ],
          },
        );
        expect(storedIds(k).filter((i) => i === KeyId.ML_KEM_512)).toHaveLength(
          1,
        );
        expect(storedIds(k).filter((i) => i === KeyId.ED25519)).toHaveLength(1);
        expect(k.hasKey(KeyId.SOL)).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "legacy `deriveBitcoin: true` still adds Bitcoin; omitting it does not",
      async () => {
        const k = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "btc",
          { deriveBitcoin: true },
        );
        expect(k.hasBitcoin).toBe(true);
        expect(k.hasEthereum).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "is deterministic: same mnemonic → same keys under different passphrases/salts",
      async () => {
        const a = await MajikKey.create(
          fullMnemonic,
          "AnotherPassphrase789!",
          "again",
          { keys: EXTRA_KEYS },
        );
        expect(a.fingerprint).toBe(fullKey.fingerprint);
        expect(a.toJSON().salt).not.toBe(fullKey.toJSON().salt);
        expect(snapshot(a)).toEqual(snapshot(fullKey));
      },
      CRYPTO_TIMEOUT,
    );

    it("throws for an invalid (bad-checksum) mnemonic phrase", async () => {
      // 12× "abandon" is a real BIP-39 phrase with a corrupted checksum word.
      const invalidMnemonic = Array(12).fill("abandon").join(" ");
      await expect(
        MajikKey.create(invalidMnemonic, PASSPHRASE, LABEL),
      ).rejects.toThrow(/Invalid BIP39 mnemonic phrase/);
    });

    it("rejects reserved, unsupported and unknown key ids before doing any work", async () => {
      const m = await newMnemonic();
      await expect(
        MajikKey.create(m, PASSPHRASE, "", { keys: [KeyId.HQC_128] }),
      ).rejects.toThrow(/reserved/);
      await expect(
        MajikKey.create(m, PASSPHRASE, "", { keys: [KeyId.FN_DSA_512] }),
      ).rejects.toThrow(/reserved/);
      await expect(
        MajikKey.create(m, PASSPHRASE, "", { keys: [KeyId.LMS] }),
      ).rejects.toThrow(/not supported/);
      await expect(
        MajikKey.create(m, PASSPHRASE, "", { keys: ["pq:nope" as any] }),
      ).rejects.toThrow(/Unknown/);
    });
  });

  // ── 2. REGISTRY ACCESSORS ─────────────────────────────────────────────────
  describe("Registry accessors", () => {
    it("hasKey / hasKeys / missingKeys", () => {
      expect(fullKey.hasKey(KeyId.ML_DSA_65)).toBe(true);
      expect(fullKey.hasKey("pq:does-not-exist" as KeyId)).toBe(false);
      expect(fullKey.hasKeys([...CORE_KEYS, ...EXTRA_KEYS, KeyId.SOL])).toBe(
        true,
      );
      expect(majikKey.hasKeys([KeyId.ETH])).toBe(false);
      expect(
        majikKey.missingKeys([KeyId.ED25519, KeyId.ETH, KeyId.ML_KEM_1024]),
      ).toEqual([KeyId.ETH, KeyId.ML_KEM_1024]);
    });

    it("availableKeys is canonical-ordered and filterable by family", () => {
      expect(fullKey.availableKeys({ family: "classic" })).toEqual([
        KeyId.X25519,
        KeyId.ED25519,
      ]);
      expect(fullKey.availableKeys({ family: "pq" })).toEqual([
        KeyId.ML_KEM_768,
        KeyId.ML_KEM_1024,
        KeyId.ML_DSA_65,
        KeyId.ML_DSA_87,
      ]);
      expect(fullKey.availableKeys({ family: "web3" })).toEqual([
        KeyId.BTC,
        KeyId.ETH,
        KeyId.SOL,
      ]);
    });

    it("listKeys describes every key without exposing secrets", () => {
      const list = fullKey.listKeys();
      expect(list.map((i) => i.id)).toEqual(fullKey.availableKeys());
      for (const info of list) {
        expect(info).toMatchObject({
          family: KEY_ALGORITHMS[info.id].family,
          purpose: KEY_ALGORITHMS[info.id].purpose,
          kind: KEY_ALGORITHMS[info.id].kind,
        });
        expect(typeof info.publicKeyBase64).toBe("string");
        expect(Object.keys(info).sort()).toEqual([
          "family",
          "id",
          "kind",
          "publicKeyBase64",
          "purpose",
          "status",
        ]);
      }
      expect(list.find((i) => i.id === KeyId.SOL)!.kind).toBe("derived");
    });

    it("getKeypair handles agree with getPublicKey/getPrivateKey for every key", () => {
      for (const id of fullKey.availableKeys()) {
        const kp = fullKey.getKeypair(id);
        expect(kp.algorithm).toBe(id);
        expect(kp.family).toBe(KEY_ALGORITHMS[id].family);
        expect(kp.purpose).toBe(KEY_ALGORITHMS[id].purpose);
        expect(kp.public).toEqual(fullKey.getPublicKey(id));
        expect(kp.publicBase64).toBe(arrayToBase64(fullKey.getPublicKey(id)));
        expect(kp.private).toEqual(fullKey.getPrivateKey(id));
        expect(kp.isUnlocked).toBe(true);
      }
    });

    it("unknown or absent keys throw a clear error", () => {
      expect(() => fullKey.getPublicKey("pq:nope" as any)).toThrow(
        /No "pq:nope"/,
      );
      expect(() => majikKey.getPublicKey(KeyId.ETH)).toThrow(/No "web3:eth"/);
      expect(() => majikKey.getKeypair(KeyId.ETH)).toThrow(/No "web3:eth"/);
      expect(() => majikKey.getPrivateKey(KeyId.BTC)).toThrow(/No "web3:btc"/);
    });

    it("MajikKey.supportedKeys() lists only keys that can really be enabled", () => {
      const s = MajikKey.supportedKeys();
      expect(s).toEqual(
        expect.arrayContaining([
          ...CORE_KEYS,
          KeyId.BTC,
          KeyId.ETH,
          KeyId.ML_KEM_1024,
          KeyId.SLH_DSA_SHAKE_128F,
        ]),
      );
      for (const reserved of [KeyId.HQC_128, KeyId.FN_DSA_512, KeyId.LMS])
        expect(s).not.toContain(reserved);
    });
  });

  // ── 3. CAPABILITY FLAGS & METADATA ────────────────────────────────────────
  // Self-contained: its own key, so lock/rotation order elsewhere can't affect it.
  describe("Capability flags and .metadata", () => {
    let flagsKey: MajikKey;

    beforeAll(async () => {
      flagsKey = await MajikKey.create(
        await newMnemonic(),
        PASSPHRASE,
        "Flags Key",
        { keys: [KeyId.BTC] },
      );
    }, CRYPTO_TIMEOUT);

    it("hasSigningKeys is true once both Ed25519 and ML-DSA public keys exist", () => {
      expect(flagsKey.hasSigningKeys).toBe(true);
      expect(flagsKey.edPublicKey).toBeDefined();
      expect(flagsKey.mlDsaPublicKey).toBeDefined();
    });

    it("metadata reflects what the account actually holds", () => {
      const meta = flagsKey.metadata;
      expect(meta.web3.hasBitcoin).toBe(true);
      expect(meta.web3.hasEthereum).toBe(false);
      expect(meta.web3.hasSolana).toBe(true); // unlocked + Ed25519 present
      expect(meta.keys).toEqual(flagsKey.availableKeys());
      expect(meta.keys).toContain(KeyId.BTC);
    });

    it("metadata stays consistent with the direct getters", () => {
      const meta = flagsKey.metadata;
      expect(meta.id).toBe(flagsKey.id);
      expect(meta.fingerprint).toBe(flagsKey.fingerprint);
      expect(meta.label).toBe(flagsKey.label);
      expect(meta.isLocked).toBe(flagsKey.isLocked);
      expect(meta.hasMlKem).toBe(flagsKey.hasMlKem);
      expect(meta.kdfVersion).toBe(flagsKey.kdfVersion);
      expect(meta.web3.hasBitcoin).toBe(flagsKey.hasBitcoin);
      expect(meta.mnemonicLanguage).toBe("en");
    });

    it("after lock(): public presence survives, unlocked-only capabilities drop", () => {
      flagsKey.lock();
      const meta = flagsKey.metadata;
      expect(meta.isLocked).toBe(true);
      expect(meta.web3.hasBitcoin).toBe(true); // public key survives lock
      expect(meta.web3.hasSolana).toBe(false); // Solana needs the unlocked Ed25519 secret
      expect(meta.keys).toEqual(flagsKey.availableKeys());
      expect(flagsKey.hasBitcoinKeypair).toBe(false);
      expect(flagsKey.hasSolanaKeypair).toBe(false);
    });

    it("metadata contains no key bytes at all", () => {
      const s = JSON.stringify(flagsKey.metadata);
      expect(s).not.toContain(flagsKey.publicKeyBase64);
    });
  });

  // ── 4. MULTI-LANGUAGE MNEMONICS ───────────────────────────────────────────
  describe("Multi-language Mnemonic Support", () => {
    const ALL_LANGUAGES: MnemonicLanguage[] = [
      "en",
      "fr",
      "es",
      "it",
      "ja",
      "ko",
      "czech",
      "pt",
      "zh-cn",
      "zh-tw",
    ];

    // Cheap tier: pure BIP-39 generation/validation against each REAL wordlist.
    it.each(ALL_LANGUAGES)(
      "generates and validates a real BIP-39 mnemonic in '%s'",
      async (language) => {
        const mnemonic = await newMnemonic(language);
        expect(typeof mnemonic).toBe("string");
        expect(mnemonic.trim().length).toBeGreaterThan(0);
        expect(MajikKey.validateMnemonic(mnemonic)).toBe(true);
      },
    );

    it("generateMnemonic: 256-bit strength gives 24 words; bad strength/language rejected", async () => {
      expect(
        (await MajikKey.generateMnemonic(256, "en")).split(" "),
      ).toHaveLength(24);
      expect(
        (await MajikKey.generateMnemonic(128, "en")).split(" "),
      ).toHaveLength(12);
      await expect(MajikKey.generateMnemonic(192 as any, "en")).rejects.toThrow(
        /Strength must be 128 or 256/,
      );
      await expect(
        MajikKey.generateMnemonic(128, "klingon" as any),
      ).rejects.toThrow(/Unsupported language/);
    });

    // Full-pipeline tier: derive a complete identity from a non-English mnemonic.
    it.each(ALL_LANGUAGES)(
      "creates a fully-derived MajikKey from a '%s' mnemonic",
      async (language) => {
        const mnemonic = await newMnemonic(language);
        const key = await MajikKey.create(
          mnemonic,
          PASSPHRASE,
          `Key (${language})`,
          { mnemonicLanguage: language },
        );
        expect(key.mnemonicLanguage).toBe(language);
        expect(key.isArgon2id).toBe(true);
        expect(key.isCoreComplete).toBe(true);
        expect(key.isFullyUpgraded).toBe(true);
        expect(key.metadata.mnemonicLanguage).toBe(language);
      },
      CRYPTO_TIMEOUT,
    );

    // Round-trip tier: scripts most likely to expose Unicode-normalization bugs.
    it.each<MnemonicLanguage>(["ja", "zh-cn"])(
      "lock → unlock round-trips a '%s' key",
      async (language) => {
        const key = await MajikKey.create(
          await newMnemonic(language),
          PASSPHRASE,
          LABEL,
          { mnemonicLanguage: language },
        );
        const before = snapshot(key);
        key.lock();
        await key.unlock(PASSPHRASE);
        expect(key.isUnlocked).toBe(true);
        expect(snapshot(key)).toEqual(before);
        expect(key.getPrivateKey(KeyId.ML_KEM_768).length).toBe(2400);
      },
      CRYPTO_TIMEOUT,
    );

    it("rejects a mnemonic validated against the wrong language's wordlist", async () => {
      const japanese = await newMnemonic("ja");
      await expect(
        MajikKey.create(japanese, PASSPHRASE, LABEL, {
          mnemonicLanguage: "en",
        }),
      ).rejects.toThrow(/Invalid BIP39 mnemonic phrase/);
    });

    // The language must survive EVERY persistence path (importFromMnemonicBackup used to reset it to "en").
    it(
      "the language survives JSON, backup import, addKeys and MnemonicJSON for a non-English account",
      async () => {
        const mnemonic = await newMnemonic("ja");
        const key = await MajikKey.create(mnemonic, PASSPHRASE, "ja", {
          mnemonicLanguage: "ja",
        });

        expect(MajikKey.fromJSON(key.toJSON()).mnemonicLanguage).toBe("ja");
        expect(
          MajikKey.fromJSON(key.toJSON({ legacy: false })).mnemonicLanguage,
        ).toBe("ja");
        expect(key.toMnemonicJSON(mnemonic).language).toBe("ja");

        const imported = await MajikKey.importFromMnemonicBackup(
          key.backup,
          mnemonic,
          PASSPHRASE,
          "ja",
          {
            mnemonicLanguage: "ja",
          },
        );
        expect(imported.mnemonicLanguage).toBe("ja");
        expect(imported.fingerprint).toBe(key.fingerprint);

        // addKeys validates the mnemonic against the ACCOUNT's language
        expect(await key.addKeys([KeyId.ETH], mnemonic, PASSPHRASE)).toEqual([
          KeyId.ETH,
        ]);
        expect(key.hasEthereum).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 5. LOCK / UNLOCK / AUTO-LOCK ──────────────────────────────────────────
  describe("Locking and Unlocking", () => {
    it("lock() purges every secret and exposes nothing but public data", () => {
      const handle = majikKey.getKeypair(KeyId.ML_DSA_87); // taken BEFORE locking
      majikKey.lock();

      expect(majikKey.isLocked).toBe(true);
      expect(majikKey.isUnlocked).toBe(false);

      for (const id of CORE_KEYS) {
        expect(() => majikKey.getPrivateKey(id)).toThrow(/MajikKey is locked/);
        expect(majikKey.getPublicKey(id).length).toBe(SIZES[id]!.pk); // public still fine
      }
      // handle obtained before lock() never serves stale/zeroized bytes
      expect(handle.isUnlocked).toBe(false);
      expect(() => handle.private).toThrow(/locked/);
      expect(handle.public.length).toBe(2592);
      expect(majikKey.mlKemSecretKey).toBeUndefined();
      expect(() => majikKey.getPublicKey(KeyId.SOL)).toThrow(/locked/); // derived view needs the secret
      expect(majikKey.web3).toBeUndefined();
    });

    it(
      "lock() zeroizes secret buffers in place",
      async () => {
        const k = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "zero",
        );
        const refs = CORE_KEYS.map((id) => k.getPrivateKey(id));
        k.lock();
        for (const r of refs) expect(r.every((b) => b === 0)).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "unlocks with the correct passphrase and restores every key",
      async () => {
        await majikKey.unlock(PASSPHRASE);
        expect(majikKey.isLocked).toBe(false);
        expect(majikKey.isUnlocked).toBe(true);
        for (const id of CORE_KEYS)
          expect(majikKey.getPrivateKey(id).length).toBe(SIZES[id]!.sk);
        expect(majikKey.getKeypair(KeyId.ED25519).isUnlocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it("throws when unlocking an already-unlocked key", async () => {
      await expect(majikKey.unlock(PASSPHRASE)).rejects.toThrow(
        /already unlocked/,
      );
    });

    it(
      "rejects an incorrect passphrase and stays FULLY locked (atomic unlock)",
      async () => {
        majikKey.lock();
        // Real AES-GCM: a wrong passphrase is a genuine auth-tag failure.
        await expect(
          majikKey.unlock("totally-wrong-passphrase"),
        ).rejects.toThrow(/incorrect passphrase or corrupted data/);
        expect(majikKey.isLocked).toBe(true);
        for (const id of CORE_KEYS)
          expect(() => majikKey.getPrivateKey(id)).toThrow(/locked/);

        await majikKey.unlock(PASSPHRASE); // restore for the rest of the suite
        expect(majikKey.isUnlocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verify() checks a passphrase without changing lock state",
      async () => {
        expect(await majikKey.verify(PASSPHRASE)).toBe(true);
        expect(await majikKey.verify("nope-nope-nope")).toBe(false);
        expect(majikKey.isUnlocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // Exercises MajikKey.withAutoLock() as a scoped secret-key helper. The key must
  // already be unlocked; the helper never accepts a passphrase. lock() runs in a
  // `finally`, so the key is locked after success AND after throw/reject.
  describe("Auto-lock operation helper (.withAutoLock)", () => {
    let autoLockKey: MajikKey;

    beforeAll(async () => {
      autoLockKey = await MajikKey.create(
        await newMnemonic(),
        PASSPHRASE,
        "Auto-lock Test Key",
        {
          keys: [KeyId.ETH],
        },
      );
    }, CRYPTO_TIMEOUT);

    it("runs the operation and locks the key afterwards", async () => {
      expect(autoLockKey.isUnlocked).toBe(true);
      const kp = autoLockKey.getKeypair(KeyId.ED25519);

      const result = await MajikKey.withAutoLock(autoLockKey, (key) => {
        expect(key).toBe(autoLockKey);
        expect(key.isUnlocked).toBe(true);
        return key.getSolanaAddress();
      });

      expect(typeof result).toBe("string");
      expect(result).toBeTruthy();
      expect(autoLockKey.isLocked).toBe(true);
      expect(() => autoLockKey.getPrivateKey(KeyId.ED25519)).toThrow(
        /MajikKey is locked/,
      );
      expect(() => kp.private).toThrow(/locked/); // outstanding handles go dead too
    });

    it(
      "supports async operations that use registry secrets",
      async () => {
        await autoLockKey.unlock(PASSPHRASE);
        const result = await MajikKey.withAutoLock(autoLockKey, async (key) => {
          expect(key.isUnlocked).toBe(true);
          const secret = key.getPrivateKey(KeyId.ED25519);
          await Promise.resolve();
          return secret.length;
        });
        expect(result).toBe(64);
        expect(autoLockKey.isLocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "works with Ethereum signing inside the scope",
      async () => {
        await autoLockKey.unlock(PASSPHRASE);
        const addr = autoLockKey.getEthereumAddress();
        const sig = await MajikKey.withAutoLock(autoLockKey, (key) =>
          key.web3!.ethereum!.signMessage("scoped"),
        );
        expect(sig.serialized).toMatch(/^0x[0-9a-f]{130}$/);
        expect(autoLockKey.isLocked).toBe(true);
        expect(autoLockKey.getEthereumAddress()).toBe(addr); // address is public → works locked
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "locks even when the operation throws",
      async () => {
        await autoLockKey.unlock(PASSPHRASE);
        await expect(
          MajikKey.withAutoLock(autoLockKey, () => {
            expect(autoLockKey.isUnlocked).toBe(true);
            throw new Error("operation failed");
          }),
        ).rejects.toThrow("operation failed");
        expect(autoLockKey.isLocked).toBe(true);
        expect(() => autoLockKey.getEdSecretKey()).toThrow(
          /MajikKey is locked/,
        );
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "locks even when the async operation rejects",
      async () => {
        await autoLockKey.unlock(PASSPHRASE);
        await expect(
          MajikKey.withAutoLock(autoLockKey, async () => {
            await Promise.resolve();
            throw new Error("async operation failed");
          }),
        ).rejects.toThrow("async operation failed");
        expect(autoLockKey.isLocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it("rejects a locked key instead of unlocking it, and never runs the callback", async () => {
      expect(autoLockKey.isLocked).toBe(true);
      let ran = false;
      await expect(
        MajikKey.withAutoLock(autoLockKey, () => {
          ran = true;
        }),
      ).rejects.toThrow(
        /MajikKey must be unlocked before calling withAutoLock/,
      );
      expect(ran).toBe(false);
      expect(autoLockKey.isLocked).toBe(true);
    });

    it(
      "rejects a non-function operation and a non-MajikKey without changing state",
      async () => {
        await autoLockKey.unlock(PASSPHRASE);
        await expect(
          MajikKey.withAutoLock(autoLockKey, null as any),
        ).rejects.toThrow(/Operation must be a function/);
        expect(autoLockKey.isUnlocked).toBe(true); // validation happens before the try/finally
        await expect(MajikKey.withAutoLock({} as any, () => 1)).rejects.toThrow(
          /valid MajikKey instance/,
        );
        autoLockKey.lock();
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 6. SERIALIZATION & MIGRATION ──────────────────────────────────────────
  describe("Serialization and Parsing", () => {
    it("toJSON writes the registry AND (by default) the legacy flat fields", () => {
      const json: any = fullKey.toJSON();
      expect(json.id).toBe(fullKey.id);
      expect(json.publicKey).toBeDefined();
      expect(json.kdfVersion).toBe(KDF_VERSION.ARGON2ID);
      expect(json.keysVersion).toBe(1);
      expect(json.keys.map((e: any) => e.id)).toEqual(storedIds(fullKey));
      // legacy flat fields for the original five…
      expect(json.mlKemPublicKey).toBeDefined();
      expect(json.encryptedMlKemSecretKey).toBeDefined();
      expect(json.edPublicKey).toBeDefined();
      expect(json.btcPublicKey).toBeDefined();
      // …but newer algorithms exist ONLY in `keys`
      expect(JSON.stringify(Object.keys(json))).not.toMatch(/1024|Eth|eth/);
      expect(
        json.keys.find((e: any) => e.id === KeyId.ETH).derivation.path,
      ).toBe("m/44'/60'/0'/0/0");
    });

    it("toJSON({ legacy: false }) is registry-only; JSON.stringify(key) works", () => {
      const lean: any = fullKey.toJSON({ legacy: false });
      expect(lean.keys.length).toBe(storedIds(fullKey).length);
      expect(lean.encryptedPrivateKey).toBeUndefined();
      expect(lean.encryptedMlKemSecretKey).toBeUndefined();
      expect(lean.publicKey).toBe(fullKey.publicKeyBase64);
      expect(JSON.parse(JSON.stringify(fullKey)).keys).toBeDefined();
      expect(fullKey.toString()).toBe(JSON.stringify(fullKey.toJSON()));
      expect(fullKey.toString(true)).toContain("\n");
    });

    it("never serializes raw secrets", () => {
      const s = JSON.stringify(fullKey.toJSON());
      for (const id of storedIds(fullKey))
        expect(s).not.toContain(arrayToBase64(fullKey.getPrivateKey(id)));
      expect(s).not.toMatch(/privateKeyBase64|SecretKeyBase64|secretKeys/);
    });

    it("round-trips via fromJSON (both shapes) into a LOCKED key with the same identity", () => {
      for (const json of [
        majikKey.toJSON(),
        majikKey.toJSON({ legacy: false }),
      ]) {
        const re = MajikKey.fromJSON(json);
        expect(re).toBeInstanceOf(MajikKey);
        expect(re.id).toBe(majikKey.id);
        expect(re.label).toBe(majikKey.label);
        expect(re.isLocked).toBe(true);
        expect(re.availableKeys()).toEqual(majikKey.availableKeys());
        expect(re.getPublicKey(KeyId.ML_DSA_87)).toEqual(
          majikKey.getPublicKey(KeyId.ML_DSA_87),
        );
        expect(re.timestamp.toISOString()).toBe(
          majikKey.timestamp.toISOString(),
        );
      }
    });

    it(
      "unlocks correctly after a JSON round-trip, including keys that only exist in `keys`",
      async () => {
        const re = MajikKey.fromJSON(fullKey.toJSON({ legacy: false }));
        await re.unlock(PASSPHRASE);
        expect(snapshot(re)).toEqual(snapshot(fullKey));
        // and from a string
        const re2 = MajikKey.fromJSON(fullKey.toString());
        await re2.unlock(PASSPHRASE);
        expect(snapshot(re2)).toEqual(snapshot(fullKey));
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "auto-migrates legacy flat JSON (no `keys`) and re-serializes the upgraded shape",
      async () => {
        const legacy: any = JSON.parse(JSON.stringify(fullKey.toJSON()));
        delete legacy.keys;
        delete legacy.keysVersion;
        const migrated = MajikKey.fromJSON(legacy);

        // Only the five pre-registry algorithms exist in legacy JSON
        expect(storedIds(migrated)).toEqual([
          KeyId.X25519,
          KeyId.ED25519,
          KeyId.ML_KEM_768,
          KeyId.ML_DSA_87,
          KeyId.BTC,
        ]);
        expect(migrated.isCoreComplete).toBe(true);
        expect((migrated.toJSON() as any).keys).toHaveLength(5);

        await migrated.unlock(PASSPHRASE);
        expect(arrayToBase64(migrated.getPrivateKey(KeyId.ED25519))).toBe(
          arrayToBase64(fullKey.getPrivateKey(KeyId.ED25519)),
        );
      },
      CRYPTO_TIMEOUT,
    );

    it("legacy JSON missing optional keys migrates as an incomplete account", () => {
      const legacy: any = JSON.parse(JSON.stringify(majikKey.toJSON()));
      for (const f of [
        "keys",
        "keysVersion",
        "edPublicKey",
        "encryptedEdSecretKey",
        "mlDsaPublicKey",
        "encryptedMlDsaSecretKey",
        "mlKemPublicKey",
        "encryptedMlKemSecretKey",
      ])
        delete legacy[f];
      const old = MajikKey.fromJSON(legacy);
      expect(old.availableKeys()).toEqual([KeyId.X25519]);
      expect(old.isCoreComplete).toBe(false);
      expect(old.hasMlKem).toBe(false);
      expect(old.hasSigningKeys).toBe(false);
      expect(old.isFullyUpgraded).toBe(false);
      expect(old.missingKeys()).toEqual([
        KeyId.ED25519,
        KeyId.ML_KEM_768,
        KeyId.ML_DSA_87,
      ]);
      expect(old.metadata.hasMlKem).toBe(false);
    });

    it("rejects malformed, conflicting and too-new JSON", () => {
      const j: any = JSON.parse(JSON.stringify(majikKey.toJSON()));
      expect(() => MajikKey.fromJSON("not json at all")).toThrow();
      expect(() => MajikKey.fromJSON({ ...j, publicKey: "AAAA" })).toThrow(
        /does not match/,
      );
      expect(() => MajikKey.fromJSON({ ...j, keysVersion: 99 })).toThrow(
        /Upgrade the library/,
      );
      expect(() => MajikKey.fromJSON({ ...j, keys: [] })).toThrow(
        /classic:x25519/,
      );
      expect(() =>
        MajikKey.fromJSON({ ...j, keys: [j.keys[0], j.keys[0]] }),
      ).toThrow(/Duplicate/);
      const { salt, ...noSalt } = j;
      expect(() =>
        MajikKey.fromJSON({ ...noSalt, keys: j.keys } as any),
      ).toThrow(/salt/);
    });

    it("preserves entries from a NEWER library version untouched across a round-trip", () => {
      const j: any = JSON.parse(
        JSON.stringify(majikKey.toJSON({ legacy: false })),
      );
      const future = {
        id: "pq:future-kem-9000",
        publicKey: "AAAA",
        encryptedSecretKey: "BBBB",
        derivation: { scheme: "x", version: 9 },
      };
      const re = MajikKey.fromJSON({ ...j, keys: [...j.keys, future] });
      expect(re.availableKeys()).not.toContain("pq:future-kem-9000" as any); // not interpretable here…
      expect((re.toJSON({ legacy: false }) as any).keys.at(-1)).toEqual(future); // …but never dropped
    });

    it("toContact / toKeyIdentity / toSerializedIdentity expose the right public data", () => {
      // Capture exactly what MajikKey hands to the contact constructor (works with any MajikContact subclass).
      let seen: any;
      class Spy extends MajikContact {
        constructor(data: any) {
          super(data);
          seen = data;
        }
      }
      const contact = majikKey.toContact(Spy as any, {
        label: "ignored-default",
      });
      expect(contact).toBeInstanceOf(MajikContact);
      expect(seen.id).toBe(majikKey.id);
      expect(seen.fingerprint).toBe(majikKey.fingerprint);
      expect(seen.publicKey.raw).toEqual(majikKey.getPublicKey(KeyId.X25519));
      expect(seen.mlKey).toBe(
        arrayToBase64(majikKey.getPublicKey(KeyId.ML_KEM_768)),
      );
      expect(seen.edPublicKeyBase64).toBe(
        arrayToBase64(majikKey.getPublicKey(KeyId.ED25519)),
      );
      expect(seen.mlDsaPublicKeyBase64).toBe(
        arrayToBase64(majikKey.getPublicKey(KeyId.ML_DSA_87)),
      );
      expect(seen.meta.label).toBe("ignored-default"); // initialMeta overrides the key's label
      expect(majikKey.toContact()).toBeInstanceOf(MajikContact);

      const ident = majikKey.toKeyIdentity();
      expect(ident.fingerprint).toBe(majikKey.fingerprint);
      expect(ident.privateKey.raw).toEqual(
        majikKey.getPrivateKey(KeyId.X25519),
      );
      expect(ident.mlKemSecretKey).toEqual(
        majikKey.getPrivateKey(KeyId.ML_KEM_768),
      );
      expect(ident.encryptedPrivateKey.byteLength).toBeGreaterThan(32); // IV + ciphertext + tag

      const ser = majikKey.toSerializedIdentity();
      expect(ser.publicKey).toBe(majikKey.publicKeyBase64);
      expect(ser.salt).toBe(majikKey.toJSON().salt);
    });

    it("toKeyIdentity / toSerializedIdentity / toMnemonicJSON refuse a locked key", async () => {
      const k = MajikKey.fromJSON(majikKey.toJSON());
      expect(() => k.toKeyIdentity()).toThrow(/Unlock first/);
      expect(() => k.toSerializedIdentity()).toThrow(/Unlock first/);
      expect(() => k.toDangerousJSON()).toThrow(/must be unlocked/);
    });
  });

  // ── 7. DANGEROUS JSON ─────────────────────────────────────────────────────
  // Self-contained: unencrypted, no-KDF code path gets its own isolated key.
  describe("Dangerous JSON Export/Import (unencrypted, server-side use)", () => {
    let dangerousKey: MajikKey;

    beforeAll(async () => {
      dangerousKey = await MajikKey.create(
        await newMnemonic(),
        PASSPHRASE,
        "Dangerous Export Key",
        { keys: EXTRA_KEYS },
      );
    }, CRYPTO_TIMEOUT);

    it("throws if the key is locked", async () => {
      const locked = MajikKey.fromJSON(dangerousKey.toJSON());
      expect(() => locked.toDangerousJSON()).toThrow(/must be unlocked/);
    });

    it("exports raw secrets for the legacy fields AND a `secretKeys` map for every stored key", () => {
      const d: any = dangerousKey.toDangerousJSON();
      expect(d.privateKeyBase64).toBeTruthy();
      expect(d.mlKemSecretKeyBase64).toBeTruthy();
      expect(d.edSecretKeyBase64).toBeTruthy();
      expect(d.mlDsaSecretKeyBase64).toBeTruthy();
      expect(d.btcSecretKeyBase64).toBeTruthy();
      expect(Object.keys(d.secretKeys).sort()).toEqual(
        [...storedIds(dangerousKey)].sort(),
      );
      for (const id of storedIds(dangerousKey))
        expect(d.secretKeys[id]).toBe(
          arrayToBase64(dangerousKey.getPrivateKey(id)),
        );
    });

    it("reconstructs an instantly-unlocked key with identical raw key material for every key", () => {
      const solanaBefore = dangerousKey.getSolanaKeypairMaterial();
      const bitcoinBefore = dangerousKey.getBitcoinKeypairMaterial();
      const reconstructed = MajikKey.fromDangerousJSON(
        dangerousKey.toDangerousJSON(),
      );

      expect(reconstructed.isUnlocked).toBe(true); // no KDF involved
      expect(reconstructed.id).toBe(dangerousKey.id);
      expect(reconstructed.fingerprint).toBe(dangerousKey.fingerprint);
      expect(reconstructed.label).toBe(dangerousKey.label);
      expect(reconstructed.availableKeys()).toEqual(
        dangerousKey.availableKeys(),
      );
      expect(snapshot(reconstructed)).toEqual(snapshot(dangerousKey));
      expect(reconstructed.getSolanaKeypairMaterial()).toEqual(solanaBefore);
      expect(reconstructed.getBitcoinKeypairMaterial()).toEqual(bitcoinBefore);
      expect(reconstructed.getEthereumAddress()).toBe(
        dangerousKey.getEthereumAddress(),
      );
    });

    it("accepts a string and the pre-registry shape (no `keys` / `secretKeys`)", () => {
      const d: any = dangerousKey.toDangerousJSON();
      expect(MajikKey.fromDangerousJSON(JSON.stringify(d)).isUnlocked).toBe(
        true,
      );

      const legacy: any = { ...d };
      delete legacy.keys;
      delete legacy.keysVersion;
      delete legacy.secretKeys;
      const k = MajikKey.fromDangerousJSON(legacy);
      expect(storedIds(k)).toEqual([
        KeyId.X25519,
        KeyId.ED25519,
        KeyId.ML_KEM_768,
        KeyId.ML_DSA_87,
        KeyId.BTC,
      ]);
      expect(k.getPrivateKey(KeyId.ML_DSA_87)).toEqual(
        dangerousKey.getPrivateKey(KeyId.ML_DSA_87),
      );
    });

    it(
      "refuses to export an unlocked account that is missing core keys",
      async () => {
        const legacy: any = JSON.parse(JSON.stringify(majikKey.toJSON()));
        for (const f of [
          "keys",
          "keysVersion",
          "edPublicKey",
          "encryptedEdSecretKey",
        ])
          delete legacy[f];
        const incomplete = MajikKey.fromJSON(legacy); // only X25519 + ML-KEM/ML-DSA blobs
        await incomplete.unlock(PASSPHRASE); // majikKey still uses PASSPHRASE at this point in the suite
        expect(incomplete.isCoreComplete).toBe(false);
        expect(() => incomplete.toDangerousJSON()).toThrow(/missing core keys/);
      },
      CRYPTO_TIMEOUT,
    );

    it("throws for a payload missing required secret fields", () => {
      const incomplete = {
        id: "fake-id",
        fingerprint: "fake-fingerprint",
        publicKey: "AAAA",
      };
      expect(() => MajikKey.fromDangerousJSON(incomplete as any)).toThrow(
        /missing required fields/,
      );
    });
  });

  // ── 8. MNEMONICJSON ───────────────────────────────────────────────────────
  // fromMnemonicJSON() calls create() → fresh salt/ciphertext, so it gets its own key.
  describe("MnemonicJSON Export/Import", () => {
    let mnemonic: string;
    let mjKey: MajikKey;

    beforeAll(async () => {
      mnemonic = await newMnemonic();
      mjKey = await MajikKey.create(mnemonic, PASSPHRASE, "MnemonicJSON Key");
    }, CRYPTO_TIMEOUT);

    it("throws if the key is locked", () => {
      const locked = MajikKey.fromJSON(mjKey.toJSON());
      expect(() => locked.toMnemonicJSON(mnemonic, PASSPHRASE)).toThrow(
        /Unlock first/,
      );
    });

    it("exports the real seed array, backup id, language and optional passphrase", () => {
      const json: MnemonicJSON = mjKey.toMnemonicJSON(mnemonic, PASSPHRASE);
      expect(json.id).toBe(mjKey.backup);
      expect(json.seed).toEqual(mnemonic.split(" "));
      expect(json.phrase).toBe(PASSPHRASE);
      expect(json.language).toBe("en");
    });

    it("omits `phrase` when no passphrase is passed", () => {
      expect(mjKey.toMnemonicJSON(mnemonic).phrase).toBeUndefined();
    });

    it(
      "reconstructs the identical id/fingerprint under a new passphrase (object or string)",
      async () => {
        const json = mjKey.toMnemonicJSON(mnemonic, PASSPHRASE);
        for (const input of [json, JSON.stringify(json)]) {
          const re = await MajikKey.fromMnemonicJSON(
            input,
            NEW_PASSPHRASE,
            "Reconstructed",
          );
          expect(re.id).toBe(mjKey.id);
          expect(re.fingerprint).toBe(mjKey.fingerprint);
          expect(re.isUnlocked).toBe(true);
          expect(re.isFullyUpgraded).toBe(true);
          expect(await re.verify(NEW_PASSPHRASE)).toBe(true);
          expect(await re.verify(PASSPHRASE)).toBe(false);
        }
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "forwards `keys` so a restored account can include extra algorithms",
      async () => {
        const re = await MajikKey.fromMnemonicJSON(
          mjKey.toMnemonicJSON(mnemonic),
          NEW_PASSPHRASE,
          "extras",
          {
            keys: [KeyId.ETH, KeyId.ML_KEM_1024],
          },
        );
        expect(re.hasKeys([KeyId.ETH, KeyId.ML_KEM_1024])).toBe(true);
        expect(re.fingerprint).toBe(mjKey.fingerprint);
      },
      CRYPTO_TIMEOUT,
    );

    it("rejects a malformed/missing seed array", async () => {
      await expect(
        MajikKey.fromMnemonicJSON(
          { id: "x", seed: "not-an-array" } as any,
          PASSPHRASE,
        ),
      ).rejects.toThrow(/Invalid MnemonicJSON/);
      await expect(
        MajikKey.fromMnemonicJSON({ seed: ["a"] } as any, PASSPHRASE),
      ).rejects.toThrow(/Invalid MnemonicJSON/);
    });
  });

  // ── 9. STATE UPDATES ──────────────────────────────────────────────────────
  describe("State Updates", () => {
    it("updates the label, returning `this` for chaining", () => {
      const newLabel = "Updated Key Name";
      expect(majikKey.updateLabel(newLabel)).toBe(majikKey);
      expect(majikKey.label).toBe(newLabel);
      expect(majikKey.toJSON().label).toBe(newLabel);
      majikKey.updateLabel("");
      expect(majikKey.label).toBe("");
      majikKey.updateLabel(newLabel);
    });

    it(
      "rotates the passphrase (new salt, old passphrase dead, secrets unchanged)",
      async () => {
        const previousSalt = majikKey.toJSON().salt;
        const before = snapshot(majikKey);

        await majikKey.updatePassphrase(PASSPHRASE, NEW_PASSPHRASE);

        expect(majikKey.toJSON().salt).not.toBe(previousSalt);
        expect(await majikKey.verify(PASSPHRASE)).toBe(false);
        expect(await majikKey.verify(NEW_PASSPHRASE)).toBe(true);
        expect(snapshot(majikKey)).toEqual(before);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "unlocks with the new passphrase after a lock/unlock cycle",
      async () => {
        majikKey.lock();
        await expect(majikKey.unlock(PASSPHRASE)).rejects.toThrow();
        await majikKey.unlock(NEW_PASSPHRASE);
        expect(majikKey.isUnlocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "rotates EVERY stored key (core + Bitcoin + Ethereum + ML-KEM-1024 + ML-DSA-65) in one call",
      async () => {
        // Isolated key, so this doesn't depend on the shared key's rotation history.
        const key = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "Rotate All",
          { keys: EXTRA_KEYS },
        );
        expect(storedIds(key)).toHaveLength(
          CORE_KEYS.length + EXTRA_KEYS.length,
        );
        const before = snapshot(key);
        const saltBefore = key.toJSON().salt;
        const blobsBefore = JSON.stringify(
          (key.toJSON({ legacy: false }) as any).keys.map(
            (e: any) => e.encryptedSecretKey,
          ),
        );

        const ROTATE_PASS = "RotateAllBlobs!321";
        await key.updatePassphrase(PASSPHRASE, ROTATE_PASS);

        expect(key.toJSON().salt).not.toBe(saltBefore);
        expect(key.kdfVersion).toBe(KDF_VERSION.ARGON2ID);
        expect(await key.verify(PASSPHRASE)).toBe(false);
        expect(await key.verify(ROTATE_PASS)).toBe(true);
        // every ciphertext changed (fresh IV + new key)…
        const blobsAfter = JSON.stringify(
          (key.toJSON({ legacy: false }) as any).keys.map(
            (e: any) => e.encryptedSecretKey,
          ),
        );
        expect(blobsAfter).not.toBe(blobsBefore);
        // …yet the live in-memory secrets are unchanged
        expect(snapshot(key)).toEqual(before);

        // A full persistence round-trip under the NEW passphrase decrypts every blob independently
        const re = MajikKey.fromJSON(key.toJSON({ legacy: false }));
        await re.unlock(ROTATE_PASS);
        expect(snapshot(re)).toEqual(before);
        await expect(
          MajikKey.fromJSON(key.toJSON()).unlock(PASSPHRASE),
        ).rejects.toThrow();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "a failed rotation (wrong current passphrase) changes nothing — atomic",
      async () => {
        const key = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "Atomic",
          { keys: [KeyId.ETH] },
        );
        const jsonBefore = JSON.stringify(key.toJSON({ legacy: false }));

        await expect(
          key.updatePassphrase("wrong-current-pass", NEW_PASSPHRASE),
        ).rejects.toThrow();

        expect(JSON.stringify(key.toJSON({ legacy: false }))).toBe(jsonBefore);
        expect(await key.verify(PASSPHRASE)).toBe(true);
        expect(key.isUnlocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it("updatePassphrase requires an unlocked key", async () => {
      const locked = MajikKey.fromJSON(majikKey.toJSON());
      await expect(
        locked.updatePassphrase(NEW_PASSPHRASE, "Whatever-Pass-1!"),
      ).rejects.toThrow(/must be unlocked/);
    });

    it("migrate() is a no-op on an Argon2id account", async () => {
      const before = JSON.stringify(majikKey.toJSON({ legacy: false }));
      expect(await majikKey.migrate(NEW_PASSPHRASE)).toBe(majikKey);
      expect(JSON.stringify(majikKey.toJSON({ legacy: false }))).toBe(before);
    });
  });

  // ── 10. BACKUP & RESTORATION ──────────────────────────────────────────────
  describe("Backup and Restoration", () => {
    let backupString: string;

    it(
      "exports a valid mnemonic backup string (versioned salt generation recorded)",
      async () => {
        backupString = await majikKey.exportMnemonicBackup(validMnemonic);
        expect(typeof backupString).toBe("string");
        expect(backupString.length).toBeGreaterThan(0);

        const payload = JSON.parse(base64ToUtf8(backupString));
        expect(payload.fingerprint).toBe(majikKey.fingerprint);
        expect(payload.backupKdfVersion).toBe(KDF_VERSION.ARGON2ID);
        expect([1, 2]).toContain(payload.backupSaltVersion);
        expect(payload.ciphertext).toBeTruthy();
        // a backup never contains the mnemonic or the raw key in the clear
        expect(base64ToUtf8(backupString)).not.toContain(validMnemonic);
      },
      CRYPTO_TIMEOUT,
    );

    it("an unlocked key is required to export a backup", async () => {
      const locked = MajikKey.fromJSON(majikKey.toJSON());
      await expect(locked.exportMnemonicBackup(validMnemonic)).rejects.toThrow(
        /must be unlocked/,
      );
    });

    it(
      "imports from a backup: same id/fingerprint, fully upgraded, unlocked under the NEW passphrase",
      async () => {
        const imported = await MajikKey.importFromMnemonicBackup(
          backupString,
          validMnemonic,
          NEW_PASSPHRASE,
          "Imported Recovery Key",
        );
        expect(imported).toBeInstanceOf(MajikKey);
        // Core guarantee of the library: same mnemonic → same identity.
        expect(imported.id).toBe(majikKey.id);
        expect(imported.fingerprint).toBe(majikKey.fingerprint);
        expect(imported.label).toBe("Imported Recovery Key");
        expect(imported.isFullyUpgraded).toBe(true);
        expect(imported.isCoreComplete).toBe(true);
        expect(imported.isUnlocked).toBe(true);
        expect(imported.backup).toBe(backupString);
        expect(await imported.verify(NEW_PASSPHRASE)).toBe(true);
        expect(snapshot(imported)).toEqual(snapshot(majikKey));
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "import honours `keys` / `deriveBitcoin` for extra algorithms",
      async () => {
        const withEth = await MajikKey.importFromMnemonicBackup(
          backupString,
          validMnemonic,
          NEW_PASSPHRASE,
          "x",
          {
            keys: [KeyId.ETH],
          },
        );
        expect(withEth.hasEthereum).toBe(true);
        expect(withEth.hasBitcoin).toBe(false);
        const withBtc = await MajikKey.importFromMnemonicBackup(
          backupString,
          validMnemonic,
          NEW_PASSPHRASE,
          "x",
          {
            deriveBitcoin: true,
          },
        );
        expect(withBtc.hasBitcoin).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "rejects the wrong mnemonic",
      async () => {
        const wrong = await newMnemonic();
        await expect(
          MajikKey.importFromMnemonicBackup(
            backupString,
            wrong,
            NEW_PASSPHRASE,
            "Should Fail",
          ),
        ).rejects.toThrow(/Failed to decrypt backup/);
      },
      CRYPTO_TIMEOUT,
    );

    it("rejects malformed backups", async () => {
      await expect(
        MajikKey.importFromMnemonicBackup("", validMnemonic, NEW_PASSPHRASE),
      ).rejects.toThrow(/non-empty string/);
      const bad = utf8ToBase64(JSON.stringify({ iv: "x" }));
      await expect(
        MajikKey.importFromMnemonicBackup(bad, validMnemonic, NEW_PASSPHRASE),
      ).rejects.toThrow(/Invalid backup format/);
    });

    it(
      "rejects a tampered backup (flipped ciphertext) instead of importing wrong keys",
      async () => {
        const payload = JSON.parse(base64ToUtf8(backupString));
        const ct = Buffer.from(payload.ciphertext, "base64");
        ct[0] ^= 0xff;
        payload.ciphertext = ct.toString("base64");
        await expect(
          MajikKey.importFromMnemonicBackup(
            utf8ToBase64(JSON.stringify(payload)),
            validMnemonic,
            NEW_PASSPHRASE,
          ),
        ).rejects.toThrow(/Failed to decrypt backup/);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "a backup exported from an account with extra keys still restores the identity",
      async () => {
        const backup = await fullKey.exportMnemonicBackup(fullMnemonic);
        const re = await MajikKey.importFromMnemonicBackup(
          backup,
          fullMnemonic,
          NEW_PASSPHRASE,
          "full",
          { keys: EXTRA_KEYS },
        );
        expect(re.fingerprint).toBe(fullKey.fingerprint);
        expect(snapshot(re)).toEqual(snapshot(fullKey));
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 11. addKeys ───────────────────────────────────────────────────────────
  describe("addKeys (mnemonic-gated key additions)", () => {
    let mnemonic: string;
    let key: MajikKey;

    beforeAll(async () => {
      mnemonic = await newMnemonic();
      key = await MajikKey.create(mnemonic, PASSPHRASE, "addKeys");
    }, CRYPTO_TIMEOUT);

    it(
      "rejects the wrong mnemonic and the wrong passphrase, adding nothing",
      async () => {
        await expect(
          key.addKeys([KeyId.ETH], await newMnemonic(), PASSPHRASE),
        ).rejects.toThrow(/does not belong/);
        await expect(
          key.addKeys([KeyId.ETH], mnemonic, "wrong-passphrase!"),
        ).rejects.toThrow();
        expect(key.hasEthereum).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it("rejects reserved / unsupported / unknown algorithms", async () => {
      await expect(
        key.addKeys([KeyId.HQC_128], mnemonic, PASSPHRASE),
      ).rejects.toThrow(/reserved/);
      await expect(
        key.addKeys([KeyId.LMS], mnemonic, PASSPHRASE),
      ).rejects.toThrow(/not supported/);
      await expect(
        key.addKeys(["pq:nope" as any], mnemonic, PASSPHRASE),
      ).rejects.toThrow(/Unknown/);
    });

    it(
      "adds only what is missing, reports exactly that, and the new keys are usable immediately",
      async () => {
        const added = await key.addKeys(
          [KeyId.ETH, KeyId.ED25519, KeyId.ML_KEM_512, KeyId.ETH, KeyId.SOL],
          mnemonic,
          PASSPHRASE,
        );
        expect(added).toEqual([KeyId.ETH, KeyId.ML_KEM_512]); // order: as requested; core/derived/duplicates skipped
        expect(key.hasKeys([KeyId.ETH, KeyId.ML_KEM_512])).toBe(true);
        expect(key.getPrivateKey(KeyId.ETH).length).toBe(32); // unlocked account → secret available at once
        expect(key.web3!.ethereum!.address).toBe(key.getEthereumAddress());
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "is idempotent",
      async () => {
        expect(
          await key.addKeys(
            [KeyId.ETH, KeyId.ML_KEM_512],
            mnemonic,
            PASSPHRASE,
          ),
        ).toEqual([]);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "persists across lock/unlock and JSON round-trips, and survives passphrase rotation",
      async () => {
        const before = snapshot(key);
        key.lock();
        const re = MajikKey.fromJSON(key.toJSON({ legacy: false }));
        await re.unlock(PASSPHRASE);
        expect(snapshot(re)).toEqual(before);

        await re.updatePassphrase(PASSPHRASE, NEW_PASSPHRASE);
        const re2 = MajikKey.fromJSON(re.toJSON({ legacy: false }));
        await re2.unlock(NEW_PASSPHRASE);
        expect(snapshot(re2)).toEqual(before);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "adding to a LOCKED account stores the key without ever exposing its secret",
      async () => {
        const k = MajikKey.fromJSON(
          (await MajikKey.create(mnemonic, PASSPHRASE, "locked add")).toJSON(),
        );
        expect(k.isLocked).toBe(true);
        expect(
          await k.addKeys([KeyId.ML_DSA_44], mnemonic, PASSPHRASE),
        ).toEqual([KeyId.ML_DSA_44]);
        expect(k.isLocked).toBe(true);
        expect(() => k.getPrivateKey(KeyId.ML_DSA_44)).toThrow(/locked/);
        expect(k.getPublicKey(KeyId.ML_DSA_44).length).toBe(1312);
        await k.unlock(PASSPHRASE);
        expect(k.getPrivateKey(KeyId.ML_DSA_44).length).toBe(2560);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "a legacy-KDF account must migrate() before addKeys()",
      async () => {
        // Hand-build a minimal PBKDF2-era account is covered in the v2 suite; here we assert the guard.
        const legacy: any = JSON.parse(
          JSON.stringify(
            (await MajikKey.create(mnemonic, PASSPHRASE, "kdf")).toJSON(),
          ),
        );
        legacy.kdfVersion = KDF_VERSION.PBKDF2;
        const k = MajikKey.fromJSON(legacy);
        expect(k.isArgon2id).toBe(false);
        await expect(
          k.addKeys([KeyId.ETH], mnemonic, PASSPHRASE),
        ).rejects.toThrow(/migrate/);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 12. DEPRECATED API (must keep working until the next major) ───────────
  describe("Deprecated per-algorithm API still works and agrees with the registry", () => {
    it("getters, secret accessors and capability flags are identical wrappers", () => {
      const k = fullKey;
      expect(k.mlKemPublicKey).toEqual(k.getPublicKey(KeyId.ML_KEM_768));
      expect(k.mlKemSecretKey).toEqual(k.getPrivateKey(KeyId.ML_KEM_768));
      expect(k.edPublicKey).toEqual(k.getPublicKey(KeyId.ED25519));
      expect(k.mlDsaPublicKey).toEqual(k.getPublicKey(KeyId.ML_DSA_87));
      expect(k.btcPublicKey).toEqual(k.getPublicKey(KeyId.BTC));
      expect(k.getMlKemSecretKey()).toBe(k.getPrivateKey(KeyId.ML_KEM_768));
      expect(k.getEdSecretKey()).toBe(k.getPrivateKey(KeyId.ED25519));
      expect(k.getMlDsaSecretKey()).toBe(k.getPrivateKey(KeyId.ML_DSA_87));
      expect(k.getBtcSecretKey()).toBe(k.getPrivateKey(KeyId.BTC));
      expect(k.getPrivateKey().raw).toBe(k.getPrivateKey(KeyId.X25519)); // no-arg overload
      expect(k.getPrivateKeyBase64()).toBe(
        arrayToBase64(k.getPrivateKey(KeyId.X25519)),
      );
      expect(k.publicKey.raw).toEqual(k.getPublicKey(KeyId.X25519));
      expect(
        k.hasMlKem &&
          k.hasSigningKeys &&
          k.hasBitcoin &&
          k.hasBitcoinKeypair &&
          k.hasSolanaKeypair,
      ).toBe(true);
    });

    it("accessors for absent keys fail with an actionable error (pointing at addKeys)", () => {
      const k = majikKey; // core only
      expect(k.btcPublicKey).toBeUndefined();
      expect(() => k.getBtcSecretKey()).toThrow(/addKeys/);
      expect(() => k.getBitcoinKeypairMaterial()).toThrow(/addKeys/);
      expect(() => k.getEthereumAddress()).toThrow(/addKeys/);
    });

    it("web3 namespace: Solana always (when unlocked), Bitcoin/Ethereum only when present", () => {
      expect(majikKey.web3!.solana.address).toBe(majikKey.getSolanaAddress());
      expect(majikKey.web3!.bitcoin).toBeUndefined();
      expect(majikKey.web3!.ethereum).toBeUndefined();

      const w = fullKey.web3!;
      expect(w.bitcoin!.publicKey).toEqual(fullKey.getPublicKey(KeyId.BTC));
      expect(w.ethereum!.address).toBe(fullKey.getEthereumAddress());
      expect(w.ethereum!.getPrivateKeyHex()).toBe(
        fullKey.getEthereumPrivateKeyHex(),
      );
    });

    it("standard-path Bitcoin needs the mnemonic; the stored key stays the domain-separated one", async () => {
      expect(() =>
        fullKey.getBitcoinKeypairMaterial({ standard: true }),
      ).toThrow(/requires the mnemonic/);
      const standard =
        await MajikKey.deriveStandardBitcoinFromMnemonic(fullMnemonic);
      expect(standard.publicKey).not.toEqual(fullKey.getPublicKey(KeyId.BTC));
      expect(standard.publicKey.length).toBe(33);
      await expect(
        MajikKey.deriveStandardBitcoinFromMnemonic(
          Array(12).fill("abandon").join(" "),
        ),
      ).rejects.toThrow(/Invalid BIP39 mnemonic phrase/);
    });

    it("Solana: derived key is domain-separated; reuseMessageKey returns the raw Ed25519 key", () => {
      const derived = fullKey.getSolanaKeypairMaterial();
      const reused = fullKey.getSolanaKeypairMaterial({
        reuseMessageKey: true,
      });
      expect(derived.publicKey).not.toEqual(
        fullKey.getPublicKey(KeyId.ED25519),
      );
      expect(reused.publicKey).toEqual(fullKey.getPublicKey(KeyId.ED25519));
      expect(fullKey.getPublicKey(KeyId.SOL)).toEqual(derived.publicKey);
    });
  });
});
