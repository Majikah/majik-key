// majik-key.hardening.test.ts
//
// Adversarial / boundary / state-machine coverage for MajikKey.
//
// The main majik-key.test.ts suite verifies normal end-to-end behaviour.
// This suite intentionally attacks the public API with:
//   - malformed input
//   - corrupted persisted data
//   - invalid state transitions
//   - duplicate/conflicting registry entries
//   - secret/public mismatches
//   - backup tampering
//   - dangerous-import tampering
//   - unsupported/reserved algorithms
//   - atomicity checks
//
// Keep expensive Argon2id operations shared wherever possible.

import { beforeAll, describe, expect, it } from "vitest";

import { MajikKey, KeyId, CORE_KEYS } from "../src/majik-key";
import { KEY_ALGORITHMS } from "../src/core/keys/registry";
import {
  arrayToBase64,
  base64ToUint8Array,
} from "../src/core/utils";
import type { MnemonicLanguage } from "../src/core/crypto/wordlist";

const CRYPTO_TIMEOUT = 360_000;

const PASSPHRASE = "HardeningPassphrase123!";
const NEW_PASSPHRASE = "HardeningNewPassphrase456!";

const SIZES: Partial<Record<KeyId, { pk: number; sk: number }>> = {
  [KeyId.X25519]: { pk: 32, sk: 32 },
  [KeyId.ED25519]: { pk: 32, sk: 64 },

  [KeyId.ML_KEM_512]: { pk: 800, sk: 1632 },
  [KeyId.ML_KEM_768]: { pk: 1184, sk: 2400 },
  [KeyId.ML_KEM_1024]: { pk: 1568, sk: 3168 },

  [KeyId.ML_DSA_44]: { pk: 1312, sk: 2560 },
  [KeyId.ML_DSA_65]: { pk: 1952, sk: 4032 },
  [KeyId.ML_DSA_87]: { pk: 2592, sk: 4896 },

  // SLH-DSA-SHAKE-128f serialized key sizes.
  [KeyId.SLH_DSA_SHAKE_128F]: { pk: 32, sk: 64 },

  [KeyId.BTC]: { pk: 33, sk: 32 },
  [KeyId.ETH]: { pk: 33, sk: 32 },
};

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

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

const corruptCiphertextBase64 = (value: string): string => {
  const bytes = base64ToUint8Array(value);

  if (bytes.length === 0) {
    return arrayToBase64(new Uint8Array([0x01]));
  }

  const tampered = new Uint8Array(bytes);

  // Flip one real ciphertext byte while keeping
  // the serialized value valid Base64.
  tampered[tampered.length - 1] ^= 0x01;

  return arrayToBase64(tampered);
};
const newMnemonic = (language: MnemonicLanguage = "en") =>
  MajikKey.generateMnemonic(128, language);

const storedIds = (key: MajikKey): KeyId[] =>
  key
    .listKeys()
    .filter((entry) => entry.kind === "stored")
    .map((entry) => entry.id);

const snapshot = (key: MajikKey): Record<string, string> =>
  Object.fromEntries(
    storedIds(key).map((id) => [id, arrayToBase64(key.getPrivateKey(id))]),
  );

describe("MajikKey — hardening / adversarial coverage", () => {
  let coreKey: MajikKey;
  let fullKey: MajikKey;
  let mnemonic: string;

  beforeAll(async () => {
    mnemonic = await newMnemonic();

    coreKey = await MajikKey.create(mnemonic, PASSPHRASE, "Hardening Core");

    fullKey = await MajikKey.create(
      await newMnemonic(),
      PASSPHRASE,
      "Hardening Full",
      {
        keys: [
          KeyId.ML_KEM_512,
          KeyId.ML_KEM_1024,
          KeyId.ML_DSA_44,
          KeyId.ML_DSA_65,
          KeyId.SLH_DSA_SHAKE_128F,
          KeyId.BTC,
          KeyId.ETH,
        ],
      },
    );
  }, CRYPTO_TIMEOUT);

  // ===========================================================================
  // 1. INPUT VALIDATION
  // ===========================================================================

  describe("Input validation", () => {
    it.each([
      "",
      " ",
      "\t",
      "\n",
      "not a mnemonic",
      "abandon",
      "abandon abandon",
    ])("rejects invalid mnemonic: %j", async (value) => {
      await expect(
        MajikKey.create(value, PASSPHRASE, "invalid"),
      ).rejects.toThrow();
    });

    it("rejects an invalid checksum", async () => {
      await expect(
        MajikKey.create(
          Array(12).fill("abandon").join(" "),
          PASSPHRASE,
          "invalid checksum",
        ),
      ).rejects.toThrow(/Invalid BIP39 mnemonic phrase/);
    });

    it("rejects an invalid passphrase", async () => {
      await expect(MajikKey.create(mnemonic, "", "invalid")).rejects.toThrow();

      await expect(
        MajikKey.create(mnemonic, "   ", "invalid"),
      ).rejects.toThrow();

      await expect(
        MajikKey.create(mnemonic, null as any, "invalid"),
      ).rejects.toThrow();
    });

    it("rejects a non-string mnemonic", async () => {
      await expect(
        MajikKey.create(null as any, PASSPHRASE, "invalid"),
      ).rejects.toThrow();

      await expect(
        MajikKey.create(123 as any, PASSPHRASE, "invalid"),
      ).rejects.toThrow();
    });

    it("rejects invalid labels", async () => {
      await expect(
        MajikKey.create(mnemonic, PASSPHRASE, null as any),
      ).rejects.toThrow();

      await expect(
        MajikKey.create(mnemonic, PASSPHRASE, 123 as any),
      ).rejects.toThrow();
    });

    it("accepts an intentionally empty label", async () => {
      const key = await MajikKey.create(mnemonic, PASSPHRASE, "");

      expect(key.label).toBe("");
    });

    it("rejects an unsupported mnemonic language", async () => {
      await expect(
        MajikKey.create(mnemonic, PASSPHRASE, "", {
          mnemonicLanguage: "klingon" as any,
        }),
      ).rejects.toThrow(/Unsupported language/);
    });
  });

  // ===========================================================================
  // 2. EVERY SUPPORTED STORED ALGORITHM
  // ===========================================================================

  describe("Every supported stored algorithm", () => {
    const expectedSupported = MajikKey.supportedKeys().filter(
      (id) => id !== KeyId.SOL,
    );

    it("does not advertise reserved algorithms as supported", () => {
      expect(MajikKey.supportedKeys()).not.toContain(KeyId.HQC_128);

      expect(MajikKey.supportedKeys()).not.toContain(KeyId.FN_DSA_512);

      expect(MajikKey.supportedKeys()).not.toContain(KeyId.LMS);
    });

    it.each(expectedSupported)(
      "registry metadata exists for supported key %s",
      (id) => {
        expect(KEY_ALGORITHMS[id]).toBeDefined();
        expect(KEY_ALGORITHMS[id].id).toBe(id);
        expect(KEY_ALGORITHMS[id].family).toBeTruthy();
        expect(KEY_ALGORITHMS[id].purpose).toBeTruthy();
        expect(KEY_ALGORITHMS[id].kind).toBe("stored");
      },
    );

    it("contains the complete core set", () => {
      expect(storedIds(fullKey)).toEqual(
        expect.arrayContaining([...CORE_KEYS]),
      );
    });

    it.each(
      Object.entries(SIZES) as Array<[KeyId, { pk: number; sk: number }]>,
    )("stored algorithm %s has expected serialized key sizes", (id, size) => {
      if (id === KeyId.SOL) return;

      if (!fullKey.hasKey(id)) {
        return;
      }

      expect(fullKey.getPublicKey(id)).toHaveLength(size.pk);
      expect(fullKey.getPrivateKey(id)).toHaveLength(size.sk);
    });
  });

  // ===========================================================================
  // 3. LOCK STATE MACHINE
  // ===========================================================================

  describe("Lock state machine", () => {
    it("lock() is idempotent", () => {
      const key = MajikKey.fromJSON(coreKey.toJSON());

      expect(key.isLocked).toBe(true);

      expect(() => key.lock()).not.toThrow();
      expect(key.isLocked).toBe(true);

      expect(() => key.lock()).not.toThrow();
      expect(key.isLocked).toBe(true);
    });

    it("locked state exposes public material but no private material", () => {
      const key = MajikKey.fromJSON(fullKey.toJSON());

      expect(key.isLocked).toBe(true);

      for (const id of storedIds(key)) {
        expect(() => key.getPrivateKey(id)).toThrow(/MajikKey is locked/);

        expect(key.getPublicKey(id)).toBeInstanceOf(Uint8Array);
      }
    });

    it("derived Solana public access is unavailable while locked", () => {
      const key = MajikKey.fromJSON(coreKey.toJSON());

      expect(() => key.getPublicKey(KeyId.SOL)).toThrow(/locked/);
    });

    it("web3 namespace is unavailable while locked", () => {
      const key = MajikKey.fromJSON(coreKey.toJSON());

      expect(key.web3).toBeUndefined();
    });

    it("public identity survives locking", () => {
      const key = MajikKey.fromJSON(coreKey.toJSON());

      expect(key.id).toBe(coreKey.id);
      expect(key.fingerprint).toBe(coreKey.fingerprint);
      expect(key.publicKeyBase64).toBe(coreKey.publicKeyBase64);

      key.lock();

      expect(key.id).toBe(coreKey.id);
      expect(key.fingerprint).toBe(coreKey.fingerprint);
      expect(key.publicKeyBase64).toBe(coreKey.publicKeyBase64);
    });
  });

  // ===========================================================================
  // 4. UNLOCK ATOMICITY
  // ===========================================================================

  describe("Unlock atomicity", () => {
    it(
      "wrong passphrase never partially unlocks",
      async () => {
        const key = MajikKey.fromJSON(fullKey.toJSON());

        await expect(key.unlock("wrong-passphrase")).rejects.toThrow();

        expect(key.isLocked).toBe(true);

        for (const id of storedIds(key)) {
          expect(() => key.getPrivateKey(id)).toThrow(/locked/);
        }
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "unlock restores all stored secrets after a successful attempt",
      async () => {
        const key = MajikKey.fromJSON(fullKey.toJSON());

        await key.unlock(PASSPHRASE);

        expect(snapshot(key)).toEqual(snapshot(fullKey));
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "failed unlock does not corrupt a previously locked JSON representation",
      async () => {
        const json = fullKey.toJSON({
          legacy: false,
        });

        const key = MajikKey.fromJSON(json);

        await expect(key.unlock("wrong")).rejects.toThrow();

        expect(
          JSON.stringify(
            key.toJSON({
              legacy: false,
            }),
          ),
        ).toBe(JSON.stringify(json));
      },
      CRYPTO_TIMEOUT,
    );

    it("unlocking an already-unlocked key fails before doing crypto", async () => {
      const before = JSON.stringify(
        fullKey.toJSON({
          legacy: false,
        }),
      );

      await expect(fullKey.unlock(PASSPHRASE)).rejects.toThrow(
        /already unlocked/,
      );

      expect(
        JSON.stringify(
          fullKey.toJSON({
            legacy: false,
          }),
        ),
      ).toBe(before);
    });
  });

  // ===========================================================================
  // 5. VERIFY
  // ===========================================================================

  describe("Passphrase verification", () => {
    it(
      "returns true for the correct passphrase",
      async () => {
        expect(await fullKey.verify(PASSPHRASE)).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "returns false for the wrong passphrase",
      async () => {
        expect(await fullKey.verify("definitely-wrong")).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verify() does not alter unlocked state",
      async () => {
        expect(fullKey.isUnlocked).toBe(true);

        await fullKey.verify(PASSPHRASE);

        expect(fullKey.isUnlocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "verify() does not unlock a locked key",
      async () => {
        const key = MajikKey.fromJSON(fullKey.toJSON());

        expect(key.isLocked).toBe(true);

        expect(await key.verify(PASSPHRASE)).toBe(true);

        expect(key.isLocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ===========================================================================
  // 6. AUTO LOCK
  // ===========================================================================

  describe("withAutoLock adversarial behaviour", () => {
    it(
      "always locks after a synchronous successful operation",
      async () => {
        const key = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "auto",
        );

        const value = await MajikKey.withAutoLock(
          key,
          () => key.getPrivateKey(KeyId.ED25519).length,
        );

        expect(value).toBe(64);
        expect(key.isLocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "always locks after an asynchronous successful operation",
      async () => {
        const key = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "auto async",
        );

        const value = await MajikKey.withAutoLock(key, async () => {
          await Promise.resolve();
          return key.getPrivateKey(KeyId.X25519).length;
        });

        expect(value).toBe(32);
        expect(key.isLocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "always locks after a thrown error",
      async () => {
        const key = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "auto throw",
        );

        await expect(
          MajikKey.withAutoLock(key, () => {
            throw new Error("boom");
          }),
        ).rejects.toThrow("boom");

        expect(key.isLocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "always locks after a rejected promise",
      async () => {
        const key = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "auto reject",
        );

        await expect(
          MajikKey.withAutoLock(key, async () => {
            throw new Error("async boom");
          }),
        ).rejects.toThrow("async boom");

        expect(key.isLocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it("does not execute the callback for a locked key", async () => {
      const key = MajikKey.fromJSON(coreKey.toJSON());

      let executed = false;

      await expect(
        MajikKey.withAutoLock(key, () => {
          executed = true;
        }),
      ).rejects.toThrow(/must be unlocked/);

      expect(executed).toBe(false);
      expect(key.isLocked).toBe(true);
    });

    it("rejects a non-function operation", async () => {
      await expect(MajikKey.withAutoLock(fullKey, null as any)).rejects.toThrow(
        /Operation must be a function/,
      );

      expect(fullKey.isUnlocked).toBe(true);
    });

    it("rejects a non-MajikKey object", async () => {
      await expect(MajikKey.withAutoLock({} as any, () => 1)).rejects.toThrow(
        /valid MajikKey instance/,
      );
    });
  });

  // ===========================================================================
  // 7. REGISTRY / JSON STRUCTURAL HARDENING
  // ===========================================================================

  describe("Safe JSON hardening", () => {
    it("rejects non-JSON strings", () => {
      expect(() => MajikKey.fromJSON("this is definitely not json")).toThrow();
    });

    it.each([null, undefined, 0, false, [], {}])(
      "rejects malformed root value: %j",
      (value) => {
        expect(() => MajikKey.fromJSON(value as any)).toThrow();
      },
    );

    it("rejects a mismatched X25519 public key", () => {
      const json: any = clone(
        coreKey.toJSON({
          legacy: false,
        }),
      );

      json.publicKey = "AAAA";

      expect(() => MajikKey.fromJSON(json)).toThrow(/does not match/);
    });

    it("rejects duplicate registry key IDs", () => {
      const json: any = clone(
        coreKey.toJSON({
          legacy: false,
        }),
      );

      json.keys.push(clone(json.keys[0]));

      expect(() => MajikKey.fromJSON(json)).toThrow(/Duplicate/);
    });

    it("rejects a registry without X25519", () => {
      const json: any = clone(
        coreKey.toJSON({
          legacy: false,
        }),
      );

      json.keys = json.keys.filter((entry: any) => entry.id !== KeyId.X25519);

      expect(() => MajikKey.fromJSON(json)).toThrow(/classic:x25519/);
    });

    it("rejects an empty registry", () => {
      const json: any = clone(
        coreKey.toJSON({
          legacy: false,
        }),
      );

      json.keys = [];

      expect(() => MajikKey.fromJSON(json)).toThrow();
    });

    it("rejects unsupported future keysVersion values", () => {
      const json: any = clone(
        coreKey.toJSON({
          legacy: false,
        }),
      );

      json.keysVersion = 999;

      expect(() => MajikKey.fromJSON(json)).toThrow(/Upgrade the library/);
    });

    it("preserves an unknown future registry entry", () => {
      const json: any = clone(
        coreKey.toJSON({
          legacy: false,
        }),
      );

      const future = {
        id: "pq:future-ml-kem-2048",
        publicKey: "AAAA",
        encryptedSecretKey: "BBBB",
        derivation: {
          scheme: "future-kdf",
          version: 99,
        },
      };

      json.keys.push(future);

      const key = MajikKey.fromJSON(json);

      expect(key.availableKeys()).not.toContain(future.id);

      const output: any = key.toJSON({
        legacy: false,
      });

      expect(output.keys.at(-1)).toEqual(future);
    });

    it("safe JSON never contains raw private-key material", () => {
      const json = JSON.stringify(fullKey.toJSON());

      for (const id of storedIds(fullKey)) {
        expect(json).not.toContain(arrayToBase64(fullKey.getPrivateKey(id)));
      }

      expect(json).not.toContain("secretKeys");

      expect(json).not.toContain("privateKeyBase64");
    });

    it("mutating an exported JSON object does not mutate the account", () => {
      const json: any = fullKey.toJSON({
        legacy: false,
      });

      const before = JSON.stringify(
        fullKey.toJSON({
          legacy: false,
        }),
      );

      json.label = "MUTATED";
      json.keys[0].publicKey = "AAAA";

      expect(
        JSON.stringify(
          fullKey.toJSON({
            legacy: false,
          }),
        ),
      ).toBe(before);
    });
  });

  // ===========================================================================
  // 8. ENCRYPTED BLOB CORRUPTION
  // ===========================================================================

  describe("Encrypted blob corruption", () => {
    it(
      "rejects a corrupted X25519 ciphertext on unlock",
      async () => {
        const json: any = clone(
          fullKey.toJSON({
            legacy: false,
          }),
        );

        const entry = json.keys.find((value: any) => value.id === KeyId.X25519);

        entry.encryptedSecretKey = corruptCiphertextBase64(entry.encryptedSecretKey);

        const key = MajikKey.fromJSON(json);

        await expect(key.unlock(PASSPHRASE)).rejects.toThrow();
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "rejects a corrupted ML-KEM ciphertext on unlock",
      async () => {
        const json: any = clone(
          fullKey.toJSON({
            legacy: false,
          }),
        );

        const entry = json.keys.find(
          (value: any) => value.id === KeyId.ML_KEM_768,
        );

        entry.encryptedSecretKey = corruptCiphertextBase64(entry.encryptedSecretKey);

        const key = MajikKey.fromJSON(json);

        await expect(key.unlock(PASSPHRASE)).rejects.toThrow();

        expect(key.isLocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "rejects truncated encrypted blobs",
      async () => {
        const json: any = clone(
          fullKey.toJSON({
            legacy: false,
          }),
        );

        const entry = json.keys.find((value: any) => value.id === KeyId.X25519);

        entry.encryptedSecretKey = arrayToBase64(new Uint8Array(1));

        const key = MajikKey.fromJSON(json);

        await expect(key.unlock(PASSPHRASE)).rejects.toThrow();

        expect(key.isLocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ===========================================================================
  // 9. DANGEROUS JSON INTEGRITY
  // ===========================================================================

  describe("Dangerous JSON integrity", () => {
    it("round-trips every currently stored secret", () => {
      const exported: any = fullKey.toDangerousJSON();

      const restored = MajikKey.fromDangerousJSON(exported);

      expect(restored.isUnlocked).toBe(true);
      expect(snapshot(restored)).toEqual(snapshot(fullKey));
    });

    it("accepts string-form dangerous JSON", () => {
      const exported = fullKey.toDangerousJSON();

      const restored = MajikKey.fromDangerousJSON(JSON.stringify(exported));

      expect(restored.isUnlocked).toBe(true);
    });

    it("rejects missing required secret material", () => {
      const exported: any = fullKey.toDangerousJSON();

      delete exported.secretKeys;

      delete exported.privateKeyBase64;
      delete exported.edSecretKeyBase64;
      delete exported.mlKemSecretKeyBase64;
      delete exported.mlDsaSecretKeyBase64;

      expect(() => MajikKey.fromDangerousJSON(exported)).toThrow(
        /missing|required/i,
      );
    });

    it("dangerous export is unavailable while locked", () => {
      const locked = MajikKey.fromJSON(fullKey.toJSON());

      expect(() => locked.toDangerousJSON()).toThrow(/must be unlocked/);
    });
  });

  // ===========================================================================
  // 10. MNEMONIC JSON
  // ===========================================================================

  describe("MnemonicJSON hardening", () => {
    it("exports one seed element per mnemonic word", () => {
      const json = coreKey.toMnemonicJSON(mnemonic, PASSPHRASE);

      expect(json.seed).toEqual(mnemonic.split(" "));
    });

    it("does not accidentally include the plaintext phrase when omitted", () => {
      const json = coreKey.toMnemonicJSON(mnemonic);

      expect(json.phrase).toBeUndefined();
    });

    it("rejects malformed seed arrays", async () => {
      await expect(
        MajikKey.fromMnemonicJSON(
          {
            id: "bad",
            seed: [],
          } as any,
          PASSPHRASE,
        ),
      ).rejects.toThrow();

      await expect(
        MajikKey.fromMnemonicJSON(
          {
            id: "bad",
            seed: "not-an-array",
          } as any,
          PASSPHRASE,
        ),
      ).rejects.toThrow();
    });

    it("rejects a missing id", async () => {
      await expect(
        MajikKey.fromMnemonicJSON(
          {
            seed: mnemonic.split(" "),
          } as any,
          PASSPHRASE,
        ),
      ).rejects.toThrow();
    });

    it(
      "preserves the mnemonic language",
      async () => {
        const japanese = await newMnemonic("ja");

        const key = await MajikKey.create(japanese, PASSPHRASE, "Japanese", {
          mnemonicLanguage: "ja",
        });

        const json = key.toMnemonicJSON(japanese, PASSPHRASE);

        expect(json.language).toBe("ja");

        const restored = await MajikKey.fromMnemonicJSON(
          json,
          NEW_PASSPHRASE,
          "Restored",
        );

        expect(restored.mnemonicLanguage).toBe("ja");
        expect(restored.id).toBe(key.id);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ===========================================================================
  // 11. PASSphrase ROTATION
  // ===========================================================================

  describe("Passphrase rotation hardening", () => {
    it(
      "rotation changes the salt",
      async () => {
        const key = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "rotation",
        );

        const oldSalt = key.toJSON().salt;

        await key.updatePassphrase(PASSPHRASE, NEW_PASSPHRASE);

        expect(key.toJSON().salt).not.toBe(oldSalt);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "rotation preserves every secret byte",
      async () => {
        const key = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "rotation",
          {
            keys: [KeyId.BTC, KeyId.ETH, KeyId.ML_KEM_1024, KeyId.ML_DSA_65],
          },
        );

        const before = snapshot(key);

        await key.updatePassphrase(PASSPHRASE, NEW_PASSPHRASE);

        expect(snapshot(key)).toEqual(before);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "wrong current passphrase makes zero changes",
      async () => {
        const key = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "atomic rotation",
        );

        const before = JSON.stringify(
          key.toJSON({
            legacy: false,
          }),
        );

        await expect(
          key.updatePassphrase("wrong-current", NEW_PASSPHRASE),
        ).rejects.toThrow();

        expect(
          JSON.stringify(
            key.toJSON({
              legacy: false,
            }),
          ),
        ).toBe(before);

        expect(key.isUnlocked).toBe(true);

        expect(await key.verify(PASSPHRASE)).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it("rotation requires an unlocked key", async () => {
      const key = MajikKey.fromJSON(coreKey.toJSON());

      await expect(
        key.updatePassphrase(PASSPHRASE, NEW_PASSPHRASE),
      ).rejects.toThrow(/must be unlocked/i);
    });
  });

  // ===========================================================================
  // 12. addKeys ATOMICITY
  // ===========================================================================

  describe("addKeys hardening", () => {
    it(
      "empty addKeys request is a no-op",
      async () => {
        const key = await MajikKey.create(
          await newMnemonic(),
          PASSPHRASE,
          "empty add",
        );

        expect(await key.addKeys([], mnemonic, PASSPHRASE)).toEqual([]);

        expect(key.isCoreComplete).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "duplicate requests are de-duplicated",
      async () => {
        const m = await newMnemonic();

        const key = await MajikKey.create(m, PASSPHRASE, "duplicates");

        const added = await key.addKeys(
          [KeyId.ETH, KeyId.ETH, KeyId.ETH],
          m,
          PASSPHRASE,
        );

        expect(added).toEqual([KeyId.ETH]);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "mixed invalid requests do not partially add earlier valid keys",
      async () => {
        const m = await newMnemonic();

        const key = await MajikKey.create(m, PASSPHRASE, "atomic add");

        await expect(
          key.addKeys([KeyId.ETH, KeyId.LMS], m, PASSPHRASE),
        ).rejects.toThrow();

        expect(key.hasKey(KeyId.ETH)).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "wrong mnemonic does not mutate the registry",
      async () => {
        const m = await newMnemonic();

        const key = await MajikKey.create(m, PASSPHRASE, "wrong mnemonic");

        const before = JSON.stringify(
          key.toJSON({
            legacy: false,
          }),
        );

        await expect(
          key.addKeys([KeyId.ETH], await newMnemonic(), PASSPHRASE),
        ).rejects.toThrow(/does not belong/i);

        expect(
          JSON.stringify(
            key.toJSON({
              legacy: false,
            }),
          ),
        ).toBe(before);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "wrong passphrase does not mutate the registry",
      async () => {
        const m = await newMnemonic();

        const key = await MajikKey.create(m, PASSPHRASE, "wrong password");

        const before = JSON.stringify(
          key.toJSON({
            legacy: false,
          }),
        );

        await expect(
          key.addKeys([KeyId.ETH], m, "wrong-password"),
        ).rejects.toThrow();

        expect(
          JSON.stringify(
            key.toJSON({
              legacy: false,
            }),
          ),
        ).toBe(before);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ===========================================================================
  // 13. LEGACY / RESERVED / UNKNOWN IDS
  // ===========================================================================

  describe("Algorithm admission control", () => {
    it("rejects reserved HQC", async () => {
      await expect(
        MajikKey.create(mnemonic, PASSPHRASE, "hqc", {
          keys: [KeyId.HQC_128],
        }),
      ).rejects.toThrow(/reserved/);
    });

    it("rejects reserved FN-DSA", async () => {
      await expect(
        MajikKey.create(mnemonic, PASSPHRASE, "fndsa", {
          keys: [KeyId.FN_DSA_512],
        }),
      ).rejects.toThrow(/reserved/);
    });

    it("rejects unsupported LMS", async () => {
      await expect(
        MajikKey.create(mnemonic, PASSPHRASE, "lms", {
          keys: [KeyId.LMS],
        }),
      ).rejects.toThrow(/not supported/i);
    });

    it("rejects unknown arbitrary IDs", async () => {
      await expect(
        MajikKey.create(mnemonic, PASSPHRASE, "unknown", {
          keys: ["pq:totally-fake" as any],
        }),
      ).rejects.toThrow(/Unknown/);
    });
  });

  // ===========================================================================
  // 14. DEPRECATED API LOCKED BEHAVIOUR
  // ===========================================================================

  describe("Deprecated API hardening", () => {
    it("deprecated secret getters fail while locked", () => {
      const key = MajikKey.fromJSON(fullKey.toJSON());

      expect(key.isLocked).toBe(true);

      expect(() => key.getEdSecretKey()).toThrow(/locked/i);

      expect(() => key.getMlKemSecretKey()).toThrow(/locked/i);

      expect(() => key.getMlDsaSecretKey()).toThrow(/locked/i);
    });

    it("deprecated public getters remain readable while locked", () => {
      const key = MajikKey.fromJSON(fullKey.toJSON());

      expect(key.edPublicKey).toBeInstanceOf(Uint8Array);

      expect(key.mlKemPublicKey).toBeInstanceOf(Uint8Array);

      expect(key.mlDsaPublicKey).toBeInstanceOf(Uint8Array);
    });

    it("deprecated absent-key getters remain actionable", () => {
      expect(coreKey.btcPublicKey).toBeUndefined();

      expect(() => coreKey.getBtcSecretKey()).toThrow(/addKeys/i);

      expect(() => coreKey.getBitcoinKeypairMaterial()).toThrow(/addKeys/i);

      expect(() => coreKey.getEthereumAddress()).toThrow(/addKeys/i);
    });
  });

  // ===========================================================================
  // 15. SERIALIZATION ROUND-TRIP MATRIX
  // ===========================================================================

  describe("Serialization round-trip matrix", () => {
    it.each([
      ["legacy", true],
      ["registry-only", false],
    ])("%s JSON survives object round-trip", (_, legacy) => {
      const original = fullKey.toJSON({
        legacy,
      });

      const restored = MajikKey.fromJSON(clone(original));

      expect(restored.id).toBe(fullKey.id);

      expect(restored.fingerprint).toBe(fullKey.fingerprint);

      expect(restored.label).toBe(fullKey.label);
    });

    it(
      "string JSON and object JSON behave identically",
      async () => {
        const objectKey = MajikKey.fromJSON(fullKey.toJSON());

        const stringKey = MajikKey.fromJSON(JSON.stringify(fullKey.toJSON()));

        await objectKey.unlock(PASSPHRASE);

        await stringKey.unlock(PASSPHRASE);

        expect(snapshot(objectKey)).toEqual(snapshot(stringKey));
      },
      CRYPTO_TIMEOUT,
    );

    it("JSON.stringify(key) remains parseable", () => {
      const serialized = JSON.stringify(fullKey);

      const parsed = JSON.parse(serialized);

      expect(parsed.id).toBe(fullKey.id);

      expect(parsed.keys).toBeDefined();
    });
  });

  // ===========================================================================
  // 16. MULTI-LANGUAGE BOUNDARIES
  // ===========================================================================

  describe("Multi-language hardening", () => {
    it.each(ALL_LANGUAGES)(
      "validates generated %s mnemonic",
      async (language) => {
        const m = await newMnemonic(language);

        expect(MajikKey.validateMnemonic(m)).toBe(true);
      },
    );

    it(
      "supports 24-word recovery",
      async () => {
        const m = await MajikKey.generateMnemonic(256, "en");

        expect(m.split(" ")).toHaveLength(24);

        const key = await MajikKey.create(m, PASSPHRASE, "24-word");

        expect(key.isCoreComplete).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it("wrong language rejects a valid foreign mnemonic", async () => {
      const m = await newMnemonic("ja");

      await expect(
        MajikKey.create(m, PASSPHRASE, "wrong language", {
          mnemonicLanguage: "en",
        }),
      ).rejects.toThrow(/Invalid BIP39 mnemonic phrase/);
    });

    it("all supported language labels are distinct", () => {
      expect(new Set(ALL_LANGUAGES)).toHaveProperty(
        "size",
        ALL_LANGUAGES.length,
      );
    });
  });
});
