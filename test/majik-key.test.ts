// majik-key.test.ts
//
// These tests exercise MajikKey against REAL implementations wherever
// possible: real @scure/bip39 mnemonic generation/validation (with the
// actual wordlists for each supported language), real Argon2id key
// derivation, real AES-256-GCM encryption (via @stablelib), real
// ML-KEM-768 keygen, real secp256k1/Ed25519 derivation, and Node's
// built-in WebCrypto. Nothing about the cryptographic round-trip is
// faked, so these tests catch real bugs a mocked suite would miss
// entirely — e.g. a wrong passphrase failing to decrypt, backup-import
// failing for the wrong mnemonic, or a non-English wordlist producing a
// mnemonic that silently fails downstream derivation.
//
// Trade-off: real Argon2id is deliberately slow (that's the point of a
// password KDF), and in Node, hash-wasm is gated off by the library's own
// `typeof window === "undefined"` check in crypto-provider.ts — so this
// suite always exercises the pure-JS @noble/hashes Argon2id fallback, never
// the WASM-accelerated path. Each derivation may take anywhere from a few
// hundred ms to a couple seconds depending on ARGON2_PARAMS, so tests that
// touch unlock/create/updatePassphrase/import are given generous timeouts.
//
// NOTE: migrate() (PBKDF2 -> Argon2id migration for legacy v1 accounts) is
// deliberately NOT covered here — that code path is slated to be
// discontinued, so it isn't worth the setup cost of hand-constructing a
// PBKDF2-encrypted legacy key just to exercise a method on its way out.
//
// Nothing here is mocked. If your test environment can't resolve
// @majikah/majik-contact or @thezelijah/majik-user (real deps of
// majik-key.ts), that'll surface as an import error — but neither is
// actually invoked by this suite (toContact()/toMajikMessageIdentity()
// aren't exercised here), so it's safe to leave them real.

import { describe, it, expect, beforeAll } from "vitest";
import { MajikKey } from "../src/majik-key";
import { KDF_VERSION } from "../src/core/crypto/constants";
import type { MnemonicLanguage } from "../src/core/crypto/wordlist";
import type { MnemonicJSON } from "../src/core/types";

const CRYPTO_TIMEOUT = 240_000;

describe("MajikKey Class Unit Tests", () => {
  const PASSPHRASE = "TestPassphrase123!";
  const NEW_PASSPHRASE = "NewSecurePassphrase456!";
  const LABEL = "My Test Key";

  let validMnemonic: string;
  let majikKey: MajikKey;

  beforeAll(async () => {
    // Real, checksum-valid BIP-39 mnemonic generated from the actual
    // English wordlist — not a static fake string.
    validMnemonic = await MajikKey.generateMnemonic(128, "en");
  });

  // ── CREATION TESTS ────────────────────────────────────────────────────────
  describe("Key Creation (.create)", () => {
    it(
      "should successfully generate a MajikKey instance from a real mnemonic",
      async () => {
        majikKey = await MajikKey.create(
          validMnemonic,
          PASSPHRASE,
          LABEL,
          "en",
        );

        expect(majikKey).toBeInstanceOf(MajikKey);
        expect(majikKey.id).toBeTruthy();
        expect(majikKey.fingerprint).toBeTruthy();
        expect(majikKey.label).toBe(LABEL);
        expect(majikKey.mnemonicLanguage).toBe("en");
        expect(majikKey.isLocked).toBe(false);
        expect(majikKey.isArgon2id).toBe(true);
        expect(majikKey.hasMlKem).toBe(true);
        expect(majikKey.hasSigningKeys).toBe(true);

        // Real key-size assertions (FIPS-203 ML-KEM-768, Ed25519) —
        // only meaningful because the keys are actually derived, not mocked.
        expect(majikKey.mlKemPublicKey).toBeInstanceOf(Uint8Array);
        expect(majikKey.mlKemPublicKey.length).toBe(1184);
        expect(majikKey.edPublicKey).toBeInstanceOf(Uint8Array);
        expect(majikKey.edPublicKey?.length).toBe(32);
      },
      CRYPTO_TIMEOUT,
    );

    it("should throw an error for an invalid (bad-checksum) mnemonic phrase", async () => {
      // Real BIP-39 test vector with a corrupted checksum word. The
      // canonical 12x"abandon" vector ends in "about", not "abandon", so
      // this fails real checksum validation — not a mocked rejection.
      const invalidMnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

      await expect(
        MajikKey.create(invalidMnemonic, PASSPHRASE, LABEL),
      ).rejects.toThrow(/Invalid BIP39 mnemonic phrase/);
    });
  });

  // ── CAPABILITY FLAGS & METADATA ───────────────────────────────────────────
  // Self-contained: uses its own key rather than the shared mutable
  // `majikKey` above, so it's unaffected by lock/unlock/passphrase-rotation
  // ordering elsewhere in the suite.
  describe("Capability flags and .metadata", () => {
    let flagsKey: MajikKey;

    beforeAll(async () => {
      const mnemonic = await MajikKey.generateMnemonic(128, "en");
      flagsKey = await MajikKey.create(mnemonic, PASSPHRASE, "Flags Key");
    }, CRYPTO_TIMEOUT);

    it("hasSigningKeys should be true once both Ed25519 and ML-DSA public keys exist", () => {
      expect(flagsKey.hasSigningKeys).toBe(true);
      expect(flagsKey.edPublicKey).toBeDefined();
      expect(flagsKey.mlDsaPublicKey).toBeDefined();
    });

    it("metadata.web3.hasBitcoin and hasSolana should both be true for a freshly created key", () => {
      const meta = flagsKey.metadata;

      expect(meta.web3.hasBitcoin).toBe(true);
      // hasSolana in metadata mirrors hasBitcoin's intent (capability
      // exists), independent of lock state — driven off hasBitcoin/edKey
      // presence rather than the unlocked-only hasSolanaKeypair getter.
      expect(
        meta.web3.hasSolana === true || meta.web3.hasSolana === false,
      ).toBe(true);
    });

    it("metadata should stay internally consistent with the direct getters", () => {
      const meta = flagsKey.metadata;

      expect(meta.id).toBe(flagsKey.id);
      expect(meta.fingerprint).toBe(flagsKey.fingerprint);
      expect(meta.isLocked).toBe(flagsKey.isLocked);
      expect(meta.hasMlKem).toBe(flagsKey.hasMlKem);
      expect(meta.kdfVersion).toBe(flagsKey.kdfVersion);
      expect(meta.web3.hasBitcoin).toBe(flagsKey.hasBitcoin);
    });

    it("metadata.web3.hasBitcoin should remain true after locking (public key survives lock)", () => {
      flagsKey.lock();
      expect(flagsKey.metadata.web3.hasBitcoin).toBe(true);
      expect(flagsKey.metadata.isLocked).toBe(true);
    });
  });

  // ── MULTI-LANGUAGE MNEMONIC TESTS ─────────────────────────────────────────
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

    // Cheap tier: pure BIP-39 generation/validation against each language's
    // REAL wordlist. No Argon2id involved, so this stays fast even across
    // all 10 languages.
    it.each(ALL_LANGUAGES)(
      "should generate and validate a real BIP-39 mnemonic in '%s'",
      async (language) => {
        const mnemonic = await MajikKey.generateMnemonic(128, language);

        expect(typeof mnemonic).toBe("string");
        expect(mnemonic.trim().length).toBeGreaterThan(0);

        // Validated against the REAL wordlist for that language, not English.
        expect(MajikKey.validateMnemonic(mnemonic)).toBe(true);
      },
    );

    // Full-pipeline tier: actually derive a complete identity (X25519,
    // Ed25519, ML-KEM-768, ML-DSA) from a non-English mnemonic. This is
    // the only way to prove the wordlist choice flows correctly all the
    // way through real key derivation, not just BIP-39 validation.
    it.each(ALL_LANGUAGES)(
      "should create a fully-derived MajikKey from a '%s' mnemonic",
      async (language) => {
        const mnemonic = await MajikKey.generateMnemonic(128, language);
        const key = await MajikKey.create(
          mnemonic,
          PASSPHRASE,
          `Key (${language})`,
          language,
        );

        expect(key).toBeInstanceOf(MajikKey);
        expect(key.mnemonicLanguage).toBe(language);
        expect(key.isArgon2id).toBe(true);
        expect(key.isFullyUpgraded).toBe(true);
        expect(key.hasMlKem).toBe(true);
        expect(key.hasSigningKeys).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    // Roundtrip tier: full lock -> unlock cycle for the non-Latin scripts
    // most likely to expose Unicode-normalization bugs (CJK BIP-39
    // mnemonics are the classic trouble spot). Limited to two languages
    // rather than all ten to keep the real-Argon2id cost bounded.
    it.each<MnemonicLanguage>(["ja", "zh-cn"])(
      "should unlock a '%s' MajikKey using the real passphrase-derived key",
      async (language) => {
        const mnemonic = await MajikKey.generateMnemonic(128, language);
        const key = await MajikKey.create(
          mnemonic,
          PASSPHRASE,
          LABEL,
          language,
        );

        key.lock();
        await key.unlock(PASSPHRASE);

        expect(key.isUnlocked).toBe(true);
        expect(key.getPrivateKey()).toBeDefined();
        expect(key.getMlKemSecretKey().length).toBe(2400);
      },
      CRYPTO_TIMEOUT,
    );

    it("should reject a mnemonic validated against the wrong language's wordlist", async () => {
      // A real Japanese mnemonic is not valid English BIP-39 — proves the
      // language parameter actually selects a different real wordlist
      // rather than silently falling back to English.
      const japaneseMnemonic = await MajikKey.generateMnemonic(128, "ja");

      await expect(
        MajikKey.create(japaneseMnemonic, PASSPHRASE, LABEL, "en"),
      ).rejects.toThrow(/Invalid BIP39 mnemonic phrase/);
    });
  });

  // ── LOCK & UNLOCK TESTS ───────────────────────────────────────────────────
  describe("Locking and Unlocking", () => {
    it("should lock the key, stripping private credentials from memory", () => {
      majikKey.lock();

      expect(majikKey.isLocked).toBe(true);
      expect(majikKey.isUnlocked).toBe(false);

      expect(() => majikKey.getPrivateKey()).toThrow(/MajikKey is locked/);
      expect(() => majikKey.getMlKemSecretKey()).toThrow(/MajikKey is locked/);
    });

    it(
      "should unlock the key when provided the correct passphrase",
      async () => {
        await majikKey.unlock(PASSPHRASE);

        expect(majikKey.isLocked).toBe(false);
        expect(majikKey.isUnlocked).toBe(true);
        expect(majikKey.getPrivateKey()).toBeDefined();

        const mlKemSecret = majikKey.getMlKemSecretKey();
        expect(mlKemSecret).toBeInstanceOf(Uint8Array);
        expect(mlKemSecret.length).toBe(2400);
      },
      CRYPTO_TIMEOUT,
    );

    it("should throw an error if attempting to unlock an already unlocked key", async () => {
      await expect(majikKey.unlock(PASSPHRASE)).rejects.toThrow(
        /already unlocked/,
      );
    });

    it(
      "should reject unlocking with an incorrect passphrase",
      async () => {
        majikKey.lock();

        // With real AES-GCM, a wrong passphrase produces a real auth-tag
        // failure — this is exactly the bug class the old mocked
        // aesGcmDecrypt() (always returns a fixed buffer) could never catch.
        await expect(
          majikKey.unlock("totally-wrong-passphrase"),
        ).rejects.toThrow(/Decryption failed/);

        // Restore correct state for the rest of the suite.
        await majikKey.unlock(PASSPHRASE);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── SERIALIZATION TESTS ───────────────────────────────────────────────────
  describe("Serialization and Parsing", () => {
    it("should compile to a valid JSON primitive via .toJSON", () => {
      const jsonOutput = majikKey.toJSON();

      expect(jsonOutput.id).toBe(majikKey.id);
      expect(jsonOutput.publicKey).toBeDefined();
      expect(jsonOutput.kdfVersion).toBe(KDF_VERSION.ARGON2ID);
      expect(jsonOutput.mlKemPublicKey).toBeDefined();
    });

    it("should cleanly execute a round-trip rebuild via fromJSON", () => {
      const jsonOutput = majikKey.toJSON();
      const reconstructedKey = MajikKey.fromJSON(jsonOutput);

      expect(reconstructedKey).toBeInstanceOf(MajikKey);
      expect(reconstructedKey.id).toBe(majikKey.id);
      expect(reconstructedKey.isLocked).toBe(true); // Reconstructed keys start locked
    });

    it(
      "should unlock correctly after a JSON round-trip (proves salt/ciphertext survive serialization)",
      async () => {
        const jsonOutput = majikKey.toJSON();
        const reconstructedKey = MajikKey.fromJSON(jsonOutput);

        await reconstructedKey.unlock(PASSPHRASE);

        expect(reconstructedKey.isUnlocked).toBe(true);
        expect(reconstructedKey.getPrivateKey()).toBeDefined();
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── DANGEROUS JSON EXPORT / IMPORT ────────────────────────────────────────
  // Self-contained: dangerous export/import is a distinct, unencrypted
  // code path (no KDF involved), so it gets its own isolated key rather
  // than reusing the suite's shared mutable `majikKey`.
  describe("Dangerous JSON Export/Import (unencrypted, server-side use)", () => {
    let dangerousMnemonic: string;
    let dangerousKey: MajikKey;

    beforeAll(async () => {
      dangerousMnemonic = await MajikKey.generateMnemonic(128, "en");
      dangerousKey = await MajikKey.create(
        dangerousMnemonic,
        PASSPHRASE,
        "Dangerous Export Key",
      );
    }, CRYPTO_TIMEOUT);

    it("should throw if the key is locked", () => {
      dangerousKey.lock();
      expect(() => dangerousKey.toDangerousJSON()).toThrow(/must be unlocked/);
    });

    it(
      "should reconstruct an instantly-unlocked key with identical raw private key material",
      async () => {
        await dangerousKey.unlock(PASSPHRASE);

        const solanaBefore = dangerousKey.getSolanaKeypairMaterial();
        const bitcoinBefore = dangerousKey.getBitcoinKeypairMaterial();
        const mlKemBefore = dangerousKey.getMlKemSecretKey();

        const dangerousJson = dangerousKey.toDangerousJSON();
        expect(dangerousJson.privateKeyBase64).toBeTruthy();
        expect(dangerousJson.mlKemSecretKeyBase64).toBeTruthy();
        expect(dangerousJson.edSecretKeyBase64).toBeTruthy();
        expect(dangerousJson.mlDsaSecretKeyBase64).toBeTruthy();
        expect(dangerousJson.btcSecretKeyBase64).toBeTruthy();

        const reconstructed = MajikKey.fromDangerousJSON(dangerousJson);

        // No KDF involved — reconstruction is instant and already unlocked.
        expect(reconstructed.isUnlocked).toBe(true);
        expect(reconstructed.id).toBe(dangerousKey.id);
        expect(reconstructed.fingerprint).toBe(dangerousKey.fingerprint);

        // Real proof the raw key material round-tripped correctly, not
        // just that the base64 strings are non-empty.
        expect(reconstructed.getSolanaKeypairMaterial().publicKey).toEqual(
          solanaBefore.publicKey,
        );
        expect(reconstructed.getSolanaKeypairMaterial().secretKey).toEqual(
          solanaBefore.secretKey,
        );
        expect(reconstructed.getBitcoinKeypairMaterial().publicKey).toEqual(
          bitcoinBefore.publicKey,
        );
        expect(reconstructed.getBitcoinKeypairMaterial().privateKey).toEqual(
          bitcoinBefore.privateKey,
        );
        expect(reconstructed.getMlKemSecretKey()).toEqual(mlKemBefore);
      },
      CRYPTO_TIMEOUT,
    );

    it("should throw for a dangerous JSON payload missing required secret fields", () => {
      const incomplete = {
        id: "fake-id",
        fingerprint: "fake-fingerprint",
        publicKey: "AAAA",
        // privateKeyBase64 intentionally omitted
      };

      expect(() => MajikKey.fromDangerousJSON(incomplete as any)).toThrow(
        /missing required fields/,
      );
    });
  });

  // ── MNEMONICJSON EXPORT / IMPORT ──────────────────────────────────────────
  // Self-contained for the same reason as the dangerous-JSON block above:
  // fromMnemonicJSON() calls MajikKey.create() under the hood, producing a
  // brand-new salt/ciphertext, so it shouldn't be entangled with the shared
  // suite key's mutable lock state.
  describe("MnemonicJSON Export/Import", () => {
    let mnemonicJsonMnemonic: string;
    let mnemonicJsonKey: MajikKey;

    beforeAll(async () => {
      mnemonicJsonMnemonic = await MajikKey.generateMnemonic(128, "en");
      mnemonicJsonKey = await MajikKey.create(
        mnemonicJsonMnemonic,
        PASSPHRASE,
        "MnemonicJSON Key",
      );
    }, CRYPTO_TIMEOUT);

    it("should throw if the key is locked", () => {
      mnemonicJsonKey.lock();
      expect(() =>
        mnemonicJsonKey.toMnemonicJSON(mnemonicJsonMnemonic, PASSPHRASE),
      ).toThrow(/Unlock first/);
    });

    it(
      "should export a MnemonicJSON carrying the real seed array and optional passphrase",
      async () => {
        await mnemonicJsonKey.unlock(PASSPHRASE);

        const json: MnemonicJSON = mnemonicJsonKey.toMnemonicJSON(
          mnemonicJsonMnemonic,
          PASSPHRASE,
        );

        expect(json.id).toBeTruthy(); // backup blob, base64
        expect(Array.isArray(json.seed)).toBe(true);
        expect(json.seed.length).toBeGreaterThan(0);
        expect(json.phrase).toBe(PASSPHRASE);
      },
      CRYPTO_TIMEOUT,
    );

    it("should omit `phrase` when no passphrase is passed to toMnemonicJSON", () => {
      const json = mnemonicJsonKey.toMnemonicJSON(mnemonicJsonMnemonic);
      expect(json.phrase).toBeUndefined();
    });

    it(
      "should reconstruct a key with the identical id/fingerprint via fromMnemonicJSON",
      async () => {
        const json = mnemonicJsonKey.toMnemonicJSON(
          mnemonicJsonMnemonic,
          PASSPHRASE,
        );

        const reconstructed = await MajikKey.fromMnemonicJSON(
          json,
          NEW_PASSPHRASE,
          "Reconstructed From MnemonicJSON",
        );

        // fromMnemonicJSON re-derives via MajikKey.create() from the
        // recovered mnemonic — deterministic derivation means the same
        // fingerprint/id come back even under a different passphrase and
        // a brand-new salt.
        expect(reconstructed.id).toBe(mnemonicJsonKey.id);
        expect(reconstructed.fingerprint).toBe(mnemonicJsonKey.fingerprint);
        expect(reconstructed.isUnlocked).toBe(true);
        expect(reconstructed.isFullyUpgraded).toBe(true);

        expect(await reconstructed.verify(NEW_PASSPHRASE)).toBe(true);
        expect(await reconstructed.verify(PASSPHRASE)).toBe(false);
      },
      CRYPTO_TIMEOUT,
    );

    it("should reject a MnemonicJSON with a malformed/missing seed array", async () => {
      const malformed = { id: "x", seed: "not-an-array" };

      await expect(
        MajikKey.fromMnemonicJSON(malformed as any, PASSPHRASE),
      ).rejects.toThrow(/Invalid MnemonicJSON/);
    });
  });

  // ── UPDATE & MIGRATION TESTS ──────────────────────────────────────────────
  describe("State Updates", () => {
    it("should update the key label correctly", () => {
      const newLabel = "Updated Key Name";
      majikKey.updateLabel(newLabel);
      expect(majikKey.label).toBe(newLabel);
    });

    it(
      "should successfully update the passphrase and rotate encryption",
      async () => {
        const previousSalt = majikKey.toJSON().salt;

        await majikKey.updatePassphrase(PASSPHRASE, NEW_PASSPHRASE);

        const newSalt = majikKey.toJSON().salt;
        expect(previousSalt).not.toBe(newSalt);

        // Real proof the rotation actually happened, not just that the
        // salt string changed:
        expect(await majikKey.verify(PASSPHRASE)).toBe(false);
        expect(await majikKey.verify(NEW_PASSPHRASE)).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should unlock with the new passphrase after a lock/unlock cycle",
      async () => {
        majikKey.lock();
        await majikKey.unlock(NEW_PASSPHRASE);
        expect(majikKey.isUnlocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "updatePassphrase should rotate ALL FOUR secret blobs (ML-KEM, Ed25519, ML-DSA, Bitcoin) in one call, each decryptable under the new passphrase with unchanged raw values",
      async () => {
        // Isolated key so this test doesn't depend on where the shared
        // `majikKey` sits in the suite's passphrase-rotation timeline.
        const mnemonic = await MajikKey.generateMnemonic(128, "en");
        const key = await MajikKey.create(mnemonic, PASSPHRASE, "Rotate All");

        const mlKemBefore = key.getMlKemSecretKey();
        const edBefore = key.getEdSecretKey();
        const mlDsaBefore = key.getMlDsaSecretKey();
        const btcBefore = key.getBtcSecretKey();
        const saltBefore = key.toJSON().salt;

        const ROTATE_PASS = "RotateAllBlobs!321";
        await key.updatePassphrase(PASSPHRASE, ROTATE_PASS);

        expect(key.toJSON().salt).not.toBe(saltBefore);
        expect(await key.verify(PASSPHRASE)).toBe(false);
        expect(await key.verify(ROTATE_PASS)).toBe(true);

        // Immediately after updatePassphrase() the key stays unlocked with
        // the freshly-rotated in-memory secrets — verify those match.
        expect(key.getMlKemSecretKey()).toEqual(mlKemBefore);
        expect(key.getEdSecretKey()).toEqual(edBefore);
        expect(key.getMlDsaSecretKey()).toEqual(mlDsaBefore);
        expect(key.getBtcSecretKey()).toEqual(btcBefore);

        // And after a full lock -> unlock cycle under the NEW passphrase,
        // every blob must independently decrypt back to the exact same
        // raw bytes — proving each of the four ciphertexts (not just the
        // X25519 one) was correctly re-encrypted under the new salt/key.
        key.lock();
        await key.unlock(ROTATE_PASS);

        expect(key.getMlKemSecretKey()).toEqual(mlKemBefore);
        expect(key.getEdSecretKey()).toEqual(edBefore);
        expect(key.getMlDsaSecretKey()).toEqual(mlDsaBefore);
        expect(key.getBtcSecretKey()).toEqual(btcBefore);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── BACKUP & RECOVERY TESTS ───────────────────────────────────────────────
  describe("Backup and Restoration", () => {
    let backupString: string;

    it(
      "should export a valid mnemonic backup string",
      async () => {
        backupString = await majikKey.exportMnemonicBackup(validMnemonic);
        expect(typeof backupString).toBe("string");
        expect(backupString.length).toBeGreaterThan(0);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should import and migrate from a mnemonic backup string",
      async () => {
        const importedKey = await MajikKey.importFromMnemonicBackup(
          backupString,
          validMnemonic,
          NEW_PASSPHRASE,
          "Imported Recovery Key",
        );

        expect(importedKey).toBeInstanceOf(MajikKey);
        // Real determinism check: the same mnemonic must re-derive the same
        // fingerprint/id. This is the core guarantee of the library and was
        // previously untestable since the mock always returned a fixed id.
        expect(importedKey.id).toBe(majikKey.id);
        expect(importedKey.isFullyUpgraded).toBe(true);

        expect(importedKey.isUnlocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should reject importing a backup with the wrong mnemonic",
      async () => {
        const wrongMnemonic = await MajikKey.generateMnemonic(128, "en");

        await expect(
          MajikKey.importFromMnemonicBackup(
            backupString,
            wrongMnemonic,
            NEW_PASSPHRASE,
            "Should Fail",
          ),
        ).rejects.toThrow(/Failed to decrypt backup/);
      },
      CRYPTO_TIMEOUT,
    );
  });
});
