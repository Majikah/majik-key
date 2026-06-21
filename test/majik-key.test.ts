// majik-key.test.ts
//
// These tests exercise MajikKey against REAL implementations wherever
// possible: real @scure/bip39 mnemonic generation/validation (with the
// actual wordlists for each supported language), real Argon2id key
// derivation, real AES-256-GCM encryption (via @stablelib), real
// ML-KEM-768 keygen, and Node's built-in WebCrypto. Nothing about the
// cryptographic round-trip is faked, so these tests catch real bugs a
// mocked suite would miss entirely — e.g. a wrong passphrase failing to
// decrypt, backup-import failing for the wrong mnemonic, or a non-English
// wordlist producing a mnemonic that silently fails downstream derivation.
//
// Trade-off: real Argon2id is deliberately slow (that's the point of a
// password KDF), and in Node, hash-wasm is gated off by the library's own
// `typeof window === "undefined"` check in crypto-provider.ts — so this
// suite always exercises the pure-JS @noble/hashes Argon2id fallback, never
// the WASM-accelerated path. Each derivation may take anywhere from a few
// hundred ms to a couple seconds depending on ARGON2_PARAMS, so tests that
// touch unlock/create/updatePassphrase/import are given generous timeouts.
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

const CRYPTO_TIMEOUT = 30_000;

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
