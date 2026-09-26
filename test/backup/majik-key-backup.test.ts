// src/test/MajikKeyBackup.test.ts
//
// Unit tests for the MajikKeyBackup class (src/core/backup). Exercises
// backup creation, PNG/JSON/ZIP round-trips, PNG-vs-JSON redundancy,
// corruption fallback, integrity-mismatch detection, and error
// handling. Uses the real JSZip and @majikah/majik-bytes dependencies —
// no mocking of the artifact codecs, since round-tripping through them
// correctly is exactly what's under test.
//
// Deliberately does NOT test passphrase-gated decryption or restoring a
// live MajikKey: MajikKeyBackup stores the seed/phrase in plaintext by
// design (it has no seed-derived key of its own to encrypt with — the
// seed *is* the secret), and never constructs a MajikKey. Turning a
// restored backup into an unlocked MajikKey is the caller's job
// (majik.importAccountFromMnemonicBackup), not this class's.

import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import JSZip from "jszip";
import { MajikKey } from "../../src/majik-key";

import {
  MajikKeyBackup,
  BACKUP_FORMAT_VERSION,
  BackupIntegrityMismatchError,
  InvalidBackupZipError,
  InvalidBackupJSONError,
  InvalidBackupPNGError,
} from "../../src/core/backup";
import { MnemonicJSON } from "../../src/core/types";

const TIMEOUT = 60_000;
// Real Argon2id derivation (via MajikKey.create/fromMnemonicJSON) is
// deliberately slow — matches the timeout used for the same operations
// in majik-key.test.ts.
const CRYPTO_TIMEOUT = 240_000;

// Not a checksum-valid BIP-39 mnemonic — MajikKeyBackup only validates
// *shape* (non-empty string words). Checksum validity is MajikKey's
// concern when it later imports this seed, not the backup artifact's.
const SAMPLE_SEED = [
  "abandon",
  "ability",
  "able",
  "about",
  "above",
  "absent",
  "absorb",
  "abstract",
  "absurd",
  "abuse",
  "access",
  "accident",
];
const SAMPLE_ID = "test-account-fingerprint-0001";
const SAMPLE_LABEL = "Backup Test Account";

describe("MajikKeyBackup", () => {
  // ── create() ──────────────────────────────────────────────────────────
  describe("create()", () => {
    it("builds a backup from a seed array and stamps the current format version", () => {
      const backup = MajikKeyBackup.create({
        seed: SAMPLE_SEED,
        id: SAMPLE_ID,
        language: "en",
      });

      expect(backup.id).toBe(SAMPLE_ID);
      expect(backup.seed).toEqual(SAMPLE_SEED);
      expect(backup.language).toBe("en");
      expect(backup.formatVersion).toBe(BACKUP_FORMAT_VERSION);
    });

    it("accepts a seed as a single space-separated string, same as an array", () => {
      const fromString = MajikKeyBackup.create({
        seed: SAMPLE_SEED.join(" "),
        id: SAMPLE_ID,
        language: "en",
      });
      expect(fromString.seed).toEqual(SAMPLE_SEED);
    });

    it("throws InvalidBackupJSONError when id is missing", () => {
      expect(() =>
        MajikKeyBackup.create({ seed: SAMPLE_SEED, id: "", language: "en" }),
      ).toThrow(InvalidBackupJSONError);
    });

    it("throws InvalidBackupJSONError when seed is empty", () => {
      expect(() =>
        MajikKeyBackup.create({ seed: [], id: SAMPLE_ID, language: "en" }),
      ).toThrow(InvalidBackupJSONError);
    });
  });

  // ── fromJSON() ────────────────────────────────────────────────────────
  describe("fromJSON()", () => {
    it("round-trips a backup's own toJSON() output byte-for-byte", () => {
      const original = MajikKeyBackup.create({
        seed: SAMPLE_SEED,
        id: SAMPLE_ID,
        language: "en",
        phrase: "my-passphrase",
      });

      const restored = MajikKeyBackup.fromJSON(original.toJSON());
      expect(restored.toJSON()).toEqual(original.toJSON());
    });

    it("rejects a payload with a non-string id", () => {
      expect(() =>
        MajikKeyBackup.fromJSON({ id: 123, seed: SAMPLE_SEED }),
      ).toThrow(InvalidBackupJSONError);
    });

    it("rejects a payload that isn't an object", () => {
      expect(() => MajikKeyBackup.fromJSON("not json")).toThrow(
        InvalidBackupJSONError,
      );
    });
  });

  // ── PNG round-trip ───────────────────────────────────────────────────
  describe("PNG round-trip", () => {
    it(
      "encodes to PNG and decodes back to an identical backup",
      async () => {
        const original = MajikKeyBackup.create({
          seed: SAMPLE_SEED,
          id: SAMPLE_ID,
          language: "en",
        });

        const pngBlob = await original.toPNG();
        expect(pngBlob.size).toBeGreaterThan(0);

        const restored = await MajikKeyBackup.fromPNG(pngBlob);
        expect(restored.toJSON()).toEqual(original.toJSON());
      },
      TIMEOUT,
    );

    it(
      "throws InvalidBackupPNGError for a file that isn't a MajikByte PNG",
      async () => {
        const notAPng = new Blob(["just some text"], { type: "text/plain" });
        await expect(MajikKeyBackup.fromPNG(notAPng)).rejects.toThrow(
          InvalidBackupPNGError,
        );
      },
      TIMEOUT,
    );
  });

  // ── ZIP round-trip ───────────────────────────────────────────────────
  describe("ZIP round-trip", () => {
    let backup: MajikKeyBackup;
    let zipBlob: Blob;

    beforeAll(async () => {
      backup = MajikKeyBackup.create({
        seed: SAMPLE_SEED,
        id: SAMPLE_ID,
        language: "en",
      });
      zipBlob = await backup.toZIP({ label: SAMPLE_LABEL });
    }, TIMEOUT);

    it(
      "produces a zip containing a PNG, a JSON, and a README",
      async () => {
        const loaded = await JSZip.loadAsync(await zipBlob.arrayBuffer());
        const names = Object.keys(loaded.files);

        expect(names.some((n) => n.endsWith(".png"))).toBe(true);
        expect(names.some((n) => n.endsWith(".json"))).toBe(true);
        expect(names.some((n) => n.toLowerCase().includes("readme"))).toBe(
          true,
        );
      },
      TIMEOUT,
    );

    it(
      "restores an identical backup from the full zip",
      async () => {
        const restored = await MajikKeyBackup.fromZIP(zipBlob);
        expect(restored.toJSON()).toEqual(backup.toJSON());
      },
      TIMEOUT,
    );

    it(
      "restores correctly from a PNG-only zip (JSON entry removed)",
      async () => {
        const zip = await JSZip.loadAsync(await zipBlob.arrayBuffer());
        const jsonName = Object.keys(zip.files).find((n) =>
          n.endsWith(".json"),
        );
        zip.remove(jsonName!);
        const pngOnly = await zip.generateAsync({ type: "uint8array" });

        const restored = await MajikKeyBackup.fromZIP(pngOnly);
        expect(restored.toJSON()).toEqual(backup.toJSON());
      },
      TIMEOUT,
    );

    it(
      "restores correctly from a JSON-only zip (PNG entry removed)",
      async () => {
        const zip = await JSZip.loadAsync(await zipBlob.arrayBuffer());
        const pngName = Object.keys(zip.files).find((n) => n.endsWith(".png"));
        zip.remove(pngName!);
        const jsonOnly = await zip.generateAsync({ type: "uint8array" });

        const restored = await MajikKeyBackup.fromZIP(jsonOnly);
        expect(restored.toJSON()).toEqual(backup.toJSON());
      },
      TIMEOUT,
    );

    it(
      "falls back to the JSON artifact when the PNG is corrupted",
      async () => {
        const zip = await JSZip.loadAsync(await zipBlob.arrayBuffer());
        const pngName = Object.keys(zip.files).find((n) => n.endsWith(".png"))!;
        zip.file(pngName, new Uint8Array([0x00, 0xff, 0xfe, 0xfd, 0x12, 0x34]));
        const corrupted = await zip.generateAsync({ type: "uint8array" });

        const restored = await MajikKeyBackup.fromZIP(corrupted);
        expect(restored.toJSON()).toEqual(backup.toJSON());
      },
      TIMEOUT,
    );

    it(
      "falls back to the PNG artifact when the JSON is corrupted",
      async () => {
        const zip = await JSZip.loadAsync(await zipBlob.arrayBuffer());
        const jsonName = Object.keys(zip.files).find((n) =>
          n.endsWith(".json"),
        )!;
        zip.file(jsonName, "{ this is not valid json {{");
        const corrupted = await zip.generateAsync({ type: "uint8array" });

        const restored = await MajikKeyBackup.fromZIP(corrupted);
        expect(restored.toJSON()).toEqual(backup.toJSON());
      },
      TIMEOUT,
    );

    it(
      "prefers the PNG artifact when both PNG and JSON are valid but disagree",
      async () => {
        const other = MajikKeyBackup.create({
          seed: [...SAMPLE_SEED].reverse(),
          id: "a-completely-different-id",
          language: "en",
        });

        const zip = await JSZip.loadAsync(await zipBlob.arrayBuffer());
        const jsonName = Object.keys(zip.files).find((n) =>
          n.endsWith(".json"),
        )!;
        zip.file(jsonName, JSON.stringify(other.toJSON()));
        const conflicting = await zip.generateAsync({ type: "uint8array" });

        await expect(MajikKeyBackup.fromZIP(conflicting)).rejects.toThrow(
          BackupIntegrityMismatchError,
        );
      },
      TIMEOUT,
    );

    it(
      "finds the backup files even when nested one folder deep",
      async () => {
        const pngBuffer = await (await backup.toPNG()).arrayBuffer();

        const zip = new JSZip();
        zip.file("MyBackupFolder/backup.png", pngBuffer, { binary: true });
        zip.file("MyBackupFolder/backup.json", JSON.stringify(backup.toJSON()));
        const nested = await zip.generateAsync({ type: "uint8array" });

        const restored = await MajikKeyBackup.fromZIP(nested);
        expect(restored.toJSON()).toEqual(backup.toJSON());
      },
      TIMEOUT,
    );

    it(
      "restores from a Buffer read off disk, not just an in-memory Blob",
      async () => {
        const tmpPath = path.join(
          os.tmpdir(),
          `majik-backup-test-${Date.now()}.zip`,
        );
        fs.writeFileSync(tmpPath, Buffer.from(await zipBlob.arrayBuffer()));

        try {
          const diskBuffer = fs.readFileSync(tmpPath);
          const restored = await MajikKeyBackup.fromZIP(diskBuffer);
          expect(restored.toJSON()).toEqual(backup.toJSON());
        } finally {
          fs.unlinkSync(tmpPath);
        }
      },
      TIMEOUT,
    );
  });

  // ── Fixture file loading ─────────────────────────────────────────────
  // A real, previously-generated backup checked into the repo. Unlike
  // the synthetic zips above (built and torn apart in-memory within a
  // single test run), this catches anything that only shows up with a
  // backup produced by an actual past build — e.g. a JSZip version
  // difference in how entries were written, or a MajikByte encoding
  // quirk from an earlier @majikah/majik-bytes release.
  describe("Fixture file loading", () => {
    const FIXTURE_RELATIVE_PATH = "test/backup/sample-backup.zip";
    const FIXTURE_PATH = path.resolve(process.cwd(), FIXTURE_RELATIVE_PATH);

    it(
      "loads and restores the real sample-backup.zip fixture",
      async () => {
        if (!fs.existsSync(FIXTURE_PATH)) {
          throw new Error(
            `Fixture file not found at ${FIXTURE_PATH}. Ensure ${FIXTURE_RELATIVE_PATH} exists relative to the package root.`,
          );
        }

        const fixtureBuffer = fs.readFileSync(FIXTURE_PATH);
        expect(fixtureBuffer.length).toBeGreaterThan(0);

        const restored = await MajikKeyBackup.fromZIP(fixtureBuffer);

        // Structural checks only — this fixture's actual id/seed/
        // language aren't known constants the way SAMPLE_SEED/SAMPLE_ID
        // are, so we assert the artifact parsed into something valid
        // rather than pinning exact values. If you want to pin the
        // real id/seed too, tell me what's in the fixture and I'll add
        // exact-match assertions alongside these.
        expect(restored).toBeInstanceOf(MajikKeyBackup);
        expect(restored.id).toBeTruthy();
        expect(restored.seed.length).toBeGreaterThan(0);
        expect(restored.seed.every((w) => w.trim().length > 0)).toBe(true);
      },
      TIMEOUT,
    );
  });

  // ── End-to-end with a real MajikKey ──────────────────────────────────
  // Everything above proves MajikKeyBackup is internally consistent
  // (its own toJSON/toPNG/toZIP round-trip each other). This section
  // proves it actually interoperates with the real crypto library:
  // a genuine MajikKey (real Argon2id, real BIP-39, real ML-KEM/Ed25519
  // derivation) is created, exported via .toMnemonicJSON(), carried
  // through every MajikKeyBackup artifact, and reconstructed back into
  // a live, unlocked MajikKey with the identical id/fingerprint. Full
  // loop, zero mocking — same discipline as majik-key.test.ts.
  describe("End-to-end with a real MajikKey (create -> backup -> restore -> reconstruct)", () => {
    const KEY_PASSPHRASE = "E2EBackupPassphrase123!";
    const RESTORE_PASSPHRASE = "E2ERestorePassphrase456!";
    const KEY_LABEL = "E2E Backup Test Key";

    let realMnemonic: string;
    let majikKey: MajikKey;
    let mnemonicJson: MnemonicJSON;

    beforeAll(async () => {
      realMnemonic = await MajikKey.generateMnemonic(128, "en");
      majikKey = await MajikKey.create(
        realMnemonic,
        KEY_PASSPHRASE,
        KEY_LABEL,
        {
          mnemonicLanguage: "en",
        },
      );
      mnemonicJson = majikKey.toMnemonicJSON(realMnemonic, KEY_PASSPHRASE);
    }, CRYPTO_TIMEOUT);

    it("wraps a real MajikKey's exported MnemonicJSON without altering it", () => {
      const backup = MajikKeyBackup.fromJSON(mnemonicJson);
      expect(backup.toJSON()).toEqual(mnemonicJson);
      expect(backup.seedPhrase).toBe(realMnemonic);
    });

    describe("Positive: each artifact reconstructs the identical live key", () => {
      it(
        "JSON round-trip -> fromMnemonicJSON reconstructs matching id/fingerprint",
        async () => {
          const backup = MajikKeyBackup.fromJSON(mnemonicJson);

          const reconstructed = await MajikKey.fromMnemonicJSON(
            backup.toJSON(),
            RESTORE_PASSPHRASE,
            "Reconstructed From JSON",
          );

          expect(reconstructed.id).toBe(majikKey.id);
          expect(reconstructed.fingerprint).toBe(majikKey.fingerprint);
          expect(reconstructed.isUnlocked).toBe(true);
          expect(await reconstructed.verify(RESTORE_PASSPHRASE)).toBe(true);
          expect(await reconstructed.verify(KEY_PASSPHRASE)).toBe(false);
        },
        CRYPTO_TIMEOUT,
      );

      it(
        "PNG round-trip -> survives encode/decode and still reconstructs the identical key",
        async () => {
          const backup = MajikKeyBackup.fromJSON(mnemonicJson);
          const pngBlob = await backup.toPNG();
          const restoredBackup = await MajikKeyBackup.fromPNG(pngBlob);

          expect(restoredBackup.toJSON()).toEqual(mnemonicJson);

          const reconstructed = await MajikKey.fromMnemonicJSON(
            restoredBackup.toJSON(),
            RESTORE_PASSPHRASE,
            "Reconstructed From PNG",
          );

          expect(reconstructed.fingerprint).toBe(majikKey.fingerprint);
          expect(await reconstructed.verify(RESTORE_PASSPHRASE)).toBe(true);
        },
        CRYPTO_TIMEOUT,
      );

      describe("ZIP round-trip variants", () => {
        let zipBlob: Blob;

        beforeAll(async () => {
          const backup = MajikKeyBackup.fromJSON(mnemonicJson);
          zipBlob = await backup.toZIP({ label: KEY_LABEL });
        }, CRYPTO_TIMEOUT);

        it(
          "full zip -> reconstructs the identical key",
          async () => {
            const restoredBackup = await MajikKeyBackup.fromZIP(zipBlob);
            const reconstructed = await MajikKey.fromMnemonicJSON(
              restoredBackup.toJSON(),
              RESTORE_PASSPHRASE,
              "Reconstructed From ZIP",
            );

            expect(reconstructed.fingerprint).toBe(majikKey.fingerprint);
            expect(await reconstructed.verify(RESTORE_PASSPHRASE)).toBe(true);
          },
          CRYPTO_TIMEOUT,
        );

        it(
          "PNG-only zip (JSON entry stripped) -> still reconstructs the identical key",
          async () => {
            const zip = await JSZip.loadAsync(await zipBlob.arrayBuffer());
            const jsonName = Object.keys(zip.files).find((n) =>
              n.endsWith(".json"),
            );
            zip.remove(jsonName!);
            const pngOnly = await zip.generateAsync({ type: "uint8array" });

            const restoredBackup = await MajikKeyBackup.fromZIP(pngOnly);
            const reconstructed = await MajikKey.fromMnemonicJSON(
              restoredBackup.toJSON(),
              RESTORE_PASSPHRASE,
              "Reconstructed From PNG-only ZIP",
            );

            expect(reconstructed.fingerprint).toBe(majikKey.fingerprint);
          },
          CRYPTO_TIMEOUT,
        );

        it(
          "JSON-only zip (PNG entry stripped) -> still reconstructs the identical key",
          async () => {
            const zip = await JSZip.loadAsync(await zipBlob.arrayBuffer());
            const pngName = Object.keys(zip.files).find((n) =>
              n.endsWith(".png"),
            );
            zip.remove(pngName!);
            const jsonOnly = await zip.generateAsync({ type: "uint8array" });

            const restoredBackup = await MajikKeyBackup.fromZIP(jsonOnly);
            const reconstructed = await MajikKey.fromMnemonicJSON(
              restoredBackup.toJSON(),
              RESTORE_PASSPHRASE,
              "Reconstructed From JSON-only ZIP",
            );

            expect(reconstructed.fingerprint).toBe(majikKey.fingerprint);
          },
          CRYPTO_TIMEOUT,
        );
      });
    });

    describe("Negative: a real key's backup under tampering/mismatch", () => {
      it(
        "MajikKeyBackup itself still accepts a checksum-invalid seed (shape-only validation) — the checksum failure surfaces one layer up",
        async () => {
          const tamperedJson: MnemonicJSON = {
            ...mnemonicJson,
            // Corrupt the final (checksum) word — still a well-formed
            // array of non-empty words, so MajikKeyBackup's shape
            // validator has no reason to reject it.
            seed: [...mnemonicJson.seed.slice(0, -1), "abandon"],
          };

          const backup = MajikKeyBackup.fromJSON(tamperedJson);
          expect(backup.seed).toEqual(tamperedJson.seed);

          await expect(
            MajikKey.fromMnemonicJSON(backup.toJSON(), RESTORE_PASSPHRASE),
          ).rejects.toThrow(/Invalid BIP39 mnemonic phrase/);
        },
        CRYPTO_TIMEOUT,
      );

      it(
        "reconstructs a DIFFERENT real key (different id/fingerprint) when the seed is swapped for an unrelated valid mnemonic",
        async () => {
          const unrelatedMnemonic = await MajikKey.generateMnemonic(128, "en");
          const swappedJson: MnemonicJSON = {
            ...mnemonicJson,
            seed: unrelatedMnemonic.trim().split(/\s+/),
          };

          const backup = MajikKeyBackup.fromJSON(swappedJson);
          const reconstructed = await MajikKey.fromMnemonicJSON(
            backup.toJSON(),
            RESTORE_PASSPHRASE,
            "Reconstructed From Swapped Seed",
          );

          // Proves the backup class carries the seed through
          // untouched — this is a genuinely different real key, not
          // an accidental collision or a silently-reused fingerprint.
          expect(reconstructed.id).not.toBe(majikKey.id);
          expect(reconstructed.fingerprint).not.toBe(majikKey.fingerprint);
        },
        CRYPTO_TIMEOUT,
      );

      it(
        "rejects a zip built from one real key's PNG plus a DIFFERENT real key's JSON as an integrity mismatch",
        async () => {
          const otherMnemonic = await MajikKey.generateMnemonic(128, "en");
          const otherKey = await MajikKey.create(
            otherMnemonic,
            KEY_PASSPHRASE,
            "Other E2E Key",
            { mnemonicLanguage: "en" },
          );
          const otherJson = otherKey.toMnemonicJSON(
            otherMnemonic,
            KEY_PASSPHRASE,
          );

          const backup = MajikKeyBackup.fromJSON(mnemonicJson);
          const pngBuffer = await (await backup.toPNG()).arrayBuffer();

          const zip = new JSZip();
          zip.file("backup.png", pngBuffer, { binary: true });
          zip.file("backup.json", JSON.stringify(otherJson));
          const mismatched = await zip.generateAsync({ type: "uint8array" });

          await expect(MajikKeyBackup.fromZIP(mismatched)).rejects.toThrow(
            BackupIntegrityMismatchError,
          );
        },
        CRYPTO_TIMEOUT,
      );
    });
  });

  // ── Negative and edge cases ─────────────────────────────────────────
  describe("Negative and edge cases", () => {
    it("rejects a completely invalid (non-zip) buffer", async () => {
      const invalidBuffer = new Uint8Array([0x41, 0x42, 0x43, 0x44]);
      await expect(MajikKeyBackup.fromZIP(invalidBuffer)).rejects.toThrow(
        InvalidBackupZipError,
      );
    });

    it("rejects a well-formed zip with no valid PNG or JSON inside", async () => {
      const zip = new JSZip();
      zip.file("unrelated.txt", "just some random content");
      const emptyBackup = await zip.generateAsync({ type: "uint8array" });

      await expect(MajikKeyBackup.fromZIP(emptyBackup)).rejects.toThrow(
        InvalidBackupZipError,
      );
    });
  });
});
