import type { MnemonicLanguage } from "../crypto/wordlist";

import { validateMnemonicJSONShape } from "./validator";
import {
  InvalidBackupPNGError,
  InvalidBackupZipError,
  BackupIntegrityMismatchError,
} from "./error";
import {
  getJSZip,
  getMajikBytes,
  looksLikePNG,
  toSafeFileName,
  buildReadmeText,
} from "./utils";
import { MnemonicJSON } from "../types";
import {
  BACKUP_FORMAT_VERSION,
  CreateBackupParams,
  ToZipOptions,
} from "./types";
import { base64ToUtf8, utf8ToBase64 } from "../utils";

const BACKUP_JSON_FILENAME = "backup.json";
const BACKUP_PNG_FILENAME = "backup.png";
const README_FILENAME = "IMPORTANT README.txt";

/**
 * A validated Majik Key backup payload, and the single place that knows
 * how to read/write it as JSON, a MajikByte PNG, or a .zip archive
 * containing both plus a README.
 *
 * Every construction path (create, fromJSON, fromPNG, fromZIP) funnels
 * through the same shape validator, so there is exactly one definition
 * of "valid backup" anywhere in the app.
 */
export class MajikKeyBackup {
  private constructor(private readonly data: Readonly<MnemonicJSON>) {}

  // ────────────────────────────────────────────────────────────────
  // Static constructors
  // ────────────────────────────────────────────────────────────────

  /** Builds a fresh backup from a newly generated seed. Pure — no I/O. */
  static create(params: CreateBackupParams): MajikKeyBackup {
    const seedArray = Array.isArray(params.seed)
      ? params.seed
      : params.seed.trim().split(/\s+/);

    const json: MnemonicJSON = {
      id: params.id,
      seed: seedArray,
      language: params.language,
      phrase: params.phrase,
      version: BACKUP_FORMAT_VERSION,
    };

    validateMnemonicJSONShape(json);
    return new MajikKeyBackup(json);
  }

  /** Validates and wraps an already-parsed JSON payload (e.g. a bare .json file the user dropped, no zip/PNG involved). */
  static fromJSON(input: unknown): MajikKeyBackup {
    validateMnemonicJSONShape(input);
    return new MajikKeyBackup(input);
  }

  /** Decodes a MajikByte PNG backup and validates the embedded payload. */
  static async fromPNG(file: File | Blob): Promise<MajikKeyBackup> {
    const { MajikBytes } = await getMajikBytes();

    const check = await MajikBytes.isValidPNG(file);
    if (!check?.isValid) {
      throw new InvalidBackupPNGError("not a recognized MajikByte PNG");
    }

    let decoded: unknown;
    try {
      const mbyte = await MajikBytes.fromPNG(file);
      const base64 = mbyte.toStringValue();
      decoded = JSON.parse(base64ToUtf8(base64));
    } catch (err) {
      throw new InvalidBackupPNGError(
        `could not decode embedded payload (${(err as Error)?.message ?? err})`,
      );
    }

    validateMnemonicJSONShape(decoded);
    return new MajikKeyBackup(decoded);
  }

  /**
   * Parses a `.zip` backup archive. Walks every file entry — JSZip
   * already flattens nested folders into full relative paths in
   * `archive.files`, so no manual recursion is needed even for a zip
   * re-created one folder level deeper than expected.
   *
   * Classification is by magic bytes, not filename/extension, so a
   * renamed or oddly-cased file is still found.
   *
   * PNG wins when both a valid PNG and a valid JSON backup are present
   * (harder to tamper with — carries the MajikByte integrity check).
   * Falls back to JSON only if no valid PNG is found anywhere in the
   * archive. If both are present but describe different accounts,
   * that's a real integrity problem and is surfaced as one, not
   * silently resolved by picking a winner.
   */
  static async fromZIP(
    file: File | Blob | Uint8Array,
  ): Promise<MajikKeyBackup> {
    const JSZip = await getJSZip();

    let archive: any;
    try {
      archive = await JSZip.loadAsync(file);
    } catch (err) {
      throw new InvalidBackupZipError(
        `could not open archive (${(err as Error)?.message ?? err})`,
      );
    }

    let pngResult: MajikKeyBackup | null = null;
    let pngError: unknown = null;
    let jsonResult: MajikKeyBackup | null = null;

    for (const relativePath of Object.keys(archive.files)) {
      const entry = archive.files[relativePath];
      if (entry.dir) continue;

      const bytes: Uint8Array = await entry.async("uint8array");

      if (!pngResult && looksLikePNG(bytes)) {
        try {
          const blob = new Blob([bytes as BlobPart], { type: "image/png" });
          pngResult = await MajikKeyBackup.fromPNG(blob);
        } catch (err) {
          // Keep the first PNG-shaped-but-invalid error for the final
          // message, but keep scanning — a later entry might still be
          // a valid JSON backup.
          pngError = pngError ?? err;
        }
        continue;
      }

      if (!jsonResult) {
        try {
          const text = new TextDecoder("utf-8").decode(bytes);
          const parsed = JSON.parse(text);
          jsonResult = MajikKeyBackup.fromJSON(parsed);
        } catch {
          // Not every non-PNG entry is the backup JSON (e.g. the
          // README) — skip silently, we only error if *nothing* valid
          // turns up anywhere in the archive.
        }
      }
    }

    if (pngResult && jsonResult) {
      const idsMatch = pngResult.data.id === jsonResult.data.id;
      const seedsMatch =
        pngResult.data.seed.join(" ") === jsonResult.data.seed.join(" ");

      if (!idsMatch || !seedsMatch) {
        throw new BackupIntegrityMismatchError(
          "the PNG and JSON backups inside this archive do not describe the same account",
        );
      }
    }

    if (pngResult) return pngResult;
    if (jsonResult) return jsonResult;

    const reason = pngError
      ? `a PNG-shaped file was found but is invalid (${(pngError as Error)?.message ?? pngError})`
      : "no valid backup.png or backup.json found inside the archive";
    throw new InvalidBackupZipError(reason);
  }

  // ────────────────────────────────────────────────────────────────
  // Instance accessors
  // ────────────────────────────────────────────────────────────────

  toJSON(): MnemonicJSON {
    return { ...this.data };
  }

  get id(): string {
    return this.data.id;
  }

  get seed(): string[] {
    return [...this.data.seed];
  }

  get seedPhrase(): string {
    return this.data.seed.join(" ");
  }

  get language(): MnemonicLanguage | undefined {
    return this.data.language;
  }

  get formatVersion(): number | undefined {
    return this.data.version;
  }

  // ────────────────────────────────────────────────────────────────
  // Instance serializers
  // ────────────────────────────────────────────────────────────────

  async toPNG(): Promise<Blob> {
    const { MajikBytes } = await getMajikBytes();
    const base64 = utf8ToBase64(JSON.stringify(this.toJSON()));
    const mbyte = await MajikBytes.create(base64);
    return mbyte.toPNG();
  }

  async toZIP(_opts: ToZipOptions = {}): Promise<Blob> {
    const JSZip = await getJSZip();

    const json = this.toJSON();
    const pngBlob = await this.toPNG();
    const pngBuffer = await pngBlob.arrayBuffer();

    const zip = new JSZip();
    zip.file(BACKUP_JSON_FILENAME, JSON.stringify(json));
    zip.file(BACKUP_PNG_FILENAME, pngBuffer, { binary: true });
    zip.file(README_FILENAME, buildReadmeText(new Date()));

    return zip.generateAsync({
      type: "blob",
      compression: "DEFLATE",
      compressionOptions: { level: 9 },
    });
  }

  /** Convenience for callers building a native `save()` dialog default path. */
  suggestedFileName(label?: string): string {
    return toSafeFileName(
      `${label ?? "Majik Key"} - ${this.data.id} - SEED KEY - ${new Date().toISOString()}`,
    );
  }
}


// Freeze static methods (e.g., MajikKey.create, MajikKey.fromJSON)
Object.freeze(MajikKeyBackup);

// Freeze instance methods (e.g., this.lock, this.unlock)
Object.freeze(MajikKeyBackup.prototype);
