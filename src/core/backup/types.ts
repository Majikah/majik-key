import type { MnemonicLanguage } from "../crypto/wordlist";

/**
 * Bump this whenever the *shape* of MnemonicJSON or the zip layout
 * changes in a way that could break parsing of older backups. Written
 * into every backup created by `MajikKeyBackup.create()`; read back
 * (but not currently enforced) by `fromJSON`/`fromPNG`/`fromZIP`, so
 * future versions can branch on it if the shape ever diverges.
 */
export const BACKUP_FORMAT_VERSION = 1;

/** Which artifact inside a parsed backup archive supplied the winning payload. */
export type BackupSource = "png" | "json";

export interface CreateBackupParams {
  /** Either the full mnemonic string ("word1 word2 ...") or a pre-split word array. */
  seed: string | string[];
  id: string;
  language: MnemonicLanguage;
  phrase?: string;
}

export interface ToZipOptions {
  /** Used only to build the human-facing filename hint (suggestedFileName); purely cosmetic. */
  label?: string;
}
