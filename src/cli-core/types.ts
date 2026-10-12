/**
 * src/cli-core/types.ts
 *
 * CLI intent types. src/cli.ts parses argv into these shapes and the
 * operation layer translates them into MajikKey calls.
 */

export interface CliResult {
  ok: boolean;
  command: string;
  message: string;

  [key: string]: unknown;
}

/** Where a secret (passphrase) may come from besides the interactive prompt. */
export interface PassphraseSourceOptions {
  /** Read the passphrase from the first line of stdin. */
  passphraseStdin: boolean;
}

/** Shared by every command that writes a file. */
export interface WriteOptions {
  /** Output file, or output directory. Defaults to the current directory. */
  output?: string;
  /** Allow replacing an existing file. */
  overwrite: boolean;
}

/** Shared by commands that can emit a Majik Key JSON file. */
export interface SaveFormatOptions {
  /** Save raw, UNENCRYPTED private keys instead of the passphrase-encrypted JSON. */
  dangerous: boolean;
  iUnderstandTheRisk: boolean;
  /** Skip the typed confirmation for --dangerous (required when non-interactive). */
  yes: boolean;
  /** Omit the pre-registry flat fields from normal JSON. */
  registryOnly: boolean;
}

export interface JsonOption {
  json: boolean;
}

export interface NewKeyOptions
  extends WriteOptions,
    SaveFormatOptions,
    PassphraseSourceOptions,
    JsonOption {
  label?: string;
  language?: string;
  /** Extra keypairs on top of the core four. Raw CSV items, e.g. ["btc", "web3:eth"]. */
  keys: string[];
  /**
   * Also write the mnemonic as plaintext MnemonicJSON.
   * `true` = default file name in the output directory, string = explicit path.
   */
  mnemonicOut?: boolean | string;
}

export interface GenerateCliOptions extends NewKeyOptions {
  /** Mnemonic length in words: 12 or 24. */
  size: number;
  /** Skip the "type back 3 words" write-it-down check. */
  skipConfirm: boolean;
}

export interface CreateCliOptions extends NewKeyOptions {
  /** Plain-text mnemonic file or MnemonicJSON file. Otherwise: env var, then hidden prompt. */
  mnemonicFile?: string;
}

export interface ImportCliOptions extends NewKeyOptions {
  /** Mnemonic backup: .json, .png or .zip. */
  backup: string;
}

export interface InfoCliOptions extends JsonOption {
  input: string;
}

export interface KeysCliOptions extends JsonOption {
  input?: string;
  supported: boolean;
  full: boolean;
}

export interface VerifyCliOptions extends PassphraseSourceOptions, JsonOption {
  input: string;
}

export interface LabelCliOptions extends WriteOptions, JsonOption {
  input: string;
  /** When omitted, the current label is reported and nothing is written. */
  label?: string;
}

export interface PassphraseCliOptions extends WriteOptions, JsonOption {
  input: string;
}

export interface MigrateCliOptions
  extends WriteOptions,
    PassphraseSourceOptions,
    JsonOption {
  input: string;
}

export interface AddKeysCliOptions extends WriteOptions, JsonOption {
  input: string;
  keys: string[];
  mnemonicFile?: string;
}

export type BackupFormat = "json" | "png" | "zip";

export interface BackupCliOptions extends WriteOptions, JsonOption {
  input: string;
  format: BackupFormat;
  mnemonicFile?: string;
}

export interface ExportCliOptions
  extends WriteOptions,
    SaveFormatOptions,
    PassphraseSourceOptions,
    JsonOption {
  input: string;
  /** Export the PUBLIC contact JSON instead of the key file. */
  contact: boolean;
  /** Print to stdout instead of writing a file. */
  stdout: boolean;
}
