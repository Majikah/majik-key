/**
 * src/cli-core/operations.ts
 *
 * One function per CLI command. Each takes parsed options, performs the work
 * against MajikKey, and returns a CliResult (or throws a CliError).
 */

import { randomInt } from "node:crypto";
import { basename, dirname, sep } from "node:path";

import { mnemonicToSeed } from "@scure/bip39";

import { MajikKey } from "../majik-key.js";
import type { MnemonicLanguage } from "../core/crypto/wordlist.js";
import { KeyId } from "../core/keys/key-id.js";
import { deriveKeys } from "../core/keys/key-impls.js";
import { KEY_ALGORITHMS } from "../core/keys/registry.js";
import { fingerprintFromPublicRaw } from "../core/crypto/crypto-provider.js";
import { MajikKeyBackup } from "../core/backup/majik-key-backup.js";
import { looksLikePNG, looksLikeZip } from "../core/backup/utils.js";

import { CliError, UsageError, errorMessage } from "./errors.js";
import {
  readBytes,
  readText,
  resolveCliPath,
  resolveOutputPath,
  shortFingerprint,
  writeJsonSecure,
  writeSecureFile,
} from "./io.js";
import {
  assertLanguage,
  describeKey,
  loadKeyFile,
  lockKey,
  parseKeyIds,
  saveKey,
  serializeKey,
  unlockKey,
  defaultKeyFileName,
  type LoadedKey,
} from "./key.js";
import {
  ENV_NEW_PASSPHRASE,
  ENV_PASSPHRASE,
  assertMnemonicShape,
  confirmYes,
  getNewPassphrase,
  getPassphrase,
  isInteractive,
  normalizeMnemonic,
  promptMnemonic,
  readHidden,
  type PassphraseSource,
} from "./prompt.js";
import { printMnemonic } from "./output.js";
import type {
  AddKeysCliOptions,
  BackupCliOptions,
  CliResult,
  CreateCliOptions,
  ExportCliOptions,
  GenerateCliOptions,
  ImportCliOptions,
  InfoCliOptions,
  KeysCliOptions,
  LabelCliOptions,
  MigrateCliOptions,
  NewKeyOptions,
  PassphraseCliOptions,
  PassphraseSourceOptions,
  SaveFormatOptions,
  VerifyCliOptions,
  WriteOptions,
} from "./types.js";

// ─── Shared helpers ──────────────────────────────────────────────────────────

function sourceOf(options: PassphraseSourceOptions): PassphraseSource {
  return { stdin: options.passphraseStdin, envVar: ENV_PASSPHRASE };
}

function assertDangerousFlag(options: SaveFormatOptions): void {
  if (options.dangerous && !options.iUnderstandTheRisk) {
    throw new UsageError(
      "--dangerous writes your PRIVATE KEYS UNENCRYPTED. " +
        "Add --i-understand-the-risk to confirm you want that.",
    );
  }
}

/**
 * Typed confirmation before raw private keys are written anywhere.
 * Non-interactive callers must say --yes explicitly.
 */
async function confirmDangerous(
  fingerprint: string,
  yes: boolean,
): Promise<void> {
  if (yes) return;

  if (!isInteractive()) {
    throw new UsageError(
      "Dangerous export needs confirmation. Run it in an interactive terminal, " +
        "or add --yes for non-interactive use.",
    );
  }

  const tail = fingerprint.slice(-8);

  process.stderr.write(
    "\nThis will output PRIVATE KEY material in PLAINTEXT. Anyone with it controls this key.\n" +
      `Key fingerprint: ${fingerprint}\n`,
  );

  const typed = await readHidden(
    `Type the last 8 characters of the fingerprint (${tail}) to confirm: `,
  );

  if (typed.trim() !== tail) {
    throw new CliError("Confirmation did not match — nothing was written.");
  }
}

/** Mnemonic from a file (plain text or MnemonicJSON), env var, or hidden prompt. */
async function readMnemonicInput(
  mnemonicFile: string | undefined,
): Promise<{ mnemonic: string; language?: string }> {
  if (!mnemonicFile) {
    return { mnemonic: await promptMnemonic() };
  }

  const text = await readText(resolveCliPath(mnemonicFile));
  const trimmed = text.trim();

  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed) as {
        seed?: unknown;
        language?: string;
      };

      if (Array.isArray(parsed.seed)) {
        const mnemonic = normalizeMnemonic(parsed.seed.join(" "));
        assertMnemonicShape(mnemonic);
        return { mnemonic, language: parsed.language };
      }
    } catch {
      // Fall through and treat it as plain text.
    }
  }

  const mnemonic = normalizeMnemonic(trimmed);
  assertMnemonicShape(mnemonic);
  return { mnemonic };
}

/** Pick `count` distinct random indices out of `length`. */
function pickPositions(length: number, count: number): number[] {
  const indices = Array.from({ length }, (_, i) => i);

  for (let i = indices.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [indices[i], indices[j]] = [indices[j]!, indices[i]!];
  }

  return indices.slice(0, Math.min(count, length)).sort((a, b) => a - b);
}

async function confirmWrittenDown(words: string[]): Promise<void> {
  process.stderr.write(
    "Confirm you wrote it down — type the requested words.\n",
  );

  for (const position of pickPositions(words.length, 3)) {
    const typed = await readHidden(`Word #${position + 1}: `);

    if (
      typed.trim().toLowerCase().normalize("NFKD") !==
      words[position]!.normalize("NFKD")
    ) {
      throw new CliError(
        `That doesn't match word #${position + 1}. Nothing was saved — ` +
          "run the command again once you've written the phrase down.",
      );
    }
  }
}

/** Does `mnemonic` derive the account `key`? Cheap: no KDF, no passphrase. */
async function mnemonicBelongsTo(
  key: MajikKey,
  mnemonic: string,
): Promise<boolean> {
  const seed = await mnemonicToSeed(mnemonic);

  try {
    const probe = deriveKeys(seed, [KeyId.X25519]).get(KeyId.X25519)!;
    return fingerprintFromPublicRaw(probe.publicKey) === key.fingerprint;
  } finally {
    seed.fill(0);
  }
}

async function saveBack(
  loaded: LoadedKey,
  key: MajikKey,
  options: WriteOptions,
): Promise<string> {
  const target = options.output
    ? await resolveOutputPath(options.output, basename(loaded.path))
    : loaded.path;

  /** Editing a file in place is the whole point of the command — no --overwrite needed. */
  const overwrite = options.overwrite || target === loaded.path;

  await writeJsonSecure(
    target,
    serializeKey(key, { dangerous: loaded.dangerous, registryOnly: false }),
    overwrite,
  );

  return target;
}

function requireEncryptedKey(loaded: LoadedKey, what: string): void {
  if (loaded.dangerous) {
    throw new UsageError(
      `${what} needs a regular (passphrase-encrypted) key file, but "${basename(loaded.path)}" ` +
        "holds raw private keys.",
    );
  }
}

// ─── Creating keys ───────────────────────────────────────────────────────────

/** Shared tail of generate / create / import: build, confirm, save. */
async function buildAndSaveKey(
  command: string,
  mnemonic: string,
  passphrase: string,
  language: MnemonicLanguage,
  options: NewKeyOptions,
): Promise<CliResult> {
  const keyIds = parseKeyIds(options.keys);

  const key = await MajikKey.create(mnemonic, passphrase, options.label, {
    mnemonicLanguage: language,
    keys: keyIds,
  });

  try {
    if (options.dangerous) {
      await confirmDangerous(key.fingerprint, options.yes);
    }

    const keyFile = await saveKey(key, options);

    let mnemonicFile: string | undefined;

    if (options.mnemonicOut) {
      const target =
        typeof options.mnemonicOut === "string"
          ? options.mnemonicOut
          : dirname(keyFile) + sep;

      mnemonicFile = await resolveOutputPath(
        target,
        defaultKeyFileName(key, false).replace(/\.json$/, ".mnemonic.json"),
      );

      await writeJsonSecure(
        mnemonicFile,
        key.toMnemonicJSON(mnemonic),
        options.overwrite,
      );
    }

    return {
      ok: true,
      command,
      message: options.dangerous
        ? "Majik Key saved as DANGEROUS plaintext JSON."
        : "Majik Key saved.",
      keyFile,
      format: options.dangerous
        ? "DANGEROUS — raw private keys, unencrypted"
        : "passphrase-encrypted JSON",
      label: key.label || undefined,
      fingerprint: key.fingerprint,
      keys: key.availableKeys(),
      mnemonicFile,
      warning: mnemonicFile
        ? "The mnemonic file is PLAINTEXT. Move it somewhere safe and offline."
        : undefined,
    };
  } finally {
    lockKey(key);
  }
}

export async function runGenerate(
  options: GenerateCliOptions,
): Promise<CliResult> {
  if (options.size !== 12 && options.size !== 24) {
    throw new UsageError("--size must be 12 or 24.");
  }

  assertLanguage(options.language);
  assertDangerousFlag(options);
  parseKeyIds(options.keys); // fail on bad ids before prompting

  const language = (options.language ?? "en") as MnemonicLanguage;

  const passphrase = await getNewPassphrase(sourceOf(options));

  const mnemonic = await MajikKey.generateMnemonic(
    options.size === 24 ? 256 : 128,
    language,
  );
  const words = mnemonic.split(/\s+/);

  printMnemonic(words);

  if (isInteractive() && !options.skipConfirm) {
    await confirmWrittenDown(words);
  }

  return buildAndSaveKey("generate", mnemonic, passphrase, language, options);
}

export async function runCreate(options: CreateCliOptions): Promise<CliResult> {
  assertLanguage(options.language);
  assertDangerousFlag(options);
  parseKeyIds(options.keys);

  const { mnemonic, language: fileLanguage } = await readMnemonicInput(
    options.mnemonicFile,
  );

  assertLanguage(fileLanguage);

  const language = (options.language ?? fileLanguage ?? "en") as MnemonicLanguage;
  const passphrase = await getNewPassphrase(sourceOf(options));

  return buildAndSaveKey("create", mnemonic, passphrase, language, options);
}

export async function runImport(options: ImportCliOptions): Promise<CliResult> {
  assertLanguage(options.language);
  assertDangerousFlag(options);
  parseKeyIds(options.keys);

  const path = resolveCliPath(options.backup);
  const bytes = await readBytes(path);

  let backup: MajikKeyBackup;

  try {
    if (looksLikePNG(bytes)) {
      backup = await MajikKeyBackup.fromPNG(
        new Blob([bytes as BlobPart], { type: "image/png" }),
      );
    } else if (looksLikeZip(bytes)) {
      backup = await MajikKeyBackup.fromZIP(bytes);
    } else {
      backup = MajikKeyBackup.fromJSON(
        JSON.parse(new TextDecoder("utf-8").decode(bytes)),
      );
    }
  } catch (error) {
    throw new CliError(`Could not read backup "${path}": ${errorMessage(error)}`);
  }

  assertLanguage(backup.language);

  const language = (options.language ?? backup.language ?? "en") as MnemonicLanguage;
  const passphrase = await getNewPassphrase(sourceOf(options));

  return buildAndSaveKey(
    "import",
    backup.seedPhrase,
    passphrase,
    language,
    options,
  );
}

// ─── Inspecting keys ─────────────────────────────────────────────────────────

export async function runInfo(options: InfoCliOptions): Promise<CliResult> {
  const { key, path, dangerous } = await loadKeyFile(options.input);

  return {
    ok: true,
    command: "info",
    message: `Majik Key${key.label ? ` "${key.label}"` : ""}`,
    file: path,
    ...describeKey(key),
    containsRawPrivateKeys: dangerous ? true : undefined,
  };
}

export async function runKeys(options: KeysCliOptions): Promise<CliResult> {
  if (options.supported) {
    const keys = MajikKey.supportedKeys().map((id) => {
      const definition = KEY_ALGORITHMS[id];

      return {
        id,
        family: definition.family,
        purpose: definition.purpose,
        kind: definition.kind,
        status: definition.status,
        standard: definition.standard,
      };
    });

    return {
      ok: true,
      command: "keys",
      message: `${keys.length} key algorithms can be enabled.`,
      keys,
    };
  }

  if (!options.input) {
    throw new UsageError("Provide a key file, or use --supported.");
  }

  const { key } = await loadKeyFile(options.input);
  const showFull = options.full || options.json;

  const keys = key.listKeys().map((info) => {
    const publicKey = info.publicKeyBase64;

    return {
      id: info.id,
      purpose: info.purpose,
      kind: info.kind,
      status: info.status,
      publicKey:
        publicKey && !showFull && publicKey.length > 24
          ? `${publicKey.slice(0, 20)}… (${publicKey.length} chars)`
          : publicKey,
    };
  });

  return {
    ok: true,
    command: "keys",
    message: `${keys.length} key(s) on this account.`,
    keys,
  };
}

export async function runVerify(options: VerifyCliOptions): Promise<CliResult> {
  const loaded = await loadKeyFile(options.input);
  requireEncryptedKey(loaded, "Passphrase verification");

  const passphrase = await getPassphrase(sourceOf(options));
  const valid = await loaded.key.verify(passphrase);

  return {
    ok: valid,
    command: "verify",
    message: valid ? "Passphrase is correct." : "Incorrect passphrase.",
    valid,
    fingerprint: loaded.key.fingerprint,
  };
}

// ─── Editing keys ────────────────────────────────────────────────────────────

export async function runLabel(options: LabelCliOptions): Promise<CliResult> {
  const loaded = await loadKeyFile(options.input);

  if (options.label === undefined) {
    return {
      ok: true,
      command: "label",
      message: loaded.key.label
        ? `Label: ${loaded.key.label}`
        : "This key has no label.",
      label: loaded.key.label || undefined,
    };
  }

  const previous = loaded.key.label;
  loaded.key.updateLabel(options.label);

  const file = await saveBack(loaded, loaded.key, options);

  return {
    ok: true,
    command: "label",
    message: "Label updated.",
    previousLabel: previous || undefined,
    label: loaded.key.label || undefined,
    file,
  };
}

export async function runPassphrase(
  options: PassphraseCliOptions,
): Promise<CliResult> {
  const loaded = await loadKeyFile(options.input);
  requireEncryptedKey(loaded, "Changing the passphrase");

  const { key } = loaded;

  try {
    const currentPassphrase = await getPassphrase(
      { envVar: ENV_PASSPHRASE },
      "Current passphrase: ",
    );

    if (!(await key.verify(currentPassphrase))) {
      throw new CliError("Incorrect passphrase.");
    }

    await key.unlock(currentPassphrase);

    const next = await getNewPassphrase(
      { envVar: ENV_NEW_PASSPHRASE },
      "New passphrase: ",
    );

    if (next === currentPassphrase) {
      throw new UsageError("The new passphrase is the same as the current one.");
    }

    await key.updatePassphrase(currentPassphrase, next);

    const file = await saveBack(loaded, key, options);

    return {
      ok: true,
      command: "passphrase",
      message: "Passphrase updated. Keys were re-encrypted under a fresh salt.",
      fingerprint: key.fingerprint,
      file,
    };
  } finally {
    lockKey(key);
  }
}

export async function runMigrate(options: MigrateCliOptions): Promise<CliResult> {
  const loaded = await loadKeyFile(options.input);
  requireEncryptedKey(loaded, "Migration");

  const { key } = loaded;

  if (key.isArgon2id) {
    return {
      ok: true,
      command: "migrate",
      message: "Already on Argon2id — nothing to do.",
      kdf: "argon2id",
    };
  }

  const passphrase = await getPassphrase(sourceOf(options));

  if (!(await key.verify(passphrase))) {
    throw new CliError("Incorrect passphrase.");
  }

  await key.migrate(passphrase);
  const file = await saveBack(loaded, key, options);

  return {
    ok: true,
    command: "migrate",
    message: "Migrated from PBKDF2 to Argon2id.",
    kdf: "argon2id",
    file,
  };
}

export async function runAddKeys(options: AddKeysCliOptions): Promise<CliResult> {
  const ids = parseKeyIds(options.keys);

  if (ids.length === 0) {
    throw new UsageError("Provide at least one key with --keys, e.g. --keys btc,eth.");
  }

  const loaded = await loadKeyFile(options.input);
  requireEncryptedKey(loaded, "Adding keys");

  const { key } = loaded;
  const passphrase = await getPassphrase({ envVar: ENV_PASSPHRASE });

  if (!(await key.verify(passphrase))) {
    throw new CliError("Incorrect passphrase.");
  }

  // New keys are derived from the seed, which is never stored.
  const { mnemonic } = await readMnemonicInput(options.mnemonicFile);

  const migrated = !key.isArgon2id;
  if (migrated) await key.migrate(passphrase);

  try {
    const added = await key.addKeys(ids, mnemonic, passphrase);

    if (added.length === 0 && !migrated) {
      return {
        ok: true,
        command: "add-keys",
        message: "Nothing to add — those keys are already on this account.",
        keys: key.availableKeys(),
      };
    }

    const file = await saveBack(loaded, key, options);

    return {
      ok: true,
      command: "add-keys",
      message:
        added.length > 0
          ? `Added ${added.length} key(s).`
          : "Migrated to Argon2id; no new keys were needed.",
      added,
      migratedToArgon2id: migrated ? true : undefined,
      file,
    };
  } finally {
    lockKey(key);
  }
}

// ─── Serialization ───────────────────────────────────────────────────────────

export async function runExport(options: ExportCliOptions): Promise<CliResult> {
  if (options.json && options.stdout) {
    throw new UsageError("--json cannot be combined with --stdout.");
  }
  if (options.contact && options.dangerous) {
    throw new UsageError("--contact is public data; it cannot be combined with --dangerous.");
  }

  assertDangerousFlag(options);

  const loaded = await loadKeyFile(options.input);
  const { key } = loaded;

  try {
    let content: string;
    let defaultName: string;
    let kind: string;

    if (options.contact) {
      const contact = await key.toContact().toJSON();

      content = JSON.stringify(contact, null, 2) + "\n";
      defaultName = `majik-contact-${shortFingerprint(key.fingerprint)}.json`;
      kind = "public contact JSON";
    } else {
      if (options.dangerous) {
        await unlockKey(key, sourceOf(options));
        await confirmDangerous(key.fingerprint, options.yes);
      }

      content = JSON.stringify(serializeKey(key, options), null, 2) + "\n";
      defaultName = defaultKeyFileName(key, options.dangerous);
      kind = options.dangerous
        ? "DANGEROUS — raw private keys, unencrypted"
        : "passphrase-encrypted JSON";
    }

    if (options.stdout) {
      process.stdout.write(content);

      return {
        ok: true,
        command: "export",
        message: "Exported to stdout.",
        format: kind,
        fingerprint: key.fingerprint,
      };
    }

    const file = await resolveOutputPath(options.output, defaultName);
    await writeSecureFile(file, content, options.overwrite);

    return {
      ok: true,
      command: "export",
      message: "Exported.",
      format: kind,
      file,
      fingerprint: key.fingerprint,
    };
  } finally {
    lockKey(key);
  }
}

export async function runBackup(options: BackupCliOptions): Promise<CliResult> {
  const loaded = await loadKeyFile(options.input);
  const { key } = loaded;

  const { mnemonic } = await readMnemonicInput(options.mnemonicFile);

  if (!(await mnemonicBelongsTo(key, mnemonic))) {
    throw new CliError("That recovery phrase does not belong to this key.");
  }

  const backup = MajikKeyBackup.create({
    seed: mnemonic,
    id: key.backup,
    language: key.mnemonicLanguage,
  });

  let data: string | Uint8Array;

  try {
    if (options.format === "json") {
      data = JSON.stringify(backup.toJSON(), null, 2) + "\n";
    } else if (options.format === "png") {
      data = new Uint8Array(await (await backup.toPNG()).arrayBuffer());
    } else {
      data = new Uint8Array(await (await backup.toZIP()).arrayBuffer());
    }
  } catch (error) {
    throw new CliError(errorMessage(error));
  }

  const defaultName = `${backup.suggestedFileName(key.label || undefined)}.${options.format}`;
  const targetOption = options.output;

  const file =
    targetOption && !/\.[A-Za-z0-9]+$/.test(targetOption)
      ? await resolveOutputPath(targetOption + `.${options.format}`, defaultName)
      : await resolveOutputPath(targetOption, defaultName);

  await writeSecureFile(file, data, options.overwrite);

  return {
    ok: true,
    command: "backup",
    message: `Mnemonic backup written as ${options.format.toUpperCase()}.`,
    file,
    fingerprint: key.fingerprint,
    warning:
      "This backup contains your recovery phrase. Store it offline and keep it private.",
  };
}
