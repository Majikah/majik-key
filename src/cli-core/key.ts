/**
 * src/cli-core/key.ts
 *
 * Loading, unlocking, saving and describing Majik Keys for the CLI.
 */

import { extname } from "node:path";

import { MajikKey } from "../majik-key.js";
import type { MajikKeyDangerousJSON } from "../core/types.js";
import { WORDLISTS } from "../core/crypto/wordlist.js";
import { KeyId } from "../core/keys/key-id.js";
import { knownKeyIds } from "../core/keys/registry.js";

import { CliError, UsageError, errorMessage } from "./errors.js";
import {
  readJsonFile,
  resolveCliPath,
  resolveOutputPath,
  shortFingerprint,
  slugify,
  writeJsonSecure,
} from "./io.js";
import {
  ENV_PASSPHRASE,
  getPassphrase,
  isInteractive,
  type PassphraseSource,
} from "./prompt.js";

export interface LoadedKey {
  key: MajikKey;
  /** Absolute path the key was read from. */
  path: string;
  /** The file held RAW private keys (dangerous JSON), so the key is already unlocked. */
  dangerous: boolean;
}

function looksDangerous(json: unknown): json is MajikKeyDangerousJSON {
  return (
    typeof json === "object" &&
    json !== null &&
    typeof (json as Record<string, unknown>).privateKeyBase64 === "string"
  );
}

/**
 * Load a Majik Key JSON file — regular (passphrase-encrypted) or dangerous.
 * The returned key is NOT unlocked unless the file was dangerous JSON.
 */
export async function loadKeyFile(path: string): Promise<LoadedKey> {
  const resolved = resolveCliPath(path);
  const extension = extname(resolved).toLowerCase();

  if (extension === ".png" || extension === ".zip") {
    throw new UsageError(
      `"${path}" looks like a mnemonic backup, not a key file. ` +
        "Restore it into a key file with `majik-key import`.",
    );
  }

  const json = await readJsonFile(resolved);

  try {
    if (looksDangerous(json)) {
      return {
        key: MajikKey.fromDangerousJSON(json),
        path: resolved,
        dangerous: true,
      };
    }

    return { key: MajikKey.fromJSON(json as never), path: resolved, dangerous: false };
  } catch (error) {
    throw new CliError(
      `Failed to load Majik Key "${resolved}": ${errorMessage(error)}`,
    );
  }
}

/**
 * Unlock a key. Interactive sessions get three tries at the passphrase;
 * env/stdin sources get exactly one (retrying a fixed value is pointless).
 */
export async function unlockKey(
  key: MajikKey,
  source: PassphraseSource = { envVar: ENV_PASSPHRASE },
): Promise<void> {
  if (key.isUnlocked) return;

  const canRetry = isInteractive() && !source.stdin && !process.env[ENV_PASSPHRASE];

  for (let attempt = 1; attempt <= (canRetry ? 3 : 1); attempt++) {
    const passphrase = await getPassphrase(source, "Passphrase: ");

    try {
      await key.unlock(passphrase);
      return;
    } catch {
      if (attempt < (canRetry ? 3 : 1)) {
        process.stderr.write("Incorrect passphrase. Try again.\n");
      }
    }
  }

  throw new CliError("Incorrect passphrase, or the key file is corrupted.");
}

export function lockKey(key: MajikKey): void {
  try {
    if (key.isUnlocked) key.lock();
  } catch {
    // Cleanup must never replace the real result or error.
  }
}

// ─── Serialization ───────────────────────────────────────────────────────────

export interface SerializeOptions {
  dangerous: boolean;
  registryOnly: boolean;
}

export function serializeKey(key: MajikKey, options: SerializeOptions): unknown {
  return options.dangerous
    ? key.toDangerousJSON()
    : key.toJSON({ legacy: !options.registryOnly });
}

export function defaultKeyFileName(key: MajikKey, dangerous: boolean): string {
  const fingerprint = shortFingerprint(key.fingerprint);
  const label = key.label ? slugify(key.label) : "";
  const stem = label ? `${label}-${fingerprint}` : fingerprint;

  return `majik-key-${stem}${dangerous ? ".dangerous" : ""}.json`;
}

export async function saveKey(
  key: MajikKey,
  options: SerializeOptions & { output?: string; overwrite: boolean },
): Promise<string> {
  const path = await resolveOutputPath(
    options.output,
    defaultKeyFileName(key, options.dangerous),
  );

  await writeJsonSecure(path, serializeKey(key, options), options.overwrite);
  return path;
}

// ─── Key id / language parsing ───────────────────────────────────────────────

export const MNEMONIC_LANGUAGES = Object.keys(WORDLISTS);

export function assertLanguage(language: string | undefined): void {
  if (language !== undefined && !MNEMONIC_LANGUAGES.includes(language)) {
    throw new UsageError(
      `Unsupported language "${language}". Choose one of: ${MNEMONIC_LANGUAGES.join(", ")}.`,
    );
  }
}

/**
 * Accepts full ids ("web3:btc") or the part after the colon ("btc").
 * Library-level checks (reserved / unsupported / unimplemented) still apply
 * when the ids reach MajikKey.create() / addKeys().
 */
export function parseKeyIds(items: string[]): KeyId[] {
  const known = knownKeyIds();
  const result: KeyId[] = [];

  for (const raw of items) {
    const wanted = raw.trim().toLowerCase();
    if (!wanted) continue;

    const match =
      known.find((id) => id === wanted) ??
      known.find((id) => id.split(":")[1] === wanted);

    if (!match) {
      throw new UsageError(
        `Unknown key "${raw}". Run \`majik-key keys --supported\` to see what can be enabled.`,
      );
    }

    if (!result.includes(match)) result.push(match);
  }

  return result;
}

// ─── Description ─────────────────────────────────────────────────────────────

export function describeKey(key: MajikKey): Record<string, unknown> {
  return {
    label: key.label || undefined,
    id: key.id !== key.fingerprint ? key.id : undefined,
    fingerprint: key.fingerprint,
    createdAt: key.timestamp.toISOString(),
    kdf: key.isArgon2id ? "argon2id" : "pbkdf2 (legacy — run `migrate`)",
    mnemonicLanguage: key.mnemonicLanguage,
    coreComplete: key.isCoreComplete,
    missingCoreKeys: key.isCoreComplete ? undefined : key.missingKeys(),
    keys: key.availableKeys(),
  };
}
