/**
 * src/cli-core/prompt.ts
 *
 * Interactive input for secrets. All prompts are written to STDERR so that
 * stdout stays clean for `--json` and `--stdout` consumers.
 *
 * Passphrases are never accepted as command-line arguments (they would land
 * in shell history and the process list). Sources, in order:
 *
 *   1. --passphrase-stdin          first line of stdin
 *   2. MAJIK_KEY_PASSPHRASE        (MAJIK_KEY_NEW_PASSPHRASE for `passphrase`)
 *   3. hidden interactive prompt
 */

import { createInterface } from "node:readline/promises";

import { CliError, UsageError } from "./errors.js";
import { readStdinLine } from "./io.js";

export const ENV_PASSPHRASE = "MAJIK_KEY_PASSPHRASE";
export const ENV_NEW_PASSPHRASE = "MAJIK_KEY_NEW_PASSPHRASE";
export const ENV_MNEMONIC = "MAJIK_KEY_MNEMONIC";

export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY);
}

const ANSI_ESCAPE = /\u001b\[[0-9;]*[A-Za-z~]/g;

/** Read one line from the terminal without echoing it. */
export function readHidden(message: string): Promise<string> {
  const stdin = process.stdin;

  if (!stdin.isTTY || typeof stdin.setRawMode !== "function") {
    throw new CliError(
      "An interactive terminal is required for this prompt. " +
        `Use ${ENV_PASSPHRASE} or --passphrase-stdin for non-interactive use.`,
    );
  }

  return new Promise<string>((resolve, reject) => {
    let value = "";
    let done = false;

    const cleanup = () => {
      if (done) return;
      done = true;

      stdin.removeListener("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stderr.write("\n");
    };

    const onData = (chunk: Buffer | string) => {
      const text = chunk.toString("utf8").replace(ANSI_ESCAPE, "");

      for (const character of text) {
        if (character === "\u0003") {
          cleanup();
          reject(new CliError("Operation cancelled.", 130));
          return;
        }

        if (character === "\r" || character === "\n" || character === "\u0004") {
          cleanup();
          resolve(value);
          return;
        }

        if (character === "\u0008" || character === "\u007f") {
          value = value.slice(0, -1);
          continue;
        }

        if (character < " ") {
          continue;
        }

        value += character;
      }
    };

    try {
      // Raw mode (no echo) must be on BEFORE the prompt is visible, otherwise
      // type-ahead or a fast paste in the gap would be echoed to the screen.
      stdin.setRawMode(true);
      stdin.resume();
      stdin.on("data", onData);
      process.stderr.write(message);
    } catch (error) {
      cleanup();
      reject(error);
    }
  });
}

/** Read one visible line (confirmations, yes/no). */
export async function readLine(message: string): Promise<string> {
  if (!isInteractive()) {
    throw new CliError("An interactive terminal is required for this prompt.");
  }

  const rl = createInterface({ input: process.stdin, output: process.stderr });

  try {
    return await rl.question(message);
  } finally {
    rl.close();
  }
}

function envValue(name: string): string | undefined {
  const value = process.env[name];
  return value !== undefined && value !== "" ? value : undefined;
}

export interface PassphraseSource {
  /** Honour --passphrase-stdin. */
  stdin?: boolean;
  /** Environment variable to consult before prompting. */
  envVar?: string;
}

async function fromNonInteractiveSource(
  source: PassphraseSource,
): Promise<string | undefined> {
  if (source.stdin) {
    const line = await readStdinLine();

    if (line === "") {
      throw new UsageError("--passphrase-stdin was given but stdin was empty.");
    }

    return line;
  }

  return source.envVar ? envValue(source.envVar) : undefined;
}

function noSourceError(source: PassphraseSource): CliError {
  return new CliError(
    "A passphrase is required, but stdin is not an interactive terminal. " +
      `Set ${source.envVar ?? ENV_PASSPHRASE} or pass --passphrase-stdin.`,
  );
}

/** Ask for an existing passphrase (single entry). */
export async function getPassphrase(
  source: PassphraseSource = { envVar: ENV_PASSPHRASE },
  message = "Passphrase: ",
): Promise<string> {
  const fixed = await fromNonInteractiveSource(source);
  if (fixed !== undefined) return fixed;

  if (!isInteractive()) throw noSourceError(source);

  return readHidden(message);
}

/** Ask for a NEW passphrase, entered twice, with a weak-passphrase warning. */
export async function getNewPassphrase(
  source: PassphraseSource = { envVar: ENV_PASSPHRASE },
  message = "Set a passphrase: ",
): Promise<string> {
  const fixed = await fromNonInteractiveSource(source);
  if (fixed !== undefined) return fixed;

  if (!isInteractive()) throw noSourceError(source);

  for (let attempt = 0; attempt < 3; attempt++) {
    const first = await readHidden(message);

    if (first.trim() === "") {
      process.stderr.write("Passphrase cannot be empty.\n");
      continue;
    }

    const second = await readHidden("Confirm passphrase: ");

    if (first !== second) {
      process.stderr.write("Passphrases didn't match. Try again.\n");
      continue;
    }

    if (first.length < 8) {
      process.stderr.write(
        "Warning: that passphrase is short. Longer is much safer.\n",
      );
    }

    return first;
  }

  throw new CliError("Too many failed attempts.");
}

/** Normalise a typed/pasted mnemonic: lowercase, single spaces. */
export function normalizeMnemonic(raw: string): string {
  return raw.trim().toLowerCase().split(/\s+/).filter(Boolean).join(" ");
}

const VALID_WORD_COUNTS = new Set([12, 15, 18, 21, 24]);

export function assertMnemonicShape(mnemonic: string): void {
  const count = mnemonic === "" ? 0 : mnemonic.split(" ").length;

  if (!VALID_WORD_COUNTS.has(count)) {
    throw new CliError(
      `Expected a 12, 15, 18, 21 or 24 word recovery phrase, got ${count} word(s).`,
    );
  }
}

/** Mnemonic from env var, otherwise a hidden prompt (never argv). */
export async function promptMnemonic(
  message = "Recovery phrase: ",
): Promise<string> {
  const fromEnv = envValue(ENV_MNEMONIC);

  const raw = fromEnv ?? (await readHidden(message));
  const mnemonic = normalizeMnemonic(raw);

  assertMnemonicShape(mnemonic);
  return mnemonic;
}

export async function confirmYes(message: string): Promise<boolean> {
  const answer = await readLine(message);
  return answer.trim().toLowerCase() === "y";
}
