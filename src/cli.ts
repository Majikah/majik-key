#!/usr/bin/env node

/**
 * src/cli.ts
 *
 * Majik Key CLI — create, inspect, edit, export and back up Majik Keys.
 *
 *   npx @majikah/majik-key --help
 *   npx @majikah/majik-key generate
 *
 * Also exposed as the `@majikah/majik-key/cli` export so the program can be
 * embedded or driven from tests via `createProgram()`.
 */

import { Command, CommanderError, Option } from "commander";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import {
  CliError,
  getPackageVersion,
  printFailure,
  printJsonResult,
  printResult,
  runAddKeys,
  runBackup,
  runCreate,
  runExport,
  runGenerate,
  runImport,
  runInfo,
  runKeys,
  runLabel,
  runMigrate,
  runPassphrase,
  runVerify,
} from "./cli-core/index.js";
import type { CliResult } from "./cli-core/index.js";
import { MNEMONIC_LANGUAGES } from "./cli-core/key.js";

type RawOptions = Record<string, any>;

/**
 * Run one command: print its result, translate errors into exit codes.
 * `dataOnStdout` routes the human summary to stderr so exported data (or any
 * other payload written to stdout) stays clean.
 */
async function exec(
  work: () => Promise<CliResult>,
  json: boolean,
  dataOnStdout = false,
): Promise<void> {
  try {
    const result = await work();

    if (json) {
      printJsonResult(result);
    } else {
      printResult(result, dataOnStdout ? "stderr" : "stdout");
    }

    process.exitCode = result.ok ? 0 : 1;
  } catch (error) {
    printFailure(error, json);
    process.exitCode = error instanceof CliError ? error.exitCode : 1;
  }
}

function parseCsv(value: string, previous: string[] = []): string[] {
  return [
    ...previous,
    ...value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
  ];
}

const KEYS_HELP =
  "Extra keypairs on top of the core four, comma-separated. Short names work: btc,eth,sol,ml-kem-1024.";

function addPassphraseStdin(command: Command): Command {
  return command.option(
    "--passphrase-stdin",
    "Read the passphrase from the first line of stdin.",
  );
}

function addWriteOptions(command: Command, whatDefault: string): Command {
  return command
    .option(
      "-o, --output <path>",
      `Output file, or directory. Defaults to ${whatDefault}.`,
    )
    .option("--overwrite", "Replace the output file if it already exists.");
}

function addSaveFormat(command: Command): Command {
  return command
    .option(
      "--dangerous",
      "Save RAW, UNENCRYPTED private keys instead of passphrase-encrypted JSON.",
    )
    .option(
      "--i-understand-the-risk",
      "Required with --dangerous. Acknowledges that the file grants full control of the key.",
    )
    .option(
      "--yes",
      "Skip the typed confirmation for --dangerous (needed when non-interactive).",
    )
    .option(
      "--registry-only",
      "Omit the legacy pre-registry fields from the JSON (not readable by older library versions).",
    );
}

function addNewKeyOptions(command: Command): Command {
  addPassphraseStdin(command);
  addWriteOptions(command, "the current directory");
  addSaveFormat(command);

  return command
    .option("-l, --label <label>", "Human-readable name for the key.")
    .option("-k, --keys <ids>", KEYS_HELP, parseCsv, [])
    .option(
      "--mnemonic-out [path]",
      "Also save the recovery phrase as PLAINTEXT JSON (default: next to the key file).",
    )
    .option("--json", "Emit machine-readable JSON.");
}

function saveFormat(options: RawOptions) {
  return {
    dangerous: Boolean(options.dangerous),
    iUnderstandTheRisk: Boolean(options.iUnderstandTheRisk),
    yes: Boolean(options.yes),
    registryOnly: Boolean(options.registryOnly),
  };
}

function newKeyOptions(options: RawOptions) {
  return {
    output: options.output as string | undefined,
    overwrite: Boolean(options.overwrite),
    passphraseStdin: Boolean(options.passphraseStdin),
    json: Boolean(options.json),
    label: options.label as string | undefined,
    language: options.language as string | undefined,
    keys: (options.keys ?? []) as string[],
    mnemonicOut: options.mnemonicOut as boolean | string | undefined,
    ...saveFormat(options),
  };
}

/**
 * Build the Commander application.
 *
 * Exported so Vitest can drive the real parser without spawning a process.
 */
export function createProgram(version = "test"): Command {
  const program = new Command();

  program
    .name("majik-key")
    .description(
      "Majik Key CLI — create, inspect, edit, export and back up post-quantum-ready Majik Keys.",
    )
    .version(version)
    // Commander's own usage errors throw instead of calling process.exit();
    // runProgram() maps them to exit code 2.
    .exitOverride()
    .showHelpAfterError()
    .showSuggestionAfterError()
    .addHelpText(
      "after",
      `
Quick start:
  majik-key generate                      new 24-word key, saved to the current directory
  majik-key generate --size 12            12-word recovery phrase instead
  majik-key info ./majik-key-*.json       inspect a key file (no passphrase needed)

Passphrases are never taken as arguments (they would end up in shell history).
They come from, in order: --passphrase-stdin, an environment variable, or a
hidden prompt:
  MAJIK_KEY_PASSPHRASE       passphrase for the key (new or existing)
  MAJIK_KEY_NEW_PASSPHRASE   new passphrase for \`passphrase\`
  MAJIK_KEY_MNEMONIC         recovery phrase for \`create\`, \`add-keys\`, \`backup\`

Exit codes: 0 ok · 1 operation failed · 2 usage error · 130 cancelled.`,
    );

  // ── generate ───────────────────────────────────────────────────────────────
  addNewKeyOptions(
    program
      .command("generate")
      .alias("new")
      .description(
        "Generate a brand-new recovery phrase and key, then save the key file.",
      )
      .addOption(
        new Option("-s, --size <words>", "Recovery phrase length in words.")
          .choices(["12", "24"])
          .default("24"),
      )
      .addOption(
        new Option("--language <code>", "BIP-39 wordlist language.")
          .choices(MNEMONIC_LANGUAGES)
          .default("en"),
      )
      .option(
        "--skip-confirm",
        "Don't ask you to type back words from the phrase.",
      ),
  )
    .addHelpText(
      "after",
      `
The recovery phrase is shown ONCE on stderr. On a terminal you must type back
three random words to prove you wrote it down. The key file is saved as
majik-key-<label>-<fingerprint>.json in the current directory unless -o is given.

Examples:
  majik-key generate
  majik-key generate --size 12 --label alice
  majik-key generate -o ~/keys/ --keys btc,eth
  majik-key generate --dangerous --i-understand-the-risk`,
    )
    .action(async (options: RawOptions) => {
      await exec(
        () =>
          runGenerate({
            ...newKeyOptions(options),
            size: Number(options.size),
            skipConfirm: Boolean(options.skipConfirm),
          }),
        Boolean(options.json),
      );
    });

  // ── create ─────────────────────────────────────────────────────────────────
  addNewKeyOptions(
    program
      .command("create")
      .description("Create a key from a recovery phrase you already have.")
      .addOption(
        new Option("--language <code>", "BIP-39 wordlist language.").choices(
          MNEMONIC_LANGUAGES,
        ),
      )
      .option(
        "--mnemonic-file <path>",
        "Read the phrase from a text file or MnemonicJSON file instead of prompting.",
      ),
  ).action(async (options: RawOptions) => {
    await exec(
      () =>
        runCreate({
          ...newKeyOptions(options),
          mnemonicFile: options.mnemonicFile,
        }),
      Boolean(options.json),
    );
  });

  // ── import ─────────────────────────────────────────────────────────────────
  addNewKeyOptions(
    program
      .command("import <backup>")
      .description(
        "Restore a key from a mnemonic backup (.json, .png or .zip) under a new passphrase.",
      )
      .addOption(
        new Option(
          "--language <code>",
          "Override the wordlist language stored in the backup.",
        ).choices(MNEMONIC_LANGUAGES),
      ),
  ).action(async (backup: string, options: RawOptions) => {
    await exec(
      () => runImport({ ...newKeyOptions(options), backup }),
      Boolean(options.json),
    );
  });

  // ── info ───────────────────────────────────────────────────────────────────
  program
    .command("info <key>")
    .description("Show a key's non-secret details. No passphrase needed.")
    .option("--json", "Emit machine-readable JSON.")
    .action(async (input: string, options: RawOptions) => {
      await exec(
        () => runInfo({ input, json: Boolean(options.json) }),
        Boolean(options.json),
      );
    });

  // ── keys ───────────────────────────────────────────────────────────────────
  program
    .command("keys [key]")
    .description(
      "List the keypairs on an account, or every algorithm that can be enabled.",
    )
    .option("--supported", "List every algorithm this version can enable.")
    .option("--full", "Print full public keys instead of shortened ones.")
    .option("--json", "Emit machine-readable JSON.")
    .action(async (input: string | undefined, options: RawOptions) => {
      await exec(
        () =>
          runKeys({
            input,
            supported: Boolean(options.supported),
            full: Boolean(options.full),
            json: Boolean(options.json),
          }),
        Boolean(options.json),
      );
    });

  // ── verify ─────────────────────────────────────────────────────────────────
  addPassphraseStdin(
    program
      .command("verify <key>")
      .description(
        "Check a passphrase against a key file. Exit code 1 if wrong.",
      ),
  )
    .option("--json", "Emit machine-readable JSON.")
    .action(async (input: string, options: RawOptions) => {
      await exec(
        () =>
          runVerify({
            input,
            passphraseStdin: Boolean(options.passphraseStdin),
            json: Boolean(options.json),
          }),
        Boolean(options.json),
      );
    });

  // ── label ──────────────────────────────────────────────────────────────────
  addWriteOptions(
    program
      .command("label <key> [label]")
      .description(
        "Show or change a key's label. Edits the file in place unless -o is given.",
      ),
    "the key file itself",
  )
    .option("--json", "Emit machine-readable JSON.")
    .action(
      async (input: string, label: string | undefined, options: RawOptions) => {
        await exec(
          () =>
            runLabel({
              input,
              label,
              output: options.output,
              overwrite: Boolean(options.overwrite),
              json: Boolean(options.json),
            }),
          Boolean(options.json),
        );
      },
    );

  // ── passphrase ─────────────────────────────────────────────────────────────
  addWriteOptions(
    program
      .command("passphrase <key>")
      .description(
        "Change a key's passphrase. Re-encrypts every key; edits the file in place unless -o is given.",
      ),
    "the key file itself",
  )
    .option("--json", "Emit machine-readable JSON.")
    .addHelpText(
      "after",
      "\nNon-interactive: set MAJIK_KEY_PASSPHRASE (current) and MAJIK_KEY_NEW_PASSPHRASE (new).",
    )
    .action(async (input: string, options: RawOptions) => {
      await exec(
        () =>
          runPassphrase({
            input,
            output: options.output,
            overwrite: Boolean(options.overwrite),
            json: Boolean(options.json),
          }),
        Boolean(options.json),
      );
    });

  // ── migrate ────────────────────────────────────────────────────────────────
  addPassphraseStdin(
    addWriteOptions(
      program
        .command("migrate <key>")
        .description(
          "Upgrade a legacy PBKDF2 key to Argon2id without changing its passphrase.",
        ),
      "the key file itself",
    ),
  )
    .option("--json", "Emit machine-readable JSON.")
    .action(async (input: string, options: RawOptions) => {
      await exec(
        () =>
          runMigrate({
            input,
            output: options.output,
            overwrite: Boolean(options.overwrite),
            passphraseStdin: Boolean(options.passphraseStdin),
            json: Boolean(options.json),
          }),
        Boolean(options.json),
      );
    });

  // ── add-keys ───────────────────────────────────────────────────────────────
  addWriteOptions(
    program
      .command("add-keys <key>")
      .description(
        "Add keypairs the account doesn't have yet. Needs the key's passphrase AND its recovery phrase.",
      )
      .requiredOption("-k, --keys <ids>", KEYS_HELP, parseCsv, [])
      .option(
        "--mnemonic-file <path>",
        "Read the phrase from a text file or MnemonicJSON file instead of prompting.",
      ),
    "the key file itself",
  )
    .option("--json", "Emit machine-readable JSON.")
    .action(async (input: string, options: RawOptions) => {
      await exec(
        () =>
          runAddKeys({
            input,
            keys: options.keys ?? [],
            mnemonicFile: options.mnemonicFile,
            output: options.output,
            overwrite: Boolean(options.overwrite),
            json: Boolean(options.json),
          }),
        Boolean(options.json),
      );
    });

  // ── export ─────────────────────────────────────────────────────────────────
  addSaveFormat(
    addPassphraseStdin(
      addWriteOptions(
        program
          .command("export <key>")
          .description(
            "Serialize a key: normal JSON, DANGEROUS plaintext JSON, or its public contact JSON.",
          )
          .option(
            "--contact",
            "Export the PUBLIC contact JSON (safe to share) instead of the key file.",
          )
          .option("--stdout", "Print to stdout instead of writing a file."),
        "the current directory",
      ),
    ),
  )
    .option("--json", "Emit machine-readable JSON.")
    .addHelpText(
      "after",
      `
Examples:
  majik-key export key.json --registry-only -o ./clean/
  majik-key export key.json --contact
  majik-key export key.json --dangerous --i-understand-the-risk
  majik-key export key.json --dangerous --i-understand-the-risk --yes --stdout | your-secrets-tool`,
    )
    .action(async (input: string, options: RawOptions) => {
      await exec(
        () =>
          runExport({
            input,
            output: options.output,
            overwrite: Boolean(options.overwrite),
            passphraseStdin: Boolean(options.passphraseStdin),
            json: Boolean(options.json),
            contact: Boolean(options.contact),
            stdout: Boolean(options.stdout),
            ...saveFormat(options),
          }),
        Boolean(options.json),
        Boolean(options.stdout),
      );
    });

  // ── backup ─────────────────────────────────────────────────────────────────
  addWriteOptions(
    program
      .command("backup <key>")
      .description(
        "Write a recovery-phrase backup (json, png or zip) for a key. Needs the recovery phrase.",
      )
      .addOption(
        new Option("-f, --format <format>", "Backup file format.")
          .choices(["json", "png", "zip"])
          .default("json"),
      )
      .option(
        "--mnemonic-file <path>",
        "Read the phrase from a text file or MnemonicJSON file instead of prompting.",
      ),
    "the current directory",
  )
    .option("--json", "Emit machine-readable JSON.")
    .addHelpText(
      "after",
      "\npng and zip need the optional packages @majikah/majik-bytes and jszip to be installed.",
    )
    .action(async (input: string, options: RawOptions) => {
      await exec(
        () =>
          runBackup({
            input,
            format: options.format,
            mnemonicFile: options.mnemonicFile,
            output: options.output,
            overwrite: Boolean(options.overwrite),
            json: Boolean(options.json),
          }),
        Boolean(options.json),
      );
    });

  return program;
}

/**
 * Parse and run argv. Commander usage errors (unknown option, invalid choice,
 * missing argument) already printed their message; they become exit code 2.
 * --help and --version exit 0.
 */
export async function runProgram(
  program: Command,
  argv: string[],
): Promise<void> {
  try {
    await program.parseAsync(argv);
  } catch (error) {
    if (error instanceof CommanderError) {
      process.exitCode = error.exitCode === 0 ? 0 : 2;
      return;
    }

    throw error;
  }
}

export async function main(argv = process.argv): Promise<void> {
  await runProgram(createProgram(await getPackageVersion()), argv);
}

/**
 * Run only when this file is the entry point.
 *
 * `npx`/`npm bin` invoke us through a symlink (node_modules/.bin/majik-key),
 * so argv[1] must be resolved to its real path before comparing it with
 * import.meta.url — a plain resolve() comparison silently does nothing.
 */
function isDirectExecution(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;

  try {
    return (
      realpathSync(resolve(entry)) ===
      realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
}

if (isDirectExecution()) {
  main().catch((error) => {
    printFailure(error);
    process.exitCode = 2;
  });
}
