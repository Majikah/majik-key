/**
 * src/cli-core/io.ts
 *
 * Node.js filesystem + stdin helpers for the Majik Key CLI.
 *
 * Every file this CLI writes can contain key material, so writes are created
 * with owner-only permissions (0600) and never replace an existing file unless
 * the caller explicitly opts in.
 */

import {
  mkdir,
  readFile,
  rename,
  stat,
  writeFile,
  chmod,
  rm,
} from "node:fs/promises";
import { basename, dirname, extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { CliError } from "./errors.js";

export function resolveCliPath(path: string): string {
  return resolve(process.cwd(), path);
}

export async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

export async function isDirectory(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

export async function readBytes(path: string): Promise<Uint8Array> {
  try {
    return new Uint8Array(await readFile(path));
  } catch (error) {
    throw new CliError(
      `Cannot read "${path}": ${
        (error as NodeJS.ErrnoException).code === "ENOENT"
          ? "file not found"
          : error instanceof Error
            ? error.message
            : String(error)
      }`,
    );
  }
}

export async function readText(path: string): Promise<string> {
  return new TextDecoder("utf-8").decode(await readBytes(path));
}

export async function readJsonFile<T = unknown>(path: string): Promise<T> {
  const text = await readText(path);

  try {
    return JSON.parse(text) as T;
  } catch (error) {
    throw new CliError(
      `Invalid JSON in "${path}": ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/**
 * Write a file with owner-only permissions.
 *
 * - `overwrite: false` uses exclusive creation, so an existing file is never
 *   touched (and there is no check-then-write race).
 * - `overwrite: true` writes a sibling temp file and renames it into place, so
 *   a crash mid-write cannot leave a truncated key file behind.
 */
export async function writeSecureFile(
  path: string,
  data: string | Uint8Array,
  overwrite: boolean,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true });

  if (!overwrite) {
    try {
      await writeFile(path, data, { flag: "wx", mode: 0o600 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new CliError(
          `Output already exists: "${path}". Use --overwrite to replace it.`,
        );
      }
      throw error;
    }
    return;
  }

  const temp = `${path}.${process.pid}.tmp`;

  try {
    await writeFile(temp, data, { mode: 0o600 });
    await chmod(temp, 0o600).catch(() => undefined);
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true }).catch(() => undefined);
    throw error;
  }
}

export async function writeJsonSecure(
  path: string,
  value: unknown,
  overwrite: boolean,
): Promise<void> {
  await writeSecureFile(path, JSON.stringify(value, null, 2) + "\n", overwrite);
}

/**
 * Turn `--output` into a concrete file path.
 *
 *  - not provided                    → <cwd>/<defaultName>
 *  - existing directory, or ends "/" → <that dir>/<defaultName>
 *  - anything else                   → treated as a file path
 *                                      (".json" appended if it has no extension)
 */
export async function resolveOutputPath(
  output: string | undefined,
  defaultName: string,
): Promise<string> {
  if (!output) {
    return resolve(process.cwd(), defaultName);
  }

  const resolved = resolveCliPath(output);
  const endsWithSeparator = output.endsWith("/") || output.endsWith(sep);

  if (endsWithSeparator || (await isDirectory(resolved))) {
    return resolve(resolved, defaultName);
  }

  return extname(resolved) === "" ? `${resolved}.json` : resolved;
}

/** Filesystem-safe fragment: letters, digits, dash, underscore. */
export function slugify(value: string, max = 40): string {
  return value
    .normalize("NFKD")
    .replace(/[^A-Za-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, max);
}

/** Short filename-safe piece of a base64 fingerprint. */
export function shortFingerprint(fingerprint: string, length = 8): string {
  return fingerprint.replace(/[^A-Za-z0-9]/g, "").slice(0, length);
}

/**
 * Read the first line of stdin. Used by `--passphrase-stdin` so a passphrase
 * can be piped in without touching shell history or the process list.
 */
export async function readStdinLine(): Promise<string> {
  const chunks: Buffer[] = [];

  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);

    // Stop at the first newline so a long-lived pipe doesn't hang us.
    if (Buffer.concat(chunks).includes(0x0a)) {
      break;
    }
  }

  const text = Buffer.concat(chunks).toString("utf8");
  const firstLine = text.split(/\r?\n/, 1)[0] ?? "";

  return firstLine;
}

export async function getPackageVersion(): Promise<string> {
  /**
   * dist/cli-core/io.js  →  ../../package.json  (package root)
   * src/cli-core/io.ts   →  ../../package.json  (same, when run from source)
   */
  const packageJsonPath = resolve(
    dirname(fileURLToPath(import.meta.url)),
    "../../package.json",
  );

  try {
    const packageJson = await readJsonFile<{ version?: string }>(
      packageJsonPath,
    );
    return packageJson.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

export function fileLabel(path: string): string {
  return basename(path);
}
