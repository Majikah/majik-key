/**
 * src/cli-core/output.ts
 *
 * Human-readable and machine-readable result presentation.
 * Results go to stdout by default; `--stdout` exports route them to stderr so
 * the exported data is the only thing on stdout.
 */

import { errorMessage } from "./errors.js";
import type { CliResult } from "./types.js";

type Stream = "stdout" | "stderr";

const HIDDEN_FIELDS = new Set(["ok", "command", "message"]);

function write(stream: Stream, line: string): void {
  (stream === "stderr" ? process.stderr : process.stdout).write(line + "\n");
}

function humanLabel(key: string): string {
  const spaced = key.replace(/([a-z0-9])([A-Z])/g, "$1 $2");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

interface KeyRow {
  id: string;
  family?: string;
  purpose?: string;
  kind?: string;
  status?: string;
  publicKey?: string;
  standard?: string;
}

function isKeyRows(value: unknown): value is KeyRow[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every(
      (item) =>
        typeof item === "object" &&
        item !== null &&
        typeof (item as KeyRow).id === "string",
    )
  );
}

function printKeyTable(stream: Stream, rows: KeyRow[]): void {
  const all: Array<[string, (row: KeyRow) => string]> = [
    ["ID", (row: KeyRow) => row.id],
    ["Purpose", (row: KeyRow) => row.purpose ?? ""],
    ["Kind", (row: KeyRow) => row.kind ?? ""],
    ["Status", (row: KeyRow) => row.status ?? ""],
    ["Standard", (row: KeyRow) => row.standard ?? ""],
    ["Public key", (row: KeyRow) => row.publicKey ?? ""],
  ];
  const columns = all.filter(([, get]) => rows.some((row) => get(row) !== ""));

  const widths = columns.map(([title, get]) =>
    Math.max(title.length, ...rows.map((row) => get(row).length)),
  );

  const line = (cells: string[]) =>
    "  " + cells.map((cell, i) => cell.padEnd(widths[i]!)).join("  ").trimEnd();

  write(stream, line(columns.map(([title]) => title)));
  write(stream, line(widths.map((width) => "─".repeat(width))));

  for (const row of rows) {
    write(stream, line(columns.map(([, get]) => get(row))));
  }
}

function printField(stream: Stream, label: string, value: unknown): void {
  if (value === undefined || value === null || value === "") return;

  const prefix = `${humanLabel(label).padEnd(20)} `;

  if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
    if (value.length === 0) return;
    write(stream, prefix + value.join(", "));
    return;
  }

  if (isKeyRows(value)) {
    write(stream, humanLabel(label));
    printKeyTable(stream, value);
    return;
  }

  if (typeof value === "object") {
    write(stream, prefix + JSON.stringify(value));
    return;
  }

  write(stream, prefix + String(value));
}

export function printResult(result: CliResult, stream: Stream = "stdout"): void {
  if (!result.ok) {
    process.stderr.write(`✘ ${result.message}\n`);
    return;
  }

  write(stream, `→ ${result.message}`);

  for (const [key, value] of Object.entries(result)) {
    if (!HIDDEN_FIELDS.has(key)) printField(stream, key, value);
  }
}

export function printJsonResult(result: CliResult): void {
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
}

export function printFailure(error: unknown, json = false): void {
  const message = errorMessage(error);

  if (json) {
    printJsonResult({ ok: false, command: "error", message });
    return;
  }

  process.stderr.write(`✘ ${message}\n`);
}

/** Print a warning block to stderr. */
export function printWarning(lines: string[]): void {
  const width = Math.min(
    78,
    Math.max(...lines.map((line) => line.length)) + 4,
  );
  const bar = "═".repeat(width);

  process.stderr.write(`\n${bar}\n`);
  for (const line of lines) process.stderr.write(`  ${line}\n`);
  process.stderr.write(`${bar}\n\n`);
}

export function printMnemonic(words: string[]): void {
  const columns = words.length > 12 ? 3 : 2;
  const rows = Math.ceil(words.length / columns);

  printWarning([
    "WRITE THIS RECOVERY PHRASE DOWN. It is shown ONCE.",
    "It is the only way to recover this key if the file or passphrase is lost.",
    "Anyone who has it controls this key. Never store it online.",
  ]);

  for (let row = 0; row < rows; row++) {
    let line = "  ";

    for (let col = 0; col < columns; col++) {
      const index = row + col * rows;
      const word = words[index];
      if (word === undefined) continue;
      line += `${String(index + 1).padStart(2)}. ${word}`.padEnd(24);
    }

    process.stderr.write(line.trimEnd() + "\n");
  }

  process.stderr.write("\n");
}
