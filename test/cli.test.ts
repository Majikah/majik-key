import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createProgram, runProgram } from "../src/cli.js";

const PASS = "correct horse battery staple";

let dir: string;
let stdout: string;
let stderr: string;

async function run(...args: string[]): Promise<number> {
  process.exitCode = undefined;
  stdout = "";
  stderr = "";

  const out = vi
    .spyOn(process.stdout, "write")
    .mockImplementation((chunk: any) => ((stdout += String(chunk)), true));
  const err = vi
    .spyOn(process.stderr, "write")
    .mockImplementation((chunk: any) => ((stderr += String(chunk)), true));

  try {
    await runProgram(createProgram("test"), ["node", "majik-key", ...args]);
    return Number(process.exitCode ?? 0);
  } finally {
    out.mockRestore();
    err.mockRestore();
    process.exitCode = undefined;
  }
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "majik-key-cli-"));
  process.env.MAJIK_KEY_PASSPHRASE = PASS;
});

afterEach(async () => {
  delete process.env.MAJIK_KEY_PASSPHRASE;
  delete process.env.MAJIK_KEY_NEW_PASSPHRASE;
  await rm(dir, { recursive: true, force: true });
});

describe("majik-key CLI", () => {
  it("generate saves a 24-word key into the output directory by default size", async () => {
    const code = await run(
      "generate", "-o", `${dir}/`, "--label", "alice", "--mnemonic-out", "--json",
    );
    expect(code).toBe(0);

    const result = JSON.parse(stdout);
    expect(result.ok).toBe(true);
    expect(result.keyFile.startsWith(dir)).toBe(true);

    const mnemonic = JSON.parse(await readFile(result.mnemonicFile, "utf8"));
    expect(mnemonic.seed).toHaveLength(24);

    const key = JSON.parse(await readFile(result.keyFile, "utf8"));
    expect(key.label).toBe("alice");
    expect(key.privateKeyBase64).toBeUndefined();
  }, 60_000);

  it("generate --size 12 produces a 12-word phrase", async () => {
    const code = await run(
      "generate", "--size", "12", "-o", `${dir}/`, "--mnemonic-out", "--json",
    );
    expect(code).toBe(0);
    const { mnemonicFile } = JSON.parse(stdout);
    expect(JSON.parse(await readFile(mnemonicFile, "utf8")).seed).toHaveLength(12);
  }, 60_000);

  it("rejects an invalid --size", async () => {
    expect(await run("generate", "--size", "18")).toBe(2);
  });

  it("refuses to overwrite without --overwrite", async () => {
    const file = join(dir, "k.json");
    expect(await run("generate", "--size", "12", "-o", file)).toBe(0);
    expect(await run("generate", "--size", "12", "-o", file, "--json")).toBe(1);
    expect(JSON.parse(stdout).message).toMatch(/--overwrite/);
  }, 60_000);

  it("info / keys / verify work, and verify fails on a wrong passphrase", async () => {
    const file = join(dir, "k.json");
    await run("generate", "--size", "12", "-o", file);

    expect(await run("info", file, "--json")).toBe(0);
    expect(JSON.parse(stdout).coreComplete).toBe(true);

    expect(await run("keys", file, "--json")).toBe(0);
    expect(JSON.parse(stdout).keys.map((k: any) => k.id)).toContain("pq:ml-dsa-87");

    expect(await run("verify", file)).toBe(0);

    process.env.MAJIK_KEY_PASSPHRASE = "not the passphrase";
    expect(await run("verify", file)).toBe(1);
  }, 120_000);

  it("label edits the file in place", async () => {
    const file = join(dir, "k.json");
    await run("generate", "--size", "12", "-o", file);
    expect(await run("label", file, "renamed")).toBe(0);
    expect(JSON.parse(await readFile(file, "utf8")).label).toBe("renamed");
  }, 60_000);

  it("passphrase changes the passphrase", async () => {
    const file = join(dir, "k.json");
    await run("generate", "--size", "12", "-o", file);

    process.env.MAJIK_KEY_NEW_PASSPHRASE = "a brand new passphrase";
    expect(await run("passphrase", file)).toBe(0);

    expect(await run("verify", file)).toBe(1); // old passphrase
    process.env.MAJIK_KEY_PASSPHRASE = "a brand new passphrase";
    expect(await run("verify", file)).toBe(0);
  }, 180_000);

  it("dangerous export is gated and, when allowed, contains raw keys", async () => {
    const file = join(dir, "k.json");
    await run("generate", "--size", "12", "-o", file);

    expect(await run("export", file, "--dangerous", "-o", join(dir, "d.json"))).toBe(2);
    const out = join(dir, "d.json");
    expect(
      await run("export", file, "--dangerous", "--i-understand-the-risk", "--yes", "-o", out),
    ).toBe(0);
    const dangerous = JSON.parse(await readFile(out, "utf8"));
    expect(typeof dangerous.privateKeyBase64).toBe("string");
  }, 120_000);

  it("create restores the same account from a mnemonic file", async () => {
    const first = join(dir, "a.json");
    await run("generate", "--size", "12", "-o", first, "--mnemonic-out", join(dir, "m.json"));

    const second = join(dir, "b.json");
    expect(await run("create", "--mnemonic-file", join(dir, "m.json"), "-o", second)).toBe(0);

    const a = JSON.parse(await readFile(first, "utf8"));
    const b = JSON.parse(await readFile(second, "utf8"));
    expect(b.fingerprint).toBe(a.fingerprint);
  }, 120_000);

  it("add-keys rejects a mnemonic that belongs to another account", async () => {
    const file = join(dir, "k.json");
    await run("generate", "--size", "12", "-o", file);

    const bad = join(dir, "bad.txt");
    await writeFile(
      bad,
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );

    expect(await run("add-keys", file, "--keys", "btc", "--mnemonic-file", bad)).toBe(1);
    expect((await readdir(dir)).filter((f) => f.endsWith(".tmp"))).toHaveLength(0);
  }, 120_000);
});
