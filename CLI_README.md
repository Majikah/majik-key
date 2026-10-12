# Majik Key CLI

`majik-key` is the command-line interface for **Majik Key**, the post-quantum-ready seed-phrase account library for the Majikah ecosystem. It lets you create, inspect, edit, export, back up, and restore Majik Keys from a terminal, with no code required.

One recovery phrase (a BIP-39 mnemonic) deterministically produces a whole set of keypairs:

- **X25519** and **ML-KEM-768 (FIPS-203)** for encryption / key agreement
- **Ed25519** and **ML-DSA-87 (FIPS-204)** for signing
- Optional extras on top: more ML-KEM / ML-DSA sizes, SLH-DSA (FIPS-205), Falcon, **Bitcoin**, **Ethereum**, and **Solana**
- Every secret key is encrypted at rest with your passphrase (**Argon2id** + AES-256-GCM)

The CLI covers the full key lifecycle:

- Generate a brand-new key with a recovery phrase in one command
- Rebuild a key from a phrase you already have, or from a `.json` / `.png` / `.zip` backup
- Inspect a key and list its keypairs without needing the passphrase
- Edit a key's label, change its passphrase, upgrade legacy keys, add new keypairs
- Export as normal JSON, **dangerous** (raw, unencrypted) JSON, or public contact JSON
- Write recovery-phrase backups as JSON, PNG, or ZIP
- Machine-readable JSON output and non-interactive use for scripts and CI

The npm package is:

```text
@majikah/majik-key
```

The executable exposed by the package is:

```text
majik-key
```

---

## Table of Contents

- [Majik Key CLI](#majik-key-cli)
  - [Table of Contents](#table-of-contents)
  - [Quick Start](#quick-start)
    - [Run directly with `npx`](#run-directly-with-npx)
    - [Install globally](#install-globally)
    - [Your first key in 30 seconds](#your-first-key-in-30-seconds)
- [Feature Overview](#feature-overview)
- [Available Commands](#available-commands)
- [Core Concepts](#core-concepts)
  - [The key file vs. the recovery phrase](#the-key-file-vs-the-recovery-phrase)
  - [File formats this CLI reads and writes](#file-formats-this-cli-reads-and-writes)
  - [Which keypairs a key contains](#which-keypairs-a-key-contains)
  - [Choosing extra keypairs with `--keys`](#choosing-extra-keypairs-with---keys)
- [Secrets: Passphrases and Recovery Phrases](#secrets-passphrases-and-recovery-phrases)
  - [Passphrase resolution](#passphrase-resolution)
  - [Which command needs which secret](#which-command-needs-which-secret)
  - [Recovery phrase input](#recovery-phrase-input)
  - [Interactive use](#interactive-use)
  - [Non-interactive use](#non-interactive-use)
- [Where Files Are Saved](#where-files-are-saved)
  - [The `--output` rules](#the---output-rules)
  - [Default file names](#default-file-names)
  - [Overwriting and permissions](#overwriting-and-permissions)

---

## Quick Start

### Run directly with `npx`

```bash
npx @majikah/majik-key --help
```

Pin a specific version for reproducible automation:

```bash
npx @majikah/majik-key@<version> --help
```

### Install globally

```bash
npm install -g @majikah/majik-key
```

Then use:

```bash
majik-key --help
majik-key --version
```

### Your first key in 30 seconds

```bash
npx @majikah/majik-key generate
```

What happens:

1. You are asked to **set a passphrase** (typed twice, hidden, never stored in shell history).
2. A **24-word recovery phrase** is shown once. Write it down.
3. You are asked to **type back 3 random words** to prove you wrote it down.
4. The encrypted key file is saved **in the folder you ran the command from**, for example:

```text
→ Majik Key saved.
Key File             /home/you/project/majik-key-AbC123xy.json
Format               passphrase-encrypted JSON
Fingerprint          AbC123xy...
Keys                 classic:x25519, classic:ed25519, pq:ml-kem-768, pq:ml-dsa-87, web3:sol
```

Want a shorter phrase? Use `--size 12`:

```bash
npx @majikah/majik-key generate --size 12
```

---

# Feature Overview

| Feature                        | CLI support | Purpose                                                                   |
| ------------------------------ | ----------- | ------------------------------------------------------------------------- |
| Generate a new key             | Yes         | New recovery phrase + key in one step (12 or 24 words).                   |
| Create from an existing phrase | Yes         | Rebuild a key from a phrase you typed or stored in a file.                |
| Restore from a backup          | Yes         | Import a `.json`, `.png`, or `.zip` recovery-phrase backup.               |
| Inspect without a passphrase   | Yes         | `info` and `keys` read only public, non-secret data.                      |
| Verify a passphrase            | Yes         | Check a passphrase against a key file (exit code `1` if wrong).           |
| Edit label                     | Yes         | Show or change the human-readable key name.                               |
| Change passphrase              | Yes         | Re-encrypt every secret key under a new passphrase and fresh salt.        |
| Upgrade legacy keys            | Yes         | Move old PBKDF2 keys to Argon2id (`migrate`).                             |
| Add keypairs later             | Yes         | Add Bitcoin, Ethereum, and more to an existing key (`add-keys`).          |
| Export normal JSON             | Yes         | Passphrase-encrypted key file; safe at rest.                              |
| Export dangerous JSON          | Yes         | Raw, unencrypted private keys, behind explicit safety gates.              |
| Export public contact JSON     | Yes         | Shareable public identity, no secrets.                                    |
| Recovery-phrase backups        | Yes         | Write JSON, PNG, or ZIP backups (`backup`).                               |
| Pipe to other tools            | Yes         | `export --stdout` prints data to stdout for secrets managers.             |
| JSON output                    | Yes         | `--json` on every command for scripts and CI.                             |
| Passphrase from stdin or env   | Yes         | `--passphrase-stdin` and `MAJIK_KEY_PASSPHRASE` for non-interactive runs. |
| Passphrase as an argument      | **No**      | Deliberately unsupported: it would end up in shell history.               |
| 10 mnemonic languages          | Yes         | `en`, `fr`, `es`, `it`, `ja`, `ko`, `pt`, `czech`, `zh-cn`, `zh-tw`.      |

---

# Available Commands

| Command                         | Main purpose                                       |             Needs a passphrase?             | Needs the recovery phrase? | Typical output                    |
| ------------------------------- | -------------------------------------------------- | :-----------------------------------------: | :------------------------: | --------------------------------- |
| `majik-key --help`              | Show CLI help                                      |                     No                      |             No             | Help text                         |
| `majik-key --version`           | Show installed CLI version                         |                     No                      |             No             | Version string                    |
| `majik-key generate`            | Create a brand-new key (alias: `new`)              |              Yes (new, twice)               |     Generated for you      | Key file (+ optional phrase file) |
| `majik-key create`              | Create a key from a phrase you already have        |              Yes (new, twice)               |            Yes             | Key file                          |
| `majik-key import <backup>`     | Restore a key from a `.json`/`.png`/`.zip` backup  |              Yes (new, twice)               |      Read from backup      | Key file                          |
| `majik-key info <key>`          | Show non-secret key details                        |                     No                      |             No             | Key summary                       |
| `majik-key keys [key]`          | List a key's keypairs, or all supported algorithms |                     No                      |             No             | Table of keypairs                 |
| `majik-key verify <key>`        | Check a passphrase                                 |               Yes (existing)                |             No             | Pass/fail + exit code             |
| `majik-key label <key> [label]` | Show or change the label                           |                     No                      |             No             | Updated key file                  |
| `majik-key passphrase <key>`    | Change the passphrase                              |              Yes (old and new)              |             No             | Updated key file                  |
| `majik-key migrate <key>`       | Upgrade legacy PBKDF2 to Argon2id                  |               Yes (existing)                |             No             | Updated key file                  |
| `majik-key add-keys <key>`      | Add keypairs the key doesn't have yet              |               Yes (existing)                |            Yes             | Updated key file                  |
| `majik-key export <key>`        | Serialize: normal, dangerous, or contact JSON      | Only for `--dangerous` on an encrypted file |             No             | JSON file or stdout               |
| `majik-key backup <key>`        | Write a recovery-phrase backup                     |                     No                      |            Yes             | `.json` / `.png` / `.zip` backup  |

---

# Core Concepts

## The key file vs. the recovery phrase

A Majik Key has two separate things you must protect, and they do different jobs.

| Thing                  | What it is                                                      | Protects against                                  | If you lose it                                                                                              |
| ---------------------- | --------------------------------------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **Key file** (`.json`) | Your keypairs, each secret key encrypted with your passphrase.  | Daily use: signing, decrypting, exporting.        | Rebuild it from the recovery phrase with `create` or `import`.                                              |
| **Recovery phrase**    | 12 or 24 words that deterministically regenerate every keypair. | Losing the key file or forgetting the passphrase. | The key file still works, but you can never recover from a lost file, and `add-keys`/`backup` stop working. |
| **Passphrase**         | Encrypts the secret keys inside the key file.                   | Someone stealing the key file.                    | The key file becomes unusable. Recreate it from the recovery phrase.                                        |

> **Rule of thumb:** the **recovery phrase** is the master secret. Anyone who has it controls every key, forever. The **key file** is only safe to leave lying around because it is encrypted. Write the phrase on paper; keep it offline.

## File formats this CLI reads and writes

| Format                        | Contains                                       | Safe at rest? | Written by                                      | Read by                                                                   |
| ----------------------------- | ---------------------------------------------- | :-----------: | ----------------------------------------------- | ------------------------------------------------------------------------- |
| **Normal key JSON** (default) | Public keys + passphrase-encrypted secret keys |      Yes      | `generate`, `create`, `import`, `export`, edits | All key commands                                                          |
| **Registry-only JSON**        | Same, without legacy pre-registry fields       |      Yes      | `--registry-only`                               | All key commands (older library versions can't read it)                   |
| **Dangerous JSON**            | **Raw, unencrypted** private keys              |    **NO**     | `--dangerous`                                   | `info`, `keys`, `label`, `export` (see [Dangerous JSON](#dangerous-json)) |
| **Contact JSON**              | Public keys only                               | Yes (public)  | `export --contact`                              | Majik contact tooling                                                     |
| **Mnemonic JSON**             | The recovery phrase in **plaintext**           |    **NO**     | `--mnemonic-out`, `backup -f json`              | `create --mnemonic-file`, `import`, `add-keys`, `backup`                  |
| **Backup PNG**                | Recovery phrase encoded into an image          |    **NO**     | `backup -f png`                                 | `import`                                                                  |
| **Backup ZIP**                | PNG + JSON + a README                          |    **NO**     | `backup -f zip`                                 | `import`                                                                  |

> "Safe at rest" means safe to store on disk without extra protection, apart from normal file hygiene. Everything marked **NO** gives full control of your key to anyone who can read it.

## Which keypairs a key contains

Every new key always contains the **core four**:

| Keypair           | Used for                                                |
| ----------------- | ------------------------------------------------------- |
| `classic:x25519`  | Classical key agreement; the key's fingerprint/identity |
| `classic:ed25519` | Classical signatures                                    |
| `pq:ml-kem-768`   | Post-quantum encryption (FIPS-203)                      |
| `pq:ml-dsa-87`    | Post-quantum signatures (FIPS-204)                      |

`web3:sol` (Solana) is a **derived view** of the Ed25519 key, so every key can produce a Solana address without storing anything extra.

Everything else is **opt-in**: you choose extras when you create the key (`--keys`) or add them later (`add-keys`).

## Choosing extra keypairs with `--keys`

`--keys` (short: `-k`) takes a comma-separated list, and can be repeated. You can use the full id (`web3:btc`) or just the part after the colon (`btc`).

| Short name                                 | Full id                           | Kind                                          |
| ------------------------------------------ | --------------------------------- | --------------------------------------------- |
| `btc`                                      | `web3:btc`                        | Bitcoin (BIP-32 / BIP-84)                     |
| `eth`                                      | `web3:eth`                        | Ethereum (BIP-44)                             |
| `sol`                                      | `web3:sol`                        | Solana (derived; already included)            |
| `ml-kem-512`                               | `pq:ml-kem-512`                   | Post-quantum KEM                              |
| `ml-kem-1024`                              | `pq:ml-kem-1024`                  | Post-quantum KEM                              |
| `ml-dsa-44`, `ml-dsa-65`                   | `pq:ml-dsa-44`, `pq:ml-dsa-65`    | Post-quantum signatures                       |
| `slh-dsa-sha2-128s` … `slh-dsa-shake-256f` | `pq:slh-dsa-…`                    | Hash-based signatures (FIPS-205), 12 variants |
| `falcon-512`, `falcon-1024`                | `pq:falcon-512`, `pq:falcon-1024` | Falcon (experimental)                         |

See the live list for your installed version at any time:

```bash
majik-key keys --supported
```

Examples:

```bash
majik-key generate --keys btc,eth
majik-key generate -k btc -k eth          # same thing
majik-key generate --keys web3:btc,pq:ml-dsa-65
```

Algorithms that are defined but not usable yet (HQC, FN-DSA, LMS) are rejected with a clear error.

---

# Secrets: Passphrases and Recovery Phrases

**The CLI never accepts a passphrase or recovery phrase as a command-line argument.** Anything you type after a command is saved in your shell history and visible to other processes. Secrets come from safer places instead.

## Passphrase resolution

The CLI looks for a passphrase in this order:

1. `--passphrase-stdin` (first line of standard input), on commands that offer it
2. The `MAJIK_KEY_PASSPHRASE` environment variable
3. A **hidden interactive prompt**

The `passphrase` command also uses `MAJIK_KEY_NEW_PASSPHRASE` for the new passphrase.

## Which command needs which secret

| Command                                            | Passphrase                                                                                  | `--passphrase-stdin` | Recovery phrase                                    |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------- | :------------------: | -------------------------------------------------- |
| `generate`                                         | **New**; typed twice when prompting                                                         |         Yes          | Generated and shown to you                         |
| `create`                                           | **New**; typed twice when prompting                                                         |         Yes          | Prompt, `MAJIK_KEY_MNEMONIC`, or `--mnemonic-file` |
| `import`                                           | **New**; typed twice when prompting                                                         |         Yes          | Read from the backup file                          |
| `verify`                                           | Existing                                                                                    |         Yes          | No                                                 |
| `migrate`                                          | Existing                                                                                    |         Yes          | No                                                 |
| `export --dangerous`                               | Existing (not needed if the input is already a dangerous file)                              |         Yes          | No                                                 |
| `passphrase`                                       | Current (`MAJIK_KEY_PASSPHRASE` / prompt) **and** new (`MAJIK_KEY_NEW_PASSPHRASE` / prompt) |          No          | No                                                 |
| `add-keys`                                         | Existing (`MAJIK_KEY_PASSPHRASE` / prompt)                                                  |          No          | Prompt, `MAJIK_KEY_MNEMONIC`, or `--mnemonic-file` |
| `backup`                                           | **Not needed**                                                                              |          —           | Prompt, `MAJIK_KEY_MNEMONIC`, or `--mnemonic-file` |
| `info`, `keys`, `label`, `export` (normal/contact) | **Not needed**                                                                              |          —           | No                                                 |

## Recovery phrase input

Where a command needs your phrase (`create`, `add-keys`, `backup`), it is read from:

1. `--mnemonic-file <path>`, if given
2. The `MAJIK_KEY_MNEMONIC` environment variable
3. A **hidden interactive prompt**

A `--mnemonic-file` may be either:

- A **plain text** file with the words separated by spaces or newlines, or
- A **Mnemonic JSON** file (what `--mnemonic-out` and `backup -f json` write):

```json
{
  "id": "…",
  "seed": ["word1", "word2", "…"],
  "language": "en",
  "version": 1
}
```

Phrases are normalized (lower-cased, extra whitespace collapsed) and must be **12, 15, 18, 21, or 24 words**.

## Interactive use

```bash
majik-key generate
```

You will see prompts like:

```text
Set a passphrase:
Confirm passphrase:
```

Typing is hidden. Backspace works, Ctrl-C cancels (exit code `130`). A passphrase can't be empty, and a warning appears if it is shorter than 8 characters.

## Non-interactive use

PowerShell:

```powershell
$env:MAJIK_KEY_PASSPHRASE="your-passphrase"
```

Bash/Zsh:

```bash
export MAJIK_KEY_PASSPHRASE="your-passphrase"
```

Then:

```bash
majik-key verify ./majik-key-AbC123xy.json
```

Or pipe it in from a secrets tool so it never touches shell history:

```bash
your-secrets-tool get majik-passphrase | majik-key verify ./key.json --passphrase-stdin
```

> **Security note:** environment variables can be exposed by process inspection, CI configuration, logs, or debugging tools. Use your CI platform's secret mechanism for production automation. Avoid typing `echo "secret" | majik-key …` directly: the `echo` line is itself saved in your shell history.

---

# Where Files Are Saved

## The `--output` rules

Every command that writes a file accepts `-o, --output <path>`. The rules are the same everywhere:

| You pass                                    | Result                                                                                         |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Nothing                                     | Saved in the **current directory** (where you ran the command) with a default name.            |
| An existing folder, or a path ending in `/` | Saved inside that folder with the default name. Missing folders are created.                   |
| A path with an extension (`./alice.json`)   | Used exactly as the file path.                                                                 |
| A path with no extension (`./alice`)        | Treated as a file name; the right extension is added (`.json`, or `.png`/`.zip` for `backup`). |

Commands that **edit** an existing key (`label`, `passphrase`, `migrate`, `add-keys`) default to **editing the file in place** instead of the current directory. Pass `-o` to write a copy elsewhere and leave the original untouched.

## Default file names

| File                 | Default name                                      | Example                                   |
| -------------------- | ------------------------------------------------- | ----------------------------------------- |
| Key file             | `majik-key-<label>-<fingerprint8>.json`           | `majik-key-alice-AbC123xy.json`           |
| Key file (no label)  | `majik-key-<fingerprint8>.json`                   | `majik-key-AbC123xy.json`                 |
| Dangerous key file   | `majik-key-<label>-<fingerprint8>.dangerous.json` | `majik-key-alice-AbC123xy.dangerous.json` |
| Recovery phrase file | `majik-key-<label>-<fingerprint8>.mnemonic.json`  | `majik-key-alice-AbC123xy.mnemonic.json`  |
| Public contact       | `majik-contact-<fingerprint8>.json`               | `majik-contact-AbC123xy.json`             |
| Backup               | `majik-key-<label>-<fingerprint8>-backup.<ext>`   | `majik-key-alice-AbC123xy-backup.zip`     |

The label is made filename-safe (letters, digits, `-`, `_`).

## Overwriting and permissions

- The CLI **never replaces an existing file** unless you add `--overwrite`. (Editing a key **in place** is the one exception: that is the whole point of those commands.)
- Every file it writes is created **owner-read/write only** (`0600`) on systems that support permissions, because any of them can hold key material.
- Writes that replace a file go through a temporary file and a rename, so a crash can't leave a half-written key behind.