# Security Policy

This document describes the security model of `@majikah/majik-key`, what it does and does not guarantee, and how to report a vulnerability. It is written to match the actual implementation — if something here looks inconsistent with the code, please [report it](#reporting-a-vulnerability).

---

## Table of Contents

- [Security Policy](#security-policy)
  - [Table of Contents](#table-of-contents)
  - [Reporting a Vulnerability](#reporting-a-vulnerability)
  - [Security Model](#security-model)
    - [What this library actually does](#what-this-library-actually-does)
    - [Deterministic multi-key identity](#deterministic-multi-key-identity)
    - [Encrypted key vault](#encrypted-key-vault)
    - [Post-quantum coverage](#post-quantum-coverage)
    - [Key derivation and domain separation](#key-derivation-and-domain-separation)
    - [X25519 and Ed25519 relationship](#x25519-and-ed25519-relationship)
    - [Recovery and compatibility](#recovery-and-compatibility)
    - [Secret lifecycle and locking](#secret-lifecycle-and-locking)
    - [Atomic state transitions](#atomic-state-transitions)
  - [Scope](#scope)
    - [In scope](#in-scope)
    - [Out of scope](#out-of-scope)
  - [Known Limitations \& Non-Goals](#known-limitations--non-goals)
  - [Dependency \& Supply Chain](#dependency--supply-chain)
  - [Secure Usage Guidelines](#secure-usage-guidelines)
  - [Cryptographic Details](#cryptographic-details)
  - [Disclosure Policy](#disclosure-policy)
  - [Contact](#contact)

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via:

**Email** — [business@majikah.solutions](mailto:business@majikah.solutions), preferably with `SECURITY` in the subject line.

Please include:

* A description of the issue and its potential impact
* Steps to reproduce, or a minimal proof-of-concept
* The affected version(s), and whether the issue is in this package or a dependency
* Whether the issue concerns the core key-management path, derivation, encrypted storage, recovery, or the experimental Web3 functionality
* Any relevant runtime information (browser, Node.js, operating system, etc.)

**This is an independently maintained project — response times are best-effort, not a contractual SLA.**

We aim to acknowledge reports as soon as reasonably possible, investigate in good faith, and prioritize confirmed issues according to severity and exploitability.

We ask that reporters give us a reasonable opportunity to investigate and address an issue before public disclosure.

We do not currently operate a paid bug bounty program.

---

## Security Model

### What this library actually does

Majik Key is a **deterministic cryptographic identity and key-management library**.

A 12- or 24-word BIP-39 mnemonic acts as the root recovery secret. From that seed, Majik Key can deterministically derive a registry of classical, post-quantum, and experimental Web3 key material.

The resulting private key material is encrypted at rest using **AES-256-GCM**, with an encryption key derived from the account passphrase using **Argon2id**.

Majik Key is designed to provide:

* Deterministic key generation and recovery
* Multi-algorithm key management
* Encrypted private-key storage
* Post-quantum key support
* Local-first key derivation
* Password-protected account unlocking
* Explicit secret lifecycle management
* Backward-compatible account migration

It does **not** provide a centralized recovery service, a master recovery key, or a guarantee that JavaScript memory can be cryptographically erased from a compromised process.

### Deterministic multi-key identity

Every new account contains the four core keypairs:

| Key               | Algorithm  | Purpose                              |
| ----------------- | ---------- | ------------------------------------ |
| `classic:x25519`  | X25519     | Identity and classical key agreement |
| `classic:ed25519` | Ed25519    | Classical signing                    |
| `pq:ml-kem-768`   | ML-KEM-768 | Post-quantum key encapsulation       |
| `pq:ml-dsa-87`    | ML-DSA-87  | Post-quantum signing                 |

Additional algorithms can be explicitly requested through the key registry.

Supported stable optional families include:

* ML-KEM-512 / ML-KEM-1024
* ML-DSA-44 / ML-DSA-65
* SLH-DSA parameter sets

Experimental support includes:

* Falcon
* Bitcoin
* Ethereum
* Solana

The registry is designed so that adding another key does not alter the derivation of keys that already exist.

### Encrypted key vault

Majik Key's normal account representation does not persist private keys in plaintext.

Stored secret material is encrypted with:

* **AES-256-GCM**
* A per-account vault key derived from the passphrase
* **Argon2id**
* A separate random IV for each stored key

The current Argon2id configuration is:

* **64 MB memory**
* **3 iterations**
* **4 parallel lanes**

A WASM implementation is used through `hash-wasm` where available, with a pure-JavaScript fallback based on `@noble/hashes`.

The fallback is intended to be bit-identical with the WASM implementation and does not intentionally weaken the KDF parameters.

The vault key is derived once per operation and reused across the account's encrypted key entries rather than running a separate KDF for every algorithm.

### Post-quantum coverage

Majik Key includes NIST-standardized post-quantum algorithms alongside classical primitives:

* **ML-KEM — FIPS 203**
* **ML-DSA — FIPS 204**
* **SLH-DSA — FIPS 205**

The default account contains ML-KEM-768 and ML-DSA-87.

This is a defense-in-depth and migration-ready design. It is **not** a claim that the classical algorithms are currently broken.

SLH-DSA is stable but some `s` parameter sets are substantially slower in JavaScript and may block a browser UI thread. Applications using them should consider a Web Worker or equivalent isolated execution environment.

Falcon support is explicitly experimental. The Falcon identifiers represent the Falcon submission rather than a finalized FN-DSA / FIPS 206 implementation.

LMS/HSS is intentionally not supported because it is stateful and its signing-state requirements conflict with deterministic mnemonic recovery, backups, restores, and multi-device workflows.

### Key derivation and domain separation

Majik Key deterministically derives key material from the BIP-39 seed.

The original core derivation recipes are frozen and protected by known-answer test vectors so that a future release does not silently change the keys produced from an existing mnemonic.

Core derivation includes:

| Key        | Derivation                                     |
| ---------- | ---------------------------------------------- |
| X25519     | Ed25519 key converted through `ed2curve`       |
| Ed25519    | BIP-39 seed-derived                            |
| ML-KEM-768 | Full 64-byte BIP-39 seed                       |
| ML-DSA-87  | Domain-separated hash of the BIP-39 seed       |
| Bitcoin    | BIP-32/84, Majik domain-separated path         |
| Ethereum   | BIP-32/44, standard Ethereum path              |
| Solana     | Domain-separated from the Ed25519 signing seed |

Additional algorithms use a versioned **HKDF-SHA512** construction with a per-`KeyId` `info` value.

This domain separation is important: optional algorithms are not intended to receive the same underlying seed material directly, and adding an algorithm must not modify an existing algorithm's derivation.

Each stored key also records its derivation recipe in the serialized registry.

### X25519 and Ed25519 relationship

The X25519 identity/encryption key is derived by converting the account's Ed25519 key through `ed2curve`.

This is intentional and part of the frozen legacy derivation model.

Therefore, X25519 and Ed25519 should **not** be treated as independently generated random keypairs. They have a deterministic cryptographic relationship established by the conversion.

Applications requiring independent key provenance between those protocol roles should account for this design explicitly.

### Recovery and compatibility

The mnemonic is the root recovery secret.

Re-importing the same mnemonic reproduces the same deterministic account identity and key material, subject to the selected key set and documented derivation rules.

This provides a deliberately simple recovery model:

**mnemonic → deterministic keys → encrypted local account**

Legacy accounts remain readable where supported.

In particular:

* Older JSON formats can be loaded and upgraded in memory
* Legacy PBKDF2-protected accounts remain unlockable
* `migrate()` can move legacy accounts to Argon2id
* Existing accounts can be extended with missing algorithms through `addKeys()`
* Older core keys retain their frozen derivation recipes
* Newer serialized registry entries are preserved during round-trips rather than silently discarded

`addKeys()` requires both the account's mnemonic and its current passphrase. The mnemonic must reproduce the account identity/fingerprint, while the passphrase must authenticate the encrypted account.

### Secret lifecycle and locking

`lock()` is intended to minimize the lifetime of secret material in memory.

It:

* Removes secret material from the active account state
* Zeroizes secret buffers in place where the runtime permits
* Clears cached secret Web3 material
* Prevents private-key access until the account is unlocked again

`withAutoLock()` provides a scoped mechanism that re-locks the account after an operation completes, including when the operation throws.

Registry key handles are live views into the account rather than permanent copies of private key material. After locking, private access through the handle fails instead of returning stale key material.

Public-key access remains available when it does not require private material.

### Atomic state transitions

Security-sensitive account operations are designed to behave atomically.

In particular:

* `unlock()` either succeeds completely or leaves the account locked
* `updatePassphrase()` validates and decrypts existing material before committing the new encrypted state
* `migrate()` completes the KDF transition before committing the new account representation
* Failed transitions should not leave a partially migrated mixture of salts, ciphertext, or KDF versions

This is intended to reduce the chance of partially applied security-state changes corrupting the account.

---

## Scope

### In scope

* Key generation and deterministic derivation
* BIP-39 mnemonic validation and seed handling
* Key registry and `KeyId` handling
* X25519 and Ed25519 derivation and storage
* ML-KEM and ML-DSA key derivation and storage
* SLH-DSA key handling
* Experimental Falcon key handling
* AES-256-GCM encryption/decryption of stored private key material
* Argon2id KDF implementation and configuration
* Legacy PBKDF2 compatibility and migration
* Serialization/deserialization and registry persistence
* `toJSON()` / `fromJSON()`
* `exportMnemonicBackup()` / `importFromMnemonicBackup()`
* `toMnemonicJSON()` / `fromMnemonicJSON()`
* `toDangerousJSON()` / `fromDangerousJSON()`
* `lock()` / `unlock()`
* `verify()`
* `updatePassphrase()`
* `migrate()`
* `addKeys()`
* `withAutoLock()`
* Secret-buffer lifecycle and zeroization behavior
* Deterministic recovery guarantees
* Derivation domain separation
* Public/private registry access
* Experimental Bitcoin functionality
* Experimental Ethereum functionality
* Experimental Solana functionality
* Security-relevant serialization or API design issues
* Vulnerabilities that can cause unauthorized private-key disclosure or incorrect key derivation
* Vulnerabilities that cause an attacker to obtain a valid private key or otherwise bypass the account's intended security boundaries

### Out of scope

* Vulnerabilities entirely contained inside upstream dependencies such as `@noble/*`, `@noble/post-quantum`, `@stablelib/*`, `@scure/bip39`, `hash-wasm`, `ed2curve`, or other third-party libraries
* Vulnerabilities in optional Web3 peer dependencies such as `@scure/btc-signer` or `@solana/kit`
* Applications that misuse the documented API in an explicitly unsafe manner
* Social engineering
* Attacks that require arbitrary code execution or unrestricted memory access in the same process
* Malicious browser extensions that already have full page privileges
* Rooted or jailbroken operating systems with unrestricted process inspection
* Loss of a mnemonic where the library is operating as documented
* Weak user-selected passphrases where no cryptographic bypass is involved

Upstream and platform issues may still be worth reporting because they can affect the overall security of an application using Majik Key.

---

## Known Limitations & Non-Goals

Documented honestly, so you can design around them:

* **No guaranteed JavaScript memory erasure.** `lock()` zeroizes buffers where possible, but JavaScript runtimes cannot guarantee that every historical copy of secret material has disappeared from memory. Garbage collection, runtime copies, JIT behavior, debugging facilities, swap, and operating-system behavior can all defeat absolute erasure guarantees.

* **The mnemonic is the master secret.** Anyone who obtains the mnemonic can deterministically reproduce the account's keys. There is no centralized recovery key, backdoor, or administrator override.

* **A passphrase does not replace the mnemonic.** The passphrase protects the encrypted account representation. It is not an alternative recovery secret for a lost mnemonic.

* **Weak passphrases remain weak.** Argon2id raises the cost of offline guessing, but it cannot create entropy that was not present in the original passphrase.

* **`toMnemonicJSON()` is plaintext.** It contains the mnemonic and may contain the supplied passphrase. It is a transport/recovery format, not secure persistent storage.

* **`toDangerousJSON()` bypasses encryption.** It contains raw private-key material and reconstructs an already-unlocked account. It exists for tightly controlled server-side secret injection and is not intended as a backup or normal persistence format.

* **Web3 functionality is experimental.** Bitcoin, Ethereum, and Solana support has a different maturity level from the core key-management functionality and should be independently reviewed before production custody of valuable assets.

* **Standard wallet paths reduce protocol isolation.** Ethereum uses the standard BIP-44 Ethereum path. Majik Key also exposes a standard BIP-84 Bitcoin derivation helper. Those paths improve interoperability but mean the resulting keys are directly controlled by the mnemonic just as they are in other compatible wallets.

* **The default Bitcoin path is Majik-specific.** The stored Bitcoin key uses `m/84'/1971'/0'/0/0`, not the standard BIP-84 mainnet wallet path. Applications must not assume those two derivations produce the same address.

* **Solana protocol separation can be disabled.** The recommended Solana derivation is domain-separated from the Ed25519 signing key. An explicit option exists to reuse the message-signing Ed25519 key directly; doing so removes that protocol separation and is not recommended.

* **Optional algorithms have different maturity levels.** ML-KEM, ML-DSA, and SLH-DSA are standardized, while Falcon is experimental. Algorithms should be selected according to the application's actual security and interoperability requirements rather than simply choosing the largest available parameter set.

* **No independent public security audit.** Majik Key has not undergone a public independent third-party security audit as of this writing. Code review, adversarial testing, and known-answer vectors are not equivalent to a formal external cryptographic audit.

* **No cryptographic guarantee against a compromised host.** If an attacker already controls the process, the operating system, or the user's runtime with sufficient privilege, Majik Key cannot provide a meaningful confidentiality boundary for keys while they are in use.

* **Pre-1.0 API stability.** Until `1.0.0`, minor releases may include breaking changes, including changes to experimental or security-relevant APIs. Review release notes carefully when upgrading.

---

## Dependency & Supply Chain

Majik Key delegates cryptographic primitives to established third-party libraries rather than implementing the underlying algorithms from scratch.

| Dependency                          | Role                                                        |
| ----------------------------------- | ----------------------------------------------------------- |
| `@scure/bip39`                      | BIP-39 mnemonic generation and validation                   |
| `@noble/post-quantum`               | ML-KEM, ML-DSA, and related PQ primitives                   |
| `@noble/hashes`                     | Hashing, HKDF, and pure-JavaScript cryptographic support    |
| `hash-wasm`                         | WASM-accelerated Argon2id implementation                    |
| `ed2curve`                          | Ed25519 ↔ X25519 conversion                                 |
| `@stablelib/*`                      | Supporting classical cryptographic functionality where used |
| `@scure/btc-signer` (optional peer) | Bitcoin-native address / PSBT functionality                 |
| `@solana/kit` (optional peer)       | Solana-native signer and address functionality              |

The exact dependency set may change between releases. The package lockfile and published package metadata are the authoritative dependency sources for a particular release.

Majik Key does not independently reimplement the underlying mathematical primitives above. Vulnerabilities in those primitives should generally be reported upstream as well as to us, because fixing such an issue may require updating the corresponding dependency.

Because supply-chain compromise can occur without a vulnerability in Majik Key's own source, users should:

* Keep dependencies updated
* Review npm security advisories
* Audit their own lockfiles regularly
* Pin dependencies appropriately for security-sensitive deployments
* Verify the provenance of production artifacts where applicable

---

## Secure Usage Guidelines

The most important rules:

* ✅ Back up the **mnemonic offline**. It is the master recovery secret for the entire deterministic identity.

* ✅ Use `toJSON()` / `toString()` for normal persistent account storage.

* ✅ Call `key.lock()` as soon as practical after signing, decrypting, or otherwise using private key material.

* ✅ Prefer `MajikKey.withAutoLock()` for bounded operations where possible so a thrown error does not leave the account unlocked.

* ✅ Use the registry APIs such as `getPublicKey()`, `getPrivateKey(id)`, and `getKeypair(id)` rather than relying on deprecated per-algorithm accessors.

* ✅ Add only the algorithms actually required by the application. Every stored private key increases the amount of secret material that must be protected.

* ✅ Treat Bitcoin, Ethereum, and Solana functionality as experimental until your application's complete Web3 threat model has been reviewed.

* ✅ Treat the mnemonic and all dangerous exports as equivalent to full account compromise.

* ❌ Never log a mnemonic, private key, WIF, Ethereum private key, raw secret-key bytes, `secretKeys`, `toMnemonicJSON()` output, or `toDangerousJSON()` output.

* ❌ Never store `toMnemonicJSON()` output unencrypted as ordinary application data.

* ❌ Never use `toDangerousJSON()` as a backup, database record, client-side persistence format, or general transport format.

* ❌ Never assume `lock()` provides guaranteed forensic destruction of every historical copy of key material from JavaScript memory.

* ❌ Do not assume that an Ethereum or standard BIP-84 Bitcoin address has Majik-specific wallet isolation. Those are standard wallet derivation paths controlled by the mnemonic.

* ❌ Do not reuse a funded mnemonic in untrusted applications or environments merely because the application uses Majik Key.

---

## Cryptographic Details

| Property                             | Value                                          |
| ------------------------------------ | ---------------------------------------------- |
| Root identity material               | BIP-39 mnemonic, 128-bit or 256-bit entropy    |
| Current KDF                          | Argon2id                                       |
| Argon2id memory                      | 64 MB                                          |
| Argon2id iterations                  | 3                                              |
| Argon2id parallel lanes              | 4                                              |
| Legacy KDF                           | PBKDF2-SHA256 (v1)                             |
| Stored-key encryption                | AES-256-GCM                                    |
| Per-key IV                           | Random, stored with the encrypted key material |
| Classical encryption / key agreement | X25519                                         |
| Classical signature                  | Ed25519                                        |
| Post-quantum KEM                     | ML-KEM-768 (NIST FIPS-203)                     |
| Post-quantum signature               | ML-DSA-87 (NIST FIPS-204)                      |
| Additional PQ KEMs                   | ML-KEM-512 / ML-KEM-1024                       |
| Additional PQ signatures             | ML-DSA-44 / ML-DSA-65                          |
| Hash-based signatures                | SLH-DSA (NIST FIPS-205)                        |
| Experimental signatures              | Falcon                                         |
| Optional-key derivation              | HKDF-SHA512, versioned/domain-separated        |
| X25519 relationship                  | Ed25519-derived via `ed2curve`                 |
| Bitcoin stored derivation            | BIP-32/84, `m/84'/1971'/0'/0/0`                |
| Bitcoin standard-wallet helper       | BIP-84 mainnet derivation                      |
| Ethereum derivation                  | BIP-44, `m/44'/60'/0'/0/0`                     |
| Solana default derivation            | Domain-separated from Ed25519 signing material |

Legacy core derivation recipes are frozen and protected by known-answer test vectors.

The registry additionally records derivation metadata for stored keys so that derivation schemes can evolve without silently changing previously established identities.

---

## Disclosure Policy

We follow a **coordinated disclosure** approach:

1. You report privately, per [Reporting a Vulnerability](#reporting-a-vulnerability).

2. We reproduce the issue, assess its severity and affected versions, and work on a fix or mitigation without public disclosure.

3. Once a fix or mitigation is published, we credit the reporter if they wish to be credited.

4. Disclosure timing is coordinated in good faith. We ask that researchers give us a reasonable opportunity to address confirmed issues before publishing technical details.

5. If a report remains unacknowledged for an extended period despite reasonable good-faith attempts to contact us, responsible public disclosure may be appropriate. We would rather support responsible disclosure than have a serious vulnerability remain indefinitely undisclosed because of communication delays.

We do not currently operate a paid bug bounty program.

---

## Contact

* **Security reports**: [business@majikah.solutions](mailto:business@majikah.solutions) (subject: `SECURITY`)
* **Project documentation**: [README](./README.md)
* **License**: [Apache-2.0](./LICENSE)
* **Maintainer**: Josef Elijah Fabian / Zelijah

---

Thank you for helping keep Majik Key and the Majikah ecosystem secure.
