# Majik Key

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

**Majik Key** is a next-generation seed phrase account library for creating and managing mnemonic-based identities. It provides a post-quantum ready, high-security bridge between BIP39 mnemonics and the Majikah ecosystem.

![npm](https://img.shields.io/npm/v/@majikah/majik-key) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-key) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-key) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)



---
- [Majik Key](#majik-key)
  - [Next-Gen Security Architecture](#next-gen-security-architecture)
    - [1. Post-Quantum Ready (ML-KEM)](#1-post-quantum-ready-ml-kem)
    - [2. Argon2id Key Derivation](#2-argon2id-key-derivation)
    - [3. Seamless Auto-Migration](#3-seamless-auto-migration)
  - [Overview](#overview)
    - [What is a Majik Key?](#what-is-a-majik-key)
    - [Use Cases](#use-cases)
  - [Features](#features)
    - [Security \& Post-Quantum Readiness](#security--post-quantum-readiness)
    - [BIP39 Compliance \& Key Derivation](#bip39-compliance--key-derivation)
    - [Developer Experience](#developer-experience)
    - [Import / Export \& Storage](#import--export--storage)
    - [Interoperability](#interoperability)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [API Reference](#api-reference)
    - [Static Methods](#static-methods)
      - [`MajikKey.create(mnemonic, passphrase, label?)`](#majikkeycreatemnemonic-passphrase-label)
      - [`MajikKey.fromJSON(json)`](#majikkeyfromjsonjson)
      - [`MajikKey.fromMnemonicJSON(mnemonicJson, passphrase, label?)`](#majikkeyfrommnemonicjsonmnemonicjson-passphrase-label)
      - [`MajikKey.importFromMnemonicBackup(backup, mnemonic, passphrase, label?)`](#majikkeyimportfrommnemonicbackupbackup-mnemonic-passphrase-label)
      - [`MajikKey.generateMnemonic(strength?)`](#majikkeygeneratemnemonicstrength)
      - [`MajikKey.validateMnemonic(mnemonic)`](#majikkeyvalidatemnemonicmnemonic)
    - [Instance Methods](#instance-methods)
      - [`unlock(passphrase)`](#unlockpassphrase)
      - [`lock()`](#lock)
      - [`verify(passphrase)`](#verifypassphrase)
      - [`updateLabel(newLabel)`](#updatelabelnewlabel)
      - [`updatePassphrase(currentPassphrase, newPassphrase)`](#updatepassphrasecurrentpassphrase-newpassphrase)
      - [`getPrivateKey()`](#getprivatekey)
      - [`getPrivateKeyBase64()`](#getprivatekeybase64)
      - [`toJSON()`](#tojson)
      - [`toString(pretty?)`](#tostringpretty)
      - [`toMnemonicJSON(mnemonic, passphrase?)`](#tomnemonicjsonmnemonic-passphrase)
      - [`exportMnemonicBackup(mnemonic)`](#exportmnemonicbackupmnemonic)
      - [`toContact()`](#tocontact)
      - [`toMajikMessageIdentity(user, options?)`](#tomajikmessageidentityuser-options)
    - [Getters](#getters)
      - [`id: string`](#id-string)
      - [`fingerprint: string`](#fingerprint-string)
      - [`publicKey: CryptoKey | { raw: Uint8Array }`](#publickey-cryptokey---raw-uint8array-)
      - [`publicKeyBase64: string`](#publickeybase64-string)
      - [`label: string`](#label-string)
      - [`backup: string`](#backup-string)
      - [`timestamp: Date`](#timestamp-date)
      - [`isLocked: boolean`](#islocked-boolean)
      - [`isUnlocked: boolean`](#isunlocked-boolean)
      - [`metadata: MajikKeyMetadata`](#metadata-majikkeymetadata)
  - [Usage Examples](#usage-examples)
    - [Example 1: Create and Manage a Key](#example-1-create-and-manage-a-key)
    - [Example 2: Lock/Unlock Pattern](#example-2-lockunlock-pattern)
    - [Example 3: Backup and Recovery](#example-3-backup-and-recovery)
    - [Example 4: Update Passphrase](#example-4-update-passphrase)
    - [Example 5: Verify Passphrase](#example-5-verify-passphrase)
  - [Integration with Majik Message](#integration-with-majik-message)
    - [Importing to Majik Message](#importing-to-majik-message)
    - [Converting to Majik Message Identity](#converting-to-majik-message-identity)
  - [Security Considerations](#security-considerations)
    - [Best Practices](#best-practices)
    - [What NOT to Do](#what-not-to-do)
    - [What TO Do](#what-to-do)
    - [Tips \& Reminders](#tips--reminders)
      - [For Developers](#for-developers)
      - [For Users](#for-users)
  - [Related Projects](#related-projects)
    - [Majik Message](#majik-message)
  - [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)
  - [About the Developer](#about-the-developer)
  - [Contact](#contact)




---

## Next-Gen Security Architecture

Majik Key has been upgraded to meet modern and future cryptographic standards.

### 1. Post-Quantum Ready (ML-KEM)
Every identity now generates a dual-key system derived deterministically from a 64-byte BIP39 seed:
* **X25519 (Curve25519):** Derived from the first 32 bytes of the seed. Used for fingerprints, contact identity, and legacy compatibility.
* **ML-KEM-768 (FIPS-203):** Derived from the full 64-byte seed. Provides post-quantum key encapsulation for "v3" secure envelopes.

### 2. Argon2id Key Derivation
We have transitioned to **Argon2id** (KDF v2) for encrypting private keys at rest.
* **Memory-Hard:** Configured with 128 MB of memory, 4 iterations, and 4 parallelism factors.
* **Brute-Force Resistant:** Engineered to defeat GPU and ASIC-based cracking attempts that easily bypass older PBKDF2 implementations.

### 3. Seamless Auto-Migration
The library handles "Security Debt" automatically during standard workflows:
* **On Import:** `importFromMnemonicBackup()` detects v1 (PBKDF2) accounts and performs a full upgrade to v2. 
* **Deterministic Recovery:** If ML-KEM keys are missing from an old backup, they are re-derived from the mnemonic during the upgrade process.
* **Password Updates:** Changing a passphrase via `updatePassphrase()` automatically migrates the account to the latest Argon2id standard.
---



## Overview

**Majik Key** is a comprehensive library for managing seed phrase-based cryptographic accounts. It provides a secure, intuitive way to create, store, and manage mnemonic-based identities with built-in encryption, backup, and recovery features.

### What is a Majik Key?

A Majik Key is a seed phrase account that:
- Derives cryptographic key pairs from BIP39 mnemonic phrases
- Encrypts private keys at rest with a user-defined passphrase
- Supports secure backup and recovery via mnemonic encryption
- Provides locked/unlocked state management for enhanced security
- Is fully compatible with **Majik Message** and other Majikah products

### Use Cases

- **Majik Message Integration**: Create seed phrase accounts that can be imported directly into Majik Message
- **Cryptographic Identity Management**: Manage multiple identities with deterministic key derivation
- **Secure Messaging**: Generate signing keys for end-to-end encrypted communication
- **Blockchain Applications**: Create wallet-like accounts from mnemonic phrases
- **Majikah Ecosystem**: Use across all Majikah products and services

---

## Features

### Security & Post-Quantum Readiness
- **Post-Quantum Ready**: Implements **ML-KEM-768 (FIPS-203)** for key encapsulation, ensuring identities are secure against future quantum computing threats.
- **Argon2id Key Derivation**: Uses memory-hard **Argon2id** (KDF v2) for passphrase encryption (128 MB / 4 iterations / 4 parallelism), providing industry-leading resistance to GPU/ASIC brute-force attacks.
- **Seamless Auto-Migration**: Automatically detects and upgrades legacy v1 (PBKDF2) accounts to v2 (Argon2id) during import, re-deriving missing ML-KEM keys deterministically from the seed.
- **AES-GCM Authenticated Encryption**: Industry-standard encryption for private keys at rest with unique, per-identity salts and random IVs.
- **Locked/Unlocked States**: Private keys are only decrypted into memory when explicitly unlocked and are purged immediately upon calling `.lock()`.

### BIP39 Compliance & Key Derivation
- **Standard Mnemonic Generation**: Generate high-entropy 12 or 24-word seed phrases (128/256-bit strength).
- **Deterministic Multi-Key Derivation**: 
    - **X25519 (Curve25519)**: Derived from the first 32 bytes of the seed for legacy compatibility and fingerprints.
    - **ML-KEM-768**: Derived from the full 64-byte seed for post-quantum security.
- **Built-in Validation**: Full BIP39 mnemonic validation and error handling.

### Developer Experience
- **First-Class TypeScript Support**: Full type definitions included for all interfaces and classes.
- **Fluent API**: Intuitive method chaining for common operations (e.g., `key.unlock(p).updateLabel(l)`).
- **Comprehensive Error Handling**: Specialized `MajikKeyError` and `CryptoError` classes for precise debugging.
- **Isomorphic Support**: Works across Node.js and modern browser environments.

### Import / Export & Storage
- **Security-Minded JSON Serialization**: Export accounts to JSON format for storage without ever exposing raw private keys or seed phrases.
- **MnemonicJSON Format**: A secure, portable format for seed phrase storage and recovery.
- **Mnemonic-Encrypted Backups**: Export and import specialized backup strings that utilize the mnemonic as a secondary encryption layer.

### Interoperability
- **Majik Message Integration**: Native support for exporting identities compatible with **Majik Message v3** envelopes.
- **Contact Portability**: Convert Majik Keys directly into contact formats for easy sharing of public identities.
- **Ecosystem Ready**: Designed as the core identity provider for all current and future Majikah products.
---

## Installation

```bash
# Using npm
npm install @majikah/majik-key

```

---

## Quick Start

```ts
import { MajikKey } from '@majikah/majik-key';

// Generate a new mnemonic
const mnemonic = MajikKey.generateMnemonic(); // 12 words
console.log('Save this mnemonic:', mnemonic);

// Create a new Majik Key (unlocked state)
const key = await MajikKey.create(mnemonic, 'secure-passphrase', 'My PQ Account');

// 2. Access your keys (requires unlock)
console.log('Fingerprint:', key.fingerprint);
console.log('PQ Ready:', key.metadata.kdfVersion); // 'argon2id'
console.log('Key ID:', key.id);
console.log('Is Unlocked:', key.isUnlocked); // true

// Lock the key (clear private keys from memory)
key.lock();
console.log('Is Locked:', key.isLocked); // true

// Unlock when needed
await key.unlock('my-secure-passphrase');
console.log('Is Unlocked:', key.isUnlocked); // true

// Access private key (only when unlocked)
const privateKey = key.getPrivateKey();
const privateKeyBase64 = key.getPrivateKeyBase64();

// Save to storage (private keys never included)
const json = key.toJSON();
localStorage.setItem('myKey', JSON.stringify(json));

// Load from storage (locked state)
const loadedKey = MajikKey.fromJSON(json);
await loadedKey.unlock('my-secure-passphrase');
```

---

## API Reference

### Static Methods

#### `MajikKey.create(mnemonic, passphrase, label?)`
Create a new Majik Key from a mnemonic phrase. Generates a new Argon2id-protected account.

**Parameters:**
- `mnemonic: string` - BIP39 mnemonic phrase (12-24 words)
- `passphrase: string` - Passphrase to encrypt the private key at rest
- `label?: string` - Optional label for the key

**Returns:** `Promise<MajikKey>` - A new unlocked MajikKey instance

**Example:**
```ts
const mnemonic = 'witch collapse practice feed shame open despair creek road again ice least';
const key = await MajikKey.create(mnemonic, 'my-password', 'Personal Account');

```

---

#### `MajikKey.fromJSON(json)`
Load a Majik Key from JSON (locked state).

**Parameters:**
- `json: MajikKeyJSON | string` - JSON object or string

**Returns:** `MajikKey` - A locked MajikKey instance

**Example:**
```ts
const json = localStorage.getItem('myKey');
const key = MajikKey.fromJSON(json);
await key.unlock('my-password');
```

---

#### `MajikKey.fromMnemonicJSON(mnemonicJson, passphrase, label?)`
Create a Majik Key from MnemonicJSON format. Auto-migrates legacy PBKDF2 accounts to Argon2id + ML-KEM.

**Parameters:**
- `mnemonicJson: MnemonicJSON | string` - MnemonicJSON object or string
- `passphrase: string` - Passphrase to encrypt the key at rest
- `label?: string` - Optional label for the key

**Returns:** `Promise<MajikKey>` - A new unlocked MajikKey instance

**Example:**
```ts
const mnemonicData = {
  id: 'backup-id',
  seed: ['word1', 'word2', ...],
  phrase: 'optional-encryption-phrase'
};

const key = await MajikKey.fromMnemonicJSON(mnemonicData, 'my-password');
```

---

#### `MajikKey.importFromMnemonicBackup(backup, mnemonic, passphrase, label?)`
Import a Majik Key from a mnemonic-encrypted backup. Auto-migrates legacy PBKDF2 accounts to Argon2id + ML-KEM.

**Parameters:**
- `backup: string` - Base64-encoded backup string
- `mnemonic: string` - The mnemonic phrase used to encrypt the backup
- `passphrase: string` - Passphrase to encrypt the imported key
- `label?: string` - Optional label for the key

**Returns:** `Promise<MajikKey>` - A new unlocked MajikKey instance

**Example:**
```ts
const backupString = 'eT8xY2F...'; // From exportMnemonicBackup()
const key = await MajikKey.importFromMnemonicBackup(
  backupString,
  mnemonic,
  'new-password',
  'Restored Account'
);
```

---

#### `MajikKey.generateMnemonic(strength?)`
Generate a new BIP39 mnemonic phrase.

**Parameters:**
- `strength?: 128 | 256` - Entropy strength (128 = 12 words, 256 = 24 words). Default: 128

**Returns:** `string` - A new mnemonic phrase

**Example:**
```ts
const mnemonic12 = MajikKey.generateMnemonic();      // 12 words
const mnemonic24 = MajikKey.generateMnemonic(256);   // 24 words
```

---

#### `MajikKey.validateMnemonic(mnemonic)`
Validate a BIP39 mnemonic phrase.

**Parameters:**
- `mnemonic: string` - Mnemonic phrase to validate

**Returns:** `boolean` - true if valid, false otherwise

**Example:**
```ts
const isValid = MajikKey.validateMnemonic('witch collapse practice...');
```

---

### Instance Methods

#### `unlock(passphrase)`
Unlock the Majik Key by decrypting the private key. Decrypts X25519 and ML-KEM private keys into memory.

**Parameters:**
- `passphrase: string` - Passphrase to decrypt the private key

**Returns:** `Promise<this>` - This instance for chaining

**Throws:** `MajikKeyError` if passphrase is incorrect or key is already unlocked

**Example:**
```ts
await key.unlock('my-password');
```

---

#### `lock()`
Lock the Majik Key by clearing private keys from memory.

**Returns:** `this` - This instance for chaining

**Example:**
```ts
key.lock();
```

---

#### `verify(passphrase)`
Verify that a passphrase can decrypt the private key.

**Parameters:**
- `passphrase: string` - Passphrase to verify

**Returns:** `Promise<boolean>` - true if valid, false otherwise

**Example:**
```ts
const isValid = await key.verify('my-password');
```

---

#### `updateLabel(newLabel)`
Update the label of the Majik Key.

**Parameters:**
- `newLabel: string` - New label value

**Returns:** `this` - This instance for chaining

**Example:**
```ts
key.updateLabel('Work Account');
```

---

#### `updatePassphrase(currentPassphrase, newPassphrase)`
Change the passphrase used to encrypt the private key. Re-encrypts keys and triggers an auto-migration to KDF v2.

**Parameters:**
- `currentPassphrase: string` - Current passphrase
- `newPassphrase: string` - New passphrase

**Returns:** `Promise<this>` - This instance for chaining

**Throws:** `MajikKeyError` if current passphrase is incorrect

**Example:**
```ts
await key.updatePassphrase('old-password', 'new-password');
```

---

#### `getPrivateKey()`
Get the private key (only when unlocked).

**Returns:** `CryptoKey | { raw: Uint8Array }` - The private key

**Throws:** `MajikKeyError` if the key is locked

**Example:**
```ts
const privateKey = key.getPrivateKey();
```

---

#### `getPrivateKeyBase64()`
Get the private key as base64 (only when unlocked).

**Returns:** `string` - The private key in base64 format

**Throws:** `MajikKeyError` if the key is locked

**Example:**
```ts
const privateKeyBase64 = key.getPrivateKeyBase64();
```

---

#### `toJSON()`
Export to JSON format (safe for storage).

**Returns:** `MajikKeyJSON` - JSON representation (private keys never included)

**Example:**
```ts
const json = key.toJSON();
localStorage.setItem('myKey', JSON.stringify(json));
```

---

#### `toString(pretty?)`
Export to JSON string.

**Parameters:**
- `pretty?: boolean` - Whether to pretty-print. Default: false

**Returns:** `string` - JSON string representation

**Example:**
```ts
const jsonString = key.toString(true);
```

---

#### `toMnemonicJSON(mnemonic, passphrase?)`
Export to MnemonicJSON format.

**Parameters:**
- `mnemonic: string` - The BIP39 mnemonic phrase
- `passphrase?: string` - Optional passphrase

**Returns:** `MnemonicJSON` - MnemonicJSON object

**Throws:** `MajikKeyError` if the key is locked

**Example:**
```ts
const mnemonicData = key.toMnemonicJSON(mnemonic, 'encryption-phrase');
```

---

#### `exportMnemonicBackup(mnemonic)`
Export a mnemonic-encrypted backup.

**Parameters:**
- `mnemonic: string` - The original mnemonic phrase

**Returns:** `Promise<string>` - Base64-encoded backup string

**Throws:** `MajikKeyError` if the key is locked

**Example:**
```ts
const backup = await key.exportMnemonicBackup(mnemonic);
```

---

#### `toContact()`
Create a MajikContact from this Majik Key.

**Returns:** `MajikContact` - A MajikContact instance

**Example:**
```ts
const contact = key.toContact();
```

---

#### `toMajikMessageIdentity(user, options?)`
Convert to MajikMessageIdentity for use in Majik Message.

**Parameters:**
- `user: MajikUser` - MajikUser instance
- `options?: { label?: string, restricted?: boolean }` - Optional configuration

**Returns:** `Promise<MajikMessageIdentity>` - MajikMessageIdentity instance

**Example:**
```ts
const identity = await key.toMajikMessageIdentity(user, {
  label: 'My Account',
  restricted: false
});
```

---

### Getters

#### `id: string`
The unique identifier (fingerprint).

#### `fingerprint: string`
The cryptographic fingerprint.

#### `publicKey: CryptoKey | { raw: Uint8Array }`
The public key.

#### `publicKeyBase64: string`
The public key in base64 format.

#### `label: string`
The user-defined label.

#### `backup: string`
The mnemonic backup identifier.

#### `timestamp: Date`
The creation timestamp.

#### `isLocked: boolean`
Whether the key is currently locked.

#### `isUnlocked: boolean`
Whether the key is currently unlocked.

#### `metadata: MajikKeyMetadata`
Safe metadata object (no sensitive data).

**Example:**
```ts
console.log(key.metadata);
// {
//   id: 'fingerprint-id',
//   fingerprint: 'fingerprint-id',
//   label: 'My Key',
//   timestamp: Date,
//   isLocked: false
// }
```

---

## Usage Examples

### Example 1: Create and Manage a Key

```ts
import { MajikKey } from '@majikah/majik-key';

async function createKey() {
  // Generate mnemonic
  const mnemonic = MajikKey.generateMnemonic();
  console.log('🔑 Save this mnemonic safely:', mnemonic);

  // Create key
  const key = await MajikKey.create(
    mnemonic,
    'secure-passphrase',
    'Personal Account'
  );

  console.log('✅ Key created!');
  console.log('ID:', key.id);
  console.log('Fingerprint:', key.fingerprint);
  console.log('Label:', key.label);

  // Save to storage
  const json = key.toJSON();
  localStorage.setItem('myKey', JSON.stringify(json));

  return { key, mnemonic };
}

createKey();
```

---

### Example 2: Lock/Unlock Pattern

```ts
import { MajikKey } from '@majikah/majik-key';

async function secureLockPattern() {
  const json = localStorage.getItem('myKey');
  const key = MajikKey.fromJSON(json);

  // Key is locked by default when loaded from JSON
  console.log('Locked:', key.isLocked); // true

  try {
    // This will throw an error
    const privateKey = key.getPrivateKey();
  } catch (error) {
    console.log('❌ Cannot access private key when locked');
  }

  // Unlock to use private key
  await key.unlock('secure-passphrase');
  console.log('Unlocked:', key.isUnlocked); // true

  // Now we can access private keys
  const privateKey = key.getPrivateKey();
  const privateKeyBase64 = key.getPrivateKeyBase64();

  // Use the key for cryptographic operations
  // ...

  // Lock again when done
  key.lock();
  console.log('🔒 Key locked again');
}

secureLockPattern();
```

---

### Example 3: Backup and Recovery

```ts
import { MajikKey } from '@majikah/majik-key';

async function backupAndRecover() {
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'password123', 'Original Key');

  //Download as Blob JSON File

  const jsonData = await key.toMnemonicJSON(mnemonic, 'password123');
  const jsonString = JSON.stringify(jsonData);
  const blob = new Blob([jsonString], {
    type: "application/json;charset=utf-8",
  });
  downloadBlob(
    blob,
    "json",
    `${label} | ${key.id} | SEED KEY`,
  );



  // Later... recover from backup

  //Parse the downloaded JSON into this object
  const jsonData: MnemonicJSON = {
    id: "abc123",
    seed: ["word1", "word2", ...],
    phrase: 'password123',
  };

  const recoveredKey = await MajikKey.importFromMnemonicBackup(
    jsonData.id,
    seedArrayToString(jsonData.seed),
    jsonData.phrase,
    'Recovered Key'
  );

  console.log('✅ Key recovered!');
  console.log('Same fingerprint:', key.fingerprint === recoveredKey.fingerprint);
}

backupAndRecover();
```


---

### Example 4: Update Passphrase

```ts
import { MajikKey } from '@majikah/majik-key';

async function changePassphrase() {
  const json = localStorage.getItem('myKey');
  const key = MajikKey.fromJSON(json);

  // Must unlock first
  await key.unlock('old-password');

  // Change passphrase
  await key.updatePassphrase('old-password', 'new-secure-password');
  console.log('✅ Passphrase updated!');

  // Save updated key
  localStorage.setItem('myKey', JSON.stringify(key.toJSON()));

  // Verify new passphrase works
  key.lock();
  await key.unlock('new-secure-password');
  console.log('✅ New passphrase verified!');
}

changePassphrase();
```

---

### Example 5: Verify Passphrase

```ts
import { MajikKey } from '@majikah/majik-key';

async function verifyPassphrase() {
  const json = localStorage.getItem('myKey');
  const key = MajikKey.fromJSON(json);

  // Verify without unlocking
  const isValid = await key.verify('user-entered-password');

  if (isValid) {
    console.log('✅ Passphrase is correct');
    await key.unlock('user-entered-password');
    // Proceed with operations...
  } else {
    console.log('❌ Invalid passphrase');
    // Show error to user
  }
}

verifyPassphrase();
```

---

## Integration with Majik Message

Majik Key is fully compatible with **Majik Message** as its seed phrase account implementation. Keys created with Majik Key can be directly imported into Majik Message.

### Importing to Majik Message

```ts
import { MajikKey } from '@majikah/majik-key';

async function importToMajikMessage() {
  // Create or load a Majik Key
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'password', 'Message Account');

  // Export to MnemonicJSON format for Majik Message
  const mnemonicData = key.toMnemonicJSON(mnemonic, 'password');
  const jsonString = JSON.stringify(mnemonicData);

  // Download this blob as a JSON locally
  const blob = new Blob([jsonString], {
    type: "application/json;charset=utf-8",
  });

  // This mnemonicData can be imported directly into Majik Message
  // as a seed phrase account
  console.log('Import the saved JSON to Majik Message:', mnemonicData);
}
```

### Converting to Majik Message Identity

```ts
import { MajikKey } from '@majikah/majik-key';
import { MajikUser } from '@thezelijah/majik-user';

async function createMessageIdentity() {
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'password', 'Message Identity');

  // Create/parse a MajikUser instance
  const user = new MajikUser({
    username: 'myusername',
    // ... other user properties
  });

  // Convert to Majik Message Identity
  const identity = await key.toMajikMessageIdentity(user, {
    label: 'My Message Account',
    restricted: false
  });

  console.log('Majik Message Identity created:', identity);
}
```

---

## Security Considerations

### Best Practices

1. **Never expose mnemonics**: Treat mnemonic phrases like root passwords. Never log or store them unencrypted.

2. **Lock when not in use**: Always call .lock() when private key access is no longer required to purge the heap.

3. **PQ Readiness**: For all new communication protocols, ensure you are utilizing the mlKemPublicKey.

Security Summary
- **Primary KDF**: Argon2id (128MB / 4t / 4p).

- **Legacy KDF**: PBKDF2-SHA256 (250,000 iterations).

- **Encryption**: AES-256-GCM with unique salts and IVs.

- **Post-Quantum**: ML-KEM-768 (Lattice-based cryptography).

### What NOT to Do

❌ **DON'T** store mnemonics in code or version control  
❌ **DON'T** transmit mnemonics over insecure channels  
❌ **DON'T** use weak passphrases like "password123"  
❌ **DON'T** share mnemonics or passphrases with anyone  
❌ **DON'T** screenshot or photograph mnemonics  

### What TO Do

✅ **DO** use password managers for mnemonic storage  
✅ **DO** write mnemonics on paper and store securely  
✅ **DO** use hardware security modules when possible  
✅ **DO** test recovery procedures before relying on them  
✅ **DO** keep multiple encrypted backups in different locations  

---

### Tips & Reminders

#### For Developers

- **Remember**: Always validate user input before creating or unlocking keys.

- **Security**: Never log sensitive data (mnemonics, private keys, passphrases) in production.

- **Performance**: Lock keys when not in use to free memory and reduce attack surface.

- **Testing**: Test backup/recovery procedures in development before deploying to production.

- **Dependencies**: Keep `@scure/bip39` and other crypto dependencies up to date.

#### For Users

- **Backup**: Always keep multiple backups of your mnemonic phrase in secure locations.

- **Passphrase**: Use a strong, unique passphrase for each Majik Key.

- **Recovery**: Test your ability to recover keys from backups before you need to.

- **Organization**: Use meaningful labels to identify different keys.
- **Loss Prevention**: Losing your mnemonic phrase means permanent loss of access to your key.

---

## Related Projects

### [Majik Message](https://message.majikah.solutions)
Secure messaging platform using Majik Keys

[Read more about Majik Message here](https://majikah.solutions/products/majik-message)

[![Majik Message Thumbnail](https://github.com/user-attachments/assets/d433c6b8-1841-4fa1-a6da-b348029d1dbe)](https://message.majikah.solutions)

> Click the image to try Majik Message live.

[Read Docs](https://majikah.solutions/products/majik-message/docs)


Also available on [Microsoft Store](https://apps.microsoft.com/detail/9pmjgvzzjspn) for free.

[Official Repository](https://github.com/Majikah/majik-message)
[SDK Library](https://www.npmjs.com/package/@majikah/majik-message)

---

## Contributing

If you want to contribute or help extend support to more platforms, reach out via email. All contributions are welcome!  

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---
## Author

Made with 💙 by [@thezelijah](https://github.com/jedlsf)

## About the Developer

- **Developer**: Josef Elijah Fabian
- **GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)
- **Project Repository**: [https://github.com/jedlsf/majik-key](https://github.com/jedlsf/majik-key)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
