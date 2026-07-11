import { MnemonicLanguage } from "./crypto/wordlist";

/** ISO 8601 timestamp string, e.g. `"2026-07-11T00:00:00.000Z"`. */
export type ISODateString = string;

export type MajikMessageAccountID = string;

export type MajikMessagePublicKey = string;

export type MajikMessageChatID = string;

/** Base64-encoded public key material. Safe to store, log, or transmit. */
export type MajikKeyAddress = string;

/** Base64-encoded SHA-256 digest of a MajikKey's X25519 public key. Doubles as the account `id`. */
export type MajikKeyFingerprint = string;

/**
 * Safe, serializable snapshot of a MajikKey — what `toJSON()` / `toString()` produce.
 *
 * Every `encrypted*` field is an AES-256-GCM ciphertext (IV + ciphertext,
 * base64-encoded) protected by a passphrase-derived Argon2id key (or legacy
 * PBKDF2, see `kdfVersion`). None of these fields ever contain raw private
 * key material — this shape is safe to persist in a database, localStorage,
 * or anywhere else at rest.
 *
 * Load one of these back into a live instance with `MajikKey.fromJSON()`.
 */
export interface MajikKeyJSON {
  /** Account identifier. Equal to `fingerprint` for accounts created by this library. */
  id: string;
  /** Human-readable, user-editable account name. */
  label: string;
  /** X25519 public key, base64. */
  publicKey: MajikKeyAddress; // base64
  /** SHA-256 fingerprint of `publicKey`. Stable identity anchor for the account. */
  fingerprint: MajikKeyFingerprint;
  /** AES-256-GCM-encrypted X25519 private key (IV + ciphertext), base64. Requires the passphrase to decrypt. */
  encryptedPrivateKey: string; // base64
  /** Random salt used to derive the passphrase-based encryption key. Shared across all key types on this account. */
  salt: string; // base64
  /**
   * Encrypted, mnemonic-verification blob (base64 JSON). Decryptable only with
   * the original mnemonic — used internally to verify a supplied mnemonic
   * before `importFromMnemonicBackup()` re-derives the full identity. Not a
   * general-purpose backup of the private key.
   */
  backup: string; // base64
  /** Account creation time, ISO 8601. */
  timestamp: string; // ISO 8601
  /** KDF used for every `encrypted*` field on this account: `1` = legacy PBKDF2 (read-only), `2` = Argon2id (current). Defaults to `1` if omitted. */
  kdfVersion?: number;

  /** ML-KEM-768 (FIPS-203) public key, base64. Post-quantum key encapsulation. */
  mlKemPublicKey?: string;
  /** AES-256-GCM-encrypted ML-KEM-768 secret key, base64. */
  encryptedMlKemSecretKey?: string;

  /** Ed25519 public key, base64. Classical signing — same keypair the X25519 identity key is converted from. */
  edPublicKey?: string;
  /** AES-256-GCM-encrypted Ed25519 secret key, base64. */
  encryptedEdSecretKey?: string;
  /** ML-DSA-87 (FIPS-204) public key, base64. Post-quantum signing. */
  mlDsaPublicKey?: string;
  /** AES-256-GCM-encrypted ML-DSA-87 secret key, base64. */
  encryptedMlDsaSecretKey?: string;

  /** @experimental secp256k1 Bitcoin public key, base64. Domain-separated BIP-32/84 derivation by default — see `MajikKeyBitcoinNamespace`. */
  btcPublicKey?: string;
  /** @experimental AES-256-GCM-encrypted Bitcoin private key, base64. */
  encryptedBtcSecretKey?: string;

  /** BIP-39 wordlist language the original mnemonic was generated/validated against. Defaults to `"en"`. */
  mnemonicLanguage?: MnemonicLanguage;
}

/**
 * ⚠️ DANGEROUS. Every field below is a *raw, unencrypted* private key,
 * base64-encoded — no passphrase, no KDF, no AES-GCM. Anyone with this
 * object has full control of the account.
 *
 * Intended for one narrow use case: injecting a pre-unlocked signing key
 * into a server process at boot (e.g. loaded from a secrets manager). Never
 * log, store in a database, send over the network, or write to disk outside
 * of a secrets manager.
 *
 * Produced by `toDangerousJSON()`, consumed by `MajikKey.fromDangerousJSON()`.
 */
export interface MajikKeyDangerousJSON extends MajikKeyJSON {
  /** ⚠️ Raw X25519 private key, base64. Unencrypted. */
  privateKeyBase64: string;
  /** ⚠️ Raw ML-KEM-768 secret key, base64. Unencrypted. */
  mlKemSecretKeyBase64: string;
  /** ⚠️ Raw Ed25519 secret key, base64. Unencrypted. */
  edSecretKeyBase64: string;
  /** ⚠️ Raw ML-DSA-87 secret key, base64. Unencrypted. */
  mlDsaSecretKeyBase64: string;
  /** @experimental ⚠️ Raw Bitcoin private key, base64. Unencrypted. */
  btcSecretKeyBase64?: string;
}

/**
 * Lightweight, non-secret summary of a MajikKey — useful for account
 * pickers, dashboards, or anywhere you want to display account state
 * without touching encrypted key material. Contains no key bytes at all
 * (not even encrypted ones), so it's cheaper to pass around than `MajikKeyJSON`.
 *
 * Get one via the `metadata` getter on a live `MajikKey` instance.
 */
export interface MajikKeyMetadata {
  id: string;
  fingerprint: MajikKeyFingerprint;
  label: string;
  timestamp: Date;
  /** `true` if private key material is currently purged from memory (i.e. `lock()` was called, or it hasn't been `unlock()`ed yet). */
  isLocked: boolean;
  /** `1` = legacy PBKDF2, `2` = Argon2id. See `MajikKeyJSON.kdfVersion`. */
  kdfVersion: number;
  /** `true` if this account has ML-KEM-768 keys (i.e. is post-quantum-encryption capable). `false` means it's a legacy account pending migration. */
  hasMlKem: boolean;
  /** @experimental Presence flags for optional Web3 key material. */
  web3: {
    /** @experimental `true` if this account has a stored Bitcoin keypair. */
    hasBitcoin?: boolean;
    /** @experimental `true` if this account can derive a Solana keypair (i.e. has an Ed25519 signing key and is unlocked). */
    hasSolana?: boolean;
  };
  mnemonicLanguage?: MnemonicLanguage;
}

/**
 * Portable seed export — the format behind `toMnemonicJSON()` /
 * `MajikKey.fromMnemonicJSON()`.
 *
 * ⚠️ Unlike `MajikKeyJSON`, this is **not an encrypted-at-rest format**.
 * `seed` is the raw mnemonic, split into words, in plaintext. If a
 * passphrase is included, it's plaintext too. Treat any `MnemonicJSON`
 * exactly like the mnemonic itself — fine for a one-time, protected
 * transport (e.g. into an encrypted file you control), not for long-term
 * storage. Use `MajikKeyJSON` / `toJSON()` for anything persisted at rest.
 */
export interface MnemonicJSON {
  /** Raw mnemonic, split into individual words. ⚠️ Plaintext — this *is* the recovery phrase. */
  seed: string[];
  /** The account's encrypted backup blob (`MajikKeyJSON.backup`), carried along so this object alone is enough to call `importFromMnemonicBackup()`. */
  id: string;
  /** Optional passphrase, carried in plaintext for convenience during export/import. ⚠️ Not encrypted. */
  phrase?: string;
}
