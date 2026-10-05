/**
 * MajikKey.ts
 * Seed phrase account library for the Majikah ecosystem.
 *
 * v0.8 — key REGISTRY. Every account stores a set of keypairs in a KeyStore,
 * addressed by namespaced id (see core/keys/key-id.ts). The core four
 * (classic:x25519, classic:ed25519, pq:ml-kem-768, pq:ml-dsa-87) are always
 * present on new accounts; anything else is opt-in via `keys` / `addKeys()`.
 *
 * The pre-registry per-algorithm getters still work and are marked
 * @deprecated: they are thin wrappers over the registry accessors.
 *
 * Derivation (all deterministic from the BIP-39 mnemonic) lives in
 * core/keys/key-impls.ts. Frozen "legacy-v1" recipes are pinned by
 * vectors/legacy-v1.vectors.json.
 */

import {
  generateMnemonic as bip39GenerateMnemonic,
  mnemonicToSeed,
  validateMnemonic,
} from "@scure/bip39";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  deriveKeyFromPassphraseArgon2,
  deriveKeyFromMnemonicArgon2,
  deriveKeyFromPassphrase,
  fingerprintFromPublicRaw,
  generateRandomBytes,
  IV_LENGTH,
} from "./core/crypto/crypto-provider.js";
import {
  MajikContactData,
  MajikContactMeta,
} from "@majikah/majik-contact/dist/types.js";
import { MajikContact } from "@majikah/majik-contact/dist/contacts/majik-contact.js";
import {
  arrayToBase64,
  base64ToArrayBuffer,
  utf8ToBase64,
  base64ToUtf8,
  seedStringToArray,
  seedArrayToString,
  base64ToUint8Array,
} from "./core/utils.js";

import {
  KDF_VERSION,
  LEGACY_MAJIK_MNEMONIC_SALT,
  BACKUP_SALT_WRITE_VERSION,
  backupSaltFor,
} from "./core/crypto/constants.js";
import { MajikKeyValidator } from "./core/validator.js";
import { MajikKeyError } from "./core/error.js";
import type {
  BitcoinRawPublicKey,
  ED25519RawPublicKey,
  MajikKeyAddress,
  MajikKeyDangerousJSON,
  MajikKeyFingerprint,
  MajikKeyJSON,
  MajikKeyMetadata,
  MLDSA87RawPublicKey,
  MLKEM768RawPublicKey,
  MnemonicJSON,
  X25519RawKey,
} from "./core/types.js";
import { MajikMessageIdentity } from "./core/database/system/identity.js";
import { MajikUser } from "@thezelijah/majik-user/dist/core/majik-user.js";
import { MnemonicLanguage, WORDLISTS } from "./core/crypto/wordlist.js";

import {
  MajikKeyWeb3Namespace,
  BitcoinDerivationOptions,
  BitcoinKeypairMaterial,
  deriveBitcoinKeypairFromSeed,
  signWithBitcoinMaterial,
  toBitcoinAddress,
  toWIF,
  deriveSolanaKeypairFromEdSecretKey,
  signWithSolanaMaterial,
  solanaAddressFromPublicKey,
  SolanaKeypairMaterial,
  solanaMaterialFromEd25519SecretKey,
  toSolanaAddress,
  toSolanaKeyPairSigner,
  EthereumKeypairMaterial,
  ethereumAddressFromPublicKey,
  signEthereumHash,
  signEthereumMessage,
  toEthereumPrivateKeyHex,
} from "./core/web3/index.js";

import { CORE_KEYS, KeyFamily, KeyId } from "./core/keys/key-id.js";
import {
  KEY_ALGORITHMS,
  enableableKeyIds,
  getAlgorithm,
  knownKeyIds,
  resolveRequestedKeys,
} from "./core/keys/registry.js";
import { deriveKeys } from "./core/keys/key-impls.js";
import { KeyStore, KeySlot } from "./core/keys/key-store.js";
import { KeyInfo, MajikKeypair } from "./core/keys/keypair-handle.js";

export { KeyId, KeyFamily, CORE_KEYS } from "./core/keys/key-id.js";
export { MajikKeypair } from "./core/keys/keypair-handle.js";
export type { KeyInfo } from "./core/keys/keypair-handle.js";

const secureFill = Uint8Array.prototype.fill;

const SALT_SIZE = 32;
const KEYS_VERSION = 1;

// ─── Interfaces ───────────────────────────────────────────────────────────────
/**
 * In-memory identity bundle for an *unlocked* MajikKey. Returned by
 * `toKeyIdentity()`. Kept for backward compatibility; prefer the registry
 * accessors (`getKeypair()`, `getPublicKey()`, `getPrivateKey(id)`).
 */
export interface MajikKeyIdentity {
  id: MajikKeyFingerprint;
  publicKey: X25519RawKey;
  fingerprint: MajikKeyFingerprint;
  privateKey: X25519RawKey;
  encryptedPrivateKey: ArrayBuffer;
  salt: string;
  kdfVersion: KDF_VERSION;
  mlKemPublicKey: Uint8Array;
  mlKemSecretKey?: Uint8Array;
  edPublicKey?: Uint8Array;
  edSecretKey?: Uint8Array;
  mlDsaPublicKey?: Uint8Array;
  mlDsaSecretKey?: Uint8Array;
  /** @experimental */
  btcPublicKey?: Uint8Array;
  /** @experimental */
  btcSecretKey?: Uint8Array;
}

/** @deprecated Pre-registry shape. No longer produced; kept so existing type imports keep compiling. */
export type MajikKeyDerivedIdentity = MajikKeyIdentity & {
  encryptedMlKemSecretKey: ArrayBuffer;
  encryptedEdSecretKey: ArrayBuffer;
  encryptedMlDsaSecretKey: ArrayBuffer;
  encryptedBtcSecretKey?: ArrayBuffer;
};

export interface SerializedIdentity {
  id: string;
  publicKey: MajikKeyAddress;
  fingerprint: MajikKeyFingerprint;
  encryptedPrivateKey?: string;
  salt?: string;
}

/** @deprecated Pre-registry constructor payload. The constructor now takes a KeyStore. */
export interface MajikKeyConstructorOptions {
  id: string;
  publicKey: X25519RawKey;
  publicKeyBase64: MajikKeyAddress;
  fingerprint: MajikKeyFingerprint;
  encryptedPrivateKey: ArrayBuffer;
  encryptedPrivateKeyBase64: string;
  salt: string;
  backup: string;
  label?: string;
  timestamp?: Date;
  kdfVersion?: KDF_VERSION;
  mlKemPublicKey: MLKEM768RawPublicKey;
  mlKemSecretKey?: Uint8Array;
  encryptedMlKemSecretKey?: ArrayBuffer;
  encryptedMlKemSecretKeyBase64?: string;
  privateKey?: X25519RawKey;
  edPublicKey?: ED25519RawPublicKey;
  encryptedEdSecretKey?: ArrayBuffer;
  encryptedEdSecretKeyBase64?: string;
  mlDsaPublicKey?: MLDSA87RawPublicKey;
  encryptedMlDsaSecretKey?: ArrayBuffer;
  encryptedMlDsaSecretKeyBase64?: string;
  edSecretKey?: Uint8Array;
  mlDsaSecretKey?: Uint8Array;
  btcPublicKey?: BitcoinRawPublicKey;
  encryptedBtcSecretKey?: ArrayBuffer;
  encryptedBtcSecretKeyBase64?: string;
  btcSecretKey?: Uint8Array;
  mnemonicLanguage?: MnemonicLanguage;
}

/** Options for create(), fromMnemonicJSON() and importFromMnemonicBackup(). */
export interface MajikKeyCreateOptions {
  mnemonicLanguage?: MnemonicLanguage;
  /**
   * Extra keypairs to create ON TOP of the core four (always included).
   * Defaults to none. e.g. `keys: [KeyId.BTC]`.
   */
  keys?: KeyId[];
  /** @deprecated Use `keys: [KeyId.BTC]`. `true` adds `web3:btc`; omitted/false no longer derives it. */
  deriveBitcoin?: boolean;
}

export interface MajikKeyToJSONOptions {
  /**
   * Also write the pre-registry flat fields (`encryptedMlKemSecretKey`, …)
   * so older library versions / the Rust port can read the export.
   * Defaults to TRUE in this release; planned to flip to false in the next major.
   */
  legacy?: boolean;
}

/** Internal constructor payload. */
interface MajikKeyInit {
  id: string;
  fingerprint: MajikKeyFingerprint;
  salt: string;
  backup: string;
  label?: string;
  timestamp?: Date;
  kdfVersion?: KDF_VERSION;
  mnemonicLanguage?: MnemonicLanguage;
  store: KeyStore;
}

/**
 * MajikKey
 * ---
 * Registry of keypairs deterministically derived from one BIP-39 mnemonic.
 * See core/keys/registry.ts for every supported algorithm and its status.
 */
export class MajikKey {
  private readonly _id: string;
  private readonly _publicKey: X25519RawKey;
  private readonly _publicKeyBase64: string;
  private readonly _fingerprint: string;
  private readonly _backup: string;
  private readonly _timestamp: Date;
  private readonly _mnemonicLanguage: MnemonicLanguage;

  private readonly _store: KeyStore;
  private _salt: string;
  private _label: string;
  private _kdfVersion: KDF_VERSION;

  /** @experimental derived view over classic:ed25519; cached while unlocked */
  private _solanaKeypairMaterial?: SolanaKeypairMaterial;

  private constructor(init: MajikKeyInit) {
    this._id = init.id;
    this._store = init.store;
    const xPub = init.store.getPublicKey(KeyId.X25519);
    this._publicKey = { raw: xPub };
    this._publicKeyBase64 = arrayToBase64(xPub);
    this._fingerprint = init.fingerprint;
    this._salt = init.salt;
    this._backup = init.backup;
    this._label = init.label || "";
    this._timestamp = init.timestamp || new Date();
    this._kdfVersion = init.kdfVersion ?? KDF_VERSION.PBKDF2;
    this._mnemonicLanguage = init.mnemonicLanguage || "en";
  }

  // ── Getters ─────────────────────────────────────────────────────────────────

  get id(): MajikKeyFingerprint {
    return this._id;
  }
  get fingerprint(): MajikKeyFingerprint {
    return this._fingerprint;
  }
  /** X25519 public key. Always available, even when locked. */
  get publicKey(): X25519RawKey {
    return this._publicKey;
  }
  get publicKeyBase64(): MajikKeyAddress {
    return this._publicKeyBase64;
  }
  get label(): string {
    return this._label;
  }
  get mnemonicLanguage(): MnemonicLanguage {
    return this._mnemonicLanguage;
  }
  get backup(): string {
    return this._backup;
  }
  get timestamp(): Date {
    return this._timestamp;
  }
  get kdfVersion(): KDF_VERSION {
    return this._kdfVersion;
  }
  get isArgon2id(): boolean {
    return this._kdfVersion === KDF_VERSION.ARGON2ID;
  }
  get isLocked(): boolean {
    return !this._store.isUnlocked;
  }
  get isUnlocked(): boolean {
    return this._store.isUnlocked;
  }

  /** `true` if this account holds every key in CORE_KEYS. Legacy accounts may not — see `missingKeys()` / `addKeys()`. */
  get isCoreComplete(): boolean {
    return this._store.hasAll(CORE_KEYS);
  }

  /** `true` if this account is on Argon2id *and* has ML-KEM-768 keys. */
  get isFullyUpgraded(): boolean {
    return this.isArgon2id && this.hasMlKem;
  }

  // ── Registry accessors ──────────────────────────────────────────────────────

  /** Is this key present on the account? Works while locked. Derived views (web3:sol) count when their source key exists. */
  hasKey(id: KeyId): boolean {
    if (this._store.has(id)) return true;
    const def = getAlgorithm(id);
    return (
      !!def &&
      def.kind === "derived" &&
      !!def.derivedFrom &&
      this._store.has(def.derivedFrom)
    );
  }

  hasKeys(ids: readonly KeyId[]): boolean {
    return ids.every((id) => this.hasKey(id));
  }

  /** Which of `ids` (default: the core four) are NOT on this account. */
  missingKeys(ids: readonly KeyId[] = CORE_KEYS): KeyId[] {
    return ids.filter((id) => !this.hasKey(id));
  }

  /** Namespaced ids of every key available on this account, in canonical order. */
  availableKeys(options?: { family?: KeyFamily }): KeyId[] {
    return knownKeyIds(options?.family).filter((id) => this.hasKey(id));
  }

  /** Metadata for every available key. No secret material. */
  listKeys(): KeyInfo[] {
    return this.availableKeys().map((id) => {
      const def = KEY_ALGORITHMS[id];
      let pub: string | undefined;
      try {
        pub = arrayToBase64(this.getPublicKey(id));
      } catch {
        pub = undefined; // derived view while locked
      }
      return {
        id,
        family: def.family,
        purpose: def.purpose,
        kind: def.kind,
        status: def.status,
        publicKeyBase64: pub,
      };
    });
  }

  /** Every algorithm id this library version can create/enable. */
  static supportedKeys(): KeyId[] {
    return enableableKeyIds();
  }

  /** Public key bytes for `id`. Works while locked (derived views need an unlocked account). */
  getPublicKey(id: KeyId): Uint8Array {
    if (this._store.has(id)) return this._store.getPublicKey(id);
    if (id === KeyId.SOL && this._store.has(KeyId.ED25519))
      return this.getSolanaKeypairMaterial().publicKey;
    throw new MajikKeyError(`No "${id}" key on this account`);
  }

  /**
   * With no argument: the X25519 private key wrapper.
   * @deprecated The no-argument form. Use `getPrivateKey(KeyId.X25519)`.
   */
  getPrivateKey(): X25519RawKey;
  /** Secret key bytes for `id`. Throws if locked or absent. ⚠️ Live key material. */
  getPrivateKey(id: KeyId): Uint8Array;
  getPrivateKey(id?: KeyId): X25519RawKey | Uint8Array {
    if (id === undefined) return { raw: this._requireSecret(KeyId.X25519) };
    if (id === KeyId.SOL && this._store.has(KeyId.ED25519))
      return this.getSolanaKeypairMaterial().secretKey;
    return this._requireSecret(id);
  }

  /** A live handle with `.public` / `.private` / `.publicBase64`. Reads through to the account, so it never goes stale across lock(). */
  getKeypair(id: KeyId): MajikKeypair {
    if (!this.hasKey(id))
      throw new MajikKeyError(`No "${id}" key on this account`);
    return new MajikKeypair(
      id,
      () => this.getPublicKey(id),
      () => this.getPrivateKey(id),
      () => this.isUnlocked,
    );
  }

  private _requireSecret(id: KeyId, missingMessage?: string): Uint8Array {
    if (this.isLocked) {
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    }

    const slot = this._store.slot(id);

    if (!slot) {
      throw new MajikKeyError(
        missingMessage ??
          `No "${id}" key on this account — add it with addKeys(), which requires the mnemonic.`,
      );
    }

    const secret = this._store.peekSecretKey(id);

    if (!secret) {
      if (id === KeyId.BTC) {
        throw new MajikKeyError(
          "Bitcoin private key material is unavailable; re-import via importFromMnemonicBackup.",
        );
      }

      throw new MajikKeyError(
        missingMessage ??
          `Private key material for "${id}" is unavailable. Re-import the account from its mnemonic backup.`,
      );
    }

    return secret;
  }

  // ── Deprecated per-algorithm getters (wrappers over the registry) ───────────

  /** @deprecated Use `getPublicKey(KeyId.ML_KEM_768)`. */
  get mlKemPublicKey(): MLKEM768RawPublicKey {
    return (this._store.has(KeyId.ML_KEM_768)
      ? this._store.getPublicKey(KeyId.ML_KEM_768)
      : undefined) as unknown as MLKEM768RawPublicKey;
  }
  /** @deprecated Use `getPrivateKey(KeyId.ML_KEM_768)`. */
  get mlKemSecretKey(): Uint8Array | undefined {
    return this._store.peekSecretKey(KeyId.ML_KEM_768);
  }
  /** @deprecated Use `hasKey(KeyId.ML_KEM_768)`. */
  get hasMlKem(): boolean {
    return this._store.has(KeyId.ML_KEM_768);
  }
  /** @deprecated Use `getPublicKey(KeyId.ED25519)`. */
  get edPublicKey(): ED25519RawPublicKey | undefined {
    return this._store.has(KeyId.ED25519)
      ? this._store.getPublicKey(KeyId.ED25519)
      : undefined;
  }
  /** @deprecated Use `getPublicKey(KeyId.ML_DSA_87)`. */
  get mlDsaPublicKey(): MLDSA87RawPublicKey | undefined {
    return this._store.has(KeyId.ML_DSA_87)
      ? this._store.getPublicKey(KeyId.ML_DSA_87)
      : undefined;
  }
  /** @deprecated Use `hasKeys([KeyId.ED25519, KeyId.ML_DSA_87])`. */
  get hasSigningKeys(): boolean {
    return this._store.has(KeyId.ED25519) && this._store.has(KeyId.ML_DSA_87);
  }
  /** @experimental @deprecated Use `getPublicKey(KeyId.BTC)`. */
  get btcPublicKey(): BitcoinRawPublicKey | undefined {
    return this._store.has(KeyId.BTC)
      ? this._store.getPublicKey(KeyId.BTC)
      : undefined;
  }
  /** @experimental @deprecated Use `hasKey(KeyId.BTC)`. */
  get hasBitcoin(): boolean {
    return this._store.has(KeyId.BTC);
  }

  /** @deprecated Use `getPrivateKey(KeyId.ML_KEM_768)`. */
  getMlKemSecretKey(): Uint8Array {
    return this._requireSecret(
      KeyId.ML_KEM_768,
      "No ML-KEM secret key — add it with addKeys() (requires the mnemonic).",
    );
  }
  /** @deprecated Use `getPrivateKey(KeyId.ED25519)`. */
  getEdSecretKey(): Uint8Array {
    return this._requireSecret(
      KeyId.ED25519,
      "No Ed25519 secret key — add it with addKeys() (requires the mnemonic).",
    );
  }
  /** @deprecated Use `getPrivateKey(KeyId.ML_DSA_87)`. */
  getMlDsaSecretKey(): Uint8Array {
    return this._requireSecret(
      KeyId.ML_DSA_87,
      "No ML-DSA secret key — add it with addKeys() (requires the mnemonic).",
    );
  }
  /** @experimental @deprecated Use `getPrivateKey(KeyId.BTC)`. */
  getBtcSecretKey(): Uint8Array {
    return this._requireSecret(
      KeyId.BTC,
      "No Bitcoin secret key — add it with addKeys([KeyId.BTC], mnemonic, passphrase).",
    );
  }

  /** Non-secret snapshot of this account's state. */
  get metadata(): MajikKeyMetadata {
    return {
      id: this.id,
      fingerprint: this.fingerprint,
      label: this.label,
      timestamp: this.timestamp,
      isLocked: this.isLocked,
      kdfVersion: this.kdfVersion,
      hasMlKem: this.hasMlKem,
      web3: {
        hasEthereum: this.hasEthereum,
        hasBitcoin: this.hasBitcoin,
        hasSolana: this.hasSolanaKeypair,
      },
      keys: this.availableKeys(),
      mnemonicLanguage: this.mnemonicLanguage || "en",
    };
  }

  // ── CREATE ──────────────────────────────────────────────────────────────────

  /**
   * Creates a brand-new MajikKey from a BIP-39 mnemonic and returns it UNLOCKED.
   *
   * Always derives the core four (X25519, Ed25519, ML-KEM-768, ML-DSA-87).
   * Pass `options.keys` for more, e.g. `{ keys: [KeyId.BTC] }`.
   *
   * ⚠️ Behavior change vs 0.7: Bitcoin is no longer derived by default.
   *
   * @throws {MajikKeyError} on invalid mnemonic/passphrase/label or unusable key ids.
   */
  static async create(
    mnemonic: string,
    passphrase: string,
    label?: string,
    options: MajikKeyCreateOptions = {},
  ): Promise<MajikKey> {
    try {
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      MajikKeyValidator.validateLabel(label);

      const mnemonicLanguage = options.mnemonicLanguage || "en";
      const ids = MajikKey._resolveCreateKeys(options);

      const wordlist = await MajikKey._getWordlist(mnemonicLanguage);
      if (!validateMnemonic(mnemonic, wordlist)) {
        throw new MajikKeyError("Invalid BIP39 mnemonic phrase");
      }

      const d = await MajikKey._deriveFromMnemonic(mnemonic, passphrase, ids);
      const backup = await MajikKey._exportMnemonicBackup(
        {
          id: d.fingerprint,
          fingerprint: d.fingerprint,
          publicRaw: d.xPublic,
          privateRaw: d.xSecret,
        },
        mnemonic,
      );

      return new MajikKey({
        id: d.fingerprint,
        fingerprint: d.fingerprint,
        salt: d.salt,
        backup,
        label: label || "",
        timestamp: new Date(),
        kdfVersion: KDF_VERSION.ARGON2ID,
        mnemonicLanguage,
        store: d.store,
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to create MajikKey", err);
    }
  }

  private static _resolveCreateKeys(options: MajikKeyCreateOptions): KeyId[] {
    const requested: string[] = [...(options.keys ?? [])];
    if (options.deriveBitcoin === true) requested.push(KeyId.BTC);
    return resolveRequestedKeys(requested);
  }

  // ── READ ────────────────────────────────────────────────────────────────────

  /**
   * Parse a MajikKey from JSON. Accepts BOTH shapes:
   *  - registry JSON (has `keys`)  → used as-is
   *  - legacy flat JSON (no `keys`) → auto-migrated in memory (no secrets, no
   *    passphrase, no mnemonic needed). Re-serialize with toJSON() to persist
   *    the upgraded shape.
   */
  static fromJSON(json: MajikKeyJSON | string): MajikKey {
    try {
      const parsed: MajikKeyJSON =
        typeof json === "string" ? JSON.parse(json) : json;
      const anyParsed = parsed as any;

      let store: KeyStore;
      let base: {
        id: string;
        fingerprint: string;
        salt: string;
        backup: string;
        label?: string;
        timestamp: string;
        kdfVersion?: number;
        mnemonicLanguage?: MnemonicLanguage;
      };

      if (Array.isArray(anyParsed.keys)) {
        base = MajikKey._validateRegistryJSON(anyParsed);
        store = KeyStore.fromEntries(anyParsed.keys);
        if (!store.has(KeyId.X25519))
          throw new MajikKeyError(
            "Invalid MajikKey JSON: `keys` has no classic:x25519 entry",
          );
        // If the flat legacy field is also present it must agree (corruption/tamper check).
        if (
          anyParsed.publicKey &&
          anyParsed.publicKey !==
            arrayToBase64(store.getPublicKey(KeyId.X25519))
        )
          throw new MajikKeyError(
            "Invalid MajikKey JSON: `publicKey` does not match the classic:x25519 entry",
          );
      } else {
        const validated = MajikKeyValidator.validateJSON(parsed);
        base = validated as any;
        store = KeyStore.fromLegacyJSON({
          ...anyParsed,
          publicKey: validated.publicKey,
          encryptedPrivateKey: validated.encryptedPrivateKey,
        });
      }

      return new MajikKey({
        id: base.id,
        fingerprint: base.fingerprint,
        salt: base.salt,
        backup: base.backup,
        label: base.label || "",
        timestamp: new Date(base.timestamp),
        kdfVersion:
          (base.kdfVersion as KDF_VERSION | undefined) ?? KDF_VERSION.PBKDF2,
        mnemonicLanguage: base.mnemonicLanguage || "en",
        store,
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to parse MajikKey from JSON", err);
    }
  }

  private static _validateRegistryJSON(j: any) {
    for (const f of ["id", "fingerprint", "salt", "backup", "timestamp"]) {
      if (typeof j[f] !== "string" || !j[f])
        throw new MajikKeyError(`Invalid MajikKey JSON: missing "${f}"`);
    }
    if (j.keysVersion !== undefined && j.keysVersion > KEYS_VERSION)
      throw new MajikKeyError(
        `This MajikKey JSON uses keys schema v${j.keysVersion}; this library supports up to v${KEYS_VERSION}. Upgrade the library.`,
      );
    return j as {
      id: string;
      fingerprint: string;
      salt: string;
      backup: string;
      label?: string;
      timestamp: string;
      kdfVersion?: number;
      mnemonicLanguage?: MnemonicLanguage;
    };
  }

  /**
   * Export a fully unlocked MajikKey with all raw private keys.
   * ⚠️ DANGEROUS — output contains unencrypted private key material.
   * Only use for server-side secrets injection.
   */
  toDangerousJSON(): MajikKeyDangerousJSON {
    if (this.isLocked)
      throw new MajikKeyError(
        "MajikKey must be unlocked to export dangerous JSON.",
      );
    if (!this.hasKeys(CORE_KEYS))
      throw new MajikKeyError(
        "MajikKey is missing core keys — add them with addKeys(CORE_KEYS, mnemonic, passphrase) first.",
      );

    const secretKeys: Record<string, string> = {};
    for (const [id, secret] of this._store.exportSecrets())
      secretKeys[id] = arrayToBase64(secret);

    const s = (id: KeyId) => this._store.getSecretKey(id);
    return {
      ...this.toJSON(),
      privateKeyBase64: arrayToBase64(s(KeyId.X25519)),
      mlKemSecretKeyBase64: arrayToBase64(s(KeyId.ML_KEM_768)),
      edSecretKeyBase64: arrayToBase64(s(KeyId.ED25519)),
      mlDsaSecretKeyBase64: arrayToBase64(s(KeyId.ML_DSA_87)),
      btcSecretKeyBase64: this._store.has(KeyId.BTC)
        ? arrayToBase64(s(KeyId.BTC))
        : undefined,
      secretKeys,
    };
  }

  /**
   * Reconstruct a fully unlocked MajikKey from a dangerous JSON export.
   * ⚠️ DANGEROUS — input contains unencrypted private key material.
   * No KDF is involved — reconstruction is instant.
   */
  static fromDangerousJSON(json: MajikKeyDangerousJSON | string): MajikKey {
    try {
      const parsed: MajikKeyDangerousJSON =
        typeof json === "string" ? JSON.parse(json) : json;

      if (
        !parsed.id ||
        !parsed.fingerprint ||
        !parsed.publicKey ||
        !parsed.privateKeyBase64 ||
        !parsed.edPublicKey ||
        !parsed.edSecretKeyBase64 ||
        !parsed.mlDsaPublicKey ||
        !parsed.mlDsaSecretKeyBase64 ||
        !parsed.mlKemPublicKey ||
        !parsed.mlKemSecretKeyBase64
      )
        throw new MajikKeyError(
          "Invalid MajikKeyDangerousJSON — missing required fields",
        );

      const anyParsed = parsed as any;
      const store = Array.isArray(anyParsed.keys)
        ? KeyStore.fromEntries(anyParsed.keys)
        : KeyStore.fromLegacyJSON(parsed as any);

      const secrets = new Map<string, Uint8Array>();
      const put = (id: KeyId, b64?: string) => {
        if (b64 && store.has(id)) secrets.set(id, base64ToUint8Array(b64));
      };
      put(KeyId.X25519, parsed.privateKeyBase64);
      put(KeyId.ML_KEM_768, parsed.mlKemSecretKeyBase64);
      put(KeyId.ED25519, parsed.edSecretKeyBase64);
      put(KeyId.ML_DSA_87, parsed.mlDsaSecretKeyBase64);
      put(KeyId.BTC, parsed.btcSecretKeyBase64);
      for (const [id, b64] of Object.entries(parsed.secretKeys ?? {}))
        if (store.has(id)) secrets.set(id, base64ToUint8Array(b64));
      store.attachSecrets(secrets);

      return new MajikKey({
        id: parsed.id,
        fingerprint: parsed.fingerprint,
        salt: parsed.salt,
        backup: parsed.backup,
        label: parsed.label || "",
        timestamp: parsed.timestamp ? new Date(parsed.timestamp) : undefined,
        kdfVersion: (parsed?.kdfVersion as KDF_VERSION) || KDF_VERSION.ARGON2ID,
        mnemonicLanguage: parsed.mnemonicLanguage,
        store,
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError(
        "Failed to reconstruct MajikKey from dangerous JSON",
        err,
      );
    }
  }

  // ── MnemonicJSON ─────────────────────────────────────────────────────────────

  toMnemonicJSON(mnemonic: string, passphrase?: string): MnemonicJSON {
    if (this.isLocked)
      throw new MajikKeyError(
        "Cannot export locked MajikKey to MnemonicJSON. Unlock first.",
      );
    MajikKeyValidator.validateMnemonic(mnemonic);
    if (passphrase !== undefined)
      MajikKeyValidator.validatePassphrase(passphrase, "Passphrase");
    return {
      id: this._backup,
      seed: seedStringToArray(mnemonic.trim()),
      phrase: passphrase?.trim() || undefined,
      language: this._mnemonicLanguage,
    };
  }

  static async fromMnemonicJSON(
    mnemonicJson: MnemonicJSON | string,
    passphrase: string,
    label?: string,
    options: MajikKeyCreateOptions = {},
  ): Promise<MajikKey> {
    try {
      const parsed =
        typeof mnemonicJson === "string"
          ? JSON.parse(mnemonicJson)
          : mnemonicJson;

      if (
        !parsed ||
        !parsed.id ||
        !Array.isArray(parsed.seed) ||
        parsed.seed.length === 0
      ) {
        throw new MajikKeyError("Invalid MnemonicJSON");
      }

      const mnemonic = seedArrayToString(parsed.seed);

      MajikKeyValidator.validateMnemonic(mnemonic);

      // Explicit caller option wins.
      // Otherwise preserve the language embedded
      // in the MnemonicJSON.
      const mnemonicLanguage =
        options.mnemonicLanguage ?? parsed.language ?? "en";

      const wordlist = await MajikKey._getWordlist(mnemonicLanguage);

      if (!validateMnemonic(mnemonic, wordlist)) {
        throw new MajikKeyError("Invalid BIP39 mnemonic phrase");
      }

      return await MajikKey.create(mnemonic, passphrase, label, {
        ...options,
        mnemonicLanguage,
      });
    } catch (err) {
      if (err instanceof MajikKeyError) {
        throw err;
      }

      throw new MajikKeyError("Failed to import MnemonicJSON", err);
    }
  }

  // ── UPDATE ───────────────────────────────────────────────────────────────────

  updateLabel(newLabel: string): this {
    MajikKeyValidator.validateLabel(newLabel);
    this._label = newLabel || "";
    return this;
  }

  async updatePassphrase(
    currentPassphrase: string,
    newPassphrase: string,
  ): Promise<this> {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey must be unlocked to update passphrase");
    MajikKeyValidator.validatePassphrase(
      currentPassphrase,
      "Current passphrase",
    );
    MajikKeyValidator.validatePassphrase(newPassphrase, "New passphrase");
    try {
      await this._reencryptAll(currentPassphrase, newPassphrase);
      return this;
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to update passphrase", err);
    }
  }

  /**
   * Migrate KDF from PBKDF2 to Argon2id without changing passphrase.
   * Does not add new key types — use addKeys() (requires the mnemonic).
   */
  async migrate(passphrase: string): Promise<this> {
    MajikKeyValidator.validatePassphrase(passphrase);
    if (this._kdfVersion === KDF_VERSION.ARGON2ID) return this;
    try {
      await this._reencryptAll(passphrase, passphrase);
      return this;
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to migrate MajikKey to Argon2id", err);
    }
  }

  /**
   * Add keypairs this account doesn't have yet (new algorithms, or core keys
   * missing on a legacy account). Requires the original MNEMONIC: new keys are
   * derived from the seed, which is never stored. Also requires the current
   * passphrase (to encrypt the new keys under the account's existing salt).
   *
   * Safe by construction: the mnemonic must reproduce this account's X25519
   * key, and the passphrase must decrypt it, before anything is added.
   * Keys already present are skipped. Account must be on Argon2id — call
   * `migrate(passphrase)` first if `isArgon2id` is false.
   *
   * @returns the ids that were added
   */
  async addKeys(
    ids: readonly KeyId[],
    mnemonic: string,
    passphrase: string,
  ): Promise<KeyId[]> {
    try {
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      if (!this.isArgon2id)
        throw new MajikKeyError(
          "Account is on the legacy KDF. Call migrate(passphrase) before addKeys().",
        );

      // resolveRequestedKeys validates status/implementation; we only add what was asked for AND is missing.
      const resolved = resolveRequestedKeys(ids);
      const toAdd = [...new Set(ids)].filter(
        (id) => resolved.includes(id) && !this._store.has(id),
      );
      if (toAdd.length === 0) return [];

      const wordlist = await MajikKey._getWordlist(this._mnemonicLanguage);
      if (!validateMnemonic(mnemonic, wordlist))
        throw new MajikKeyError("Invalid BIP39 mnemonic phrase");

      const salt = new Uint8Array(base64ToArrayBuffer(this._salt));
      const aesKey = await MajikKey._deriveVaultKey(passphrase, salt);
      const seed64 = await mnemonicToSeed(mnemonic);
      try {
        // 1) passphrase must be right
        const xBlob = this._store.slot(KeyId.X25519)!.encryptedSecretKey;
        if (!xBlob)
          throw new MajikKeyError("Account has no encrypted X25519 key");
        KeyStore.open(aesKey, xBlob, "classic:x25519 secret key");

        // 2) mnemonic must belong to this account
        const probe = deriveKeys(seed64, [KeyId.X25519]).get(KeyId.X25519)!;
        if (fingerprintFromPublicRaw(probe.publicKey) !== this._fingerprint)
          throw new MajikKeyError(
            "That mnemonic does not belong to this account",
          );

        // 3) derive + seal + add
        const derived = deriveKeys(seed64, toAdd);
        for (const [id, kp] of derived) {
          const slot: KeySlot = {
            id,
            publicKey: kp.publicKey,
            encryptedSecretKey: KeyStore.seal(aesKey, kp.secretKey),
            derivation: KEY_ALGORITHMS[id].derivation,
            createdAt: new Date().toISOString(),
          };
          if (this.isUnlocked) slot.secretKey = kp.secretKey;
          else secureFill.call(kp.secretKey, 0);
          this._store.add(slot);
        }
        return toAdd;
      } finally {
        secureFill.call(aesKey, 0);
        secureFill.call(seed64, 0);
        secureFill.call(salt, 0);
      }
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to add keys", err);
    }
  }

  // ── LOCK / UNLOCK ────────────────────────────────────────────────────────────

  lock(): this {
    this._store.lock();
    if (this._solanaKeypairMaterial) {
      secureFill.call(this._solanaKeypairMaterial.secretKey, 0);
    }
    this._solanaKeypairMaterial = undefined;
    return this;
  }

  /** One KDF run decrypts every key. Atomic: a failure leaves the account fully locked. */
  async unlock(passphrase: string): Promise<this> {
    try {
      if (this.isUnlocked)
        throw new MajikKeyError("MajikKey is already unlocked");
      MajikKeyValidator.validatePassphrase(passphrase);

      const salt = new Uint8Array(base64ToArrayBuffer(this._salt));
      const primaryKey = await MajikKey._deriveVaultKey(
        passphrase,
        salt,
        this._kdfVersion,
      );
      let argonKey: Uint8Array | undefined =
        this._kdfVersion === KDF_VERSION.ARGON2ID ? primaryKey : undefined;
      try {
        if (!argonKey && this._hasNonX25519Blobs())
          argonKey = await MajikKey._deriveVaultKey(
            passphrase,
            salt,
            KDF_VERSION.ARGON2ID,
          );
        this._store.unlock((slot) =>
          slot.id === KeyId.X25519 ? primaryKey : argonKey!,
        );
        return this;
      } finally {
        secureFill.call(primaryKey, 0);
        if (argonKey && argonKey !== primaryKey) secureFill.call(argonKey, 0);
        secureFill.call(salt, 0);
      }
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError(
        "Failed to unlock MajikKey — incorrect passphrase or corrupted data",
        err,
      );
    }
  }

  async verify(passphrase: string): Promise<boolean> {
    try {
      const salt = new Uint8Array(base64ToArrayBuffer(this._salt));
      const key = await MajikKey._deriveVaultKey(
        passphrase,
        salt,
        this._kdfVersion,
      );
      try {
        KeyStore.open(
          key,
          this._store.slot(KeyId.X25519)!.encryptedSecretKey!,
          "private key",
        );
        return true;
      } finally {
        secureFill.call(key, 0);
      }
    } catch {
      return false;
    }
  }

  /** @deprecated Use `getPrivateKey(KeyId.X25519)`. */
  getPrivateKeyBase64(): string {
    return arrayToBase64(this._requireSecret(KeyId.X25519));
  }

  /**
   * Executes an operation against an already-unlocked MajikKey and
   * automatically locks the key when the operation completes (even on throw).
   */
  static async withAutoLock<T>(
    key: MajikKey,
    operation: (key: MajikKey) => T | Promise<T>,
  ): Promise<T> {
    if (!(key instanceof MajikKey)) {
      throw new MajikKeyError("A valid MajikKey instance is required");
    }
    if (key.isLocked) {
      throw new MajikKeyError(
        "MajikKey must be unlocked before calling withAutoLock()",
      );
    }
    if (typeof operation !== "function") {
      throw new MajikKeyError("Operation must be a function");
    }
    try {
      return await operation(key);
    } finally {
      key.lock();
    }
  }

  private _hasNonX25519Blobs(): boolean {
    return this._store
      .ids()
      .some(
        (id) =>
          id !== KeyId.X25519 && !!this._store.slot(id)?.encryptedSecretKey,
      );
  }

  /**
   * Decrypt every blob under (current passphrase, current salt/KDF), re-encrypt
   * under (new passphrase, fresh salt, Argon2id), then commit atomically.
   * Does not need the account to be unlocked and never touches plaintext in memory.
   */
  private async _reencryptAll(
    currentPassphrase: string,
    newPassphrase: string,
  ): Promise<void> {
    const oldSalt = new Uint8Array(base64ToArrayBuffer(this._salt));
    const newSalt = generateRandomBytes(SALT_SIZE);
    let oldPrimary: Uint8Array | undefined;
    let oldArgon: Uint8Array | undefined;
    let newKey: Uint8Array | undefined;
    try {
      oldPrimary = await MajikKey._deriveVaultKey(
        currentPassphrase,
        oldSalt,
        this._kdfVersion,
      );
      oldArgon =
        this._kdfVersion === KDF_VERSION.ARGON2ID ? oldPrimary : undefined;
      if (!oldArgon && this._hasNonX25519Blobs())
        oldArgon = await MajikKey._deriveVaultKey(
          currentPassphrase,
          oldSalt,
          KDF_VERSION.ARGON2ID,
        );

      newKey = await MajikKey._deriveVaultKey(
        newPassphrase,
        newSalt,
        KDF_VERSION.ARGON2ID,
      );
      const blobs = this._store.prepareReseal(
        (slot) => (slot.id === KeyId.X25519 ? oldPrimary! : oldArgon!),
        newKey,
      );
      this._store.commitReseal(blobs);
      this._salt = arrayToBase64(newSalt);
      this._kdfVersion = KDF_VERSION.ARGON2ID;
    } finally {
      if (oldPrimary) secureFill.call(oldPrimary, 0);
      if (oldArgon && oldArgon !== oldPrimary) secureFill.call(oldArgon, 0);
      if (newKey) secureFill.call(newKey, 0);
      secureFill.call(oldSalt, 0);
    }
  }

  // ── SERIALIZATION ────────────────────────────────────────────────────────────

  /**
   * Serialize (safe at rest: only passphrase-encrypted secrets).
   * Writes the registry (`keys`) AND, by default, the pre-registry flat fields
   * for compatibility. Pass `{ legacy: false }` for registry-only output.
   * (JSON.stringify passes a string here; that is treated as "defaults".)
   */
  toJSON(options?: MajikKeyToJSONOptions | string): MajikKeyJSON {
    const legacy = !(typeof options === "object" && options?.legacy === false);
    return {
      id: this._id,
      label: this._label,
      publicKey: this._publicKeyBase64,
      fingerprint: this._fingerprint,
      salt: this._salt,
      backup: this._backup,
      timestamp: this._timestamp.toISOString(),
      kdfVersion: this._kdfVersion,
      mnemonicLanguage: this._mnemonicLanguage,
      keysVersion: KEYS_VERSION,
      keys: this._store.toEntries(),
      ...(legacy ? this._store.toLegacyJSON() : {}),
    } as MajikKeyJSON;
  }

  toString(pretty = false): string {
    return JSON.stringify(this.toJSON(), null, pretty ? 2 : 0);
  }

  // ── UTILITY ──────────────────────────────────────────────────────────────────

  static async generateMnemonic(
    strength: 128 | 256 = 128,
    language: MnemonicLanguage = "en",
  ): Promise<string> {
    if (strength !== 128 && strength !== 256)
      throw new MajikKeyError("Strength must be 128 or 256");
    const loader = WORDLISTS[language];
    if (!loader) throw new MajikKeyError("Unsupported language");
    const wordlist = await MajikKey._getWordlist(language);
    return bip39GenerateMnemonic(wordlist, strength);
  }

  static validateMnemonic(mnemonic: string): boolean {
    try {
      MajikKeyValidator.validateMnemonic(mnemonic);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Converts the MajikKey to a MajikContact.
   * You can pass a custom metadata type if needed, e.g., toContact<MyMeta>()
   */
  toContact<TMeta extends MajikContactMeta = MajikContactMeta>(
    initialMeta?: Partial<TMeta>,
  ): MajikContact<TMeta>;
  /** Build any MajikContact subclass by passing its constructor. */
  toContact<
    TMeta extends MajikContactMeta,
    TContact extends MajikContact<TMeta>,
  >(
    ContactClass: new (data: MajikContactData<TMeta>) => TContact,
    initialMeta?: Partial<TMeta>,
  ): TContact;
  toContact(arg1?: unknown, arg2?: unknown): MajikContact<any> {
    const ContactClass = (
      typeof arg1 === "function" ? arg1 : MajikContact
    ) as new (data: MajikContactData<any>) => MajikContact<any>;
    const initialMeta = (typeof arg1 === "function" ? arg2 : arg1) as
      | Partial<MajikContactMeta>
      | undefined;

    return new ContactClass({
      id: this._id,
      publicKey: this._publicKey,
      fingerprint: this._fingerprint,
      meta: { label: this._label, ...initialMeta },
      mlKey: arrayToBase64(this.mlKemPublicKey),
      edPublicKeyBase64: this.edPublicKey
        ? arrayToBase64(this.edPublicKey)
        : undefined,
      mlDsaPublicKeyBase64: this.mlDsaPublicKey
        ? arrayToBase64(this.mlDsaPublicKey)
        : undefined,
    });
  }

  toKeyIdentity(): MajikKeyIdentity {
    if (this.isLocked)
      throw new MajikKeyError(
        "Cannot convert locked MajikKey to KeyIdentity. Unlock first.",
      );
    const blob = this._store.slot(KeyId.X25519)!.encryptedSecretKey!;
    return {
      id: this._id,
      publicKey: this._publicKey,
      fingerprint: this._fingerprint,
      privateKey: { raw: this._requireSecret(KeyId.X25519) },
      encryptedPrivateKey: blob.slice().buffer as ArrayBuffer,
      salt: this._salt,
      kdfVersion: this._kdfVersion,
      mlKemPublicKey: this.mlKemPublicKey,
      mlKemSecretKey: this.mlKemSecretKey,
      edPublicKey: this.edPublicKey,
      edSecretKey: this._store.peekSecretKey(KeyId.ED25519),
      mlDsaPublicKey: this.mlDsaPublicKey,
      mlDsaSecretKey: this._store.peekSecretKey(KeyId.ML_DSA_87),
      btcPublicKey: this.btcPublicKey,
      btcSecretKey: this._store.peekSecretKey(KeyId.BTC),
    };
  }

  toSerializedIdentity(): SerializedIdentity {
    if (this.isLocked)
      throw new MajikKeyError(
        "Cannot convert locked MajikKey to SerializedIdentity. Unlock first.",
      );
    return {
      id: this._id,
      publicKey: this._publicKeyBase64,
      fingerprint: this._fingerprint,
      encryptedPrivateKey: arrayToBase64(
        this._store.slot(KeyId.X25519)!.encryptedSecretKey!,
      ),
      salt: this._salt,
    };
  }

  async toMajikMessageIdentity(
    user: MajikUser,
    options?: { label?: string; restricted?: boolean },
  ): Promise<MajikMessageIdentity> {
    MajikKeyValidator.assert(user, "MajikUser is required");
    const userValidResult = user.validate();
    if (!userValidResult.isValid)
      throw new Error(
        `Invalid MajikUser: ${userValidResult.errors.join(", ")}`,
      );
    const keyContact = await this.toContact().toJSON();
    return MajikMessageIdentity.create(user, keyContact, options);
  }

  // ── BACKUP ───────────────────────────────────────────────────────────────────

  async exportMnemonicBackup(mnemonic: string): Promise<string> {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey must be unlocked to export backup");
    MajikKeyValidator.validateMnemonic(mnemonic);
    return MajikKey._exportMnemonicBackup(
      {
        id: this._id,
        fingerprint: this._fingerprint,
        publicRaw: this._publicKey.raw,
        privateRaw: this._requireSecret(KeyId.X25519),
      },
      mnemonic,
    );
  }

  /**
   * Import a MajikKey from a mnemonic-encrypted backup. Re-derives the account
   * from the mnemonic: the core four (plus `options.keys`) under a new passphrase.
   */
  static async importFromMnemonicBackup(
    backup: string,
    mnemonic: string,
    passphrase: string,
    label?: string,
    options: MajikKeyCreateOptions = {},
  ): Promise<MajikKey> {
    try {
      if (!backup || typeof backup !== "string")
        throw new MajikKeyError("Backup must be a non-empty string");
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      MajikKeyValidator.validateLabel(label);

      const mnemonicLanguage = options.mnemonicLanguage || "en";
      const ids = MajikKey._resolveCreateKeys(options);

      const wordlist = await MajikKey._getWordlist(mnemonicLanguage);
      if (!validateMnemonic(mnemonic, wordlist)) {
        throw new MajikKeyError("Invalid BIP39 mnemonic phrase");
      }

      const backupJson = base64ToUtf8(backup);
      const parsed = JSON.parse(backupJson) as {
        id?: string;
        iv: string;
        ciphertext: string;
        publicKey: string;
        fingerprint: string;
        backupKdfVersion?: number;
        /** 1 (or absent) = legacy "MajikMessage…" salt; 2 = "MajikKey…" salt. */
        backupSaltVersion?: number;
      };

      if (
        !parsed.iv ||
        !parsed.ciphertext ||
        !parsed.publicKey ||
        !parsed.fingerprint
      ) {
        throw new MajikKeyError("Invalid backup format");
      }

      const backupKdfVersion: KDF_VERSION =
        (parsed.backupKdfVersion as KDF_VERSION | undefined) ??
        KDF_VERSION.PBKDF2;

      // Verify mnemonic is correct before doing expensive re-derivation
      await MajikKey._verifyBackupDecryption(
        parsed.iv,
        parsed.ciphertext,
        mnemonic,
        backupKdfVersion,
        parsed.backupSaltVersion,
      );

      const d = await MajikKey._deriveFromMnemonic(mnemonic, passphrase, ids);

      return new MajikKey({
        id: parsed.id || d.fingerprint,
        fingerprint: d.fingerprint,
        salt: d.salt,
        backup,
        label: label || "",
        timestamp: new Date(),
        kdfVersion: KDF_VERSION.ARGON2ID,
        mnemonicLanguage, // fix: previously dropped, silently resetting to "en"
        store: d.store,
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to import from mnemonic backup", err);
    }
  }

  // ── PRIVATE: derivation + vault crypto ───────────────────────────────────────

  private static async _getWordlist(
    language: MnemonicLanguage,
  ): Promise<string[]> {
    const supported: MnemonicLanguage[] = [
      "en",
      "fr",
      "es",
      "it",
      "ja",
      "ko",
      "czech",
      "pt",
      "zh-cn",
      "zh-tw",
    ];

    if (!supported.includes(language as MnemonicLanguage)) {
      throw new MajikKeyError(`Unsupported language: ${String(language)}`);
    }

    const loader = WORDLISTS[language] ?? WORDLISTS.en;

    const mod = await loader();
    return mod.wordlist;
  }

  /**
   * Derive `ids` from the mnemonic and seal each secret under ONE Argon2id
   * key (single salt, single KDF run). Returns an UNLOCKED store.
   */
  private static async _deriveFromMnemonic(
    mnemonic: string,
    passphrase: string,
    ids: readonly KeyId[],
  ) {
    const seed64 = await mnemonicToSeed(mnemonic);
    let derived;
    try {
      derived = deriveKeys(seed64, ids);
    } finally {
      secureFill.call(seed64, 0);
    }

    const salt = generateRandomBytes(SALT_SIZE);
    const aesKey = await MajikKey._deriveVaultKey(passphrase, salt);
    try {
      const store = KeyStore.fromDerived(derived, aesKey);
      const x = derived.get(KeyId.X25519)!;
      return {
        store,
        salt: arrayToBase64(salt),
        fingerprint: fingerprintFromPublicRaw(x.publicKey),
        xPublic: x.publicKey,
        xSecret: x.secretKey,
      };
    } finally {
      secureFill.call(aesKey, 0);
    }
  }

  /** One KDF run. kdfVersion 1 = legacy PBKDF2 (X25519 blob of old accounts only). */
  private static async _deriveVaultKey(
    passphrase: string,
    salt: Uint8Array,
    kdfVersion: KDF_VERSION = KDF_VERSION.ARGON2ID,
  ): Promise<Uint8Array> {
    return kdfVersion === KDF_VERSION.ARGON2ID
      ? deriveKeyFromPassphraseArgon2(passphrase, salt)
      : deriveKeyFromPassphrase(passphrase, salt);
  }

  // ── PRIVATE: Backup ──────────────────────────────────────────────────────────

  private static async _verifyBackupDecryption(
    ivBase64: string,
    ciphertextBase64: string,
    mnemonic: string,
    backupKdfVersion: KDF_VERSION,
    backupSaltVersion?: number,
  ): Promise<void> {
    const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
    const ciphertext = base64ToArrayBuffer(ciphertextBase64);
    const mnemonicSalt = new TextEncoder().encode(
      backupSaltFor(backupSaltVersion),
    );

    if (backupKdfVersion === KDF_VERSION.ARGON2ID) {
      const keyBytes = await deriveKeyFromMnemonicArgon2(
        mnemonic,
        mnemonicSalt,
      );
      const plain = aesGcmDecrypt(keyBytes, iv, new Uint8Array(ciphertext));
      if (!plain)
        throw new MajikKeyError(
          "Failed to decrypt backup — invalid mnemonic or corrupted data",
        );
    } else {
      // PBKDF2 backups predate salt versioning: always the legacy salt.
      const legacyKey = await MajikKey._deriveLegacyMnemonicKey(mnemonic);
      try {
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          legacyKey,
          ciphertext,
        );
      } catch {
        throw new MajikKeyError(
          "Failed to decrypt backup — invalid mnemonic or corrupted data",
        );
      }
    }
  }

  private static async _exportMnemonicBackup(
    identity: {
      id: string;
      fingerprint: string;
      publicRaw: Uint8Array;
      privateRaw: Uint8Array;
    },
    mnemonic: string,
  ): Promise<string> {
    const mnemonicSalt = new TextEncoder().encode(
      backupSaltFor(BACKUP_SALT_WRITE_VERSION),
    );
    const keyBytes = await deriveKeyFromMnemonicArgon2(mnemonic, mnemonicSalt);
    const iv = generateRandomBytes(IV_LENGTH);
    const ciphertext = aesGcmEncrypt(keyBytes, iv, identity.privateRaw);

    return utf8ToBase64(
      JSON.stringify({
        id: identity.id,
        iv: arrayToBase64(iv),
        ciphertext: arrayToBase64(ciphertext),
        publicKey: arrayToBase64(identity.publicRaw),
        fingerprint: identity.fingerprint,
        backupKdfVersion: KDF_VERSION.ARGON2ID,
        backupSaltVersion: BACKUP_SALT_WRITE_VERSION,
      }),
    );
  }

  private static async _deriveLegacyMnemonicKey(
    mnemonic: string,
  ): Promise<CryptoKey> {
    const salt = new TextEncoder().encode(LEGACY_MAJIK_MNEMONIC_SALT);
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(mnemonic),
      { name: "PBKDF2" },
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 200_000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  // ── WEB3 (EXPERIMENTAL) ─────────────────────────────────────────────────────

  /**
   * @experimental
   */
  get web3(): MajikKeyWeb3Namespace | undefined {
    if (!this.hasSolanaKeypair) return undefined;

    const solanaMaterial = this._getOrDeriveSolanaMaterial();

    const btcSecret = this._store.peekSecretKey(KeyId.BTC);
    const btcMaterial: BitcoinKeypairMaterial | undefined =
      btcSecret && this._store.has(KeyId.BTC)
        ? {
            privateKey: btcSecret,
            publicKey: this._store.getPublicKey(KeyId.BTC),
          }
        : undefined;

    const ethSecret = this._store.peekSecretKey(KeyId.ETH);
    const ethMaterial: EthereumKeypairMaterial | undefined =
      ethSecret && this._store.has(KeyId.ETH)
        ? {
            privateKey: ethSecret,
            publicKey: this._store.getPublicKey(KeyId.ETH),
          }
        : undefined;

    return {
      solana: {
        publicKey: solanaMaterial.publicKey,
        secretKey: solanaMaterial.secretKey,
        address: solanaAddressFromPublicKey(solanaMaterial.publicKey),
        getSolanaKeypair: () => toSolanaKeyPairSigner(solanaMaterial),
        getSolanaAddress: () => toSolanaAddress(solanaMaterial),
        sign: (message: Uint8Array) =>
          signWithSolanaMaterial(solanaMaterial, message),
      },
      bitcoin: btcMaterial && {
        publicKey: btcMaterial.publicKey,
        privateKey: btcMaterial.privateKey,
        getBitcoinAddress: () => toBitcoinAddress(btcMaterial),
        getWIF: (options?: { compressed?: boolean }) =>
          toWIF(btcMaterial, options),
        sign: (hash: Uint8Array, scheme?: "ecdsa" | "schnorr") =>
          signWithBitcoinMaterial(btcMaterial, hash, scheme),
      },
      ethereum: ethMaterial && {
        publicKey: ethMaterial.publicKey,
        privateKey: ethMaterial.privateKey,
        address: ethereumAddressFromPublicKey(ethMaterial.publicKey),
        getPrivateKeyHex: () => toEthereumPrivateKeyHex(ethMaterial),
        signHash: (hash32: Uint8Array) => signEthereumHash(ethMaterial, hash32),
        signMessage: (message: string | Uint8Array) =>
          signEthereumMessage(ethMaterial, message),
      },
    };
  }

  // ── BITCOIN (EXPERIMENTAL) ──────────────────────────────────────────────────

  /** @experimental True if this MajikKey can currently produce Bitcoin material (unlocked + has a Bitcoin key). */
  get hasBitcoinKeypair(): boolean {
    return this._store.peekSecretKey(KeyId.BTC) !== undefined;
  }

  /**
   * @experimental Raw Bitcoin keypair material for the stored (domain-separated)
   * key. The REAL BIP-84 key needs the mnemonic:
   * use `MajikKey.deriveStandardBitcoinFromMnemonic(mnemonic)`.
   */
  getBitcoinKeypairMaterial(
    options?: BitcoinDerivationOptions,
  ): BitcoinKeypairMaterial {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    if (!options?.standard && !options?.path) {
      return {
        privateKey: this.getBtcSecretKey(),
        publicKey: this._store.getPublicKey(KeyId.BTC),
      };
    }
    throw new MajikKeyError(
      "Deriving the standard BIP-84 path requires the mnemonic — " +
        "use MajikKey.deriveStandardBitcoinFromMnemonic(mnemonic) instead.",
    );
  }

  /** @experimental Derive the REAL BIP-84 mainnet Bitcoin keypair straight from a mnemonic. */
  static async deriveStandardBitcoinFromMnemonic(
    mnemonic: string,
    mnemonicLanguage: MnemonicLanguage = "en",
  ): Promise<BitcoinKeypairMaterial> {
    MajikKeyValidator.validateMnemonic(mnemonic);
    const wordlist = await MajikKey._getWordlist(mnemonicLanguage);
    if (!validateMnemonic(mnemonic, wordlist)) {
      throw new MajikKeyError("Invalid BIP39 mnemonic phrase");
    }
    const seed = await mnemonicToSeed(mnemonic);
    return deriveBitcoinKeypairFromSeed(seed, { standard: true });
  }

  /** @experimental WIF export of the stored (domain-separated) Bitcoin key. */
  getBitcoinWIF(options?: { compressed?: boolean }): string {
    return toWIF(this.getBitcoinKeypairMaterial(), options);
  }

  // ── ETHEREUM (EXPERIMENTAL) ─────────────────────────────────────────────────

  /** @experimental True if this account has a stored Ethereum key (works while locked). */
  get hasEthereum(): boolean {
    return this._store.has(KeyId.ETH);
  }

  /**
   * @experimental EIP-55 Ethereum address (standard m/44'/60'/0'/0/0 — the same
   * address MetaMask shows for this mnemonic). Public-only, so it works while locked.
   */
  getEthereumAddress(): string {
    if (!this._store.has(KeyId.ETH))
      throw new MajikKeyError(
        "No Ethereum key — add it with addKeys([KeyId.ETH], mnemonic, passphrase).",
      );
    return ethereumAddressFromPublicKey(this._store.getPublicKey(KeyId.ETH));
  }

  /** @experimental Raw Ethereum keypair material. Requires an unlocked account. */
  getEthereumKeypairMaterial(): EthereumKeypairMaterial {
    return {
      privateKey: this._requireSecret(KeyId.ETH),
      publicKey: this._store.getPublicKey(KeyId.ETH),
    };
  }

  /** @experimental 0x-prefixed private key hex, for wallet "import private key". */
  getEthereumPrivateKeyHex(): string {
    return toEthereumPrivateKeyHex(this.getEthereumKeypairMaterial());
  }

  // ── SOLANA (EXPERIMENTAL) ───────────────────────────────────────────────────

  /** @experimental True if this MajikKey can currently produce a Solana keypair (unlocked + has Ed25519). */
  get hasSolanaKeypair(): boolean {
    return this._store.peekSecretKey(KeyId.ED25519) !== undefined;
  }

  private _getOrDeriveSolanaMaterial(): SolanaKeypairMaterial {
    const ed = this._store.peekSecretKey(KeyId.ED25519);
    if (!ed)
      throw new MajikKeyError(
        "No Ed25519 secret key — MajikKey must be unlocked and have signing keys.",
      );
    if (!this._solanaKeypairMaterial) {
      this._solanaKeypairMaterial = deriveSolanaKeypairFromEdSecretKey(ed);
    }
    return this._solanaKeypairMaterial;
  }

  /** @experimental Raw Solana keypair material. `reuseMessageKey: true` reuses the message-signing Ed25519 key. */
  getSolanaKeypairMaterial(options?: {
    reuseMessageKey?: boolean;
  }): SolanaKeypairMaterial {
    const ed = this._requireSecret(
      KeyId.ED25519,
      "No Ed25519 secret key — add it with addKeys() (requires the mnemonic).",
    );
    if (options?.reuseMessageKey) return solanaMaterialFromEd25519SecretKey(ed);
    return this._getOrDeriveSolanaMaterial();
  }

  /** @experimental Real @solana/kit Keypair instance (lazy-loads @solana/kit). */
  async getSolanaKeypair(options?: {
    reuseMessageKey?: boolean;
  }): Promise<any> {
    return toSolanaKeyPairSigner(this.getSolanaKeypairMaterial(options));
  }

  /** @experimental Base58 Solana address. Does NOT require @solana/kit. */
  getSolanaAddress(options?: { reuseMessageKey?: boolean }): string {
    return solanaAddressFromPublicKey(
      this.getSolanaKeypairMaterial(options).publicKey,
    );
  }
}

// Freeze static methods (e.g., MajikKey.create, MajikKey.fromJSON)
Object.freeze(MajikKey);

// Freeze instance methods (e.g., this.lock, this.unlock)
Object.freeze(MajikKey.prototype);
