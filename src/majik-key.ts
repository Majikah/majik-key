/**
 * MajikKey.ts
 *
 * Seed phrase account library for Majik Message.
 *
 * Every account stores TWO keypairs derived deterministically from the mnemonic:
 *   1. X25519 (Curve25519)   — fingerprint, contact identity, legacy message compat
 *   2. ML-KEM-768 (FIPS-203) — post-quantum key encapsulation for v3 envelopes
 *
 * Both are derived from the 64-byte BIP-39 seed:
 *   seed[0..32]  → Ed25519 → X25519 via ed2curve
 *   seed[0..64]  → ml_kem768.keygen(seed) — full seed, deterministic
 *
 * KDF versioning (passphrase encryption at rest):
 *   v1 — PBKDF2-SHA256, 250k iterations   (legacy read-only)
 *   v2 — Argon2id, 128 MB / 4t / 4p       (all new accounts)
 *
 * Migration policy:
 *   Old accounts (v1, no ML-KEM keys) are fully upgraded on first import
 *   via importFromMnemonicBackup(). The mnemonic is always available at that
 *   point, so ML-KEM keys can be deterministically re-derived and stored.
 *   No partial migration — either fully upgraded or not upgraded yet.
 */

import { generateMnemonic } from "@scure/bip39";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  deriveKeyFromPassphraseArgon2,
  deriveKeyFromMnemonicArgon2,
  deriveKeyFromPassphrase,
  generateRandomBytes,
  IV_LENGTH,
} from "./core/crypto/crypto-provider";
import { EncryptionEngine } from "./core/crypto/encryption-engine";
import { MajikContact } from "./core/majik-contact";
import {
  arrayBufferToBase64,
  arrayToBase64,
  base64ToArrayBuffer,
  concatUint8Arrays,
  utf8ToBase64,
  base64ToUtf8,
  seedStringToArray,
  seedArrayToString,
  base64ToUint8Array,
} from "./core/utils";
import { wordlist } from "@scure/bip39/wordlists/english";
import {
  KDF_VERSION,
  KEY_ALGO,
  MAJIK_MNEMONIC_SALT,
} from "./core/crypto/constants";
import { MajikKeyValidator } from "./core/validator";
import { MajikKeyError } from "./core/error";
import type {
  MajikKeyJSON,
  MajikKeyMetadata,
  MnemonicJSON,
} from "./core/types";
import { MajikMessageIdentity } from "./core/database/system/identity";
import { MajikUser } from "@thezelijah/majik-user";

const SALT_SIZE = 32;

// ─── Interfaces ───────────────────────────────────────────────────────────────

export interface MajikKeyIdentity {
  id: string;
  publicKey: CryptoKey | { raw: Uint8Array };
  fingerprint: string;
  privateKey: CryptoKey | { raw: Uint8Array };
  encryptedPrivateKey: ArrayBuffer;
  salt: string;
  kdfVersion: KDF_VERSION;
  mlKemPublicKey: Uint8Array;
  mlKemSecretKey?: Uint8Array;
}

export interface SerializedIdentity {
  id: string;
  publicKey: string;
  fingerprint: string;
  encryptedPrivateKey?: string;
  salt?: string;
}

export interface MajikKeyConstructorOptions {
  id: string;
  publicKey: CryptoKey | { raw: Uint8Array };
  publicKeyBase64: string;
  fingerprint: string;
  encryptedPrivateKey: ArrayBuffer;
  encryptedPrivateKeyBase64: string;
  salt: string;
  backup: string;
  label?: string;
  timestamp?: Date;
  kdfVersion?: KDF_VERSION;
  mlKemPublicKey: Uint8Array;
  mlKemSecretKey?: Uint8Array;
  encryptedMlKemSecretKey?: ArrayBuffer;
  encryptedMlKemSecretKeyBase64?: string;
  privateKey?: CryptoKey | { raw: Uint8Array };
  privateKeyBase64?: string;
}

// ─── MajikKey ─────────────────────────────────────────────────────────────────

export class MajikKey {
  private readonly _id: string;
  private readonly _publicKey: CryptoKey | { raw: Uint8Array };
  private readonly _publicKeyBase64: string;
  private readonly _fingerprint: string;
  private readonly _backup: string;
  private readonly _timestamp: Date;

  private _encryptedPrivateKey: ArrayBuffer;
  private _encryptedPrivateKeyBase64: string;
  private _salt: string;
  private _label: string;
  private _kdfVersion: KDF_VERSION;

  private _mlKemPublicKey: Uint8Array;
  private _mlKemSecretKey?: Uint8Array;
  private _encryptedMlKemSecretKey?: ArrayBuffer;
  private _encryptedMlKemSecretKeyBase64?: string;

  private _privateKey?: CryptoKey | { raw: Uint8Array };
  private _privateKeyBase64?: string;

  private constructor(options: MajikKeyConstructorOptions) {
    this._id = options.id;
    this._publicKey = options.publicKey;
    this._publicKeyBase64 = options.publicKeyBase64;
    this._fingerprint = options.fingerprint;
    this._encryptedPrivateKey = options.encryptedPrivateKey;
    this._encryptedPrivateKeyBase64 = options.encryptedPrivateKeyBase64;
    this._salt = options.salt;
    this._backup = options.backup;
    this._label = options.label || "";
    this._timestamp = options.timestamp || new Date();
    this._kdfVersion = options.kdfVersion ?? KDF_VERSION.PBKDF2;
    this._mlKemPublicKey = options.mlKemPublicKey;
    this._mlKemSecretKey = options.mlKemSecretKey;
    this._encryptedMlKemSecretKey = options.encryptedMlKemSecretKey;
    this._encryptedMlKemSecretKeyBase64 = options.encryptedMlKemSecretKeyBase64;
    this._privateKey = options.privateKey;
    this._privateKeyBase64 = options.privateKeyBase64;
  }

  // ── Getters ─────────────────────────────────────────────────────────────────

  get id(): string {
    return this._id;
  }
  get fingerprint(): string {
    return this._fingerprint;
  }
  get publicKey(): CryptoKey | { raw: Uint8Array } {
    return this._publicKey;
  }
  get publicKeyBase64(): string {
    return this._publicKeyBase64;
  }
  get label(): string {
    return this._label;
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
    return this._privateKey === undefined;
  }
  get isUnlocked(): boolean {
    return this._privateKey !== undefined;
  }
  get mlKemPublicKey(): Uint8Array {
    return this._mlKemPublicKey;
  }
  get mlKemSecretKey(): Uint8Array | undefined {
    return this._mlKemSecretKey;
  }
  get hasMlKem(): boolean {
    return this._mlKemPublicKey !== undefined;
  }
  get isFullyUpgraded(): boolean {
    return this.isArgon2id && this.hasMlKem;
  }

  get metadata(): MajikKeyMetadata {
    return {
      id: this.id,
      fingerprint: this.fingerprint,
      label: this.label,
      timestamp: this.timestamp,
      isLocked: this.isLocked,
      kdfVersion: this.kdfVersion,
      hasMlKem: this.hasMlKem,
    };
  }

  // ── CREATE ──────────────────────────────────────────────────────────────────

  static async create(
    mnemonic: string,
    passphrase: string,
    label?: string,
  ): Promise<MajikKey> {
    try {
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      MajikKeyValidator.validateLabel(label);

      const identity = await MajikKey._deriveAndEncryptFromMnemonic(
        mnemonic,
        passphrase,
      );
      const privateKeyBase64 = await MajikKey._exportKeyToBase64(
        identity.privateKey,
      );
      const publicKeyBase64 = await MajikKey._exportKeyToBase64(
        identity.publicKey,
      );
      const backup = await MajikKey._exportMnemonicBackup(identity, mnemonic);

      return new MajikKey({
        id: identity.id,
        publicKey: identity.publicKey,
        publicKeyBase64,
        fingerprint: identity.fingerprint,
        encryptedPrivateKey: identity.encryptedPrivateKey,
        encryptedPrivateKeyBase64: arrayBufferToBase64(
          identity.encryptedPrivateKey,
        ),
        salt: identity.salt,
        backup,
        label: label || "",
        timestamp: new Date(),
        kdfVersion: KDF_VERSION.ARGON2ID,
        mlKemPublicKey: identity.mlKemPublicKey,
        mlKemSecretKey: identity.mlKemSecretKey,
        encryptedMlKemSecretKey: identity.encryptedMlKemSecretKey,
        encryptedMlKemSecretKeyBase64: arrayBufferToBase64(
          identity.encryptedMlKemSecretKey,
        ),
        privateKey: identity.privateKey,
        privateKeyBase64,
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to create MajikKey", err);
    }
  }

  // ── READ ────────────────────────────────────────────────────────────────────

  static fromJSON(json: MajikKeyJSON | string): MajikKey {
    try {
      const parsed: MajikKeyJSON =
        typeof json === "string" ? JSON.parse(json) : json;
      const validated = MajikKeyValidator.validateJSON(parsed);
      const anyParsed = parsed as any;

      const publicKeyBuffer = base64ToArrayBuffer(validated.publicKey);
      const encryptedPrivateKeyBuffer = base64ToArrayBuffer(
        validated.encryptedPrivateKey,
      );

      const mlKemPublicKey = base64ToUint8Array(anyParsed.mlKemPublicKey);

      let encryptedMlKemSecretKey: ArrayBuffer | undefined;
      let encryptedMlKemSecretKeyBase64: string | undefined;
      if (anyParsed.encryptedMlKemSecretKey) {
        encryptedMlKemSecretKeyBase64 = anyParsed.encryptedMlKemSecretKey;
        encryptedMlKemSecretKey = base64ToArrayBuffer(
          anyParsed.encryptedMlKemSecretKey,
        );
      }

      return new MajikKey({
        id: validated.id,
        publicKey: { raw: new Uint8Array(publicKeyBuffer) },
        publicKeyBase64: validated.publicKey,
        fingerprint: validated.fingerprint,
        encryptedPrivateKey: encryptedPrivateKeyBuffer,
        encryptedPrivateKeyBase64: validated.encryptedPrivateKey,
        salt: validated.salt,
        backup: validated.backup,
        label: validated.label || "",
        timestamp: new Date(validated.timestamp),
        kdfVersion:
          (validated.kdfVersion as KDF_VERSION | undefined) ??
          KDF_VERSION.PBKDF2,
        mlKemPublicKey,
        encryptedMlKemSecretKey,
        encryptedMlKemSecretKeyBase64,
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to parse MajikKey from JSON", err);
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
    };
  }

  static async fromMnemonicJSON(
    mnemonicJson: MnemonicJSON | string,
    passphrase: string,
    label?: string,
  ): Promise<MajikKey> {
    try {
      const parsed: MnemonicJSON =
        typeof mnemonicJson === "string"
          ? JSON.parse(mnemonicJson)
          : mnemonicJson;
      if (!parsed.id || !parsed.seed || !Array.isArray(parsed.seed))
        throw new MajikKeyError("Invalid MnemonicJSON");
      const mnemonic = seedArrayToString(parsed.seed);
      MajikKeyValidator.validateMnemonic(mnemonic);
      return await MajikKey.create(mnemonic, passphrase, label);
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError(
        "Failed to create MajikKey from MnemonicJSON",
        err,
      );
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
    try {
      MajikKeyValidator.validatePassphrase(
        currentPassphrase,
        "Current passphrase",
      );
      MajikKeyValidator.validatePassphrase(newPassphrase, "New passphrase");

      const salt = new Uint8Array(base64ToArrayBuffer(this._salt));
      const privateKeyBuffer = await MajikKey._decryptPrivateKey(
        this._encryptedPrivateKey,
        currentPassphrase,
        salt,
        this._kdfVersion,
      );

      let mlKemSecretKeyBytes: Uint8Array | undefined;
      if (this._encryptedMlKemSecretKey) {
        mlKemSecretKeyBytes = await MajikKey._decryptMlKemSecretKey(
          this._encryptedMlKemSecretKey,
          currentPassphrase,
          salt,
        );
      }

      const newSalt = generateRandomBytes(SALT_SIZE);
      const { blob: newEncryptedPrivateKey } =
        await MajikKey._encryptPrivateKey(
          privateKeyBuffer,
          newPassphrase,
          newSalt,
        );
      this._encryptedPrivateKey = newEncryptedPrivateKey;
      this._encryptedPrivateKeyBase64 = arrayBufferToBase64(
        newEncryptedPrivateKey,
      );
      this._salt = arrayToBase64(newSalt);
      this._kdfVersion = KDF_VERSION.ARGON2ID;

      if (mlKemSecretKeyBytes) {
        const encMlKem = await MajikKey._encryptMlKemSecretKey(
          mlKemSecretKeyBytes,
          newPassphrase,
          newSalt,
        );
        this._encryptedMlKemSecretKey = encMlKem;
        this._encryptedMlKemSecretKeyBase64 = arrayBufferToBase64(encMlKem);
        this._mlKemSecretKey = mlKemSecretKeyBytes;
      }
      return this;
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to update passphrase", err);
    }
  }

  /**
   * Migrate KDF from PBKDF2 to Argon2id without changing passphrase.
   * NOTE: Does not add ML-KEM keys — use importFromMnemonicBackup() for full upgrade.
   */
  async migrate(passphrase: string): Promise<this> {
    try {
      MajikKeyValidator.validatePassphrase(passphrase);
      if (this._kdfVersion === KDF_VERSION.ARGON2ID) return this;

      const salt = new Uint8Array(base64ToArrayBuffer(this._salt));
      const privateKeyBuffer = await MajikKey._decryptPrivateKey(
        this._encryptedPrivateKey,
        passphrase,
        salt,
        KDF_VERSION.PBKDF2,
      );
      const newSalt = generateRandomBytes(SALT_SIZE);
      const { blob } = await MajikKey._encryptPrivateKey(
        privateKeyBuffer,
        passphrase,
        newSalt,
      );
      this._encryptedPrivateKey = blob;
      this._encryptedPrivateKeyBase64 = arrayBufferToBase64(blob);
      this._salt = arrayToBase64(newSalt);
      this._kdfVersion = KDF_VERSION.ARGON2ID;
      return this;
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to migrate MajikKey to Argon2id", err);
    }
  }

  // ── LOCK / UNLOCK ────────────────────────────────────────────────────────────

  lock(): this {
    this._privateKey = undefined;
    this._privateKeyBase64 = undefined;
    this._mlKemSecretKey = undefined;
    return this;
  }

  async unlock(passphrase: string): Promise<this> {
    try {
      if (this.isUnlocked)
        throw new MajikKeyError("MajikKey is already unlocked");
      MajikKeyValidator.validatePassphrase(passphrase);

      const salt = new Uint8Array(base64ToArrayBuffer(this._salt));
      const privateKeyBuffer = await MajikKey._decryptPrivateKey(
        this._encryptedPrivateKey,
        passphrase,
        salt,
        this._kdfVersion,
      );

      let privateKey: CryptoKey | { raw: Uint8Array };
      try {
        privateKey = await crypto.subtle.importKey(
          "raw",
          privateKeyBuffer,
          KEY_ALGO,
          true,
          ["sign"],
        );
      } catch {
        privateKey = {
          type: "private",
          raw: new Uint8Array(privateKeyBuffer),
        } as any;
      }
      this._privateKey = privateKey;
      this._privateKeyBase64 = arrayBufferToBase64(privateKeyBuffer);

      if (this._encryptedMlKemSecretKey) {
        this._mlKemSecretKey = await MajikKey._decryptMlKemSecretKey(
          this._encryptedMlKemSecretKey,
          passphrase,
          salt,
        );
      }
      return this;
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
      await MajikKey._decryptPrivateKey(
        this._encryptedPrivateKey,
        passphrase,
        salt,
        this._kdfVersion,
      );
      return true;
    } catch {
      return false;
    }
  }

  getPrivateKey(): CryptoKey | { raw: Uint8Array } {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    return this._privateKey!;
  }

  getPrivateKeyBase64(): string {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    return this._privateKeyBase64!;
  }

  getMlKemSecretKey(): Uint8Array {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    if (!this._mlKemSecretKey)
      throw new MajikKeyError(
        "No ML-KEM secret key — re-import via importFromMnemonicBackup() for full migration.",
      );
    return this._mlKemSecretKey;
  }

  // ── SERIALIZATION ────────────────────────────────────────────────────────────

  toJSON(): MajikKeyJSON {
    return {
      id: this._id,
      label: this._label,
      publicKey: this._publicKeyBase64,
      fingerprint: this._fingerprint,
      encryptedPrivateKey: this._encryptedPrivateKeyBase64,
      salt: this._salt,
      backup: this._backup,
      timestamp: this._timestamp.toISOString(),
      kdfVersion: this._kdfVersion,
      mlKemPublicKey: this._mlKemPublicKey
        ? arrayToBase64(this._mlKemPublicKey)
        : undefined,
      encryptedMlKemSecretKey: this._encryptedMlKemSecretKeyBase64,
    };
  }

  toString(pretty = false): string {
    return JSON.stringify(this.toJSON(), null, pretty ? 2 : 0);
  }

  // ── UTILITY ──────────────────────────────────────────────────────────────────

  static generateMnemonic(strength: 128 | 256 = 128): string {
    if (strength !== 128 && strength !== 256)
      throw new MajikKeyError("Strength must be 128 or 256");
    return generateMnemonic(wordlist, strength);
  }

  static validateMnemonic(mnemonic: string): boolean {
    try {
      MajikKeyValidator.validateMnemonic(mnemonic);
      return true;
    } catch {
      return false;
    }
  }

  toContact(): MajikContact {
    const mlKeyBase64 = arrayToBase64(this.mlKemPublicKey);
    return new MajikContact({
      id: this._id,
      publicKey: this._publicKey,
      fingerprint: this._fingerprint,
      meta: { label: this._label },
      mlKey: mlKeyBase64,
    });
  }

  toKeyIdentity(): MajikKeyIdentity {
    if (this.isLocked)
      throw new MajikKeyError(
        "Cannot convert locked MajikKey to KeyIdentity. Unlock first.",
      );
    return {
      id: this._id,
      publicKey: this._publicKey,
      fingerprint: this._fingerprint,
      privateKey: this._privateKey!,
      encryptedPrivateKey: this._encryptedPrivateKey,
      salt: this._salt,
      kdfVersion: this._kdfVersion,
      mlKemPublicKey: this._mlKemPublicKey,
      mlKemSecretKey: this._mlKemSecretKey,
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
      encryptedPrivateKey: this._encryptedPrivateKeyBase64,
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
    return MajikKey._exportMnemonicBackup(this.toKeyIdentity(), mnemonic);
  }

  /**
   * Import a MajikKey from a mnemonic-encrypted backup.
   *
   * This is the FULL MIGRATION PATH for old accounts — Argon2id + ML-KEM in one step:
   *   1. Verify the backup decrypts correctly (proves mnemonic is correct)
   *   2. Re-derive the complete identity from the mnemonic (X25519 + ML-KEM-768)
   *   3. Encrypt both private keys with Argon2id (v2) + fresh 32-byte salt
   *   4. Return a fully-upgraded MajikKey with hasMlKem: true, isArgon2id: true
   *
   * Old accounts without ML-KEM keys become fully post-quantum capable
   * automatically — no extra user steps. The mnemonic is the source of truth.
   */
  static async importFromMnemonicBackup(
    backup: string,
    mnemonic: string,
    passphrase: string,
    label?: string,
  ): Promise<MajikKey> {
    try {
      if (!backup || typeof backup !== "string")
        throw new MajikKeyError("Backup must be a non-empty string");
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      MajikKeyValidator.validateLabel(label);

      const backupJson = base64ToUtf8(backup);
      const parsed = JSON.parse(backupJson) as {
        id?: string;
        iv: string;
        ciphertext: string;
        publicKey: string;
        fingerprint: string;
        backupKdfVersion?: number;
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
      );

      // Re-derive complete identity from mnemonic — gets ML-KEM for free
      const identity = await MajikKey._deriveAndEncryptFromMnemonic(
        mnemonic,
        passphrase,
      );

      const privateKeyBase64 = await MajikKey._exportKeyToBase64(
        identity.privateKey,
      );
      const publicKeyBase64 = await MajikKey._exportKeyToBase64(
        identity.publicKey,
      );
      const id = parsed.id || identity.id;

      return new MajikKey({
        id,
        publicKey: identity.publicKey,
        publicKeyBase64,
        fingerprint: identity.fingerprint,
        encryptedPrivateKey: identity.encryptedPrivateKey,
        encryptedPrivateKeyBase64: arrayBufferToBase64(
          identity.encryptedPrivateKey,
        ),
        salt: identity.salt,
        backup,
        label: label || "",
        timestamp: new Date(),
        kdfVersion: KDF_VERSION.ARGON2ID,
        mlKemPublicKey: identity.mlKemPublicKey,
        mlKemSecretKey: identity.mlKemSecretKey,
        encryptedMlKemSecretKey: identity.encryptedMlKemSecretKey,
        encryptedMlKemSecretKeyBase64: arrayBufferToBase64(
          identity.encryptedMlKemSecretKey,
        ),
        privateKey: identity.privateKey,
        privateKeyBase64,
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to import from mnemonic backup", err);
    }
  }

  // ── PRIVATE: Core Derivation ─────────────────────────────────────────────────

  private static async _deriveAndEncryptFromMnemonic(
    mnemonic: string,
    passphrase: string,
  ): Promise<MajikKeyIdentity & { encryptedMlKemSecretKey: ArrayBuffer }> {
    const encIdentity =
      await EncryptionEngine.deriveIdentityFromMnemonic(mnemonic);

    let exportedXPrivate: ArrayBuffer;
    try {
      exportedXPrivate = await crypto.subtle.exportKey(
        "raw",
        encIdentity.privateKey as CryptoKey,
      );
    } catch {
      const anyPriv: any = encIdentity.privateKey;
      if (anyPriv?.raw instanceof Uint8Array) {
        exportedXPrivate = anyPriv.raw.buffer.slice(
          anyPriv.raw.byteOffset,
          anyPriv.raw.byteOffset + anyPriv.raw.byteLength,
        );
      } else {
        throw new MajikKeyError(
          "Cannot export private key: unsupported format",
        );
      }
    }

    // Single salt — one Argon2id derivation unlocks both keys
    const salt = generateRandomBytes(SALT_SIZE);
    const { blob: encryptedPrivateKey } = await MajikKey._encryptPrivateKey(
      exportedXPrivate,
      passphrase,
      salt,
    );

    const mlKemSecretKey = encIdentity.mlKemSecretKey!;
    const encryptedMlKemSecretKey = await MajikKey._encryptMlKemSecretKey(
      mlKemSecretKey,
      passphrase,
      salt,
    );

    return {
      id: encIdentity.fingerprint,
      publicKey: encIdentity.publicKey,
      fingerprint: encIdentity.fingerprint,
      privateKey: encIdentity.privateKey,
      encryptedPrivateKey,
      salt: arrayToBase64(salt),
      kdfVersion: KDF_VERSION.ARGON2ID,
      mlKemPublicKey: encIdentity.mlKemPublicKey,
      mlKemSecretKey,
      encryptedMlKemSecretKey,
    };
  }

  // ── PRIVATE: Encryption/Decryption ───────────────────────────────────────────

  private static async _encryptPrivateKey(
    buffer: ArrayBuffer,
    passphrase: string,
    salt: Uint8Array,
  ): Promise<{ blob: ArrayBuffer; kdfVersion: KDF_VERSION }> {
    const keyBytes = deriveKeyFromPassphraseArgon2(passphrase, salt);
    const iv = generateRandomBytes(IV_LENGTH);
    const ciphertext = aesGcmEncrypt(keyBytes, iv, new Uint8Array(buffer));
    return {
      blob: concatUint8Arrays(iv, ciphertext).buffer as ArrayBuffer,
      kdfVersion: KDF_VERSION.ARGON2ID,
    };
  }

  /**
   * Encrypt the ML-KEM secret key using the same Argon2id-derived key as X25519
   * (same passphrase + same salt) but a DIFFERENT random IV. One Argon2id
   * computation → two independently encrypted blobs.
   */
  private static async _encryptMlKemSecretKey(
    mlKemSecretKey: Uint8Array,
    passphrase: string,
    salt: Uint8Array,
  ): Promise<ArrayBuffer> {
    const keyBytes = deriveKeyFromPassphraseArgon2(passphrase, salt);
    const iv = generateRandomBytes(IV_LENGTH); // different IV from X25519 blob
    const ciphertext = aesGcmEncrypt(keyBytes, iv, mlKemSecretKey);
    return concatUint8Arrays(iv, ciphertext).buffer as ArrayBuffer;
  }

  private static async _decryptPrivateKey(
    buffer: ArrayBuffer,
    passphrase: string,
    salt: Uint8Array,
    kdfVersion: KDF_VERSION = KDF_VERSION.PBKDF2,
  ): Promise<ArrayBuffer> {
    const keyBytes =
      kdfVersion === KDF_VERSION.ARGON2ID
        ? deriveKeyFromPassphraseArgon2(passphrase, salt)
        : deriveKeyFromPassphrase(passphrase, salt);

    const full = new Uint8Array(buffer);
    const iv = full.slice(0, IV_LENGTH);
    const ciphertext = full.slice(IV_LENGTH);
    const plain = aesGcmDecrypt(keyBytes, iv, ciphertext);
    if (!plain)
      throw new MajikKeyError(
        "Decryption failed — incorrect passphrase or corrupted data",
      );
    return plain.buffer as ArrayBuffer;
  }

  private static async _decryptMlKemSecretKey(
    buffer: ArrayBuffer,
    passphrase: string,
    salt: Uint8Array,
  ): Promise<Uint8Array> {
    // ML-KEM keys are only ever written by Argon2id (v2) code
    const keyBytes = deriveKeyFromPassphraseArgon2(passphrase, salt);
    const full = new Uint8Array(buffer);
    const iv = full.slice(0, IV_LENGTH);
    const ciphertext = full.slice(IV_LENGTH);
    const plain = aesGcmDecrypt(keyBytes, iv, ciphertext);
    if (!plain) throw new MajikKeyError("Failed to decrypt ML-KEM secret key");
    return plain;
  }

  // ── PRIVATE: Backup ──────────────────────────────────────────────────────────

  private static async _verifyBackupDecryption(
    ivBase64: string,
    ciphertextBase64: string,
    mnemonic: string,
    backupKdfVersion: KDF_VERSION,
  ): Promise<void> {
    const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
    const ciphertext = base64ToArrayBuffer(ciphertextBase64);
    const mnemonicSalt = new TextEncoder().encode(MAJIK_MNEMONIC_SALT);

    if (backupKdfVersion === KDF_VERSION.ARGON2ID) {
      const keyBytes = deriveKeyFromMnemonicArgon2(mnemonic, mnemonicSalt);
      const plain = aesGcmDecrypt(keyBytes, iv, new Uint8Array(ciphertext));
      if (!plain)
        throw new MajikKeyError(
          "Failed to decrypt backup — invalid mnemonic or corrupted data",
        );
    } else {
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
    identity: MajikKeyIdentity,
    mnemonic: string,
  ): Promise<string> {
    if (!identity?.privateKey)
      throw new MajikKeyError("Identity must have privateKey to export backup");

    let privRawBuf: ArrayBuffer;
    let pubRawBuf: ArrayBuffer;

    try {
      privRawBuf = await crypto.subtle.exportKey(
        "raw",
        identity.privateKey as CryptoKey,
      );
      pubRawBuf = await crypto.subtle.exportKey(
        "raw",
        identity.publicKey as CryptoKey,
      );
    } catch {
      const anyPriv: any = identity.privateKey;
      const anyPub: any = identity.publicKey;
      if (anyPriv?.raw instanceof Uint8Array) {
        privRawBuf = anyPriv.raw.buffer.slice(
          anyPriv.raw.byteOffset,
          anyPriv.raw.byteOffset + anyPriv.raw.byteLength,
        );
      } else throw new MajikKeyError("Cannot export private key");
      if (anyPub?.raw instanceof Uint8Array) {
        pubRawBuf = anyPub.raw.buffer.slice(
          anyPub.raw.byteOffset,
          anyPub.raw.byteOffset + anyPub.raw.byteLength,
        );
      } else throw new MajikKeyError("Cannot export public key");
    }

    const mnemonicSalt = new TextEncoder().encode(MAJIK_MNEMONIC_SALT);
    const keyBytes = deriveKeyFromMnemonicArgon2(mnemonic, mnemonicSalt);
    const iv = generateRandomBytes(IV_LENGTH);
    const ciphertext = aesGcmEncrypt(keyBytes, iv, new Uint8Array(privRawBuf));

    return utf8ToBase64(
      JSON.stringify({
        id: identity.id,
        iv: arrayToBase64(iv),
        ciphertext: arrayToBase64(ciphertext),
        publicKey: arrayBufferToBase64(pubRawBuf),
        fingerprint: identity.fingerprint,
        backupKdfVersion: KDF_VERSION.ARGON2ID,
      }),
    );
  }

  private static async _deriveLegacyMnemonicKey(
    mnemonic: string,
  ): Promise<CryptoKey> {
    const salt = new TextEncoder().encode(MAJIK_MNEMONIC_SALT);
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

  private static async _exportKeyToBase64(
    key: CryptoKey | { raw: Uint8Array },
  ): Promise<string> {
    const anyKey: any = key;
    if (anyKey?.raw instanceof Uint8Array)
      return arrayBufferToBase64(anyKey.raw.buffer);
    const raw = await crypto.subtle.exportKey("raw", key as CryptoKey);
    return arrayBufferToBase64(raw);
  }
}
