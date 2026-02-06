import { generateMnemonic } from "@scure/bip39";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  deriveKeyFromMnemonic,
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
} from "./core/utils";
import { wordlist } from "@scure/bip39/wordlists/english";
import {
  KEY_ALGO,
  MAJIK_MNEMONIC_SALT,
  MAJIK_SALT,
} from "./core/crypto/constants";
import { MajikKeyValidator } from "./core/validator";
import { MajikKeyError } from "./core/error";
import { MajikKeyJSON, MnemonicJSON } from "./core/types";
import { MajikMessageIdentity } from "./core/database/system/identity";
import { MajikUser } from "@thezelijah/majik-user";

/* -------------------------------
 * Types & Interfaces
 * ------------------------------- */

export interface MajikKeyIdentity {
  id: string;
  publicKey: CryptoKey | { raw: Uint8Array };
  fingerprint: string;
  privateKey: CryptoKey | { raw: Uint8Array };
  encryptedPrivateKey: ArrayBuffer;
  salt: string; // base64 per-identity salt for PBKDF2
}

export interface SerializedIdentity {
  id: string;
  publicKey: string; // base64
  fingerprint: string;
  encryptedPrivateKey?: string; // base64
  salt?: string; // base64 per-identity salt for PBKDF2
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
  // Optional - only set when unlocked
  privateKey?: CryptoKey | { raw: Uint8Array };
  privateKeyBase64?: string;
}

export interface MajikKeyMetadata {
  id: string;
  fingerprint: string;
  label: string;
  timestamp: Date;
  isLocked: boolean;
}

/**
 * MajikKey
 * ----------------
 * A seed phrase account library for creating, managing, and parsing mnemonic-based cryptographic accounts (Majik Keys).
 * Generate deterministic key pairs from BIP39 seed phrases with simple, developer-friendly APIs.
 */
export class MajikKey {
  // Immutable properties
  private readonly _id: string;
  private readonly _publicKey: CryptoKey | { raw: Uint8Array };
  private readonly _publicKeyBase64: string;
  private readonly _fingerprint: string;
  private readonly _backup: string;
  private readonly _timestamp: Date;

  // Mutable encrypted state
  private _encryptedPrivateKey: ArrayBuffer;
  private _encryptedPrivateKeyBase64: string;
  private _salt: string;
  private _label: string;

  // Unlocked state (optional - only present when unlocked)
  private _privateKey?: CryptoKey | { raw: Uint8Array };
  private _privateKeyBase64?: string;

  /* ================================
   * Constructor
   * ================================ */

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

    // Optional unlocked state
    this._privateKey = options.privateKey;
    this._privateKeyBase64 = options.privateKeyBase64;
  }

  /* ================================
   * Public Getters
   * ================================ */

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

  get isLocked(): boolean {
    return this._privateKey === undefined;
  }

  get isUnlocked(): boolean {
    return this._privateKey !== undefined;
  }

  /**
   * Get safe metadata (no sensitive data)
   */
  get metadata(): MajikKeyMetadata {
    return {
      id: this.id,
      fingerprint: this.fingerprint,
      label: this.label,
      timestamp: this.timestamp,
      isLocked: this.isLocked,
    };
  }

  /* ================================
   * CRUD Operations
   * ================================ */

  /**
   * CREATE: Generate a new MajikKey from a mnemonic phrase.
   * The key is created in an unlocked state with private keys available.
   *
   * @param mnemonic - BIP39 mnemonic phrase (12-24 words)
   * @param passphrase - Passphrase to encrypt the private key at rest
   * @param label - Optional label for the key
   * @returns A new unlocked MajikKey instance
   */
  static async create(
    mnemonic: string,
    passphrase: string,
    label?: string,
  ): Promise<MajikKey> {
    try {
      // Validate inputs
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      MajikKeyValidator.validateLabel(label);

      // Create identity from mnemonic
      const identity = await this.createIdentityFromMnemonic(
        mnemonic,
        passphrase,
      );

      // Export keys to base64
      const privateKeyBase64 = await this.exportKeyToBase64(
        identity.privateKey,
      );
      const publicKeyBase64 = await this.exportKeyToBase64(identity.publicKey);

      // Create backup
      const backup = await this.exportIdentityMnemonicBackup(
        identity,
        mnemonic,
      );

      // Create and return unlocked instance
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
        // Unlocked state
        privateKey: identity.privateKey,
        privateKeyBase64,
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to create MajikKey", err);
    }
  }

  /**
   * Export this MajikKey to MnemonicJSON format.
   * This format is useful for storing mnemonic data with an optional passphrase.
   *
   * @param mnemonic - The BIP39 mnemonic phrase
   * @param passphrase - Optional passphrase (encryption password, not BIP39 passphrase)
   * @returns MnemonicJSON object
   */
  toMnemonicJSON(mnemonic: string, passphrase?: string): MnemonicJSON {
    if (this.isLocked) {
      throw new MajikKeyError(
        "Cannot export locked MajikKey to MnemonicJSON. Unlock first.",
      );
    }

    try {
      // Validate mnemonic
      MajikKeyValidator.validateMnemonic(mnemonic);

      // Validate passphrase if provided
      if (passphrase !== undefined) {
        MajikKeyValidator.validatePassphrase(passphrase, "Passphrase");
      }

      return {
        id: this._backup, // Use backup as identifier
        seed: seedStringToArray(mnemonic.trim()),
        phrase: passphrase?.trim() || undefined,
      };
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to create MnemonicJSON", err);
    }
  }

  /**
   * Create a MajikKey from MnemonicJSON format.
   *
   * @param mnemonicJson - MnemonicJSON object or string
   * @param passphrase - Passphrase to encrypt the key at rest
   * @param label - Optional label for the key
   * @returns A new unlocked MajikKey instance
   */
  static async fromMnemonicJSON(
    mnemonicJson: MnemonicJSON | string,
    passphrase: string,
    label?: string,
  ): Promise<MajikKey> {
    try {
      // Parse if string
      const parsed: MnemonicJSON =
        typeof mnemonicJson === "string"
          ? JSON.parse(mnemonicJson)
          : mnemonicJson;

      // Validate structure
      if (!parsed.id || !parsed.seed || !Array.isArray(parsed.seed)) {
        throw new MajikKeyError(
          "Invalid MnemonicJSON: missing id or seed array",
        );
      }

      // Convert seed array to mnemonic string
      const mnemonic = seedArrayToString(parsed.seed);

      // Validate the mnemonic
      MajikKeyValidator.validateMnemonic(mnemonic);

      // Create the MajikKey using the standard create method
      return await this.create(mnemonic, passphrase, label);
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError(
        "Failed to create MajikKey from MnemonicJSON",
        err,
      );
    }
  }

  /**
   * READ: Load a MajikKey from JSON (locked state).
   * The key must be unlocked with the unlock() method before accessing private keys.
   *
   * @param json - JSON string or object
   * @returns A locked MajikKey instance
   */
  static fromJSON(json: MajikKeyJSON | string): MajikKey {
    try {
      const parsed: MajikKeyJSON =
        typeof json === "string" ? JSON.parse(json) : json;

      const validated = MajikKeyValidator.validateJSON(parsed);

      // Convert base64 to CryptoKey/ArrayBuffer
      const publicKeyBuffer = base64ToArrayBuffer(validated.publicKey);
      const encryptedPrivateKeyBuffer = base64ToArrayBuffer(
        validated.encryptedPrivateKey,
      );

      // Create locked instance (no private key)
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
        // No private key - locked state
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to parse MajikKey from JSON", err);
    }
  }

  /**
   * UPDATE: Change the label of this MajikKey.
   *
   * @param newLabel - New label value
   * @returns This instance for chaining
   */
  updateLabel(newLabel: string): this {
    MajikKeyValidator.validateLabel(newLabel);
    this._label = newLabel || "";
    return this;
  }

  /**
   * UPDATE: Change the passphrase used to encrypt the private key.
   * Requires the current passphrase for verification.
   *
   * @param currentPassphrase - Current passphrase
   * @param newPassphrase - New passphrase
   * @returns This instance for chaining
   */
  async updatePassphrase(
    currentPassphrase: string,
    newPassphrase: string,
  ): Promise<this> {
    try {
      // Validate inputs
      MajikKeyValidator.validatePassphrase(
        currentPassphrase,
        "Current passphrase",
      );
      MajikKeyValidator.validatePassphrase(newPassphrase, "New passphrase");

      // Verify current passphrase
      const isValid = await MajikKey.isPassphraseValid(
        this.toKeyIdentity(),
        currentPassphrase,
      );

      if (!isValid) {
        throw new MajikKeyError("Current passphrase is incorrect");
      }

      // Decrypt with current passphrase
      const salt = new Uint8Array(base64ToArrayBuffer(this._salt));
      const privateKeyBuffer = await MajikKey.decryptPrivateKey(
        this._encryptedPrivateKey,
        currentPassphrase,
        salt,
      );

      // Re-encrypt with new passphrase and new salt
      const newSalt = generateRandomBytes(16);
      const newEncryptedPrivateKey = await MajikKey.encryptPrivateKey(
        privateKeyBuffer,
        newPassphrase,
        newSalt,
      );

      // Update encrypted state
      this._encryptedPrivateKey = newEncryptedPrivateKey;
      this._encryptedPrivateKeyBase64 = arrayBufferToBase64(
        newEncryptedPrivateKey,
      );
      this._salt = arrayToBase64(newSalt);

      return this;
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to update passphrase", err);
    }
  }

  /**
   * DELETE: Securely lock this MajikKey by clearing private keys from memory.
   * The encrypted private key remains stored for future unlocking.
   *
   * @returns This instance for chaining
   */
  lock(): this {
    // Clear private key from memory
    this._privateKey = undefined;
    this._privateKeyBase64 = undefined;
    return this;
  }

  /* ================================
   * Unlock/Lock Operations
   * ================================ */

  /**
   * Unlock this MajikKey by decrypting the private key with the passphrase.
   * Sets the private key in memory for cryptographic operations.
   *
   * @param passphrase - Passphrase to decrypt the private key
   * @returns This instance for chaining
   * @throws MajikKeyError if passphrase is incorrect or key is already unlocked
   */
  async unlock(passphrase: string): Promise<this> {
    try {
      // Check if already unlocked
      if (this.isUnlocked) {
        throw new MajikKeyError("MajikKey is already unlocked");
      }

      // Validate passphrase
      MajikKeyValidator.validatePassphrase(passphrase);

      // Decrypt private key
      const salt = new Uint8Array(base64ToArrayBuffer(this._salt));
      const privateKeyBuffer = await MajikKey.decryptPrivateKey(
        this._encryptedPrivateKey,
        passphrase,
        salt,
      );

      // Import as CryptoKey
      const privateKey = await crypto.subtle.importKey(
        "raw",
        privateKeyBuffer,
        KEY_ALGO,
        true,
        ["sign"],
      );

      // Set unlocked state
      this._privateKey = privateKey;
      this._privateKeyBase64 = arrayBufferToBase64(privateKeyBuffer);

      return this;
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError(
        "Failed to unlock MajikKey - incorrect passphrase or corrupted data",
        err,
      );
    }
  }

  /**
   * Verify that the encrypted private key can be decrypted with passphrase
   */
  async verify(passphrase: string): Promise<boolean> {
    return MajikKey.isPassphraseValid(this.toKeyIdentity(), passphrase);
  }

  /**
   * Get the private key (only available when unlocked).
   *
   * @returns The private key
   * @throws MajikKeyError if the key is locked
   */
  getPrivateKey(): CryptoKey | { raw: Uint8Array } {
    if (this.isLocked) {
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    }
    return this._privateKey!;
  }

  /**
   * Get the private key as base64 (only available when unlocked).
   *
   * @returns The private key in base64 format
   * @throws MajikKeyError if the key is locked
   */
  getPrivateKeyBase64(): string {
    if (this.isLocked) {
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    }
    return this._privateKeyBase64!;
  }

  /* ================================
   * Serialization
   * ================================ */

  /**
   * Export this MajikKey to JSON format (safe for storage).
   * Private keys are never included in the JSON output.
   *
   * @returns JSON representation of this MajikKey
   */
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
    };
  }

  /**
   * Export this MajikKey to a JSON string.
   *
   * @param pretty - Whether to pretty-print the JSON
   * @returns JSON string representation
   */
  toString(pretty = false): string {
    return JSON.stringify(this.toJSON(), null, pretty ? 2 : 0);
  }

  /* ================================
   * Utility Methods
   * ================================ */

  /**
   * Generate a new BIP39 mnemonic phrase.
   *
   * @param strength - Entropy strength in bits (128 = 12 words, 256 = 24 words)
   * @returns A new mnemonic phrase
   */
  static generateMnemonic(strength: 128 | 256 = 128): string {
    if (strength !== 128 && strength !== 256) {
      throw new MajikKeyError(
        "Strength must be 128 (12 words) or 256 (24 words)",
      );
    }
    return generateMnemonic(wordlist, strength);
  }

  /**
   * Validate a BIP39 mnemonic phrase.
   *
   * @param mnemonic - Mnemonic phrase to validate
   * @returns true if valid, false otherwise
   */
  static validateMnemonic(mnemonic: string): boolean {
    try {
      MajikKeyValidator.validateMnemonic(mnemonic);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Create a MajikContact from this MajikKey.
   *
   * @returns A MajikContact instance
   */
  toContact(): MajikContact {
    return new MajikContact({
      id: this._id,
      publicKey: this._publicKey,
      fingerprint: this._fingerprint,
      meta: { label: this._label },
    });
  }

  /**
   * Convert to internal MajikKeyIdentity format (for backward compatibility).
   * Note: Only includes privateKey if unlocked.
   *
   * @returns MajikKeyIdentity object
   */
  toKeyIdentity(): MajikKeyIdentity {
    if (this.isLocked) {
      throw new MajikKeyError(
        "Cannot convert locked MajikKey to KeyIdentity. Unlock first.",
      );
    }

    return {
      id: this._id,
      publicKey: this._publicKey,
      fingerprint: this._fingerprint,
      privateKey: this._privateKey!,
      encryptedPrivateKey: this._encryptedPrivateKey,
      salt: this._salt,
    };
  }

  /**
   * Convert to internal SerializedIdentity format (for Majik Message).
   *
   * @returns SerializedIdentity object
   */
  toSerializedIdentity(): SerializedIdentity {
    if (this.isLocked) {
      throw new MajikKeyError(
        "Cannot convert locked MajikKey to SerializedIdentity. Unlock first.",
      );
    }

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
    options?: {
      label?: string;
      restricted?: boolean;
    },
  ): Promise<MajikMessageIdentity> {
    MajikKeyValidator.assert(user, "MajikUser is required");
    const userValidResult = user.validate();
    if (!userValidResult.isValid) {
      throw new Error(
        `Invalid MajikUser: ${userValidResult.errors.join(", ")}`,
      );
    }

    const keyContact = await this.toContact().toJSON();

    const newMajikMessageIdentity = MajikMessageIdentity.create(
      user,
      keyContact,
      options,
    );

    return newMajikMessageIdentity;
  }

  /* ================================
   * Static Backup Methods
   * ================================ */

  /**
   * Export a mnemonic-encrypted backup for this MajikKey.
   * Requires the key to be unlocked.
   *
   * @param mnemonic - The original mnemonic phrase
   * @returns Base64-encoded backup string
   */
  async exportMnemonicBackup(mnemonic: string): Promise<string> {
    try {
      if (this.isLocked) {
        throw new MajikKeyError("MajikKey must be unlocked to export backup");
      }

      MajikKeyValidator.validateMnemonic(mnemonic);

      const identity = this.toKeyIdentity();
      return await MajikKey.exportIdentityMnemonicBackup(identity, mnemonic);
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to export mnemonic backup", err);
    }
  }

  /**
   * Import a MajikKey from a mnemonic-encrypted backup.
   *
   * @param backup - Base64-encoded backup string
   * @param mnemonic - The mnemonic phrase used to encrypt the backup
   * @param passphrase - Passphrase to encrypt the imported key
   * @param label - Optional label for the imported key
   * @returns A new unlocked MajikKey instance
   */
  static async importFromMnemonicBackup(
    backup: string,
    mnemonic: string,
    passphrase: string,
    label?: string,
  ): Promise<MajikKey> {
    try {
      // Validate inputs
      if (!backup || typeof backup !== "string") {
        throw new MajikKeyError("Backup must be a non-empty string");
      }
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      MajikKeyValidator.validateLabel(label);

      // Decode backup
      const backupJson = base64ToUtf8(backup);
      const parsed = JSON.parse(backupJson) as {
        id?: string;
        iv: string;
        ciphertext: string;
        publicKey: string;
        fingerprint: string;
      };

      if (
        !parsed.iv ||
        !parsed.ciphertext ||
        !parsed.publicKey ||
        !parsed.fingerprint
      ) {
        throw new MajikKeyError("Invalid backup format");
      }

      // Derive key from mnemonic
      const fullKey = await this.deriveKeyFromMnemonic(mnemonic);
      const iv = new Uint8Array(base64ToArrayBuffer(parsed.iv));
      const ciphertext = base64ToArrayBuffer(parsed.ciphertext);

      const rawPrivate = await crypto.subtle
        .decrypt({ name: "AES-GCM", iv }, fullKey, ciphertext)
        .catch((err) => {
          throw new MajikKeyError(
            "Failed to decrypt backup - invalid mnemonic or corrupted data",
            err,
          );
        });

      let privateKey: CryptoKey | { raw: Uint8Array };

      try {
        privateKey = await crypto.subtle.importKey(
          "raw",
          rawPrivate,
          KEY_ALGO,
          true,
          ["deriveKey", "deriveBits"],
        );
      } catch (e) {
        // WebCrypto does not support X25519 – store raw key
        privateKey = {
          type: "private",
          raw: new Uint8Array(rawPrivate),
        };
      }

      let publicKey: CryptoKey | { raw: Uint8Array };

      const rawPublic = base64ToArrayBuffer(parsed.publicKey);
      try {
        publicKey = await crypto.subtle.importKey(
          "raw",
          rawPublic,
          KEY_ALGO,
          true,
          [],
        );
      } catch (e) {
        // WebCrypto may not support X25519; return a raw-key wrapper as fallback
        const ua = new Uint8Array(rawPublic);
        const wrapper: any = { type: "public", raw: ua };
        publicKey = wrapper as unknown as CryptoKey | { raw: Uint8Array };
      }

      // Encrypt with new passphrase
      const newSalt = generateRandomBytes(16);
      const encryptedPrivateKey = await this.encryptPrivateKey(
        rawPrivate,
        passphrase,
        newSalt,
      );

      // Create unlocked instance
      return new MajikKey({
        id: parsed?.id || parsed.fingerprint,
        publicKey,
        publicKeyBase64: parsed.publicKey,
        fingerprint: parsed.fingerprint,
        encryptedPrivateKey,
        encryptedPrivateKeyBase64: arrayBufferToBase64(encryptedPrivateKey),
        salt: arrayToBase64(newSalt),
        backup,
        label: label || "",
        timestamp: new Date(),
        // Unlocked state
        privateKey,
        privateKeyBase64: arrayBufferToBase64(rawPrivate),
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to import from mnemonic backup", err);
    }
  }

  /* ================================
   * Private Static Helpers
   * ================================ */

  /**
   * Create a deterministic identity from a mnemonic and encrypt it with passphrase.
   * The identity `id` is set to the fingerprint for stable referencing.
   */
  private static async createIdentityFromMnemonic(
    mnemonic: string,
    passphrase: string,
  ): Promise<MajikKeyIdentity> {
    try {
      const identity =
        await EncryptionEngine.deriveIdentityFromMnemonic(mnemonic);
      const id = identity.fingerprint; // stable id

      // Export private key
      let exportedPrivate: ArrayBuffer;
      try {
        exportedPrivate = await crypto.subtle.exportKey(
          "raw",
          identity.privateKey as CryptoKey,
        );
      } catch (e) {
        const anyPriv: any = identity.privateKey;
        if (anyPriv?.raw instanceof Uint8Array) {
          exportedPrivate = anyPriv.raw.buffer.slice(
            anyPriv.raw.byteOffset,
            anyPriv.raw.byteOffset + anyPriv.raw.byteLength,
          );
        } else {
          throw e;
        }
      }

      // Encrypt private key
      const salt = generateRandomBytes(16);
      const encryptedPrivateKey = await this.encryptPrivateKey(
        exportedPrivate,
        passphrase,
        salt,
      );

      return {
        id,
        publicKey: identity.publicKey,
        fingerprint: identity.fingerprint,
        encryptedPrivateKey,
        privateKey: identity.privateKey,
        salt: arrayToBase64(salt),
      };
    } catch (err) {
      throw new MajikKeyError("Failed to create identity from mnemonic", err);
    }
  }

  /**
   * Export an identity encrypted with a mnemonic-derived key.
   * Returns a base64 string containing iv+ciphertext and publicKey/fingerprint in JSON.
   */
  private static async exportIdentityMnemonicBackup(
    identity: MajikKeyIdentity,
    mnemonic: string,
  ): Promise<string> {
    try {
      if (!identity?.privateKey) {
        throw new MajikKeyError(
          "Identity must have privateKey to export backup",
        );
      }

      // Export keys
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
      } catch (e) {
        const anyPriv: any = identity.privateKey;
        const anyPub: any = identity.publicKey;

        if (anyPriv?.raw instanceof Uint8Array) {
          privRawBuf = anyPriv.raw.buffer.slice(
            anyPriv.raw.byteOffset,
            anyPriv.raw.byteOffset + anyPriv.raw.byteLength,
          );
        } else {
          throw e;
        }

        if (anyPub?.raw instanceof Uint8Array) {
          pubRawBuf = anyPub.raw.buffer.slice(
            anyPub.raw.byteOffset,
            anyPub.raw.byteOffset + anyPub.raw.byteLength,
          );
        } else {
          throw e;
        }
      }

      // Derive AES key from mnemonic
      const salt = new TextEncoder().encode(MAJIK_MNEMONIC_SALT);

      const keyBytes = deriveKeyFromMnemonic(mnemonic, salt);
      const iv = generateRandomBytes(IV_LENGTH);
      const ciphertext = aesGcmEncrypt(
        keyBytes,
        iv,
        new Uint8Array(privRawBuf),
      );

      const packaged = {
        id: identity.id,
        iv: arrayToBase64(iv),
        ciphertext: arrayToBase64(ciphertext),
        publicKey: arrayBufferToBase64(pubRawBuf),
        fingerprint: identity.fingerprint,
      };

      return utf8ToBase64(JSON.stringify(packaged));
    } catch (err) {
      throw new MajikKeyError("Failed to export identity mnemonic backup", err);
    }
  }

  /**
   * Encrypt a private key with a passphrase.
   */
  private static async encryptPrivateKey(
    buffer: ArrayBuffer,
    passphrase: string,
    salt: Uint8Array,
  ): Promise<ArrayBuffer> {
    try {
      const keyBytes = deriveKeyFromPassphrase(passphrase, salt);
      const iv = generateRandomBytes(IV_LENGTH);
      const ciphertext = aesGcmEncrypt(keyBytes, iv, new Uint8Array(buffer));
      return concatUint8Arrays(iv, ciphertext).buffer as ArrayBuffer;
    } catch (err) {
      throw new MajikKeyError("Failed to encrypt private key", err);
    }
  }

  /**
   * Decrypt a private key with a passphrase.
   */
  private static async decryptPrivateKey(
    buffer: ArrayBuffer,
    passphrase: string,
    salt: Uint8Array,
  ): Promise<ArrayBuffer> {
    try {
      const keyBytes = deriveKeyFromPassphrase(passphrase, salt);
      const full = new Uint8Array(buffer);
      const iv = full.slice(0, IV_LENGTH);
      const ciphertext = full.slice(IV_LENGTH);

      const plain = aesGcmDecrypt(keyBytes, iv, ciphertext);
      if (!plain) {
        throw new MajikKeyError(
          "Decryption failed - authentication tag mismatch",
        );
      }

      return plain.buffer as ArrayBuffer;
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to decrypt private key", err);
    }
  }

  private static async deriveKeyFromMnemonic(
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
      {
        name: "PBKDF2",
        salt,
        iterations: 200_000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  /**
   * Validate whether a passphrase can decrypt the stored private key.
   * Does NOT unlock or mutate any in-memory state.
   */
  private static async isPassphraseValid(
    identity: MajikKeyIdentity,
    passphrase: string,
  ): Promise<boolean> {
    if (!passphrase) return false;

    try {
      if (!identity?.encryptedPrivateKey) return false;

      const salt = identity.salt
        ? new Uint8Array(base64ToArrayBuffer(identity.salt))
        : new TextEncoder().encode(MAJIK_SALT);

      // Attempt authenticated decryption
      await this.decryptPrivateKey(
        identity.encryptedPrivateKey,
        passphrase,
        salt,
      );
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Export a CryptoKey to base64 string.
   */
  private static async exportKeyToBase64(
    key: CryptoKey | { raw: Uint8Array },
  ): Promise<string> {
    try {
      const anyKey: any = key as any;
      if (anyKey && anyKey.raw instanceof Uint8Array) {
        return arrayBufferToBase64(anyKey.raw.buffer);
      }
      const raw = await crypto.subtle.exportKey("raw", key as CryptoKey);
      return arrayBufferToBase64(raw);
    } catch (err) {
      throw new MajikKeyError("Failed to export key to base64", err);
    }
  }
}
