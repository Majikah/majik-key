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
  generateRandomBytes,
  IV_LENGTH,
} from "./core/crypto/crypto-provider";
import { EncryptionEngine } from "./core/crypto/encryption-engine";
import { MajikContact, MajikContactMeta } from "@majikah/majik-contact";
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

import {
  KDF_VERSION,
  KEY_ALGO,
  MAJIK_MNEMONIC_SALT,
} from "./core/crypto/constants";
import { MajikKeyValidator } from "./core/validator";
import { MajikKeyError } from "./core/error";
import type {
  MajikKeyDangerousJSON,
  MajikKeyJSON,
  MajikKeyMetadata,
  MnemonicJSON,
} from "./core/types";
import { MajikMessageIdentity } from "./core/database/system/identity";
import { MajikUser } from "@thezelijah/majik-user";
import { MnemonicLanguage, WORDLISTS } from "./core/crypto/wordlist";

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
} from "./core/web3";

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

  edPublicKey?: Uint8Array;
  edSecretKey?: Uint8Array;
  mlDsaPublicKey?: Uint8Array;
  mlDsaSecretKey?: Uint8Array;

  btcPublicKey?: Uint8Array;
  btcSecretKey?: Uint8Array;
}

export type MajikKeyDerivedIdentity = MajikKeyIdentity & {
  encryptedMlKemSecretKey: ArrayBuffer;
  encryptedEdSecretKey: ArrayBuffer;
  encryptedMlDsaSecretKey: ArrayBuffer;
  encryptedBtcSecretKey: ArrayBuffer;
};

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

  edPublicKey?: Uint8Array;
  encryptedEdSecretKey?: ArrayBuffer;
  encryptedEdSecretKeyBase64?: string;
  mlDsaPublicKey?: Uint8Array;
  encryptedMlDsaSecretKey?: ArrayBuffer;
  encryptedMlDsaSecretKeyBase64?: string;

  edSecretKey?: Uint8Array;
  mlDsaSecretKey?: Uint8Array;

  btcPublicKey?: Uint8Array;
  encryptedBtcSecretKey?: ArrayBuffer;
  encryptedBtcSecretKeyBase64?: string;
  btcSecretKey?: Uint8Array;

  mnemonicLanguage?: MnemonicLanguage;
}

// ─── MajikKey ─────────────────────────────────────────────────────────────────

export class MajikKey {
  private readonly _id: string;
  private readonly _publicKey: CryptoKey | { raw: Uint8Array };
  private readonly _publicKeyBase64: string;
  private readonly _fingerprint: string;
  private readonly _backup: string;
  private readonly _timestamp: Date;
  private readonly _mnemonicLanguage: MnemonicLanguage;

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

  private _edPublicKey?: Uint8Array;
  private _edSecretKey?: Uint8Array;
  private _encryptedEdSecretKey?: ArrayBuffer;
  private _encryptedEdSecretKeyBase64?: string;

  private _mlDsaPublicKey?: Uint8Array;
  private _mlDsaSecretKey?: Uint8Array;
  private _encryptedMlDsaSecretKey?: ArrayBuffer;
  private _encryptedMlDsaSecretKeyBase64?: string;

  //Experimental
  private _solanaKeypairMaterial?: SolanaKeypairMaterial;

  private _btcPublicKey?: Uint8Array;
  private _btcSecretKey?: Uint8Array;
  private _encryptedBtcSecretKey?: ArrayBuffer;
  private _encryptedBtcSecretKeyBase64?: string;

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

    this._edPublicKey = options.edPublicKey;
    this._encryptedEdSecretKey = options.encryptedEdSecretKey;
    this._encryptedEdSecretKeyBase64 = options.encryptedEdSecretKeyBase64;
    this._mlDsaPublicKey = options.mlDsaPublicKey;
    this._encryptedMlDsaSecretKey = options.encryptedMlDsaSecretKey;
    this._encryptedMlDsaSecretKeyBase64 = options.encryptedMlDsaSecretKeyBase64;

    this._edSecretKey = options.edSecretKey;
    this._mlDsaSecretKey = options.mlDsaSecretKey;

    this._btcPublicKey = options.btcPublicKey;
    this._btcSecretKey = options.btcSecretKey;
    this._encryptedBtcSecretKey = options.encryptedBtcSecretKey;
    this._encryptedBtcSecretKeyBase64 = options.encryptedBtcSecretKeyBase64;

    this._mnemonicLanguage = options.mnemonicLanguage || "en";
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
  get btcPublicKey(): Uint8Array | undefined {
    return this._btcPublicKey;
  }

  get hasBitcoin(): boolean {
    return this._btcPublicKey !== undefined;
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
      web3: {
        hasBitcoin: this.hasBitcoin,
        hasSolana: this.hasSolanaKeypair,
      },

      mnemonicLanguage: this.mnemonicLanguage || "en",
    };
  }
  get edPublicKey(): Uint8Array | undefined {
    return this._edPublicKey;
  }

  get mlDsaPublicKey(): Uint8Array | undefined {
    return this._mlDsaPublicKey;
  }

  get hasSigningKeys(): boolean {
    return (
      this._edPublicKey !== undefined && this._mlDsaPublicKey !== undefined
    );
  }

  // ── CREATE ──────────────────────────────────────────────────────────────────

  static async create(
    mnemonic: string,
    passphrase: string,
    label?: string,
    mnemonicLanguage: MnemonicLanguage = "en",
  ): Promise<MajikKey> {
    try {
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      MajikKeyValidator.validateLabel(label);

      const wordlist = await MajikKey._getWordlist(mnemonicLanguage);

      if (!validateMnemonic(mnemonic, wordlist)) {
        throw new MajikKeyError("Invalid BIP39 mnemonic phrase");
      }

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
        edPublicKey: identity.edPublicKey,
        encryptedEdSecretKey: identity.encryptedEdSecretKey,
        encryptedEdSecretKeyBase64: arrayBufferToBase64(
          identity.encryptedEdSecretKey,
        ),
        mlDsaPublicKey: identity.mlDsaPublicKey,
        encryptedMlDsaSecretKey: identity.encryptedMlDsaSecretKey,
        encryptedMlDsaSecretKeyBase64: arrayBufferToBase64(
          identity.encryptedMlDsaSecretKey,
        ),

        edSecretKey: identity.edSecretKey,
        mlDsaSecretKey: identity.mlDsaSecretKey,

        btcPublicKey: identity.btcPublicKey,
        encryptedBtcSecretKey: identity.encryptedBtcSecretKey,
        encryptedBtcSecretKeyBase64: arrayBufferToBase64(
          identity.encryptedBtcSecretKey,
        ),
        btcSecretKey: identity.btcSecretKey,

        mnemonicLanguage: mnemonicLanguage,
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

      const edPublicKey = anyParsed.edPublicKey
        ? base64ToUint8Array(anyParsed.edPublicKey)
        : undefined;

      let encryptedEdSecretKey: ArrayBuffer | undefined;
      let encryptedEdSecretKeyBase64: string | undefined;
      if (anyParsed.encryptedEdSecretKey) {
        encryptedEdSecretKeyBase64 = anyParsed.encryptedEdSecretKey;
        encryptedEdSecretKey = base64ToArrayBuffer(
          anyParsed.encryptedEdSecretKey,
        );
      }

      const mlDsaPublicKey = anyParsed.mlDsaPublicKey
        ? base64ToUint8Array(anyParsed.mlDsaPublicKey)
        : undefined;

      let encryptedMlDsaSecretKey: ArrayBuffer | undefined;
      let encryptedMlDsaSecretKeyBase64: string | undefined;
      if (anyParsed.encryptedMlDsaSecretKey) {
        encryptedMlDsaSecretKeyBase64 = anyParsed.encryptedMlDsaSecretKey;
        encryptedMlDsaSecretKey = base64ToArrayBuffer(
          anyParsed.encryptedMlDsaSecretKey,
        );
      }

      const btcPublicKey = anyParsed.btcPublicKey
        ? base64ToUint8Array(anyParsed.btcPublicKey)
        : undefined;

      let encryptedBtcSecretKey: ArrayBuffer | undefined;
      let encryptedBtcSecretKeyBase64: string | undefined;
      if (anyParsed.encryptedBtcSecretKey) {
        encryptedBtcSecretKeyBase64 = anyParsed.encryptedBtcSecretKey;
        encryptedBtcSecretKey = base64ToArrayBuffer(
          anyParsed.encryptedBtcSecretKey,
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
        edPublicKey,
        encryptedEdSecretKey,
        encryptedEdSecretKeyBase64,
        mlDsaPublicKey,
        encryptedMlDsaSecretKey,
        encryptedMlDsaSecretKeyBase64,
        btcPublicKey,
        encryptedBtcSecretKey,
        encryptedBtcSecretKeyBase64,
        mnemonicLanguage: validated?.mnemonicLanguage || "en",
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to parse MajikKey from JSON", err);
    }
  }

  /**
   * Export a fully unlocked MajikKey with all raw private keys.
   * ⚠️ DANGEROUS — output contains unencrypted private key material.
   * Only use for server-side secrets injection.
   * Never log, store in a database, or transmit over the network.
   */
  toDangerousJSON(): MajikKeyDangerousJSON {
    if (this.isLocked)
      throw new MajikKeyError(
        "MajikKey must be unlocked to export dangerous JSON.",
      );
    if (
      !this._edSecretKey ||
      !this._mlDsaSecretKey ||
      !this._mlKemSecretKey ||
      !this._privateKeyBase64
    )
      throw new MajikKeyError(
        "MajikKey is missing secret keys — re-import via importFromMnemonicBackup() first.",
      );

    return {
      ...this.toJSON(),
      privateKeyBase64: this._privateKeyBase64,
      mlKemSecretKeyBase64: arrayToBase64(this._mlKemSecretKey),
      edSecretKeyBase64: arrayToBase64(this._edSecretKey),
      mlDsaSecretKeyBase64: arrayToBase64(this._mlDsaSecretKey),
      btcSecretKeyBase64: this._btcSecretKey
        ? arrayToBase64(this._btcSecretKey)
        : undefined,
    };
  }

  /**
   * Reconstruct a fully unlocked MajikKey from a dangerous JSON export.
   * ⚠️ DANGEROUS — input contains unencrypted private key material.
   * Intended for server-side use only (e.g. TSA signing key loaded from Cloudflare Secrets).
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

      const privateKeyBytes = base64ToUint8Array(parsed.privateKeyBase64);
      const edPublicKey = base64ToUint8Array(parsed.edPublicKey);
      const edSecretKey = base64ToUint8Array(parsed.edSecretKeyBase64);
      const mlDsaPublicKey = base64ToUint8Array(parsed.mlDsaPublicKey);
      const mlDsaSecretKey = base64ToUint8Array(parsed.mlDsaSecretKeyBase64);
      const mlKemPublicKey = base64ToUint8Array(parsed.mlKemPublicKey);
      const mlKemSecretKey = base64ToUint8Array(parsed.mlKemSecretKeyBase64);

      const btcPublicKey = parsed.btcPublicKey
        ? base64ToUint8Array(parsed.btcPublicKey)
        : undefined;
      const btcSecretKey = parsed.btcSecretKeyBase64
        ? base64ToUint8Array(parsed.btcSecretKeyBase64)
        : undefined;

      return new MajikKey({
        id: parsed.id,
        fingerprint: parsed.fingerprint,
        publicKey: { raw: base64ToUint8Array(parsed.publicKey) },
        publicKeyBase64: parsed.publicKey,
        privateKey: { raw: privateKeyBytes },
        privateKeyBase64: parsed.privateKeyBase64,
        encryptedPrivateKey: new ArrayBuffer(0),
        encryptedPrivateKeyBase64: parsed.encryptedPrivateKey,
        salt: parsed.salt,
        backup: parsed.backup,
        kdfVersion: (parsed?.kdfVersion as KDF_VERSION) || KDF_VERSION.ARGON2ID,
        mlKemPublicKey,
        mlKemSecretKey,
        edPublicKey,
        edSecretKey,
        mlDsaPublicKey,
        mlDsaSecretKey,
        btcPublicKey,
        btcSecretKey,
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

      if (this._encryptedEdSecretKey) {
        const edSecretKeyBytes = await MajikKey._decryptSigningKey(
          this._encryptedEdSecretKey,
          currentPassphrase,
          salt,
        );
        const encEd = await MajikKey._encryptSigningKey(
          edSecretKeyBytes,
          newPassphrase,
          newSalt,
        );
        this._encryptedEdSecretKey = encEd;
        this._encryptedEdSecretKeyBase64 = arrayBufferToBase64(encEd);
        this._edSecretKey = edSecretKeyBytes;
      }

      if (this._encryptedMlDsaSecretKey) {
        const mlDsaSecretKeyBytes = await MajikKey._decryptSigningKey(
          this._encryptedMlDsaSecretKey,
          currentPassphrase,
          salt,
        );
        const encDsa = await MajikKey._encryptSigningKey(
          mlDsaSecretKeyBytes,
          newPassphrase,
          newSalt,
        );
        this._encryptedMlDsaSecretKey = encDsa;
        this._encryptedMlDsaSecretKeyBase64 = arrayBufferToBase64(encDsa);
        this._mlDsaSecretKey = mlDsaSecretKeyBytes;
      }

      if (this._encryptedBtcSecretKey) {
        const btcSecretKeyBytes = await MajikKey._decryptSigningKey(
          this._encryptedBtcSecretKey,
          currentPassphrase,
          salt,
        );
        const encBtc = await MajikKey._encryptSigningKey(
          btcSecretKeyBytes,
          newPassphrase,
          newSalt,
        );
        this._encryptedBtcSecretKey = encBtc;
        this._encryptedBtcSecretKeyBase64 = arrayBufferToBase64(encBtc);
        this._btcSecretKey = btcSecretKeyBytes;
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

  // required
  lock(): this {
    this._privateKey = undefined;
    this._privateKeyBase64 = undefined;
    this._mlKemSecretKey = undefined;
    this._edSecretKey = undefined;
    this._mlDsaSecretKey = undefined;
    this._btcSecretKey = undefined;
    this._solanaKeypairMaterial = undefined;
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

      if (this._encryptedEdSecretKey) {
        this._edSecretKey = await MajikKey._decryptSigningKey(
          this._encryptedEdSecretKey,
          passphrase,
          salt,
        );
      }

      if (this._encryptedMlDsaSecretKey) {
        this._mlDsaSecretKey = await MajikKey._decryptSigningKey(
          this._encryptedMlDsaSecretKey,
          passphrase,
          salt,
        );
      }

      if (this._encryptedBtcSecretKey) {
        this._btcSecretKey = await MajikKey._decryptSigningKey(
          this._encryptedBtcSecretKey,
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

  getEdSecretKey(): Uint8Array {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    if (!this._edSecretKey)
      throw new MajikKeyError(
        "No Ed25519 secret key — re-import via importFromMnemonicBackup() for full migration.",
      );
    return this._edSecretKey;
  }

  getMlDsaSecretKey(): Uint8Array {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    if (!this._mlDsaSecretKey)
      throw new MajikKeyError(
        "No ML-DSA secret key — re-import via importFromMnemonicBackup() for full migration.",
      );
    return this._mlDsaSecretKey;
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
      edPublicKey: this._edPublicKey
        ? arrayToBase64(this._edPublicKey)
        : undefined,
      encryptedEdSecretKey: this._encryptedEdSecretKeyBase64,
      mlDsaPublicKey: this._mlDsaPublicKey
        ? arrayToBase64(this._mlDsaPublicKey)
        : undefined,
      encryptedMlDsaSecretKey: this._encryptedMlDsaSecretKeyBase64,
      btcPublicKey: this._btcPublicKey
        ? arrayToBase64(this._btcPublicKey)
        : undefined,
      encryptedBtcSecretKey: this._encryptedBtcSecretKeyBase64,
      mnemonicLanguage: this._mnemonicLanguage,
    };
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
  ): MajikContact<TMeta> {
    const mlKeyBase64 = arrayToBase64(this.mlKemPublicKey);

    // We construct the base metadata and merge with any provided initialMeta
    const meta: Partial<TMeta> = {
      label: this._label,
      ...initialMeta,
    } as Partial<TMeta>;

    return new MajikContact<TMeta>({
      id: this._id,
      publicKey: this._publicKey,
      fingerprint: this._fingerprint,
      meta: meta,
      mlKey: mlKeyBase64,
      edPublicKeyBase64: this._edPublicKey
        ? arrayToBase64(this._edPublicKey)
        : undefined,
      mlDsaPublicKeyBase64: this._mlDsaPublicKey
        ? arrayToBase64(this._mlDsaPublicKey)
        : undefined,
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
    mnemonicLanguage: MnemonicLanguage = "en",
  ): Promise<MajikKey> {
    try {
      if (!backup || typeof backup !== "string")
        throw new MajikKeyError("Backup must be a non-empty string");
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      MajikKeyValidator.validateLabel(label);

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
        edPublicKey: identity.edPublicKey,
        encryptedEdSecretKey: identity.encryptedEdSecretKey,
        encryptedEdSecretKeyBase64: arrayBufferToBase64(
          identity.encryptedEdSecretKey,
        ),
        mlDsaPublicKey: identity.mlDsaPublicKey,
        encryptedMlDsaSecretKey: identity.encryptedMlDsaSecretKey,
        encryptedMlDsaSecretKeyBase64: arrayBufferToBase64(
          identity.encryptedMlDsaSecretKey,
        ),
        edSecretKey: identity.edSecretKey,
        mlDsaSecretKey: identity.mlDsaSecretKey,
        btcPublicKey: identity.btcPublicKey,
        encryptedBtcSecretKey: identity.encryptedBtcSecretKey,
        encryptedBtcSecretKeyBase64: arrayBufferToBase64(
          identity.encryptedBtcSecretKey,
        ),
        btcSecretKey: identity.btcSecretKey,
      });
    } catch (err) {
      if (err instanceof MajikKeyError) throw err;
      throw new MajikKeyError("Failed to import from mnemonic backup", err);
    }
  }

  // ── PRIVATE: Core Derivation ─────────────────────────────────────────────────

  private static async _getWordlist(
    language: MnemonicLanguage,
  ): Promise<string[]> {
    const loader = WORDLISTS[language] ?? WORDLISTS.en;
    const mod = await loader();
    return mod.wordlist;
  }

  private static async _deriveAndEncryptFromMnemonic(
    mnemonic: string,
    passphrase: string,
  ): Promise<MajikKeyDerivedIdentity> {
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

    // after the existing ML-KEM encryption block:
    const edSecretKey = encIdentity.edSecretKey;
    const encryptedEdSecretKey = await MajikKey._encryptSigningKey(
      edSecretKey,
      passphrase,
      salt,
    );

    const mlDsaSecretKey = encIdentity.mlDsaSecretKey;
    const encryptedMlDsaSecretKey = await MajikKey._encryptSigningKey(
      mlDsaSecretKey,
      passphrase,
      salt,
    );

    // Bitcoin — real BIP-32/BIP-84 off the raw 64-byte BIP-39 seed, using
    // Majik's domain-separated path by default. Same salt, different IV,
    // same pattern as ML-KEM/Ed25519/ML-DSA above.
    const rawSeed = await mnemonicToSeed(mnemonic);
    const btcMaterial = deriveBitcoinKeypairFromSeed(rawSeed);
    const encryptedBtcSecretKey = await MajikKey._encryptSigningKey(
      btcMaterial.privateKey,
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
      edPublicKey: encIdentity.edPublicKey,
      edSecretKey,
      encryptedEdSecretKey,
      mlDsaPublicKey: encIdentity.mlDsaPublicKey,
      mlDsaSecretKey,
      encryptedMlDsaSecretKey,
      btcPublicKey: btcMaterial.publicKey,
      btcSecretKey: btcMaterial.privateKey,
      encryptedBtcSecretKey,
    };
  }

  // ── PRIVATE: Encryption/Decryption ───────────────────────────────────────────

  private static async _encryptPrivateKey(
    buffer: ArrayBuffer,
    passphrase: string,
    salt: Uint8Array,
  ): Promise<{ blob: ArrayBuffer; kdfVersion: KDF_VERSION }> {
    const keyBytes = await deriveKeyFromPassphraseArgon2(passphrase, salt);
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
    const keyBytes = await deriveKeyFromPassphraseArgon2(passphrase, salt);
    const iv = generateRandomBytes(IV_LENGTH); // different IV from X25519 blob
    const ciphertext = aesGcmEncrypt(keyBytes, iv, mlKemSecretKey);
    return concatUint8Arrays(iv, ciphertext).buffer as ArrayBuffer;
  }

  private static async _encryptSigningKey(
    keyBytes_: Uint8Array,
    passphrase: string,
    salt: Uint8Array,
  ): Promise<ArrayBuffer> {
    const aesKey = await deriveKeyFromPassphraseArgon2(passphrase, salt);
    const iv = generateRandomBytes(IV_LENGTH);
    const ciphertext = aesGcmEncrypt(aesKey, iv, keyBytes_);
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
        ? await deriveKeyFromPassphraseArgon2(passphrase, salt)
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
    const keyBytes = await deriveKeyFromPassphraseArgon2(passphrase, salt);
    const full = new Uint8Array(buffer);
    const iv = full.slice(0, IV_LENGTH);
    const ciphertext = full.slice(IV_LENGTH);
    const plain = aesGcmDecrypt(keyBytes, iv, ciphertext);
    if (!plain) throw new MajikKeyError("Failed to decrypt ML-KEM secret key");
    return plain;
  }

  private static async _decryptSigningKey(
    buffer: ArrayBuffer,
    passphrase: string,
    salt: Uint8Array,
  ): Promise<Uint8Array> {
    const keyBytes = await deriveKeyFromPassphraseArgon2(passphrase, salt);
    const full = new Uint8Array(buffer);
    const iv = full.slice(0, IV_LENGTH);
    const ciphertext = full.slice(IV_LENGTH);
    const plain = aesGcmDecrypt(keyBytes, iv, ciphertext);
    if (!plain) throw new MajikKeyError("Failed to decrypt signing key");
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
    const keyBytes = await deriveKeyFromMnemonicArgon2(mnemonic, mnemonicSalt);
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

  // ── WEB3 (EXPERIMENTAL) ─────────────────────────────────────────────────────

  getBtcSecretKey(): Uint8Array {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    if (!this._btcSecretKey)
      throw new MajikKeyError(
        "No Bitcoin secret key — re-import via importFromMnemonicBackup() for full migration.",
      );
    return this._btcSecretKey;
  }

  // ── WEB3 (EXPERIMENTAL) — updated getter ────────────────────────────────────

  get web3(): MajikKeyWeb3Namespace | undefined {
    if (!this.hasSolanaKeypair) return undefined;

    const solanaMaterial = this._getOrDeriveSolanaMaterial();

    const btcMaterial: BitcoinKeypairMaterial | undefined =
      this._btcSecretKey && this._btcPublicKey
        ? { privateKey: this._btcSecretKey, publicKey: this._btcPublicKey }
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
    };
  }

  // ── BITCON (EXPERIMENTAL)  ────────────────────────────────────

  /**
   * @experimental True if this MajikKey can currently produce Bitcoin
   * material (i.e. it's unlocked and has a Bitcoin secret key).
   */
  get hasBitcoinKeypair(): boolean {
    return this.isUnlocked && this._btcSecretKey !== undefined;
  }

  /**
   * @experimental Raw Bitcoin keypair material. Pass `{ standard: true }` to
   * get the REAL BIP-84 mainnet key (recoverable in any standard wallet from
   * the mnemonic alone) instead of Majik's default domain-separated key.
   *
   * NOTE: `{ standard: true }` re-derives from the raw seed on demand and is
   * NOT the same key as `web3.bitcoin` (which is always the stored,
   * domain-separated default) — it requires the mnemonic to reproduce again
   * outside Majik, whereas the stored default does not.
   */
  getBitcoinKeypairMaterial(
    options?: BitcoinDerivationOptions,
  ): BitcoinKeypairMaterial {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    if (!options?.standard && !options?.path) {
      if (!this._btcSecretKey || !this._btcPublicKey)
        throw new MajikKeyError(
          "No Bitcoin secret key — re-import via importFromMnemonicBackup() first.",
        );
      return { privateKey: this._btcSecretKey, publicKey: this._btcPublicKey };
    }
    throw new MajikKeyError(
      "Deriving the standard BIP-84 path requires the mnemonic — " +
        "use MajikKey.deriveStandardBitcoinFromMnemonic(mnemonic) instead.",
    );
  }

  /**
   * @experimental Derive the REAL BIP-84 mainnet Bitcoin keypair straight
   * from a mnemonic — for one-off export/verification. Does not require
   * an unlocked MajikKey instance.
   */
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

  /**
   * @experimental WIF export of the default (domain-separated) Bitcoin key.
   */
  getBitcoinWIF(options?: { compressed?: boolean }): string {
    const material = this.getBitcoinKeypairMaterial();
    return toWIF(material, options);
  }

  // ── SOLANA (EXPERIMENTAL)  ────────────────────────────────────

  /**
   * @experimental True if this MajikKey can currently produce a Solana
   * keypair (i.e. it's unlocked and has an Ed25519 signing key).
   */
  get hasSolanaKeypair(): boolean {
    return this.isUnlocked && this._edSecretKey !== undefined;
  }

  private _getOrDeriveSolanaMaterial(): SolanaKeypairMaterial {
    if (!this._edSecretKey)
      throw new MajikKeyError(
        "No Ed25519 secret key — MajikKey must be unlocked and have signing keys.",
      );
    if (!this._solanaKeypairMaterial) {
      this._solanaKeypairMaterial = deriveSolanaKeypairFromEdSecretKey(
        this._edSecretKey,
      );
    }
    return this._solanaKeypairMaterial;
  }

  /**
   * @experimental Raw Solana keypair material (public/secret key bytes).
   * Pass `{ reuseMessageKey: true }` to reuse the MajikKey's message signing
   * Ed25519 key directly instead of the domain-separated derivation.
   */
  getSolanaKeypairMaterial(options?: {
    reuseMessageKey?: boolean;
  }): SolanaKeypairMaterial {
    if (this.isLocked)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    if (!this._edSecretKey)
      throw new MajikKeyError(
        "No Ed25519 secret key — re-import via importFromMnemonicBackup() first.",
      );
    if (options?.reuseMessageKey) {
      return solanaMaterialFromEd25519SecretKey(this._edSecretKey);
    }
    return this._getOrDeriveSolanaMaterial();
  }

  /**
   * @experimental Real @solana/kit Keypair instance. Lazily loads
   * @solana/kit — throws a MajikKeyError with install instructions if
   * it isn't present in the consuming project.
   */
  async getSolanaKeypair(options?: {
    reuseMessageKey?: boolean;
  }): Promise<any> {
    return toSolanaKeyPairSigner(this.getSolanaKeypairMaterial(options));
  }

  /**
   * @experimental Base58 Solana address. Does NOT require @solana/kit.
   */
  getSolanaAddress(options?: { reuseMessageKey?: boolean }): string {
    return solanaAddressFromPublicKey(
      this.getSolanaKeypairMaterial(options).publicKey,
    );
  }
}
