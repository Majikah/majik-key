/**
 * MajikKey.ts
 * Seed phrase account library for the Majikah ecosystem.
 *
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
  MajikKeyAddress,
  MajikKeyDangerousJSON,
  MajikKeyFingerprint,
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

const secureFill = Uint8Array.prototype.fill;

const SALT_SIZE = 32;

// ─── Interfaces ───────────────────────────────────────────────────────────────
/**
 * In-memory identity bundle for an *unlocked* MajikKey — the raw CryptoKey/
 * Uint8Array material, not the encrypted-at-rest form. This is what
 * `toKeyIdentity()` returns, and what backup export starts from.
 *
 * `mlKemPublicKey`/`mlKemSecretKey` are required here because every account
 * (even ones mid-migration) is expected to carry ML-KEM material by the time
 * this shape is used. `ed*`, `mlDsa*`, and `btc*` are optional because
 * accounts imported before those key types existed may not have them yet —
 * check `hasSigningKeys` / `hasBitcoin` on the `MajikKey` instance before
 * relying on them.
 */
export interface MajikKeyIdentity {
  /** Account identifier. Equal to `fingerprint` for accounts created by this library. */
  id: string;
  /** X25519 public key — native `CryptoKey` where WebCrypto supports it, otherwise a raw-bytes wrapper. */
  publicKey: CryptoKey | { raw: Uint8Array };
  /** SHA-256 fingerprint of `publicKey`. */
  fingerprint: MajikKeyFingerprint;
  /** X25519 private key, decrypted into memory. ⚠️ Live key material — do not log or serialize directly. */
  privateKey: CryptoKey | { raw: Uint8Array };
  /** AES-256-GCM-encrypted X25519 private key (IV + ciphertext), as stored at rest. */
  encryptedPrivateKey: ArrayBuffer;
  /** Random salt used to derive the passphrase-based encryption key. Base64. */
  salt: string;
  /** KDF used to encrypt the keys on this identity: `1` = legacy PBKDF2, `2` = Argon2id. */
  kdfVersion: KDF_VERSION;
  /** ML-KEM-768 (FIPS-203) public key. Post-quantum key encapsulation. */
  mlKemPublicKey: Uint8Array;
  /** ML-KEM-768 secret key, decrypted into memory. ⚠️ Live key material. */
  mlKemSecretKey?: Uint8Array;

  /** Ed25519 public key. Classical signing — same keypair the X25519 identity key is converted from. */
  edPublicKey?: Uint8Array;
  /** Ed25519 secret key, decrypted into memory. ⚠️ Live key material. */
  edSecretKey?: Uint8Array;
  /** ML-DSA-87 (FIPS-204) public key. Post-quantum signing. */
  mlDsaPublicKey?: Uint8Array;
  /** ML-DSA-87 secret key, decrypted into memory. ⚠️ Live key material. */
  mlDsaSecretKey?: Uint8Array;

  /** @experimental secp256k1 Bitcoin public key. Domain-separated BIP-32/84 derivation by default. */
  btcPublicKey?: Uint8Array;
  /** @experimental Bitcoin private key, decrypted into memory. ⚠️ Live key material. */
  btcSecretKey?: Uint8Array;
}

/**
 * `MajikKeyIdentity` immediately after fresh derivation from a mnemonic —
 * i.e. what `create()` and `importFromMnemonicBackup()` produce internally,
 * before the result is wrapped into a `MajikKey` instance.
 *
 * Unlike the base `MajikKeyIdentity`, every `encrypted*` field here is
 * required: a fresh derivation always re-derives and re-encrypts the full
 * key set (ML-KEM, Ed25519, ML-DSA, and Bitcoin) in one pass, so there's no
 * "partially migrated" state at this point in the flow.
 */
export type MajikKeyDerivedIdentity = MajikKeyIdentity & {
  /** AES-256-GCM-encrypted ML-KEM-768 secret key, freshly re-encrypted. */
  encryptedMlKemSecretKey: ArrayBuffer;
  /** AES-256-GCM-encrypted Ed25519 secret key, freshly re-encrypted. */
  encryptedEdSecretKey: ArrayBuffer;
  /** AES-256-GCM-encrypted ML-DSA-87 secret key, freshly re-encrypted. */
  encryptedMlDsaSecretKey: ArrayBuffer;
  /** @experimental AES-256-GCM-encrypted Bitcoin secret key, freshly re-encrypted. */
  encryptedBtcSecretKey?: ArrayBuffer;
};

/**
 * Minimal identity export — just enough to identify the account and, if
 * present, re-derive access to it. Lighter than `MajikKeyJSON`: no ML-KEM,
 * Ed25519, ML-DSA, or Bitcoin fields at all. Produced by
 * `toSerializedIdentity()` (unlocked keys only).
 */
export interface SerializedIdentity {
  id: string;
  /** X25519 public key, base64. */
  publicKey: MajikKeyAddress;
  fingerprint: MajikKeyFingerprint;
  /** AES-256-GCM-encrypted X25519 private key, base64. Omitted in some contexts — check before use. */
  encryptedPrivateKey?: string;
  /** Base64 salt paired with `encryptedPrivateKey`. Omitted in some contexts — check before use. */
  salt?: string;
}

/**
 * Internal constructor payload for `MajikKey` — every static factory
 * (`create()`, `fromJSON()`, `fromDangerousJSON()`, `importFromMnemonicBackup()`,
 * etc.) builds one of these and passes it to the private constructor.
 *
 * You won't normally build this by hand; it's exported mainly for type
 * inference around the factory methods. Fields mirror `MajikKeyJSON` plus
 * the live (decrypted) counterparts where a factory is constructing an
 * already-unlocked instance.
 */
export interface MajikKeyConstructorOptions {
  id: string;
  publicKey: CryptoKey | { raw: Uint8Array };
  publicKeyBase64: MajikKeyAddress;
  fingerprint: MajikKeyFingerprint;
  encryptedPrivateKey: ArrayBuffer;
  encryptedPrivateKeyBase64: string;
  salt: string;
  /** Encrypted mnemonic-verification blob — see `MajikKeyJSON.backup`. */
  backup: string;
  label?: string;
  timestamp?: Date;
  /** Defaults to legacy PBKDF2 (`KDF_VERSION.PBKDF2`) if omitted — see the private constructor. */
  kdfVersion?: KDF_VERSION;
  mlKemPublicKey: Uint8Array;
  /** Present only when constructing an already-unlocked instance. ⚠️ Live key material. */
  mlKemSecretKey?: Uint8Array;
  encryptedMlKemSecretKey?: ArrayBuffer;
  encryptedMlKemSecretKeyBase64?: string;
  /** Present only when constructing an already-unlocked instance. ⚠️ Live key material. */
  privateKey?: CryptoKey | { raw: Uint8Array };
  /** Present only when constructing an already-unlocked instance. ⚠️ Live key material. */
  privateKeyBase64?: string;

  edPublicKey?: Uint8Array;
  encryptedEdSecretKey?: ArrayBuffer;
  encryptedEdSecretKeyBase64?: string;
  mlDsaPublicKey?: Uint8Array;
  encryptedMlDsaSecretKey?: ArrayBuffer;
  encryptedMlDsaSecretKeyBase64?: string;

  /** Present only when constructing an already-unlocked instance. ⚠️ Live key material. */
  edSecretKey?: Uint8Array;
  /** Present only when constructing an already-unlocked instance. ⚠️ Live key material. */
  mlDsaSecretKey?: Uint8Array;

  /** @experimental secp256k1 Bitcoin public key. */
  btcPublicKey?: Uint8Array;
  /** @experimental AES-256-GCM-encrypted Bitcoin private key. */
  encryptedBtcSecretKey?: ArrayBuffer;
  /** @experimental Base64 form of `encryptedBtcSecretKey`. */
  encryptedBtcSecretKeyBase64?: string;
  /** @experimental Present only when constructing an already-unlocked instance. ⚠️ Live key material. */
  btcSecretKey?: Uint8Array;

  mnemonicLanguage?: MnemonicLanguage;
}

/**
 * MajikKey
 * ---
 *
 * Seed phrase account library for the Majikah ecosystem.
 *
 * Every account stores FIVE keypairs, all deterministically derived from a
 * single BIP-39 mnemonic:
 *   1. X25519 (Curve25519)   — fingerprint, contact identity, legacy message compat
 *   2. ML-KEM-768 (FIPS-203) — post-quantum key encapsulation for v3 envelopes
 *   3. Ed25519               — classical signing
 *   4. ML-DSA-87 (FIPS-204)  — post-quantum signing
 *   5. Bitcoin (secp256k1)   — BIP-32/84 HD key, domain-separated by default (experimental)
 *
 * All derived from the 64-byte BIP-39 seed:
 *   seed[0..32]  → Ed25519 keypair — used directly for signing, AND converted
 *                  to X25519 via ed2curve for the encryption/identity keypair
 *                  (one Ed25519 keypair, two roles)
 *   seed[0..64]  → ml_kem768.keygen(seed) — full seed, deterministic
 *   hash(seed || "MajikSignatureSeedDSA") → 32-byte seed → ml_dsa87.keygen()
 *   seed[0..64]  → HDKey.fromMasterSeed(seed).derive(path) — BIP-32/84 Bitcoin key
 *
 */
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

  /**
   * @experimental
   */
  private _solanaKeypairMaterial?: SolanaKeypairMaterial;

  /**
   * @experimental
   */
  private _btcPublicKey?: Uint8Array;

  /**
   * @experimental
   */
  private _btcSecretKey?: Uint8Array;

  /**
   * @experimental
   */
  private _encryptedBtcSecretKey?: ArrayBuffer;

  /**
   * @experimental
   */
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

  /** Account identifier. Equal to `fingerprint` for accounts created by this library. */
  get id(): string {
    return this._id;
  }

  /** SHA-256 fingerprint of the X25519 public key. Stable identity anchor for the account. */
  get fingerprint(): MajikKeyFingerprint {
    return this._fingerprint;
  }

  /** X25519 public key — native `CryptoKey` where WebCrypto supports it, otherwise a raw-bytes wrapper. Always available, even when locked. */
  get publicKey(): CryptoKey | { raw: Uint8Array } {
    return this._publicKey;
  }

  /** X25519 public key, base64-encoded. Always available, even when locked. */
  get publicKeyBase64(): MajikKeyAddress {
    return this._publicKeyBase64;
  }

  /** Human-readable, user-editable account name. Update via `updateLabel()`. */
  get label(): string {
    return this._label;
  }

  /** BIP-39 wordlist language this account's mnemonic was generated/validated against. */
  get mnemonicLanguage(): MnemonicLanguage {
    return this._mnemonicLanguage;
  }

  /**
   * Encrypted mnemonic-verification blob (base64 JSON). Decryptable only
   * with the original mnemonic — used internally to verify a supplied
   * mnemonic before `importFromMnemonicBackup()` re-derives the full
   * identity. Not a general-purpose private-key backup.
   */
  get backup(): string {
    return this._backup;
  }

  /** Account creation time. */
  get timestamp(): Date {
    return this._timestamp;
  }

  /** KDF currently protecting every `encrypted*` field on this account: `1` = legacy PBKDF2, `2` = Argon2id. */
  get kdfVersion(): KDF_VERSION {
    return this._kdfVersion;
  }

  /** `true` if this account is on the current KDF (Argon2id). `false` means it's still on legacy PBKDF2 — see `migrate()` or `importFromMnemonicBackup()`. */
  get isArgon2id(): boolean {
    return this._kdfVersion === KDF_VERSION.ARGON2ID;
  }

  /** `true` if private key material is currently purged from memory (i.e. `lock()` was called, or `unlock()` hasn't been called yet). */
  get isLocked(): boolean {
    return this._privateKey === undefined;
  }

  /** `true` if private key material is currently decrypted in memory. The inverse of `isLocked`. */
  get isUnlocked(): boolean {
    return this._privateKey !== undefined;
  }

  /** ML-KEM-768 (FIPS-203) public key. Post-quantum key encapsulation. Always available, even when locked. */
  get mlKemPublicKey(): Uint8Array {
    return this._mlKemPublicKey;
  }

  /** ML-KEM-768 secret key. `undefined` unless the account is unlocked. ⚠️ Live key material — prefer `getMlKemSecretKey()` if you want a thrown error instead of `undefined` on locked accounts. */
  get mlKemSecretKey(): Uint8Array | undefined {
    return this._mlKemSecretKey;
  }

  /** `true` if this account has ML-KEM-768 keys (i.e. is post-quantum-encryption capable). `false` means it's a legacy account pending migration. */
  get hasMlKem(): boolean {
    return this._mlKemPublicKey !== undefined;
  }

  /** `true` if this account is on Argon2id *and* has ML-KEM-768 keys — i.e. fully migrated, nothing left to upgrade. */
  get isFullyUpgraded(): boolean {
    return this.isArgon2id && this.hasMlKem;
  }

  /**
   * @experimental secp256k1 Bitcoin public key. `undefined` if this account
   * has no stored Bitcoin key material (e.g. it predates Web3 support and
   * hasn't been re-imported via `importFromMnemonicBackup()`).
   */
  get btcPublicKey(): Uint8Array | undefined {
    return this._btcPublicKey;
  }

  /** @experimental `true` if this account has a stored Bitcoin keypair. */
  get hasBitcoin(): boolean {
    return this._btcPublicKey !== undefined;
  }

  /**
   * Lightweight, non-secret snapshot of this account's state — no key bytes
   * at all, encrypted or otherwise. Useful for account pickers, dashboards,
   * or anywhere you want to display status without touching key material.
   */
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

  /** Ed25519 public key. Classical signing — same keypair the X25519 identity key is converted from. Always available, even when locked. */
  get edPublicKey(): Uint8Array | undefined {
    return this._edPublicKey;
  }

  /** ML-DSA-87 (FIPS-204) public key. Post-quantum signing. Always available, even when locked. */
  get mlDsaPublicKey(): Uint8Array | undefined {
    return this._mlDsaPublicKey;
  }

  /** `true` if this account has both Ed25519 and ML-DSA-87 signing keys. `false` means it's a legacy account pending migration. */
  get hasSigningKeys(): boolean {
    return (
      this._edPublicKey !== undefined && this._mlDsaPublicKey !== undefined
    );
  }

  // ── CREATE ──────────────────────────────────────────────────────────────────

  /**
   * Creates a brand-new MajikKey account from a BIP-39 mnemonic.
   *
   * Derives the full key set in one pass — X25519, ML-KEM-768, Ed25519,
   * ML-DSA-87, and a domain-separated Bitcoin key (see `MAJIK_BITCOIN_DOMAIN_PATH`)
   * — encrypts every private key with Argon2id (KDF v2), and returns an
   * **already-unlocked** instance (no `unlock()` call needed right after
   * `create()`).
   *
   * @param mnemonic - A valid BIP-39 mnemonic phrase (12 or 24 words), matching `mnemonicLanguage`. Generate one with `MajikKey.generateMnemonic()`.
   * @param passphrase - Passphrase used to derive the Argon2id encryption key for every private key on this account. This is *not* the mnemonic — losing it without the mnemonic makes the account unrecoverable.
   * @param label - Optional human-readable account name. Defaults to an empty string. Update later via `updateLabel()`.
   * @param mnemonicLanguage - BIP-39 wordlist to validate `mnemonic` against. Defaults to `"en"`.
   * @param options.deriveBitcoin - @experimental Set `false` to skip deriving the Bitcoin keypair. Defaults to `true`.
   * @returns An unlocked `MajikKey` instance, ready for immediate use — call `.lock()` when you're done with it.
   * @throws {MajikKeyError} If `mnemonic` fails validation, `passphrase`/`label` fail their validators, or `mnemonic` doesn't match `mnemonicLanguage`'s wordlist.
   */
  static async create(
    mnemonic: string,
    passphrase: string,
    label?: string,
    options: {
      mnemonicLanguage?: MnemonicLanguage;
      /** @experimental Set `false` to skip deriving the Bitcoin keypair. Defaults to `true` for backward compatibility. */
      deriveBitcoin?: boolean;
    } = {
      deriveBitcoin: true,
      mnemonicLanguage: "en",
    },
  ): Promise<MajikKey> {
    try {
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      MajikKeyValidator.validateLabel(label);

      const { deriveBitcoin, mnemonicLanguage } = options;

      const wordlist = await MajikKey._getWordlist(mnemonicLanguage || "en");

      if (!validateMnemonic(mnemonic, wordlist)) {
        throw new MajikKeyError("Invalid BIP39 mnemonic phrase");
      }

      const identity = await MajikKey._deriveAndEncryptFromMnemonic(
        mnemonic,
        passphrase,
        { deriveBitcoin: deriveBitcoin },
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
        encryptedBtcSecretKeyBase64: identity.encryptedBtcSecretKey
          ? arrayBufferToBase64(identity.encryptedBtcSecretKey)
          : undefined,
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
    options: {
      mnemonicLanguage?: MnemonicLanguage;
      /** @experimental Set `false` to skip deriving the Bitcoin keypair. Defaults to `true` for backward compatibility. */
      deriveBitcoin?: boolean;
    } = {
      deriveBitcoin: true,
      mnemonicLanguage: "en",
    },
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
      return await MajikKey.create(mnemonic, passphrase, label, options);
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

    try {
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
    } finally {
      // Clear the temporary unencrypted buffer
      secureFill.call(new Uint8Array(privateKeyBuffer), 0);
      secureFill.call(salt, 0);
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
    // 1. Zeroize raw bytes of all active keys
    // Apply the secure fill using .call(targetArray, value)
    if (
      this._privateKey &&
      "raw" in this._privateKey &&
      this._privateKey.raw instanceof Uint8Array
    ) {
      secureFill.call(this._privateKey.raw, 0);
    }
    if (this._mlKemSecretKey) secureFill.call(this._mlKemSecretKey, 0);
    if (this._edSecretKey) secureFill.call(this._edSecretKey, 0);
    if (this._mlDsaSecretKey) secureFill.call(this._mlDsaSecretKey, 0);
    if (this._btcSecretKey) secureFill.call(this._btcSecretKey, 0);

    if (this._solanaKeypairMaterial) {
      secureFill.call(this._solanaKeypairMaterial.secretKey, 0);
    }
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
   */
  static async importFromMnemonicBackup(
    backup: string,
    mnemonic: string,
    passphrase: string,
    label?: string,
    options: {
      mnemonicLanguage?: MnemonicLanguage;
      /** @experimental Set `false` to skip deriving the Bitcoin keypair. Defaults to `true` for backward compatibility. */
      deriveBitcoin?: boolean;
    } = {
      deriveBitcoin: true,
      mnemonicLanguage: "en",
    },
  ): Promise<MajikKey> {
    try {
      if (!backup || typeof backup !== "string")
        throw new MajikKeyError("Backup must be a non-empty string");
      MajikKeyValidator.validateMnemonic(mnemonic);
      MajikKeyValidator.validatePassphrase(passphrase);
      MajikKeyValidator.validateLabel(label);

      const { deriveBitcoin, mnemonicLanguage } = options;

      const wordlist = await MajikKey._getWordlist(mnemonicLanguage || "en");

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
        { deriveBitcoin: deriveBitcoin },
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
        encryptedBtcSecretKeyBase64: identity.encryptedBtcSecretKey
          ? arrayBufferToBase64(identity.encryptedBtcSecretKey)
          : undefined,
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

  /**
   * @param mnemonic - BIP-39 mnemonic to derive the full key set from.
   * @param passphrase - Passphrase used to derive the Argon2id encryption key shared by every private key produced here.
   * @param options.deriveBitcoin - @experimental Set `false` to skip deriving the Bitcoin keypair. Defaults to `true`.
   */
  private static async _deriveAndEncryptFromMnemonic(
    mnemonic: string,
    passphrase: string,
    options?: { deriveBitcoin?: boolean },
  ): Promise<MajikKeyDerivedIdentity> {
    const deriveBitcoin = options?.deriveBitcoin ?? true;

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

    // Single salt — one Argon2id derivation unlocks every key below
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

    // @experimental Bitcoin — real BIP-32/BIP-84 off the raw 64-byte BIP-39
    // seed, using Majik's domain-separated path by default. Same salt,
    // different IV, same pattern as ML-KEM/Ed25519/ML-DSA above. Skipped
    // entirely when `deriveBitcoin` is false — no derivation cost paid,
    // no key material generated.
    let btcPublicKey: Uint8Array | undefined;
    let btcSecretKey: Uint8Array | undefined;
    let encryptedBtcSecretKey: ArrayBuffer | undefined;
    if (deriveBitcoin) {
      const rawSeed = await mnemonicToSeed(mnemonic);
      const btcMaterial = deriveBitcoinKeypairFromSeed(rawSeed);
      btcPublicKey = btcMaterial.publicKey;
      btcSecretKey = btcMaterial.privateKey;
      encryptedBtcSecretKey = await MajikKey._encryptSigningKey(
        btcMaterial.privateKey,
        passphrase,
        salt,
      );
    }

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
      btcPublicKey,
      btcSecretKey,
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

  /**
   * @experimental
   */
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

  /**
   * @experimental
   */
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


// Freeze static methods (e.g., MajikKey.create, MajikKey.fromJSON)
Object.freeze(MajikKey);

// Freeze instance methods (e.g., this.lock, this.unlock)
Object.freeze(MajikKey.prototype);