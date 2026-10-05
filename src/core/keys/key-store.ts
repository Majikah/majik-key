/**
 * key-store.ts — Phase 2c core: the single in-memory + at-rest container for
 * every key on a MajikKey account. MajikKey (phase 2c-wire) delegates to this
 * instead of holding one private field per algorithm.
 *
 * Responsibilities
 *  - hold one slot per KeyId: public key, encrypted secret (IV||AES-GCM),
 *    and — only while unlocked — the raw secret
 *  - atomic unlock / lock / re-encrypt (no half-states)
 *  - (de)serialize to the new `keys` entries AND to the legacy flat JSON fields
 *    (Tier 1 migration + optional legacy export)
 *  - round-trip entries from NEWER library versions untouched (opaque
 *    pass-through) so a downgrade-then-save never drops keys
 *
 * It never derives a KDF key itself: callers pass resolver functions, so the
 * "one Argon2id run per operation" guarantee (phase 2a) stays in MajikKey.
 */
import { MajikKeyError } from "../error.js";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  generateRandomBytes,
  IV_LENGTH,
} from "../crypto/crypto-provider.js";
import { arrayToBase64, base64ToUint8Array } from "../utils.js";
import { KeyId } from "./key-id.js";
import { KEY_ALGORITHMS, getAlgorithm, knownKeyIds } from "./registry.js";
import type { DerivedKeypair } from "./key-impls.js";
import type { KeyDerivation, KeyEntryJSON } from "./types.js";

export interface KeySlot {
  id: KeyId;
  publicKey: Uint8Array;
  /** IV(12) || AES-256-GCM ciphertext. Absent for public-only entries. */
  encryptedSecretKey?: Uint8Array;
  /** Raw secret. Present ONLY while the store is unlocked. */
  secretKey?: Uint8Array;
  derivation: KeyDerivation;
  createdAt?: string;
}

/** Supplies the AES key for a slot (X25519 of legacy accounts may need PBKDF2, the rest Argon2id). */
export type KeyResolver = (slot: KeySlot) => Uint8Array;

/** The flat, pre-registry JSON fields (a subset of MajikKeyJSON). */
export interface LegacyKeyJSON {
  publicKey: string;
  encryptedPrivateKey?: string;
  mlKemPublicKey?: string;
  encryptedMlKemSecretKey?: string;
  edPublicKey?: string;
  encryptedEdSecretKey?: string;
  mlDsaPublicKey?: string;
  encryptedMlDsaSecretKey?: string;
  btcPublicKey?: string;
  encryptedBtcSecretKey?: string;
}

const LEGACY_FIELDS: ReadonlyArray<
  readonly [KeyId, keyof LegacyKeyJSON, keyof LegacyKeyJSON]
> = [
  [KeyId.X25519, "publicKey", "encryptedPrivateKey"],
  [KeyId.ML_KEM_768, "mlKemPublicKey", "encryptedMlKemSecretKey"],
  [KeyId.ED25519, "edPublicKey", "encryptedEdSecretKey"],
  [KeyId.ML_DSA_87, "mlDsaPublicKey", "encryptedMlDsaSecretKey"],
  [KeyId.BTC, "btcPublicKey", "encryptedBtcSecretKey"],
];

const zero = (u?: Uint8Array) => u?.fill(0);

export class KeyStore {
  private readonly slots = new Map<KeyId, KeySlot>();
  /** Entries whose id this library version doesn't know. Preserved verbatim. */
  private readonly opaque: KeyEntryJSON[] = [];
  private _unlocked = false;

  // ── crypto primitives (same on-disk format as every blob since v1) ────────
  static seal(aesKey: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const iv = generateRandomBytes(IV_LENGTH);
    const ct = aesGcmEncrypt(aesKey, iv, plaintext);
    const out = new Uint8Array(iv.length + ct.length);
    out.set(iv, 0);
    out.set(ct, iv.length);
    return out;
  }

  static open(aesKey: Uint8Array, blob: Uint8Array, label: string): Uint8Array {
    const plain = aesGcmDecrypt(
      aesKey,
      blob.slice(0, IV_LENGTH),
      blob.slice(IV_LENGTH),
    );
    if (!plain)
      throw new MajikKeyError(
        `Failed to decrypt ${label} — incorrect passphrase or corrupted data`,
      );
    return plain;
  }

  // ── construction ──────────────────────────────────────────────────────────

  /** Fresh derivation (create / importFromMnemonicBackup): seals every secret, returns UNLOCKED. */
  static fromDerived(
    derived: ReadonlyMap<KeyId, DerivedKeypair>,
    aesKey: Uint8Array,
  ): KeyStore {
    const store = new KeyStore();
    for (const [id, kp] of derived) {
      store.slots.set(id, {
        id,
        publicKey: kp.publicKey,
        secretKey: kp.secretKey,
        encryptedSecretKey: KeyStore.seal(aesKey, kp.secretKey),
        derivation: KEY_ALGORITHMS[id].derivation,
        createdAt: new Date().toISOString(),
      });
    }
    store._unlocked = true;
    return store;
  }

  /** From the new `keys` JSON field. Unknown ids are preserved opaquely. */
  static fromEntries(entries: readonly KeyEntryJSON[]): KeyStore {
    const store = new KeyStore();
    const seen = new Set<string>();
    for (const e of entries) {
      if (!e || typeof e.id !== "string" || typeof e.publicKey !== "string")
        throw new MajikKeyError("Invalid key entry in `keys`");
      if (seen.has(e.id))
        throw new MajikKeyError(`Duplicate key entry "${e.id}"`);
      seen.add(e.id);
      if (!getAlgorithm(e.id)) {
        store.opaque.push(e); // from a newer version: keep, don't interpret
        continue;
      }
      store.slots.set(e.id as KeyId, {
        id: e.id as KeyId,
        publicKey: base64ToUint8Array(e.publicKey),
        encryptedSecretKey: e.encryptedSecretKey
          ? base64ToUint8Array(e.encryptedSecretKey)
          : undefined,
        derivation: e.derivation,
        createdAt: e.createdAt,
      });
    }
    return store;
  }

  /** Tier 1 migration: wrap the flat pre-registry fields. No secrets, no KDF needed. */
  static fromLegacyJSON(j: LegacyKeyJSON): KeyStore {
    const store = new KeyStore();
    for (const [id, pubField, encField] of LEGACY_FIELDS) {
      const pub = j[pubField];
      if (!pub) continue;
      const enc = j[encField];
      store.slots.set(id, {
        id,
        publicKey: base64ToUint8Array(pub),
        encryptedSecretKey: enc ? base64ToUint8Array(enc) : undefined,
        derivation: KEY_ALGORITHMS[id].derivation,
      });
    }
    if (!store.slots.has(KeyId.X25519))
      throw new MajikKeyError(
        "Legacy key JSON is missing the X25519 public key",
      );
    return store;
  }

  // ── queries ───────────────────────────────────────────────────────────────

  get isUnlocked(): boolean {
    return this._unlocked;
  }
  has(id: string): boolean {
    return this.slots.has(id as KeyId);
  }
  hasAll(ids: readonly string[]): boolean {
    return ids.every((i) => this.has(i));
  }
  missing(ids: readonly KeyId[]): KeyId[] {
    return ids.filter((i) => !this.slots.has(i));
  }
  /** Stored ids in canonical registry order. */
  ids(): KeyId[] {
    return knownKeyIds().filter((id) => this.slots.has(id));
  }
  get hasOpaqueSecrets(): boolean {
    return this.opaque.some((e) => !!e.encryptedSecretKey);
  }
  slot(id: KeyId): KeySlot | undefined {
    return this.slots.get(id);
  }

  getPublicKey(id: string): Uint8Array {
    const s = this.slots.get(id as KeyId);
    if (!s) throw new MajikKeyError(`No "${id}" key on this account`);
    return s.publicKey;
  }

  getSecretKey(id: string): Uint8Array {
    const s = this.slots.get(id as KeyId);
    if (!s) throw new MajikKeyError(`No "${id}" key on this account`);
    if (!this._unlocked || !s.secretKey)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    return s.secretKey;
  }

  /** Non-throwing: the raw secret if the store is unlocked and the slot has one. */
  peekSecretKey(id: string): Uint8Array | undefined {
    return this._unlocked ? this.slots.get(id as KeyId)?.secretKey : undefined;
  }

  /**
   * Install raw secrets onto existing slots and mark the store unlocked
   * (fromDangerousJSON). Every id must already have a slot.
   */
  attachSecrets(secrets: ReadonlyMap<string, Uint8Array>): void {
    for (const [id, secret] of secrets) {
      const s = this.slots.get(id as KeyId);
      if (!s)
        throw new MajikKeyError(`Secret supplied for unknown key "${id}"`);
      s.secretKey = secret;
    }
    this._unlocked = true;
  }

  /** Raw secrets of every slot (only while unlocked). Used by toDangerousJSON. */
  exportSecrets(): Map<KeyId, Uint8Array> {
    if (!this._unlocked)
      throw new MajikKeyError("MajikKey is locked. Call unlock() first.");
    const out = new Map<KeyId, Uint8Array>();
    for (const s of this.slots.values())
      if (s.secretKey) out.set(s.id, s.secretKey);
    return out;
  }

  // ── lock / unlock (atomic) ────────────────────────────────────────────────

  /** Decrypt every secret into temporaries; commit only if ALL succeed. */
  unlock(keyFor: KeyResolver): void {
    const staged = new Map<KeyId, Uint8Array>();
    try {
      for (const slot of this.slots.values()) {
        if (!slot.encryptedSecretKey) continue;
        staged.set(
          slot.id,
          KeyStore.open(
            keyFor(slot),
            slot.encryptedSecretKey,
            `${slot.id} secret key`,
          ),
        );
      }
    } catch (e) {
      for (const p of staged.values()) zero(p);
      throw e;
    }
    for (const [id, secret] of staged) this.slots.get(id)!.secretKey = secret;
    this._unlocked = true;
  }

  lock(): void {
    for (const s of this.slots.values()) {
      zero(s.secretKey);
      s.secretKey = undefined;
    }
    this._unlocked = false;
  }

  // ── passphrase change / KDF migration (decrypt all → seal all → commit) ───

  /** Returns freshly sealed blobs under `newKey`. Mutates nothing. */
  prepareReseal(
    oldKeyFor: KeyResolver,
    newKey: Uint8Array,
  ): Map<KeyId, Uint8Array> {
    if (this.hasOpaqueSecrets)
      throw new MajikKeyError(
        "This account holds keys from a newer library version. Upgrade the library before changing the passphrase.",
      );
    const out = new Map<KeyId, Uint8Array>();
    for (const slot of this.slots.values()) {
      if (!slot.encryptedSecretKey) continue;
      const plain = KeyStore.open(
        oldKeyFor(slot),
        slot.encryptedSecretKey,
        `${slot.id} secret key`,
      );
      try {
        out.set(slot.id, KeyStore.seal(newKey, plain));
      } finally {
        zero(plain);
      }
    }
    return out;
  }

  commitReseal(blobs: ReadonlyMap<KeyId, Uint8Array>): void {
    for (const [id, blob] of blobs)
      this.slots.get(id)!.encryptedSecretKey = blob;
  }

  /** Add keys after the fact (addKeys()). Caller has already sealed `secretKey`. */
  add(slot: KeySlot): void {
    if (this.slots.has(slot.id))
      throw new MajikKeyError(`"${slot.id}" already exists on this account`);
    this.slots.set(slot.id, slot);
  }

  // ── serialization ─────────────────────────────────────────────────────────

  toEntries(): KeyEntryJSON[] {
    const known = this.ids().map((id): KeyEntryJSON => {
      const s = this.slots.get(id)!;
      return {
        id,
        publicKey: arrayToBase64(s.publicKey),
        ...(s.encryptedSecretKey
          ? { encryptedSecretKey: arrayToBase64(s.encryptedSecretKey) }
          : {}),
        derivation: s.derivation,
        ...(s.createdAt ? { createdAt: s.createdAt } : {}),
      };
    });
    return [...known, ...this.opaque];
  }

  /** Flat pre-registry fields — for `toJSON({ legacy: true })` so older readers keep working. */
  toLegacyJSON(): LegacyKeyJSON {
    const out: Partial<LegacyKeyJSON> = {};
    for (const [id, pubField, encField] of LEGACY_FIELDS) {
      const s = this.slots.get(id);
      if (!s) continue;
      out[pubField] = arrayToBase64(s.publicKey);
      if (s.encryptedSecretKey)
        out[encField] = arrayToBase64(s.encryptedSecretKey);
    }
    return out as LegacyKeyJSON;
  }
}


Object.freeze(KeyStore);
Object.freeze(KeyStore.prototype);