import { MajikMessageIdentityJSON } from "./database/system/identity";
import { ISODateString } from "./types";
import { arrayBufferToBase64, base64ToArrayBuffer } from "./utils";

/* -------------------------------
 * Types
 * ------------------------------- */

export type SerializedMajikContact = {
  id: string;
  fingerprint: string;
  meta?: MajikContactMeta;
  publicKeyBase64: string;
  mlKey: string;
  majikah_registered?: boolean;
};


export interface MajikContactMeta {
  label?: string;
  notes?: string;
  blocked?: boolean;
  createdAt?: ISODateString;
  updatedAt?: ISODateString;
}

export interface MajikContactData {
  id: string;
  // publicKey may be a WebCrypto `CryptoKey` or a raw-key wrapper { raw: Uint8Array }
  publicKey: CryptoKey | { raw: Uint8Array };
  fingerprint: string;
  mlKey: string;
  meta?: MajikContactMeta;
  majikah_registered?: boolean;
}

export interface MajikContactCard {
  id: string;
  publicKey: string;
  fingerprint: string;
  label: string;
  mlKey: string;
}

/* -------------------------------
 * Errors
 * ------------------------------- */

export class MajikContactError extends Error {
  cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "MajikContactError";
    this.cause = cause;
  }
}

/* -------------------------------
 * MajikContact Class
 * ------------------------------- */

export class MajikContact {
  public readonly id: string;
  public readonly publicKey: CryptoKey | { raw: Uint8Array };
  public readonly fingerprint: string;
  public readonly mlKey: string;
  public meta: MajikContactMeta;
  private majikah_registered?: boolean;

  constructor(data: MajikContactData) {
    this.assertId(data.id);
    this.assertPublicKey(data.publicKey);
    this.assertMLKey(data.mlKey);
    this.assertFingerprint(data.fingerprint);

    this.id = data.id;
    this.publicKey = data.publicKey;
    this.fingerprint = data.fingerprint;
    this.mlKey = data.mlKey;

    this.meta = {
      label: data.meta?.label || "",
      notes: data.meta?.notes || "",
      blocked: data.meta?.blocked || false,
      createdAt: data.meta?.createdAt || new Date().toISOString(),
      updatedAt: data.meta?.updatedAt || new Date().toISOString(),
    };
  }

  static create(
    id: string,
    publicKey: CryptoKey | { raw: Uint8Array },
    mlKey: string,
    fingerprint: string,
    meta?: Partial<MajikContactMeta>,
  ): MajikContact {
    return new MajikContact({
      id,
      publicKey,
      fingerprint,
      meta,
      mlKey,
    });
  }

  private assertId(id: string) {
    if (!id || typeof id !== "string") {
      throw new MajikContactError("Contact ID must be a non-empty string");
    }
  }

  private assertMLKey(key: string) {
    if (!key || typeof key !== "string") {
      throw new MajikContactError("ML Key must be a non-empty string");
    }
  }

  private assertPublicKey(key: CryptoKey | { raw: Uint8Array }) {
    // Accept either a WebCrypto CryptoKey (with .type === 'public')
    // or a raw-key wrapper object that contains a Uint8Array `raw` field.
    if (!key) throw new MajikContactError("Invalid public key");
    const anyKey: any = key as any;
    if (anyKey && typeof anyKey === "object") {
      if (anyKey.type === "public") return;
      if (anyKey.raw instanceof Uint8Array) return;
    }
    throw new MajikContactError("Invalid public key");
  }

  private assertFingerprint(fingerprint: string) {
    if (!fingerprint || typeof fingerprint !== "string") {
      throw new MajikContactError("Fingerprint must be a non-empty string");
    }
  }

  private updateTimestamp() {
    this.meta.updatedAt = new Date().toISOString();
  }

  updateLabel(label: string): this {
    if (typeof label !== "string")
      throw new MajikContactError("Label must be a string");
    this.meta.label = label;
    this.updateTimestamp();
    return this;
  }

  updateNotes(notes: string): this {
    if (typeof notes !== "string")
      throw new MajikContactError("Notes must be a string");
    this.meta.notes = notes;
    this.updateTimestamp();
    return this;
  }

  isBlocked(): boolean {
    return this.meta.blocked || false;
  }

  setBlocked(blocked: boolean): this {
    if (typeof blocked !== "boolean")
      throw new MajikContactError("Blocked must be boolean");
    this.meta.blocked = blocked;
    this.updateTimestamp();
    return this;
  }

  // Idempotent block/unblock for safe scanning
  block(): this {
    if (!this.isBlocked()) this.setBlocked(true);
    return this;
  }

  unblock(): this {
    if (this.isBlocked()) this.setBlocked(false);
    return this;
  }

  isMajikahIdentityChecked(): boolean {
    return this.majikah_registered !== undefined;
  }

  isMajikahRegistered(): boolean {
    return this.majikah_registered || false;
  }

  setMajikahStatus(status: boolean): this {
    this.majikah_registered = status;
    return this;
  }

  async getDisplayName(): Promise<string> {
    return this.meta.label || (await this.getPublicKeyBase64());
  }

  /**
   * Support both CryptoKey and raw-key wrappers (fallbacks when WebCrypto X25519 unsupported)
   */
  async getPublicKeyBase64(): Promise<string> {
    try {
      // If it's a CryptoKey, export with SubtleCrypto
      const raw = await crypto.subtle.exportKey(
        "raw",
        this.publicKey as CryptoKey,
      );
      return arrayBufferToBase64(raw);
    } catch (e) {
      // Fallback: publicKey may be a wrapper with `raw` Uint8Array
      const maybe: any = this.publicKey as any;
      if (maybe && maybe.raw instanceof Uint8Array) {
        return arrayBufferToBase64(maybe.raw.buffer);
      }
      throw e;
    }
  }

  async toJSON(): Promise<SerializedMajikContact> {
    return {
      id: this.id,
      fingerprint: this.fingerprint,
      meta: { ...this.meta },
      publicKeyBase64: await this.getPublicKeyBase64(),
      majikah_registered: this.majikah_registered,
      mlKey: this.mlKey,
    };
  }

  /**
   * Reconstruct a MajikContact from its serialized form
   */
  static fromJSON(serialized: SerializedMajikContact): MajikContact {
    try {
      const publicKeyRaw = new Uint8Array(
        base64ToArrayBuffer(serialized.publicKeyBase64),
      );

      return new MajikContact({
        id: serialized.id,
        fingerprint: serialized.fingerprint,
        meta: serialized.meta,
        publicKey: { raw: publicKeyRaw },
        majikah_registered: serialized.majikah_registered,
        mlKey: serialized.mlKey,
      });
    } catch (err) {
      throw new MajikContactError("Failed to deserialize MajikContact", err);
    }
  }

  /**
   * Create a new MajikContact from a MajikMessageIdentityJSON
   */
  static async fromIdentityJSON(
    identityJSON: MajikMessageIdentityJSON,
  ): Promise<MajikContact> {
    try {
      const publicKeyRaw = new Uint8Array(
        base64ToArrayBuffer(identityJSON.public_key),
      );

      const contactData: MajikContactData = {
        id: identityJSON.id,
        publicKey: { raw: publicKeyRaw },
        fingerprint: identityJSON.id,
        meta: {
          label: identityJSON.label,
          createdAt: identityJSON.timestamp,
          updatedAt: identityJSON.timestamp,
          blocked: identityJSON.restricted,
        },
        majikah_registered: true,
        mlKey: identityJSON.ml_key,
      };

      return new MajikContact(contactData);
    } catch (err) {
      throw new MajikContactError(
        "Failed to create MajikContact from MajikMessageIdentityJSON",
        err,
      );
    }
  }

  static isBlocked(contact: MajikContact): boolean {
    return !!contact.meta.blocked;
  }
}
