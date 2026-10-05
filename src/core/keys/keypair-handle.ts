/**
 * keypair-handle.ts — the object returned by MajikKey.getKeypair(id).
 *
 * It reads LIVE through accessor closures instead of copying key bytes, so a
 * handle obtained before lock() can never expose stale (zeroized) material or
 * keep secrets alive: after lock(), `.private` throws and `.public` still works.
 */
import type { KeyFamily, KeyId } from "./key-id.js";
import { KEY_ALGORITHMS } from "./registry.js";
import type { KeyPurpose, KeyStatus } from "./types.js";
import { arrayToBase64 } from "../utils.js";

export class MajikKeypair {
  constructor(
    readonly id: KeyId,
    private readonly readPublic: () => Uint8Array,
    private readonly readPrivate: () => Uint8Array,
    private readonly readUnlocked: () => boolean,
  ) {}

  /** Namespaced algorithm id, e.g. "pq:ml-dsa-87". */
  get algorithm(): KeyId {
    return this.id;
  }
  get family(): KeyFamily {
    return KEY_ALGORITHMS[this.id].family;
  }
  get purpose(): KeyPurpose {
    return KEY_ALGORITHMS[this.id].purpose;
  }
  get status(): KeyStatus {
    return KEY_ALGORITHMS[this.id].status;
  }
  get isUnlocked(): boolean {
    return this.readUnlocked();
  }
  /** Public key bytes. Available while locked (except derived views like web3:sol). */
  get public(): Uint8Array {
    return this.readPublic();
  }
  get publicBase64(): string {
    return arrayToBase64(this.readPublic());
  }
  /** Secret key bytes. Throws if the account is locked. ⚠️ Live key material. */
  get private(): Uint8Array {
    return this.readPrivate();
  }
}

export interface KeyInfo {
  id: KeyId;
  family: KeyFamily;
  purpose: KeyPurpose;
  kind: "stored" | "derived";
  status: KeyStatus;
  /** Undefined for derived views while locked. */
  publicKeyBase64?: string;
}


Object.freeze(MajikKeypair);
Object.freeze(MajikKeypair.prototype);