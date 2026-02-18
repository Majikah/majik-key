import { MajikUser } from "@thezelijah/majik-user";

import { hash } from "@stablelib/sha256";
import { arrayToBase64 } from "../../utils";
import { SerializedMajikContact } from "../../majik-contact";

/**
 * Utility assertions
 */
function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function assertString(value: unknown, field: string): asserts value is string {
  assert(
    typeof value === "string" && value.trim().length > 0,
    `${field} must be a non-empty string`,
  );
}

function assertISODate(value: string, field: string): void {
  const date = new Date(value);
  assert(!isNaN(date.getTime()), `${field} must be a valid ISO timestamp`);
}

function sha256(input: string): string {
  const hashed = hash(new TextEncoder().encode(input));
  return arrayToBase64(hashed);
}

export interface MajikMessageIdentityJSON {
  id: string;
  user_id: string;
  public_key: string;
  ml_key: string;
  phash: string;
  label: string;
  timestamp: string;
  restricted: boolean;
}

/**
 * MajikMessageIdentity
 * Immutable identity container with integrity verification
 */
export class MajikMessageIdentity {
  // 🔒 Private backing fields
  private readonly _id: string;
  private readonly _userId: string;
  private readonly _publicKey: string;
  private readonly _mlKey: string;
  private readonly _phash: string;
  private _label: string;
  private readonly _timestamp: string;
  private readonly _restricted: boolean;

  /**
   * Constructor is private to enforce controlled creation
   */
  private constructor(params: {
    id: string;
    userId: string;
    publicKey: string;
    mlKey: string;
    phash: string;
    label: string;
    timestamp: string;
    restricted: boolean;
  }) {
    assertString(params.id, "id");
    assertString(params.userId, "user_id");
    assertString(params.publicKey, "public_key");
    assertString(params.mlKey, "ml_key");
    assertString(params.phash, "phash");
    assertString(params.label, "label");
    assertISODate(params.timestamp, "timestamp");
    assert(
      typeof params.restricted === "boolean",
      "restricted must be boolean",
    );

    this._id = params.id;
    this._userId = params.userId;
    this._publicKey = params.publicKey;
    this._mlKey = params.mlKey;
    this._phash = params.phash;
    this._label = params.label;
    this._timestamp = params.timestamp;
    this._restricted = params.restricted;

    // Final integrity check at construction
    assert(this.validateIntegrity(), "Identity integrity validation failed");
  }

  // ─────────────────────────────
  // Static factory
  // ─────────────────────────────

  /**
   * Create a new immutable identity from MajikUser
   */
  static create(
    user: MajikUser,
    account: SerializedMajikContact,
    options?: {
      label?: string;
      restricted?: boolean;
    },
  ): MajikMessageIdentity {
    assert(user, "MajikUser is required");
    const userValidResult = user.validate();
    if (!userValidResult.isValid) {
      throw new Error(
        `Invalid MajikUser: ${userValidResult.errors.join(", ")}`,
      );
    }

    const label = options?.label || account?.meta?.label || user.displayName;
    assertString(label, "label");
    const timestamp = new Date().toISOString();

    const publicKey = account.publicKeyBase64;
    const phash = sha256(
      `${user.id}:${publicKey}:${account.id}:${account.mlKey}`,
    );

    return new MajikMessageIdentity({
      id: account.id,
      userId: user.id,
      publicKey: publicKey,
      mlKey: account.mlKey,
      phash,
      label,
      timestamp,
      restricted: options?.restricted ?? false,
    });
  }

  // ─────────────────────────────
  // Getters (safe, read-only)
  // ─────────────────────────────

  get id(): string {
    return this._id;
  }

  get userID(): string {
    return this._userId;
  }

  get publicKey(): string {
    return this._publicKey;
  }

  get phash(): string {
    return this._phash;
  }

  get label(): string {
    return this._label;
  }

  get timestamp(): string {
    return this._timestamp;
  }

  get restricted(): boolean {
    return this._restricted;
  }

  // ─────────────────────────────
  // Mutators (restricted)
  // ─────────────────────────────

  /**
   * Only mutable field
   */
  set label(label: string) {
    assertString(label, "label");
    this._label = label;
  }

  // ─────────────────────────────
  // Identity checks
  // ─────────────────────────────

  /**
   * Returns true if identity is restricted
   */
  isRestricted(): boolean {
    return this._restricted === true;
  }

  /**
   * Verify identity integrity
   * Detects tampering of id/public_key
   */
  validateIntegrity(): boolean {
    const expected = sha256(
      `${this._userId}:${this._publicKey}:${this._id}:${this._mlKey}`,
    );
    return expected === this._phash;
  }

  /**
   * Explicit verification helper
   */
  matches(userId: string, publicKey: string): boolean {
    assertString(userId, "userId");
    assertString(publicKey, "publicKey");

    const hash = sha256(`${userId}:${publicKey}:${this._id}:${this._mlKey}`);
    return hash === this._phash;
  }

  // ─────────────────────────────
  // Serialization
  // ─────────────────────────────

  toJSON(): MajikMessageIdentityJSON {
    return {
      id: this._id,
      user_id: this._userId,
      public_key: this._publicKey,
      ml_key: this._mlKey,
      phash: this._phash,
      label: this._label,
      timestamp: this._timestamp,
      restricted: this._restricted,
    };
  }

  static fromJSON(
    json: string | MajikMessageIdentityJSON,
  ): MajikMessageIdentity {
    const obj = typeof json === "string" ? JSON.parse(json) : json;
    assert(typeof obj === "object" && obj !== null, "Invalid JSON object");

    const identity = new MajikMessageIdentity({
      id: obj.id as string,
      userId: obj.user_id as string,
      publicKey: obj.public_key as string,
      mlKey: obj.ml_key as string,
      phash: obj.phash as string,
      label: obj.label as string,
      timestamp: obj.timestamp as string,
      restricted: obj.restricted as boolean,
    });

    assert(identity.validateIntegrity(), "Invalid phash in JSON");
    return identity;
  }
}
