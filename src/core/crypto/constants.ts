export const KEY_ALGO = { name: "ECDH", namedCurve: "X25519" } as const;

// ── Salts ─────────────────────────────────────────────────────────────────────
// Current names (MajikKey). Used for everything written by this version.
export const MAJIK_SALT = "MajikKeySalt";
export const MAJIK_MNEMONIC_SALT = "MajikKeyMnemonicSalt";

/**
 * @deprecated Pre-0.8 salts ("MajikMessage…"). READ-ONLY: kept so backups and
 * data written by older versions still decrypt. Never use for new writes.
 * Changing/removing these would make every existing mnemonic backup unreadable.
 */
export const LEGACY_MAJIK_SALT = "MajikMessageSalt";
/** @deprecated See LEGACY_MAJIK_SALT. Existing mnemonic backups were encrypted with this salt. */
export const LEGACY_MAJIK_MNEMONIC_SALT = "MajikMessageMnemonicSalt";

/**
 * Mnemonic-backup salt generations. The backup blob records which one it used
 * (`backupSaltVersion`); blobs without the field are generation 1.
 *   1 → LEGACY_MAJIK_MNEMONIC_SALT   (every backup written before 0.8)
 *   2 → MAJIK_MNEMONIC_SALT          (written by 0.8+)
 */
export const BACKUP_SALT_VERSION = { LEGACY: 1, CURRENT: 2 } as const;
export type BACKUP_SALT_VERSION = (typeof BACKUP_SALT_VERSION)[keyof typeof BACKUP_SALT_VERSION];

/**
 * Which generation NEW backups are written with. Readers handle both.
 * ⚠️ Older library versions (and any port that hasn't been updated, e.g.
 * majik-key-rs) can only read generation 1. Flip to LEGACY to keep newly
 * created backups readable by them until they ship the new reader.
 */
export const BACKUP_SALT_WRITE_VERSION: BACKUP_SALT_VERSION = BACKUP_SALT_VERSION.CURRENT;

export const backupSaltFor = (v: number | undefined): string =>
  v === BACKUP_SALT_VERSION.CURRENT ? MAJIK_MNEMONIC_SALT : LEGACY_MAJIK_MNEMONIC_SALT;

/**
 * ⚠️ FROZEN. This string is part of the legacy-v1 ML-DSA-87 derivation
 * (sha256(seed || this)). Changing it changes every existing user's ML-DSA key.
 * It intentionally still says "Majik…" and must NOT be renamed.
 */
export const MAJIK_SIGNATURE_SEED = "MajikSignatureSeedDSA";

/**
 * KDF version identifiers.
 * Stored alongside every encrypted private key blob so the correct
 * derivation function is always used on decryption.
 */
export const KDF_VERSION = {
  PBKDF2: 1, // legacy — read-only support for existing accounts
  ARGON2ID: 2, // current — all new accounts and re-encryptions
} as const;

export type KDF_VERSION = (typeof KDF_VERSION)[keyof typeof KDF_VERSION];

/** Argon2id parameters. */
export const ARGON2_PARAMS = {
  PASSPHRASE: {
    m: 65536, // memory in KB (64 MB)
    t: 3, // time cost (passes)
    p: 4, // parallelism (lanes)
    dkLen: 32, // output length in bytes (256-bit AES key)
  },
  MNEMONIC: {
    m: 65536, // 64 MB
    t: 3,
    p: 2,
    dkLen: 32,
  },
} as const;

export type ARGON2_PARAMS = (typeof ARGON2_PARAMS)[keyof typeof ARGON2_PARAMS];