import type { KeyFamily, KeyId } from "./key-id";

export type KeyPurpose = "kem" | "key-agreement" | "signature" | "wallet";

/**
 * stable       — standardized or production-grade, safe to enable
 * experimental — works, but the spec/impl may change (ids stay, derivation may be versioned)
 * reserved     — id is claimed but cannot be enabled yet (no vetted impl / standard not final)
 * unsupported  — deliberately not offered (see `note`)
 */
export type KeyStatus = "stable" | "experimental" | "reserved" | "unsupported";

export interface KeyDerivation {
  /** "legacy-v1" (frozen pre-registry recipes) | "hkdf-sha512-v1" | "bip32" | "ed2curve" | "derived-view" */
  scheme: string;
  version: number;
  /** HKDF info string, e.g. "majik/v1/pq:ml-kem-1024". */
  info?: string;
  /** BIP-32 path for web3 keys. */
  path?: string;
  /** Free-form human note (e.g. "ed2curve(classic:ed25519)"). */
  note?: string;
}

/** One stored entry inside `MajikKeyJSON.keys`. No raw secret ever lives here. */
export interface KeyEntryJSON {
  id: KeyId;
  /** Base64 public key. */
  publicKey: string;
  /** Base64 AES-256-GCM (IV || ciphertext) under the account's passphrase-derived key. */
  encryptedSecretKey?: string;
  derivation: KeyDerivation;
  createdAt?: string;
}

export interface KeyAlgorithmDefinition {
  id: KeyId;
  family: KeyFamily;
  purpose: KeyPurpose;
  /** "stored" = encrypted at rest in `keys`; "derived" = computed on demand from another key. */
  kind: "stored" | "derived";
  status: KeyStatus;
  /** True once derive/encrypt/decrypt are wired up in the registry (phase 2+). */
  implemented: boolean;
  /** Standard / spec this follows. */
  standard: string;
  /** Recipe used when this key is derived for NEW accounts. Legacy accounts keep "legacy-v1". */
  derivation: KeyDerivation;
  /** For derived views: the stored key it is computed from. */
  derivedFrom?: KeyId;
  note?: string;
}
