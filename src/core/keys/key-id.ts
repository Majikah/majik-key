/**
 * key-id.ts
 * Namespaced identifiers for every key algorithm the MajikKey registry knows.
 * Format: "<family>:<name>". Adding an algorithm = one line here + one entry
 * in registry.ts. Existence of an id does NOT mean it is usable — see
 * `status` / `implemented` in registry.ts.
 */

export const KeyFamily = {
  CLASSIC: "classic",
  PQ: "pq",
  WEB3: "web3",
} as const;
export type KeyFamily = (typeof KeyFamily)[keyof typeof KeyFamily];

export const KeyId = {
  // ── classic ──
  X25519: "classic:x25519",
  ED25519: "classic:ed25519",

  // ── pq: KEM (FIPS 203) ──
  ML_KEM_512: "pq:ml-kem-512",
  ML_KEM_768: "pq:ml-kem-768",
  ML_KEM_1024: "pq:ml-kem-1024",

  // ── pq: KEM (HQC — NIST backup KEM, not yet final; no vetted JS impl) ──
  HQC_128: "pq:hqc-128",
  HQC_192: "pq:hqc-192",
  HQC_256: "pq:hqc-256",

  // ── pq: signatures (FIPS 204) ──
  ML_DSA_44: "pq:ml-dsa-44",
  ML_DSA_65: "pq:ml-dsa-65",
  ML_DSA_87: "pq:ml-dsa-87",

  // ── pq: signatures (FIPS 205, stateless hash-based) ──
  SLH_DSA_SHA2_128S: "pq:slh-dsa-sha2-128s",
  SLH_DSA_SHA2_128F: "pq:slh-dsa-sha2-128f",
  SLH_DSA_SHA2_192S: "pq:slh-dsa-sha2-192s",
  SLH_DSA_SHA2_192F: "pq:slh-dsa-sha2-192f",
  SLH_DSA_SHA2_256S: "pq:slh-dsa-sha2-256s",
  SLH_DSA_SHA2_256F: "pq:slh-dsa-sha2-256f",
  SLH_DSA_SHAKE_128S: "pq:slh-dsa-shake-128s",
  SLH_DSA_SHAKE_128F: "pq:slh-dsa-shake-128f",
  SLH_DSA_SHAKE_192S: "pq:slh-dsa-shake-192s",
  SLH_DSA_SHAKE_192F: "pq:slh-dsa-shake-192f",
  SLH_DSA_SHAKE_256S: "pq:slh-dsa-shake-256s",
  SLH_DSA_SHAKE_256F: "pq:slh-dsa-shake-256f",

  // ── pq: Falcon Round 3 (what libraries ship today) ──
  FALCON_512: "pq:falcon-512",
  FALCON_1024: "pq:falcon-1024",

  // ── pq: FN-DSA (FIPS 206) — RESERVED until the standard is final ──
  FN_DSA_512: "pq:fn-dsa-512",
  FN_DSA_1024: "pq:fn-dsa-1024",

  // ── pq: stateful hash-based (NIST SP 800-208) — NOT SUPPORTED, see registry ──
  LMS: "pq:lms",

  // ── web3 ──
  BTC: "web3:btc", // Majik domain-separated path (legacy default)
  ETH: "web3:eth", // standard BIP-44 m/44'/60'/0'/0/0
  SOL: "web3:sol", // derived view over classic:ed25519
} as const;
export type KeyId = (typeof KeyId)[keyof typeof KeyId];

/** Keys every account must hold from this version on (backward-compat baseline). */
export const CORE_KEYS = [
  KeyId.X25519,
  KeyId.ED25519,
  KeyId.ML_KEM_768,
  KeyId.ML_DSA_87,
] as const satisfies readonly KeyId[];

export function keyFamilyOf(id: KeyId): KeyFamily {
  return id.split(":")[0] as KeyFamily;
}
