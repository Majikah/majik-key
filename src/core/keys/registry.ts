/**
 * registry.ts — Phase 1 skeleton: DEFINITIONS ONLY (no derive/encrypt yet).
 * Phase 2 attaches derive()/publicFromSecret() implementations to each entry.
 */
import { MajikKeyError } from "../error.js";
import { CORE_KEYS, KeyFamily, KeyId, keyFamilyOf } from "./key-id.js";
import type {
  KeyAlgorithmDefinition,
  KeyDerivation,
  KeyPurpose,
  KeyStatus,
} from "./types.js";

const hkdf = (id: KeyId): KeyDerivation => ({
  scheme: "hkdf-sha512-v1",
  version: 1,
  info: `majik/v1/${id}`,
});
const legacy = (note?: string): KeyDerivation => ({
  scheme: "legacy-v1",
  version: 1,
  note,
});

function def(
  id: KeyId,
  purpose: KeyPurpose,
  standard: string,
  derivation: KeyDerivation,
  opts: Partial<
    Pick<
      KeyAlgorithmDefinition,
      "kind" | "status" | "implemented" | "derivedFrom" | "note"
    >
  > = {},
): KeyAlgorithmDefinition {
  return {
    id,
    family: keyFamilyOf(id),
    purpose,
    kind: opts.kind ?? "stored",
    status: opts.status ?? "stable",
    implemented: opts.implemented ?? false,
    standard,
    derivation,
    derivedFrom: opts.derivedFrom,
    note: opts.note,
  };
}

const SLH = (id: KeyId, variant: string) =>
  def(id, "signature", `FIPS 205 (${variant})`, hkdf(id), {
    implemented: true,
  });

export const KEY_ALGORITHMS: Readonly<Record<KeyId, KeyAlgorithmDefinition>> =
  Object.freeze({
    // ── classic ── (legacy recipes are frozen; see vectors/legacy-v1.vectors.json)
    [KeyId.X25519]: def(
      KeyId.X25519,
      "key-agreement",
      "RFC 7748",
      {
        scheme: "ed2curve",
        version: 1,
        note: "ed2curve(classic:ed25519); account id/fingerprint anchor",
      },
      { implemented: true },
    ),
    [KeyId.ED25519]: def(
      KeyId.ED25519,
      "signature",
      "RFC 8032",
      legacy("BIP-39 seed[0..32]"),
      { implemented: true },
    ),

    // ── pq KEM ──
    [KeyId.ML_KEM_512]: def(
      KeyId.ML_KEM_512,
      "kem",
      "FIPS 203",
      hkdf(KeyId.ML_KEM_512),
      { implemented: true },
    ),
    [KeyId.ML_KEM_768]: def(
      KeyId.ML_KEM_768,
      "kem",
      "FIPS 203",
      legacy("full 64-byte BIP-39 seed"),
      { implemented: true },
    ),
    [KeyId.ML_KEM_1024]: def(
      KeyId.ML_KEM_1024,
      "kem",
      "FIPS 203",
      hkdf(KeyId.ML_KEM_1024),
      { implemented: true },
    ),

    [KeyId.HQC_128]: def(
      KeyId.HQC_128,
      "kem",
      "NIST HQC (draft)",
      hkdf(KeyId.HQC_128),
      {
        status: "reserved",
        note: "NIST backup KEM; standard not final and no vetted JS implementation in the current dependency set.",
      },
    ),
    [KeyId.HQC_192]: def(
      KeyId.HQC_192,
      "kem",
      "NIST HQC (draft)",
      hkdf(KeyId.HQC_192),
      { status: "reserved", note: "See pq:hqc-128." },
    ),
    [KeyId.HQC_256]: def(
      KeyId.HQC_256,
      "kem",
      "NIST HQC (draft)",
      hkdf(KeyId.HQC_256),
      { status: "reserved", note: "See pq:hqc-128." },
    ),

    // ── pq signatures ──
    [KeyId.ML_DSA_44]: def(
      KeyId.ML_DSA_44,
      "signature",
      "FIPS 204",
      hkdf(KeyId.ML_DSA_44),
      { implemented: true },
    ),
    [KeyId.ML_DSA_65]: def(
      KeyId.ML_DSA_65,
      "signature",
      "FIPS 204",
      hkdf(KeyId.ML_DSA_65),
      { implemented: true },
    ),
    [KeyId.ML_DSA_87]: def(
      KeyId.ML_DSA_87,
      "signature",
      "FIPS 204",
      legacy('sha256(seed64 || "MajikSignatureSeedDSA")'),
      { implemented: true },
    ),

    [KeyId.SLH_DSA_SHA2_128S]: SLH(KeyId.SLH_DSA_SHA2_128S, "SHA2-128s"),
    [KeyId.SLH_DSA_SHA2_128F]: SLH(KeyId.SLH_DSA_SHA2_128F, "SHA2-128f"),
    [KeyId.SLH_DSA_SHA2_192S]: SLH(KeyId.SLH_DSA_SHA2_192S, "SHA2-192s"),
    [KeyId.SLH_DSA_SHA2_192F]: SLH(KeyId.SLH_DSA_SHA2_192F, "SHA2-192f"),
    [KeyId.SLH_DSA_SHA2_256S]: SLH(KeyId.SLH_DSA_SHA2_256S, "SHA2-256s"),
    [KeyId.SLH_DSA_SHA2_256F]: SLH(KeyId.SLH_DSA_SHA2_256F, "SHA2-256f"),
    [KeyId.SLH_DSA_SHAKE_128S]: SLH(KeyId.SLH_DSA_SHAKE_128S, "SHAKE-128s"),
    [KeyId.SLH_DSA_SHAKE_128F]: SLH(KeyId.SLH_DSA_SHAKE_128F, "SHAKE-128f"),
    [KeyId.SLH_DSA_SHAKE_192S]: SLH(KeyId.SLH_DSA_SHAKE_192S, "SHAKE-192s"),
    [KeyId.SLH_DSA_SHAKE_192F]: SLH(KeyId.SLH_DSA_SHAKE_192F, "SHAKE-192f"),
    [KeyId.SLH_DSA_SHAKE_256S]: SLH(KeyId.SLH_DSA_SHAKE_256S, "SHAKE-256s"),
    [KeyId.SLH_DSA_SHAKE_256F]: SLH(KeyId.SLH_DSA_SHAKE_256F, "SHAKE-256f"),

    [KeyId.FALCON_512]: def(
      KeyId.FALCON_512,
      "signature",
      "Falcon (NIST PQC Round 3)",
      hkdf(KeyId.FALCON_512),
      {
        status: "experimental",
        implemented: true,
        note: "Round 3 Falcon, NOT FIPS 206. FN-DSA is expected to be incompatible; it will get its own ids.",
      },
    ),
    [KeyId.FALCON_1024]: def(
      KeyId.FALCON_1024,
      "signature",
      "Falcon (NIST PQC Round 3)",
      hkdf(KeyId.FALCON_1024),
      { status: "experimental", implemented: true, note: "See pq:falcon-512." },
    ),
    [KeyId.FN_DSA_512]: def(
      KeyId.FN_DSA_512,
      "signature",
      "FIPS 206 (draft)",
      hkdf(KeyId.FN_DSA_512),
      {
        status: "reserved",
        note: "Reserved until FIPS 206 is final and an implementation tracks it.",
      },
    ),
    [KeyId.FN_DSA_1024]: def(
      KeyId.FN_DSA_1024,
      "signature",
      "FIPS 206 (draft)",
      hkdf(KeyId.FN_DSA_1024),
      { status: "reserved", note: "See pq:fn-dsa-512." },
    ),

    [KeyId.LMS]: def(
      KeyId.LMS,
      "signature",
      "NIST SP 800-208 / RFC 8554",
      hkdf(KeyId.LMS),
      {
        status: "unsupported",
        note:
          "Stateful: every signature consumes a one-time key index. Mnemonic recovery, backups and multi-device use " +
          "all reset that state and make one-time-key reuse (total forgery) likely. Not offered as a stored signing key.",
      },
    ),

    // ── web3 ──
    [KeyId.BTC]: def(
      KeyId.BTC,
      "wallet",
      "BIP-32 / BIP-84",
      {
        scheme: "bip32",
        version: 1,
        path: "m/84'/1971'/0'/0/0",
        note: "Majik domain-separated path (legacy default)",
      },
      { implemented: true },
    ),
    [KeyId.ETH]: def(
      KeyId.ETH,
      "wallet",
      "BIP-32 / BIP-44 (SLIP-44 coin 60)",
      {
        scheme: "bip32",
        version: 1,
        path: "m/44'/60'/0'/0/0",
        note: "Standard path: MetaMask-compatible",
      },
      { implemented: true },
    ),
    [KeyId.SOL]: def(
      KeyId.SOL,
      "wallet",
      "Ed25519 (Solana)",
      {
        scheme: "derived-view",
        version: 1,
        note: 'sha256(edSeed || "MajikKeySolanaSeed")',
      },
      { kind: "derived", derivedFrom: KeyId.ED25519, implemented: true },
    ),
  });

const ORDER = Object.keys(KEY_ALGORITHMS) as KeyId[];

export function getAlgorithm(id: string): KeyAlgorithmDefinition | undefined {
  return (KEY_ALGORITHMS as Record<string, KeyAlgorithmDefinition>)[id];
}

/** Everything the registry knows, in canonical order (includes reserved/unsupported). */
export function knownKeyIds(family?: KeyFamily): KeyId[] {
  return family ? ORDER.filter((id) => keyFamilyOf(id) === family) : [...ORDER];
}

/** Ids that can actually be enabled today. */
export function enableableKeyIds(): KeyId[] {
  return ORDER.filter((id) => {
    const d = KEY_ALGORITHMS[id];
    return (
      d.implemented && (d.status === "stable" || d.status === "experimental")
    );
  });
}

/**
 * Validate a caller's `keys` option and return the STORED key ids to create:
 * CORE_KEYS ∪ requested, de-duplicated, canonical order. Derived views
 * (e.g. web3:sol) are accepted as no-ops because they require a stored key
 * that is already in the core set.
 */
export function resolveRequestedKeys(
  requested: readonly string[] = [],
): KeyId[] {
  const stored = new Set<KeyId>(CORE_KEYS);
  for (const raw of requested) {
    const d = getAlgorithm(raw);
    if (!d) throw new MajikKeyError(`Unknown key algorithm "${raw}"`);
    if (d.status === "unsupported")
      throw new MajikKeyError(`"${raw}" is not supported: ${d.note}`);
    if (d.status === "reserved")
      throw new MajikKeyError(
        `"${raw}" is reserved and cannot be enabled yet: ${d.note}`,
      );
    if (!d.implemented)
      throw new MajikKeyError(
        `"${raw}" is defined but not implemented in this version`,
      );
    if (d.kind === "derived") {
      if (d.derivedFrom) stored.add(d.derivedFrom);
      continue;
    }
    stored.add(d.id);
  }
  return ORDER.filter((id) => stored.has(id));
}

export type { KeyStatus };
