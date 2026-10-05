/**
 * key-impls.ts — Phase 2b: derivation implementations for registry keys.
 *
 * Every function here takes the 64-byte BIP-39 seed and returns a keypair.
 * The "legacy-v1" recipes are FROZEN and deliberately inlined (domain strings,
 * paths) instead of imported from constants files, so a refactor of a
 * constants module can never silently change a derivation. They are pinned by
 * vectors/legacy-v1.vectors.json (test/key-impls.test.ts + test-vectors.test.ts).
 *
 * New algorithms (phase 4) register here with the "hkdf-sha512-v1" recipe.
 * Derived views (web3:sol) are NOT stored keys and are not listed here.
 */
import * as ed25519 from "@stablelib/ed25519/ed25519.js";
import ed2curve from "ed2curve";
import { hash } from "@stablelib/sha256/sha256.js";
import {
  ml_kem512,
  ml_kem768,
  ml_kem1024,
} from "@noble/post-quantum/ml-kem.js";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import {
  slh_dsa_sha2_128s,
  slh_dsa_sha2_128f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_256s,
  slh_dsa_sha2_256f,
  slh_dsa_shake_128s,
  slh_dsa_shake_128f,
  slh_dsa_shake_192s,
  slh_dsa_shake_192f,
  slh_dsa_shake_256s,
  slh_dsa_shake_256f,
} from "@noble/post-quantum/slh-dsa.js";
import { falcon512, falcon1024 } from "@noble/post-quantum/falcon.js";
import { deriveSeedHkdf } from "./hkdf-recipe.js";
import { HDKey } from "@scure/bip32/index.js";
import { MajikKeyError } from "../error.js";
import { KeyId } from "./key-id.js";

export interface DerivedKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}
export interface KeyImpl {
  id: KeyId;
  derive(seed64: Uint8Array): DerivedKeypair;
}

// ── frozen legacy-v1 recipe constants (do not "tidy" these) ──
const LEGACY_DSA_DOMAIN = "MajikSignatureSeedDSA";
const LEGACY_BTC_PATH = "m/84'/1971'/0'/0/0";
// Standard Ethereum path (SLIP-44 coin 60): MetaMask / Ledger / Trezor compatible.
const ETH_STANDARD_PATH = "m/44'/60'/0'/0/0";

function assertSeed(seed64: Uint8Array) {
  if (seed64.length !== 64)
    throw new MajikKeyError(
      `Expected the 64-byte BIP-39 seed, got ${seed64.length} bytes`,
    );
}

/** Ed25519 from seed[0..32]; X25519 is converted from this same keypair. */
function edFromSeed(seed64: Uint8Array) {
  return ed25519.generateKeyPairFromSeed(seed64.slice(0, 32));
}

const x25519Impl: KeyImpl = {
  id: KeyId.X25519,
  derive(seed64) {
    assertSeed(seed64);
    const ed = edFromSeed(seed64);
    const pk = ed2curve.convertPublicKey(ed.publicKey);
    const sk = ed2curve.convertSecretKey(ed.secretKey);
    if (!pk || !sk)
      throw new MajikKeyError(
        "Failed to convert derived Ed25519 keys to Curve25519",
      );
    return { publicKey: new Uint8Array(pk), secretKey: new Uint8Array(sk) };
  },
};

const ed25519Impl: KeyImpl = {
  id: KeyId.ED25519,
  derive(seed64) {
    assertSeed(seed64);
    const ed = edFromSeed(seed64);
    return { publicKey: ed.publicKey, secretKey: ed.secretKey }; // 32 / 64 bytes
  },
};

const mlKem768Impl: KeyImpl = {
  id: KeyId.ML_KEM_768,
  derive(seed64) {
    assertSeed(seed64);
    return ml_kem768.keygen(seed64); // full 64-byte seed (legacy-v1)
  },
};

const mlDsa87Impl: KeyImpl = {
  id: KeyId.ML_DSA_87,
  derive(seed64) {
    assertSeed(seed64);
    const domain = new TextEncoder().encode(LEGACY_DSA_DOMAIN);
    const input = new Uint8Array(seed64.length + domain.length);
    input.set(seed64, 0);
    input.set(domain, seed64.length);
    try {
      return ml_dsa87.keygen(hash(input)); // sha256(seed64 || domain) → 32-byte seed
    } finally {
      input.fill(0);
    }
  },
};

const btcImpl: KeyImpl = {
  id: KeyId.BTC,
  derive(seed64) {
    assertSeed(seed64);
    const child = HDKey.fromMasterSeed(seed64).derive(LEGACY_BTC_PATH);
    if (!child.privateKey || !child.publicKey)
      throw new MajikKeyError("Failed to derive Bitcoin keypair from seed");
    return {
      publicKey: child.publicKey.slice(),
      secretKey: child.privateKey.slice(),
    };
  },
};

const ethImpl: KeyImpl = {
  id: KeyId.ETH,
  derive(seed64) {
    assertSeed(seed64);
    const child = HDKey.fromMasterSeed(seed64).derive(ETH_STANDARD_PATH);
    if (!child.privateKey || !child.publicKey)
      throw new MajikKeyError("Failed to derive Ethereum keypair from seed");
    return {
      publicKey: child.publicKey.slice(),
      secretKey: child.privateKey.slice(),
    }; // 33 / 32 bytes
  },
};

// ── hkdf-sha512-v1 recipe (phase 4+) ─────────────────────────────────────────
// `seedLength` is FROZEN here on purpose (not read from the library): if a
// future noble release changed an algorithm's seed size, derivation would
// silently change. The guard below turns that into a loud error instead.
interface Keygen {
  lengths: { seed?: number };
  keygen(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
}
function hkdfImpl(id: KeyId, algo: Keygen, seedLength: number): KeyImpl {
  return {
    id,
    derive(seed64) {
      assertSeed(seed64);
      if (algo.lengths.seed !== seedLength)
        throw new MajikKeyError(
          `${id}: library seed length is ${algo.lengths.seed}, recipe expects ${seedLength}. Refusing to derive.`,
        );
      const seed = deriveSeedHkdf(seed64, id, seedLength);
      try {
        return algo.keygen(seed);
      } finally {
        seed.fill(0);
      }
    },
  };
}

const HKDF_IMPLS: KeyImpl[] = [
  hkdfImpl(KeyId.ML_KEM_512, ml_kem512 as unknown as Keygen, 64),
  hkdfImpl(KeyId.ML_KEM_1024, ml_kem1024 as unknown as Keygen, 64),
  hkdfImpl(KeyId.ML_DSA_44, ml_dsa44 as unknown as Keygen, 32),
  hkdfImpl(KeyId.ML_DSA_65, ml_dsa65 as unknown as Keygen, 32),
  hkdfImpl(KeyId.SLH_DSA_SHA2_128S, slh_dsa_sha2_128s as unknown as Keygen, 48),
  hkdfImpl(KeyId.SLH_DSA_SHA2_128F, slh_dsa_sha2_128f as unknown as Keygen, 48),
  hkdfImpl(KeyId.SLH_DSA_SHA2_192S, slh_dsa_sha2_192s as unknown as Keygen, 72),
  hkdfImpl(KeyId.SLH_DSA_SHA2_192F, slh_dsa_sha2_192f as unknown as Keygen, 72),
  hkdfImpl(KeyId.SLH_DSA_SHA2_256S, slh_dsa_sha2_256s as unknown as Keygen, 96),
  hkdfImpl(KeyId.SLH_DSA_SHA2_256F, slh_dsa_sha2_256f as unknown as Keygen, 96),
  hkdfImpl(
    KeyId.SLH_DSA_SHAKE_128S,
    slh_dsa_shake_128s as unknown as Keygen,
    48,
  ),
  hkdfImpl(
    KeyId.SLH_DSA_SHAKE_128F,
    slh_dsa_shake_128f as unknown as Keygen,
    48,
  ),
  hkdfImpl(
    KeyId.SLH_DSA_SHAKE_192S,
    slh_dsa_shake_192s as unknown as Keygen,
    72,
  ),
  hkdfImpl(
    KeyId.SLH_DSA_SHAKE_192F,
    slh_dsa_shake_192f as unknown as Keygen,
    72,
  ),
  hkdfImpl(
    KeyId.SLH_DSA_SHAKE_256S,
    slh_dsa_shake_256s as unknown as Keygen,
    96,
  ),
  hkdfImpl(
    KeyId.SLH_DSA_SHAKE_256F,
    slh_dsa_shake_256f as unknown as Keygen,
    96,
  ),
  // Falcon Round 3 (NOT FIPS 206) — experimental; ids are pq:falcon-*, not pq:fn-dsa-*
  hkdfImpl(KeyId.FALCON_512, falcon512 as unknown as Keygen, 48),
  hkdfImpl(KeyId.FALCON_1024, falcon1024 as unknown as Keygen, 48),
];

export const KEY_IMPLS: Readonly<Partial<Record<KeyId, KeyImpl>>> =
  Object.freeze({
    [KeyId.X25519]: x25519Impl,
    [KeyId.ED25519]: ed25519Impl,
    [KeyId.ML_KEM_768]: mlKem768Impl,
    [KeyId.ML_DSA_87]: mlDsa87Impl,
    [KeyId.BTC]: btcImpl,
    [KeyId.ETH]: ethImpl,
    ...Object.fromEntries(HKDF_IMPLS.map((i) => [i.id, i])),
  });

/** Derive the requested STORED keys from one BIP-39 seed. Caller zeroizes the seed. */
export function deriveKeys(
  seed64: Uint8Array,
  ids: readonly KeyId[],
): Map<KeyId, DerivedKeypair> {
  const out = new Map<KeyId, DerivedKeypair>();
  for (const id of ids) {
    const impl = KEY_IMPLS[id];
    if (!impl)
      throw new MajikKeyError(
        `No derivation implementation registered for "${id}"`,
      );
    out.set(id, impl.derive(seed64));
  }
  return out;
}
