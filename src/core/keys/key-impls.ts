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
import * as ed25519 from "@stablelib/ed25519";
import ed2curve from "ed2curve";
import { hash } from "@stablelib/sha256";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { HDKey } from "@scure/bip32";
import { MajikKeyError } from "../error";
import { KeyId } from "./key-id";

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

export const KEY_IMPLS: Readonly<Partial<Record<KeyId, KeyImpl>>> =
  Object.freeze({
    [KeyId.X25519]: x25519Impl,
    [KeyId.ED25519]: ed25519Impl,
    [KeyId.ML_KEM_768]: mlKem768Impl,
    [KeyId.ML_DSA_87]: mlDsa87Impl,
    [KeyId.BTC]: btcImpl,
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
