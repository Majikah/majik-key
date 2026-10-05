/**
 * hkdf-recipe.ts — the "hkdf-sha512-v1" derivation recipe for every key
 * added AFTER the registry (phase 4+). Frozen once released: changing any
 * constant here changes every key derived with it. Pinned by
 * vectors/hkdf-v1.vectors.json.
 *
 *   seed_k = HKDF-SHA512( ikm  = 64-byte BIP-39 seed,
 *                         salt = "MajikKey/hkdf-sha512/v1",
 *                         info = "majik/v1/<namespaced key id>",
 *                         L    = the algorithm's seed length )
 *
 * Domain separation is by `info`, so no two algorithms (or parameter sets of
 * the same algorithm) ever receive related seed material, and adding a new
 * algorithm can never change an existing key.
 */
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { MajikKeyError } from "../error.js";
import type { KeyId } from "./key-id.js";

export const HKDF_SALT = "MajikKey/hkdf-sha512/v1";
export const hkdfInfo = (id: KeyId) => `majik/v1/${id}`;

export function deriveSeedHkdf(
  seed64: Uint8Array,
  id: KeyId,
  length: number,
): Uint8Array {
  if (seed64.length !== 64)
    throw new MajikKeyError(
      `Expected the 64-byte BIP-39 seed, got ${seed64.length} bytes`,
    );
  const enc = new TextEncoder();
  return hkdf(
    sha512,
    seed64,
    enc.encode(HKDF_SALT),
    enc.encode(hkdfInfo(id)),
    length,
  );
}
