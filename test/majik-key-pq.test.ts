import { describe, it, expect } from "vitest";
import { hash } from "@stablelib/sha256";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { MajikKey, KeyId, CORE_KEYS } from "../src/majik-key";
import H from "../vectors/hkdf-v1.vectors.json";

const PASS = "Vector-Test-Passphrase-123!";
const sha = (u: Uint8Array) => Buffer.from(hash(u)).toString("base64");
const EXTRA = [
  KeyId.ML_KEM_1024,
  KeyId.ML_DSA_65,
  KeyId.SLH_DSA_SHAKE_128F,
  KeyId.FALCON_512,
];

function assertPq(k: MajikKey, ids: KeyId[]) {
  for (const id of ids) {
    const v = (H as any)[id];
    expect(sha(k.getPublicKey(id))).toBe(v.publicKeySha256);
    expect(sha(k.getPrivateKey(id))).toBe(v.secretKeySha256);
  }
}

describe("new algorithms on MajikKey", () => {
  it("create({keys}) → pinned keys, canonical order, usable, JSON round-trip", async () => {
    const k = await MajikKey.create(H.mnemonic, PASS, "pq", { keys: EXTRA });
    expect(k.availableKeys({ family: "pq" })).toEqual([
      KeyId.ML_KEM_768,
      KeyId.ML_KEM_1024,
      KeyId.ML_DSA_65,
      KeyId.ML_DSA_87,
      KeyId.SLH_DSA_SHAKE_128F,
      KeyId.FALCON_512,
    ]);
    expect(k.hasKeys([...CORE_KEYS, ...EXTRA])).toBe(true);
    assertPq(k, EXTRA);

    const kem = k.getKeypair(KeyId.ML_KEM_1024);
    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(kem.public);
    expect(ml_kem1024.decapsulate(cipherText, kem.private)).toEqual(
      sharedSecret,
    );
    const dsa = k.getKeypair(KeyId.ML_DSA_65),
      msg = new TextEncoder().encode("hi");
    expect(
      ml_dsa65.verify(ml_dsa65.sign(msg, dsa.private), msg, dsa.public),
    ).toBe(true);
    expect(k.getKeypair(KeyId.FALCON_512).status).toBe("experimental");

    const json: any = k.toJSON({ legacy: false });
    expect(
      json.keys.find((e: any) => e.id === KeyId.ML_KEM_1024).derivation,
    ).toMatchObject({
      scheme: "hkdf-sha512-v1",
      info: "majik/v1/pq:ml-kem-1024",
    });
    const re = MajikKey.fromJSON(json);
    await re.unlock(PASS);
    assertPq(re, EXTRA);
    // the legacy flat fields never contain the new algorithms
    expect(Object.keys(k.toJSON() as any)).not.toContain("mlKemPublicKey1024");
  });

  it("addKeys adds new algorithms to an existing account and they persist", async () => {
    const k = await MajikKey.create(H.mnemonic, PASS);
    const added = await k.addKeys(
      [KeyId.ML_KEM_512, KeyId.ML_DSA_44, KeyId.ML_KEM_512],
      H.mnemonic,
      PASS,
    );
    expect(added).toEqual([KeyId.ML_KEM_512, KeyId.ML_DSA_44]);
    assertPq(k, added);
    k.lock();
    expect(() => k.getPrivateKey(KeyId.ML_KEM_512)).toThrow(/locked/);
    const re = MajikKey.fromJSON(k.toJSON());
    await re.unlock(PASS);
    assertPq(re, added);
    await re.updatePassphrase(PASS, "Another-Passphrase-789!");
    const re2 = MajikKey.fromJSON(re.toJSON({ legacy: false }));
    await re2.unlock("Another-Passphrase-789!");
    assertPq(re2, added);
  });
});
