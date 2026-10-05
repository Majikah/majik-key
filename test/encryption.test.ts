import { describe, it, expect } from "vitest";
import { hash } from "@stablelib/sha256";
import {
  EncryptionEngine,
  CryptoError,
} from "../src/core/crypto/encryption-engine";
import V from "../vectors/legacy-v1.vectors.json";
const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
const sha = (u: Uint8Array) => b64(hash(u));

describe("EncryptionEngine delegates to the registry with identical output", () => {
  it("matches every legacy-v1 vector and keeps the {type, raw} wrapper shape", async () => {
    const i: any = await EncryptionEngine.deriveIdentityFromMnemonic(
      V.mnemonic,
    );
    expect(i.fingerprint).toBe(V.fingerprint);
    expect(b64(i.publicKey.raw)).toBe(V["classic:x25519"].publicKey);
    expect(i.publicKey.type).toBe("public");
    expect(i.privateKey.type).toBe("private");
    expect(sha(i.privateKey.raw)).toBe(V["classic:x25519"].secretKeySha256);
    expect(b64(i.edPublicKey)).toBe(V["classic:ed25519"].publicKey);
    expect(sha(i.edSecretKey)).toBe(V["classic:ed25519"].secretKeySha256);
    expect(sha(i.mlKemPublicKey)).toBe(V["pq:ml-kem-768"].publicKeySha256);
    expect(sha(i.mlKemSecretKey)).toBe(V["pq:ml-kem-768"].secretKeySha256);
    expect(sha(i.mlDsaPublicKey)).toBe(V["pq:ml-dsa-87"].publicKeySha256);
    expect(sha(i.mlDsaSecretKey)).toBe(V["pq:ml-dsa-87"].secretKeySha256);
  });
  it("rejects empty mnemonics", async () => {
    await expect(
      EncryptionEngine.deriveIdentityFromMnemonic("  "),
    ).rejects.toThrow(CryptoError);
  });
});
