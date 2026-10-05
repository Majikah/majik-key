/** Fast (no Argon2) tests for the Ethereum primitives + registry derivation. */
import { describe, it, expect } from "vitest";
import { mnemonicToSeedSync } from "@scure/bip39";
import { hash } from "@stablelib/sha256";
import { KeyId } from "../../src/core/keys/key-id";
import { deriveKeys } from "../../src/core/keys/key-impls";
import {
  ethereumAddressFromPublicKey,
  toChecksumAddress,
  hashEthereumMessage,
  signEthereumHash,
  signEthereumMessage,
  recoverEthereumAddress,
  toEthereumPrivateKeyHex,
} from "../../src/core/web3/ethereum/ethereum";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import V from "../../vectors/legacy-v1.vectors.json";

const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
const eth = () =>
  deriveKeys(new Uint8Array(mnemonicToSeedSync(V.mnemonic)), [KeyId.ETH]).get(
    KeyId.ETH,
  )!;
const N = secp256k1.Point.Fn.ORDER;

describe("web3:eth derivation (standard m/44'/60'/0'/0/0)", () => {
  it("matches the pinned vector and the well-known Hardhat/Anvil account 0", () => {
    const k = eth();
    expect(b64(k.publicKey)).toBe(V[KeyId.ETH].compressedPublicKey);
    expect(b64(hash(k.secretKey))).toBe(V[KeyId.ETH].secretKeySha256);
    expect(ethereumAddressFromPublicKey(k.publicKey)).toBe(
      V[KeyId.ETH].address,
    );
    expect(V[KeyId.ETH].address).toBe(
      "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    );
    expect(
      toEthereumPrivateKeyHex({
        privateKey: k.secretKey,
        publicKey: k.publicKey,
      }),
    ).toBe(
      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    ); // Hardhat account 0 key
  });
});

describe("address + EIP-55", () => {
  it("official EIP-55 checksum vectors", () => {
    for (const a of [
      "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
      "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
      "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
      "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ])
      expect(toChecksumAddress(a.slice(2).toLowerCase())).toBe(a);
  });
  it("private key 1 → 0x7E5F…5Bdf (well-known); accepts compressed and uncompressed pubkeys", () => {
    const sk = new Uint8Array(32);
    sk[31] = 1;
    expect(ethereumAddressFromPublicKey(secp256k1.getPublicKey(sk, true))).toBe(
      "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
    );
    expect(
      ethereumAddressFromPublicKey(secp256k1.getPublicKey(sk, false)),
    ).toBe("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    expect(() => ethereumAddressFromPublicKey(new Uint8Array(10))).toThrow(
      /33-byte/,
    );
  });
});

describe("signing", () => {
  const k = eth();
  const m = { privateKey: k.secretKey, publicKey: k.publicKey };
  const addr = V[KeyId.ETH].address;

  it("signHash: deterministic, low-s, v∈{27,28}, recovers to the signer", () => {
    const h = keccak_256(new TextEncoder().encode("majik"));
    const a = signEthereumHash(m, h),
      b = signEthereumHash(m, h);
    expect(a).toEqual(b);
    expect([27, 28]).toContain(a.v);
    expect(BigInt(a.s) <= N / 2n).toBe(true);
    expect(a.serialized).toHaveLength(2 + 130);
    expect(recoverEthereumAddress(h, a)).toBe(addr);
  });
  it("signMessage = EIP-191 personal_sign (recovers; prefix uses BYTE length)", () => {
    const sig = signEthereumMessage(m, "héllo");
    expect(recoverEthereumAddress(hashEthereumMessage("héllo"), sig)).toBe(
      addr,
    );
    const bytes = new TextEncoder().encode("héllo"); // 6 bytes, 5 chars
    const expected = keccak_256(
      new Uint8Array([
        ...new TextEncoder().encode("\x19Ethereum Signed Message:\n6"),
        ...bytes,
      ]),
    );
    expect(hashEthereumMessage("héllo")).toEqual(expected);
    expect(hashEthereumMessage(bytes)).toEqual(expected);
  });
  it("rejects non-32-byte hashes", () => {
    expect(() => signEthereumHash(m, new Uint8Array(31))).toThrow(/32-byte/);
  });
});
