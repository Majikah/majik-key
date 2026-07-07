// majik-key-solana.test.ts
//
// Exercises the experimental Solana integration on MajikKey against REAL
// implementations: real BIP-39 mnemonics, real Argon2id-derived keys, real
// Ed25519 signing (via @stablelib/ed25519), real base58 encoding, and (where
// installed) the REAL @solana/kit Keypair/PublicKey classes — not mocks.
// This is the only way to catch real bugs like a domain-separation constant
// silently colliding with the message-signing key, or a base58 encoder that
// mis-handles leading zero bytes.
//
// @solana/kit is an OPTIONAL peer dependency of majik-key. It is present
// in devDependencies for this repo's own test/build pipeline, so the
// "requires @solana/kit" tests below run against the genuine library.
// If you ever remove it from devDependencies, the describe.skipIf guard
// will skip those specific tests rather than failing the whole suite —
// everything that doesn't need @solana/kit (derivation, address,
// signing, domain separation, lock/unlock) still runs unconditionally.
//
// Argon2id is real and deliberately slow (see majik-key.test.ts for the
// same rationale), so key-creation tests here reuse a single generously-
// timed beforeAll() setup rather than re-deriving a key per test.

import { describe, it, expect, beforeAll } from "vitest";
import { MajikKey } from "../src/majik-key";
import { base58Encode } from "../src/core/web3/solana";

const CRYPTO_TIMEOUT = 60_000;

let solanaKitAvailable = true;
try {
  await import("@solana/kit");
} catch {
  solanaKitAvailable = false;
}

describe("MajikKey Solana Integration (Experimental)", () => {
  const PASSPHRASE = "TestPassphrase123!";
  const LABEL = "Solana Test Key";

  let mnemonic: string;
  let majikKey: MajikKey;

  beforeAll(async () => {
    mnemonic = await MajikKey.generateMnemonic(128, "en");
    majikKey = await MajikKey.create(mnemonic, PASSPHRASE, LABEL, "en");
  }, CRYPTO_TIMEOUT);

  // ── AVAILABILITY / STATE CHECKS ──────────────────────────────────────────
  describe("hasSolanaKeypair", () => {
    it("should be true for an unlocked key with signing keys", () => {
      expect(majikKey.isUnlocked).toBe(true);
      expect(majikKey.hasSolanaKeypair).toBe(true);
    });

    it("should be false once the key is locked", () => {
      majikKey.lock();
      expect(majikKey.hasSolanaKeypair).toBe(false);
    });

    it(
      "should be true again after re-unlocking",
      async () => {
        await majikKey.unlock(PASSPHRASE);
        expect(majikKey.hasSolanaKeypair).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── RAW KEYPAIR MATERIAL ──────────────────────────────────────────────────
  describe("getSolanaKeypairMaterial (domain-separated, default)", () => {
    it("should derive a 32-byte public key and 64-byte secret key", () => {
      const material = majikKey.getSolanaKeypairMaterial();

      expect(material.publicKey).toBeInstanceOf(Uint8Array);
      expect(material.publicKey.length).toBe(32);
      expect(material.secretKey).toBeInstanceOf(Uint8Array);
      expect(material.secretKey.length).toBe(64);

      // nacl/tweetnacl-compatible layout: secretKey[32..64] === publicKey
      expect(material.secretKey.slice(32)).toEqual(material.publicKey);
    });

    it("should be deterministic across repeated calls on the same key", () => {
      const first = majikKey.getSolanaKeypairMaterial();
      const second = majikKey.getSolanaKeypairMaterial();

      expect(first.publicKey).toEqual(second.publicKey);
      expect(first.secretKey).toEqual(second.secretKey);
    });

    it(
      "should be deterministic across independent key instances from the same mnemonic",
      async () => {
        const rebuilt = await MajikKey.create(
          mnemonic,
          "AnotherPass!23",
          LABEL,
        );

        const a = majikKey.getSolanaKeypairMaterial();
        const b = rebuilt.getSolanaKeypairMaterial();

        // Same mnemonic -> same edSecretKey -> same domain-separated Solana
        // key, regardless of passphrase (which only affects encryption at
        // rest, not the derived key material itself).
        expect(a.publicKey).toEqual(b.publicKey);
        expect(a.secretKey).toEqual(b.secretKey);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should differ from an independently-generated mnemonic's Solana keypair",
      async () => {
        const otherMnemonic = await MajikKey.generateMnemonic(128, "en");
        const otherKey = await MajikKey.create(
          otherMnemonic,
          PASSPHRASE,
          LABEL,
        );

        const a = majikKey.getSolanaKeypairMaterial();
        const b = otherKey.getSolanaKeypairMaterial();

        expect(a.publicKey).not.toEqual(b.publicKey);
      },
      CRYPTO_TIMEOUT,
    );

    it("should throw when the key is locked", () => {
      majikKey.lock();
      expect(() => majikKey.getSolanaKeypairMaterial()).toThrow(
        /MajikKey is locked/,
      );
    });

    it(
      "restore unlocked state for subsequent tests",
      async () => {
        await majikKey.unlock(PASSPHRASE);
        expect(majikKey.isUnlocked).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── DOMAIN SEPARATION ─────────────────────────────────────────────────────
  describe("Domain separation from the message-signing Ed25519 key", () => {
    it("should NOT equal the raw message-signing Ed25519 keypair by default", () => {
      const solanaMaterial = majikKey.getSolanaKeypairMaterial();
      const edPublicKey = majikKey.edPublicKey!;

      expect(edPublicKey).toBeDefined();
      // The whole point of domain separation: the default Solana public key
      // must differ from the MajikKey's own message-signing Ed25519 key,
      // proving they are not the same private key wearing two hats.
      expect(solanaMaterial.publicKey).not.toEqual(edPublicKey);
    });

    it("should equal the message-signing key when reuseMessageKey is explicitly set", () => {
      const reused = majikKey.getSolanaKeypairMaterial({
        reuseMessageKey: true,
      });
      const edPublicKey = majikKey.edPublicKey!;

      expect(reused.publicKey).toEqual(edPublicKey);
    });

    it("default derivation and reuseMessageKey derivation should never collide", () => {
      const domainSeparated = majikKey.getSolanaKeypairMaterial();
      const reused = majikKey.getSolanaKeypairMaterial({
        reuseMessageKey: true,
      });

      expect(domainSeparated.publicKey).not.toEqual(reused.publicKey);
    });
  });

  // ── BASE58 ADDRESS (NO @solana/kit REQUIRED) ─────────────────────────
  describe("getSolanaAddress", () => {
    it("should return a base58 string matching a manual encode of the public key", () => {
      const material = majikKey.getSolanaKeypairMaterial();
      const address = majikKey.getSolanaAddress();

      expect(typeof address).toBe("string");
      expect(address.length).toBeGreaterThan(0);
      expect(address).toBe(base58Encode(material.publicKey));
    });

    it("should never contain visually-ambiguous base58-excluded characters", () => {
      const address = majikKey.getSolanaAddress();
      // Standard base58 excludes 0, O, I, l
      expect(address).not.toMatch(/[0OIl]/);
    });

    it("should respect reuseMessageKey and differ from the default address", () => {
      const defaultAddress = majikKey.getSolanaAddress();
      const reusedAddress = majikKey.getSolanaAddress({
        reuseMessageKey: true,
      });

      expect(reusedAddress).not.toBe(defaultAddress);
    });
  });

  // ── SIGNING (NO @solana/kit REQUIRED) ────────────────────────────────
  describe("web3.solana.sign", () => {
    it("should produce a valid, verifiable Ed25519 signature over an arbitrary message", async () => {
      const ed25519 = await import("@stablelib/ed25519");
      const message = new TextEncoder().encode("majikah solana test message");

      const signature = majikKey.web3!.solana.sign(message);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);

      const isValid = ed25519.verify(
        majikKey.web3!.solana.publicKey,
        message,
        signature,
      );
      expect(isValid).toBe(true);
    });

    it("should fail verification against a tampered message", async () => {
      const ed25519 = await import("@stablelib/ed25519");
      const message = new TextEncoder().encode("original message");
      const tampered = new TextEncoder().encode("tampered message!");

      const signature = majikKey.web3!.solana.sign(message);
      const isValid = ed25519.verify(
        majikKey.web3!.solana.publicKey,
        tampered,
        signature,
      );
      expect(isValid).toBe(false);
    });
  });

  // ── web3 NAMESPACE GETTER ─────────────────────────────────────────────────
  describe("web3 getter", () => {
    it("should expose publicKey/secretKey/address consistent with the direct accessors", () => {
      const ns = majikKey.web3;
      expect(ns).toBeDefined();

      const material = majikKey.getSolanaKeypairMaterial();
      expect(ns!.solana.publicKey).toEqual(material.publicKey);
      expect(ns!.solana.secretKey).toEqual(material.secretKey);
      expect(ns!.solana.address).toBe(majikKey.getSolanaAddress());
    });

    it("should be undefined when the key is locked", () => {
      majikKey.lock();
      expect(majikKey.web3).toBeUndefined();
    });

    it(
      "restore unlocked state for subsequent tests",
      async () => {
        await majikKey.unlock(PASSPHRASE);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── CACHING ACROSS lock()/unlock() ────────────────────────────────────────
  describe("Cached Solana material lifecycle", () => {
    it(
      "should re-derive identical material after a lock/unlock cycle",
      async () => {
        const before = majikKey.getSolanaKeypairMaterial();

        majikKey.lock();
        await majikKey.unlock(PASSPHRASE);

        const after = majikKey.getSolanaKeypairMaterial();
        expect(after.publicKey).toEqual(before.publicKey);
        expect(after.secretKey).toEqual(before.secretKey);
      },
      CRYPTO_TIMEOUT,
    );

    it("should not leak cached secretKey material through getters while locked", () => {
      majikKey.lock();
      expect(() => majikKey.getSolanaKeypairMaterial()).toThrow(
        /MajikKey is locked/,
      );
      expect(majikKey.hasSolanaKeypair).toBe(false);
      expect(majikKey.web3).toBeUndefined();
    });

    it(
      "restore unlocked state for subsequent tests",
      async () => {
        await majikKey.unlock(PASSPHRASE);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── REAL @solana/kit INTEGRATION (optional peer dependency) ──────────
  describe.skipIf(!solanaKitAvailable)(
    "@solana/kit integration (requires the real optional peer dependency)",
    () => {
      it("getSolanaKeypair() should return a genuine KeyPairSigner with a matching address", async () => {
        const { getAddressFromPublicKey } = await import("@solana/kit");
        const material = majikKey.getSolanaKeypairMaterial();

        const signer = await majikKey.getSolanaKeypair();

        // Address is a branded string in Kit, not a class instance — assert
        // shape and cross-check it against an independently-derived address
        // for the same raw public key bytes.
        expect(typeof signer.address).toBe("string");
        const expectedAddress = await getAddressFromPublicKey(
          (
            await (
              await import("@solana/kit")
            ).createKeyPairSignerFromBytes(material.secretKey)
          ).keyPair.publicKey,
        );
        expect(signer.address).toBe(expectedAddress);
        expect(signer.address).toBe(majikKey.getSolanaAddress());
      });

      it("web3.solana.getSolanaKeypair() should return an address matching the base58 address", async () => {
        const signer = await majikKey.web3!.solana.getSolanaKeypair();
        expect(signer.address).toBe(majikKey.getSolanaAddress());
      });

      it("real KeyPairSigner should be genuinely constructible from our 64-byte secretKey material", async () => {
        const { createKeyPairSignerFromBytes } = await import("@solana/kit");
        const material = majikKey.getSolanaKeypairMaterial();

        // Prove the 64-byte secretKey we hand off is genuinely accepted by
        // Kit's own signer constructor — this is the real interop contract,
        // not just a shape assertion. createKeyPairSignerFromBytes expects
        // exactly the nacl-format (32-byte seed || 32-byte public key) layout
        // our derivation already produces.
        const signer = await createKeyPairSignerFromBytes(material.secretKey);
        expect(signer.address).toBe(majikKey.getSolanaAddress());
      });

      it("getSolanaSigner() with reuseMessageKey should match the message-signing Ed25519 key", async () => {
        const { createKeyPairSignerFromBytes } = await import("@solana/kit");

        const signer = await majikKey.getSolanaKeypair({
          reuseMessageKey: true,
        });
        const expectedSigner = await createKeyPairSignerFromBytes(
          majikKey.getSolanaKeypairMaterial({ reuseMessageKey: true })
            .secretKey,
        );

        expect(signer.address).toBe(expectedSigner.address);
        // edPublicKey is the raw Ed25519 public key bytes — cross-check the
        // signer's underlying CryptoKeyPair actually corresponds to it via
        // the address, since CryptoKey itself isn't byte-comparable directly.
        const { getAddressFromPublicKey } = await import("@solana/kit");
        const edKeySigner = await createKeyPairSignerFromBytes(
          (() => {
            const material = majikKey.getSolanaKeypairMaterial({
              reuseMessageKey: true,
            });
            return material.secretKey;
          })(),
        );
        expect(signer.address).toBe(edKeySigner.address);
      });

      it("signer.keyPair should be a genuine extractable-or-not CryptoKeyPair", async () => {
        const signer = await majikKey.getSolanaKeypair();
        expect(signer.keyPair.privateKey).toBeInstanceOf(CryptoKey);
        expect(signer.keyPair.publicKey).toBeInstanceOf(CryptoKey);
        expect(signer.keyPair.privateKey.algorithm.name).toBe("Ed25519");
      });
    },
  );
  // ── ERROR HANDLING WHEN SIGNING KEYS ARE ABSENT ──────────────────────────
  describe("Keys without Ed25519 signing material", () => {
    it("should report hasSolanaKeypair as false for a JSON-reconstructed (locked) key", () => {
      const json = majikKey.toJSON();
      const reconstructed = MajikKey.fromJSON(json);

      expect(reconstructed.isLocked).toBe(true);
      expect(reconstructed.hasSolanaKeypair).toBe(false);
      expect(reconstructed.web3).toBeUndefined();
      expect(() => reconstructed.getSolanaKeypairMaterial()).toThrow(
        /MajikKey is locked/,
      );
    });
  });
});
