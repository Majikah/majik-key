// majik-key-bitcoin.test.ts
//
// Exercises the experimental Bitcoin integration on MajikKey against REAL
// implementations: real BIP-39 mnemonics, real Argon2id-derived keys, real
// BIP-32/BIP-84 HD derivation (via @scure/bip32), real secp256k1
// ECDSA/Schnorr signing (via @noble/curves), real WIF/base58check encoding,
// and (where installed) the REAL @scure/btc-signer for bech32 address
// derivation — not mocks. This is the only way to catch real bugs like the
// domain path colliding with the standard BIP-84 path, a WIF encoder
// mishandling the compression flag byte, or a Schnorr signature actually
// being verified against the wrong (33-byte vs x-only 32-byte) public key.
//
// @scure/btc-signer is an OPTIONAL peer dependency of majik-key, lazily
// loaded only for bech32 address derivation (loadBtcSigner() in
// core/web3/bitcoin.ts). If it isn't installed, the describe.skipIf guard
// below skips only the address-derivation tests — everything else
// (derivation, WIF, signing, domain separation, lock/unlock) still runs
// unconditionally since none of it touches @scure/btc-signer.
//
// Argon2id is real and deliberately slow (see majik-key.test.ts for the
// same rationale), so key-creation tests here reuse a single generously-
// timed beforeAll() setup rather than re-deriving a key per test.

import { describe, it, expect, beforeAll } from "vitest";
import { MajikKey } from "../src/majik-key";
import { base58Encode } from "../src/core/web3/utils";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";

const CRYPTO_TIMEOUT = 180_000;

let btcSignerAvailable = true;
try {
  await import("@scure/btc-signer");
} catch {
  btcSignerAvailable = false;
}

describe("MajikKey Bitcoin Integration (Experimental)", () => {
  const PASSPHRASE = "TestPassphrase123!";
  const LABEL = "Bitcoin Test Key";

  let mnemonic: string;
  let majikKey: MajikKey;

  beforeAll(async () => {
    mnemonic = await MajikKey.generateMnemonic(128, "en");
    majikKey = await MajikKey.create(mnemonic, PASSPHRASE, LABEL, {
      mnemonicLanguage: "en",
    });
  }, CRYPTO_TIMEOUT);

  // ── AVAILABILITY / STATE CHECKS ──────────────────────────────────────────
  describe("hasBitcoin vs hasBitcoinKeypair", () => {
    it("hasBitcoin should be true as soon as the key is created (public key only, no unlock required)", () => {
      expect(majikKey.hasBitcoin).toBe(true);
      expect(majikKey.btcPublicKey).toBeInstanceOf(Uint8Array);
      expect(majikKey.btcPublicKey?.length).toBe(33); // compressed secp256k1
    });

    it("hasBitcoin should remain true even after locking (it's the public key, not the secret)", () => {
      majikKey.lock();
      expect(majikKey.hasBitcoin).toBe(true);
    });

    it("hasBitcoinKeypair should be false once locked (requires the decrypted secret key)", () => {
      expect(majikKey.hasBitcoinKeypair).toBe(false);
    });

    it(
      "hasBitcoinKeypair should be true again after re-unlocking",
      async () => {
        await majikKey.unlock(PASSPHRASE);
        expect(majikKey.hasBitcoinKeypair).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── RAW KEYPAIR MATERIAL (DOMAIN-SEPARATED DEFAULT) ──────────────────────
  describe("getBitcoinKeypairMaterial (domain-separated, default)", () => {
    it("should derive a 32-byte private key and 33-byte compressed public key", () => {
      const material = majikKey.getBitcoinKeypairMaterial();

      expect(material.privateKey).toBeInstanceOf(Uint8Array);
      expect(material.privateKey.length).toBe(32);
      expect(material.publicKey).toBeInstanceOf(Uint8Array);
      expect(material.publicKey.length).toBe(33);
      // Compressed pubkey prefix must be 0x02 or 0x03
      expect([0x02, 0x03]).toContain(material.publicKey[0]);
    });

    it("the public key should be independently re-derivable from the private key via secp256k1", () => {
      const material = majikKey.getBitcoinKeypairMaterial();
      const recomputed = secp256k1.getPublicKey(material.privateKey, true);
      expect(recomputed).toEqual(material.publicKey);
    });

    it("should be deterministic across repeated calls on the same key", () => {
      const first = majikKey.getBitcoinKeypairMaterial();
      const second = majikKey.getBitcoinKeypairMaterial();

      expect(first.publicKey).toEqual(second.publicKey);
      expect(first.privateKey).toEqual(second.privateKey);
    });

    it(
      "should be deterministic across independent key instances from the same mnemonic",
      async () => {
        const rebuilt = await MajikKey.create(
          mnemonic,
          "AnotherPass!23",
          LABEL,
        );

        const a = majikKey.getBitcoinKeypairMaterial();
        const b = rebuilt.getBitcoinKeypairMaterial();

        // Same mnemonic -> same raw BIP-39 seed -> same BIP-32 derivation at
        // MAJIK_BITCOIN_DOMAIN_PATH, regardless of passphrase (which only
        // affects encryption at rest, not the derived key material itself).
        expect(a.publicKey).toEqual(b.publicKey);
        expect(a.privateKey).toEqual(b.privateKey);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should differ from an independently-generated mnemonic's Bitcoin keypair",
      async () => {
        const otherMnemonic = await MajikKey.generateMnemonic(128, "en");
        const otherKey = await MajikKey.create(
          otherMnemonic,
          PASSPHRASE,
          LABEL,
        );

        const a = majikKey.getBitcoinKeypairMaterial();
        const b = otherKey.getBitcoinKeypairMaterial();

        expect(a.publicKey).not.toEqual(b.publicKey);
        expect(a.privateKey).not.toEqual(b.privateKey);
      },
      CRYPTO_TIMEOUT,
    );

    it("should throw when the key is locked", () => {
      majikKey.lock();
      expect(() => majikKey.getBitcoinKeypairMaterial()).toThrow(
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

  // ── DOMAIN PATH vs STANDARD BIP-84 PATH ──────────────────────────────────
  describe("Domain-separated path vs the real standard BIP-84 path", () => {
    it("getBitcoinKeypairMaterial({ standard: true }) should throw and point to the dedicated static method", () => {
      expect(() =>
        majikKey.getBitcoinKeypairMaterial({ standard: true }),
      ).toThrow(/deriveStandardBitcoinFromMnemonic/);
    });

    it("getBitcoinKeypairMaterial({ path: <custom> }) should also throw (only the stored domain key is served here)", () => {
      expect(() =>
        majikKey.getBitcoinKeypairMaterial({ path: "m/84'/0'/0'/0/1" }),
      ).toThrow(/deriveStandardBitcoinFromMnemonic/);
    });

    it(
      "deriveStandardBitcoinFromMnemonic should return the REAL BIP-84 mainnet key, distinct from the domain-separated default",
      async () => {
        const standard =
          await MajikKey.deriveStandardBitcoinFromMnemonic(mnemonic);
        const domainSeparated = majikKey.getBitcoinKeypairMaterial();

        expect(standard.privateKey.length).toBe(32);
        expect(standard.publicKey.length).toBe(33);

        // The whole point of using two different BIP-32 branches: the
        // "real" wallet-recoverable key must differ from Majik's private
        // default, even though both come from the exact same mnemonic.
        expect(standard.publicKey).not.toEqual(domainSeparated.publicKey);
        expect(standard.privateKey).not.toEqual(domainSeparated.privateKey);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "deriveStandardBitcoinFromMnemonic should be deterministic for the same mnemonic",
      async () => {
        const a = await MajikKey.deriveStandardBitcoinFromMnemonic(mnemonic);
        const b = await MajikKey.deriveStandardBitcoinFromMnemonic(mnemonic);

        expect(a.publicKey).toEqual(b.publicKey);
        expect(a.privateKey).toEqual(b.privateKey);
      },
      CRYPTO_TIMEOUT,
    );

    it("deriveStandardBitcoinFromMnemonic should reject an invalid mnemonic", async () => {
      const badMnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

      await expect(
        MajikKey.deriveStandardBitcoinFromMnemonic(badMnemonic),
      ).rejects.toThrow();
    });
  });

  // ── WIF EXPORT (WALLET IMPORT FORMAT) ────────────────────────────────────
  describe("getBitcoinWIF", () => {
    it("should return a compressed WIF starting with 'K' or 'L' (mainnet, version 0x80 + compression flag)", () => {
      const wif = majikKey.getBitcoinWIF();

      expect(typeof wif).toBe("string");
      expect(wif.length).toBeGreaterThan(0);
      expect(wif[0]).toMatch(/[KL]/);
    });

    it("should return an uncompressed WIF starting with '5' when compressed: false", () => {
      const wif = majikKey.getBitcoinWIF({ compressed: false });
      expect(wif[0]).toBe("5");
    });

    it("compressed and uncompressed WIFs should differ for the same private key", () => {
      const compressed = majikKey.getBitcoinWIF({ compressed: true });
      const uncompressed = majikKey.getBitcoinWIF({ compressed: false });

      expect(compressed).not.toBe(uncompressed);
    });

    it("should be deterministic across repeated calls", () => {
      const first = majikKey.getBitcoinWIF();
      const second = majikKey.getBitcoinWIF();
      expect(first).toBe(second);
    });

    it("should never contain visually-ambiguous base58-excluded characters", () => {
      const wif = majikKey.getBitcoinWIF();
      // Standard base58 excludes 0, O, I, l
      expect(wif).not.toMatch(/[0OIl]/);
    });

    it("should match a manual base58check encoding of version || privateKey || compressionFlag", async () => {
      // Independent re-implementation of base58check to prove toWIF() isn't
      // just returning an opaque string — it must decode to the exact
      // version byte (0x80, mainnet) + the real 32-byte private key + the
      // 0x01 compression flag, with a valid double-SHA256 checksum.
      const { hash } = await import("@stablelib/sha256");
      const material = majikKey.getBitcoinKeypairMaterial();

      const payload = new Uint8Array(34);
      payload[0] = 0x80;
      payload.set(material.privateKey, 1);
      payload[33] = 0x01;
      const checksum = hash(hash(payload)).slice(0, 4);
      const full = new Uint8Array(38);
      full.set(payload, 0);
      full.set(checksum, 34);

      expect(majikKey.getBitcoinWIF()).toBe(base58Encode(full));
    });
  });

  // ── NATIVE SEGWIT ADDRESS (requires @scure/btc-signer) ───────────────────
  describe.skipIf(!btcSignerAvailable)(
    "getBitcoinAddress (requires the real optional peer dependency @scure/btc-signer)",
    () => {
      it("should return a bech32 'bc1...' native SegWit mainnet address", async () => {
        const material = majikKey.getBitcoinKeypairMaterial();
        const address = await toBitcoinAddressForTest(material);

        expect(address.startsWith("bc1")).toBe(true);
      });

      it("should be deterministic across repeated calls", async () => {
        const material = majikKey.getBitcoinKeypairMaterial();
        const a = await toBitcoinAddressForTest(material);
        const b = await toBitcoinAddressForTest(material);
        expect(a).toBe(b);
      });

      it("web3.bitcoin.getBitcoinAddress() should match the same address derived directly", async () => {
        const direct = await toBitcoinAddressForTest(
          majikKey.getBitcoinKeypairMaterial(),
        );
        const viaNamespace = await majikKey.web3!.bitcoin!.getBitcoinAddress();
        expect(viaNamespace).toBe(direct);
      });

      // Local helper mirroring core/web3/bitcoin.ts#toBitcoinAddress, since
      // that function isn't exported directly off MajikKey — this proves
      // the real @scure/btc-signer p2wpkh encoding is reachable and correct
      // for our derived compressed public key.
      async function toBitcoinAddressForTest(material: {
        publicKey: Uint8Array;
      }): Promise<string> {
        const btc = await import("@scure/btc-signer");
        const p2wpkh = btc.p2wpkh(material.publicKey);
        if (!p2wpkh.address) throw new Error("Failed to derive address");
        return p2wpkh.address;
      }
    },
  );

  // ── SIGNING: ECDSA (default) ─────────────────────────────────────────────
  describe("web3.bitcoin.sign — ECDSA (default scheme)", () => {
    it("should produce a valid, independently-verifiable ECDSA signature over a 32-byte hash", async () => {
      const { hash } = await import("@stablelib/sha256");
      const messageHash = hash(
        new TextEncoder().encode("majikah bitcoin test message"),
      );

      const signature = majikKey.web3!.bitcoin!.sign(messageHash);
      const isValid = secp256k1.verify(
        signature,
        messageHash,
        majikKey.web3!.bitcoin!.publicKey,
        { prehash: false },
      );
      expect(isValid).toBe(true);
    });

    it("should fail verification against a tampered hash", async () => {
      const { hash } = await import("@stablelib/sha256");
      const messageHash = hash(new TextEncoder().encode("original message"));
      const tamperedHash = hash(new TextEncoder().encode("tampered message!"));

      const signature = majikKey.web3!.bitcoin!.sign(messageHash);
      const isValid = secp256k1.verify(
        signature,
        tamperedHash,
        majikKey.web3!.bitcoin!.publicKey,
      );
      expect(isValid).toBe(false);
    });

    it("should fail verification against the wrong public key", async () => {
      const { hash } = await import("@stablelib/sha256");
      const messageHash = hash(new TextEncoder().encode("some message"));
      const otherMaterial =
        await MajikKey.deriveStandardBitcoinFromMnemonic(mnemonic);

      const signature = majikKey.web3!.bitcoin!.sign(messageHash);
      const isValid = secp256k1.verify(
        signature,
        messageHash,
        otherMaterial.publicKey,
      );
      expect(isValid).toBe(false);
    });
  });

  // ── SIGNING: SCHNORR (opt-in scheme) ─────────────────────────────────────
  describe("web3.bitcoin.sign — Schnorr (opt-in scheme)", () => {
    it("should produce a valid, independently-verifiable Schnorr (BIP-340) signature", async () => {
      const { hash } = await import("@stablelib/sha256");
      const messageHash = hash(
        new TextEncoder().encode("majikah taproot test message"),
      );

      const signature = majikKey.web3!.bitcoin!.sign(messageHash, "schnorr");
      // BIP-340 Schnorr verification uses the 32-byte x-only public key —
      // i.e. the compressed pubkey with its 0x02/0x03 prefix byte stripped.
      const xOnlyPublicKey = majikKey.web3!.bitcoin!.publicKey.slice(1);

      const isValid = schnorr.verify(signature, messageHash, xOnlyPublicKey);
      expect(isValid).toBe(true);
    });

    it("should fail verification against a tampered hash", async () => {
      const { hash } = await import("@stablelib/sha256");
      const messageHash = hash(new TextEncoder().encode("original"));
      const tamperedHash = hash(new TextEncoder().encode("tampered!!"));
      const xOnlyPublicKey = majikKey.web3!.bitcoin!.publicKey.slice(1);

      const signature = majikKey.web3!.bitcoin!.sign(messageHash, "schnorr");
      const isValid = schnorr.verify(signature, tamperedHash, xOnlyPublicKey);
      expect(isValid).toBe(false);
    });

    it("ECDSA and Schnorr signatures over the same hash should never be byte-identical", async () => {
      const { hash } = await import("@stablelib/sha256");
      const messageHash = hash(new TextEncoder().encode("dual-scheme test"));

      const ecdsaSig = majikKey.web3!.bitcoin!.sign(messageHash, "ecdsa");
      const schnorrSig = majikKey.web3!.bitcoin!.sign(messageHash, "schnorr");

      expect(ecdsaSig).not.toEqual(schnorrSig);
    });
  });

  // ── web3 NAMESPACE GETTER ─────────────────────────────────────────────────
  describe("web3.bitcoin namespace getter", () => {
    it("should expose publicKey/privateKey consistent with the direct accessor", () => {
      const ns = majikKey.web3;
      expect(ns).toBeDefined();
      expect(ns!.bitcoin).toBeDefined();

      const material = majikKey.getBitcoinKeypairMaterial();
      expect(ns!.bitcoin!.publicKey).toEqual(material.publicKey);
      expect(ns!.bitcoin!.privateKey).toEqual(material.privateKey);
    });

    it("should be undefined when the key is locked (web3 getter requires an unlocked Solana key first)", () => {
      majikKey.lock();
      expect(majikKey.web3).toBeUndefined();
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

  // ── CACHING / LIFECYCLE ACROSS lock() / unlock() ─────────────────────────
  describe("Bitcoin material lifecycle across lock/unlock", () => {
    it(
      "should re-derive identical material after a lock/unlock cycle (re-decrypted, not re-derived from scratch)",
      async () => {
        const before = majikKey.getBitcoinKeypairMaterial();

        // 1. Create hard copies of the bytes before locking
        const expectedPublicKey = new Uint8Array(before.publicKey);
        const expectedPrivateKey = new Uint8Array(before.privateKey);

        // 2. Lock the key (this safely zeroes out the original 'before' references)
        majikKey.lock();

        // 3. Unlock and generate fresh arrays
        await majikKey.unlock(PASSPHRASE);

        const after = majikKey.getBitcoinKeypairMaterial();

        // 4. Compare the newly derived arrays against your hard copies
        expect(after.publicKey).toEqual(expectedPublicKey);
        expect(after.privateKey).toEqual(expectedPrivateKey);
      },
      CRYPTO_TIMEOUT,
    );

    it("should not leak cached private key material through getters while locked", () => {
      majikKey.lock();
      expect(() => majikKey.getBitcoinKeypairMaterial()).toThrow(
        /MajikKey is locked/,
      );
      expect(() => majikKey.getBtcSecretKey()).toThrow(/MajikKey is locked/);
      expect(majikKey.hasBitcoinKeypair).toBe(false);
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

  // ── getBtcSecretKey ────────────────────────────────────────────────────────
  describe("getBtcSecretKey", () => {
    it("should return the same 32-byte private key exposed via getBitcoinKeypairMaterial", () => {
      const material = majikKey.getBitcoinKeypairMaterial();
      expect(majikKey.getBtcSecretKey()).toEqual(material.privateKey);
    });
  });

  // ── PASSPHRASE ROTATION SHOULD PRESERVE BITCOIN KEY MATERIAL ─────────────
  describe("updatePassphrase rotates Bitcoin encryption without changing the key itself", () => {
    it(
      "should decrypt to the identical Bitcoin keypair under the new passphrase",
      async () => {
        const before = majikKey.getBitcoinKeypairMaterial();
        const NEW_PASS = "RotatedPass!789";

        await majikKey.updatePassphrase(PASSPHRASE, NEW_PASS);
        majikKey.lock();
        await majikKey.unlock(NEW_PASS);

        const after = majikKey.getBitcoinKeypairMaterial();
        expect(after.publicKey).toEqual(before.publicKey);
        expect(after.privateKey).toEqual(before.privateKey);

        // Restore original passphrase so this test doesn't affect ordering
        // of any later re-run / dependent suites.
        await majikKey.updatePassphrase(NEW_PASS, PASSPHRASE);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── ERROR HANDLING WHEN BITCOIN MATERIAL IS ABSENT ───────────────────────
  describe("Keys without Bitcoin material", () => {
    it("should report hasBitcoin/hasBitcoinKeypair as false for a JSON-reconstructed (locked) key missing the public key field", () => {
      // fromJSON only carries btcPublicKey through if it was present in the
      // serialized JSON; toJSON() does include it, so simulate a legacy
      // pre-Bitcoin export by stripping the field.
      const json = majikKey.toJSON();
      delete (json as any).btcPublicKey;
      delete (json as any).encryptedBtcSecretKey;

      const reconstructed = MajikKey.fromJSON(json);

      expect(reconstructed.isLocked).toBe(true);
      expect(reconstructed.hasBitcoin).toBe(false);
      expect(reconstructed.hasBitcoinKeypair).toBe(false);
      expect(() => reconstructed.getBitcoinKeypairMaterial()).toThrow(
        /MajikKey is locked/,
      );
    });

    it(
      "should throw a distinct 're-import' error for an unlocked key that legitimately has no Bitcoin secret key",
      async () => {
        // A JSON round-trip preserves btcPublicKey but drops the raw secret
        // key by design (it's only ever held in memory or re-derived via
        // importFromMnemonicBackup). Unlocking a reconstructed key without
        // the encrypted blob present should surface the "re-import" guard
        // rather than silently returning nothing.
        const json = majikKey.toJSON();
        delete (json as any).encryptedBtcSecretKey;

        const reconstructed = MajikKey.fromJSON(json);
        await reconstructed.unlock(PASSPHRASE);

        expect(reconstructed.hasBitcoin).toBe(true); // public key still present
        expect(() => reconstructed.getBtcSecretKey()).toThrow(
          /re-import via importFromMnemonicBackup/,
        );
      },
      CRYPTO_TIMEOUT,
    );
  });
});
