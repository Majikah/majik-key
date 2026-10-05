/** Salt rename safety: old "MajikMessage…" backups must still import; new ones use "MajikKey…". */
import { describe, it, expect } from "vitest";
import { MajikKey } from "../src/majik-key";
import {
  deriveKeyFromMnemonicArgon2,
  aesGcmEncrypt,
  generateRandomBytes,
  IV_LENGTH,
} from "../src/core/crypto/crypto-provider";
import {
  LEGACY_MAJIK_MNEMONIC_SALT,
  MAJIK_MNEMONIC_SALT,
  MAJIK_SALT,
  LEGACY_MAJIK_SALT,
  MAJIK_SIGNATURE_SEED,
  BACKUP_SALT_WRITE_VERSION,
} from "../src/core/crypto/constants";
import { arrayToBase64, utf8ToBase64, base64ToUtf8 } from "../src/core/utils";
import { deriveKeys } from "../src/core/keys/key-impls";
import { KeyId } from "../src/core/keys/key-id";
import { mnemonicToSeedSync } from "@scure/bip39";
import { fingerprintFromPublicRaw } from "../src/core/crypto/crypto-provider";
import V from "../vectors/legacy-v1.vectors.json";

const PASS = "Vector-Test-Passphrase-123!";
const enc = (s: string) => new TextEncoder().encode(s);

async function legacyArgonBackup() {
  const x = deriveKeys(new Uint8Array(mnemonicToSeedSync(V.mnemonic)), [
    KeyId.X25519,
  ]).get(KeyId.X25519)!;
  const key = await deriveKeyFromMnemonicArgon2(
    V.mnemonic,
    enc(LEGACY_MAJIK_MNEMONIC_SALT),
  );
  const iv = generateRandomBytes(IV_LENGTH);
  return utf8ToBase64(
    JSON.stringify({
      // exactly what 0.7 wrote: no backupSaltVersion
      id: V.fingerprint,
      iv: arrayToBase64(iv),
      ciphertext: arrayToBase64(aesGcmEncrypt(key, iv, x.secretKey)),
      publicKey: arrayToBase64(x.publicKey),
      fingerprint: fingerprintFromPublicRaw(x.publicKey),
      backupKdfVersion: 2,
    }),
  );
}

describe("constants", () => {
  it("names: new MajikKey salts, legacy kept, signature seed FROZEN", () => {
    expect(MAJIK_SALT).toBe("MajikKeySalt");
    expect(MAJIK_MNEMONIC_SALT).toBe("MajikKeyMnemonicSalt");
    expect(LEGACY_MAJIK_SALT).toBe("MajikMessageSalt");
    expect(LEGACY_MAJIK_MNEMONIC_SALT).toBe("MajikMessageMnemonicSalt");
    expect(MAJIK_SIGNATURE_SEED).toBe("MajikSignatureSeedDSA");
  });
});

describe("mnemonic backup salt generations", () => {
  it("new backups record the current salt generation and import", async () => {
    const k = await MajikKey.create(V.mnemonic, PASS);
    const parsed = JSON.parse(base64ToUtf8(k.backup));
    expect(parsed.backupSaltVersion).toBe(BACKUP_SALT_WRITE_VERSION);
    const re = await MajikKey.importFromMnemonicBackup(
      k.backup,
      V.mnemonic,
      PASS,
    );
    expect(re.fingerprint).toBe(V.fingerprint);
    await expect(
      MajikKey.importFromMnemonicBackup(
        k.backup,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        PASS,
      ),
    ).rejects.toThrow(/invalid mnemonic/);
  });
  it("a pre-0.8 backup (legacy 'MajikMessage…' salt, no version field) still imports", async () => {
    const old = await legacyArgonBackup();
    const re = await MajikKey.importFromMnemonicBackup(old, V.mnemonic, PASS);
    expect(re.fingerprint).toBe(V.fingerprint);
    expect(re.backup).toBe(old);
  });
  it("lying about the salt generation fails (no silent fallback)", async () => {
    const old = JSON.parse(base64ToUtf8(await legacyArgonBackup()));
    const forged = utf8ToBase64(
      JSON.stringify({ ...old, backupSaltVersion: 2 }),
    );
    await expect(
      MajikKey.importFromMnemonicBackup(forged, V.mnemonic, PASS),
    ).rejects.toThrow(/invalid mnemonic/);
  });
  it("legacy PBKDF2 backups (backupKdfVersion 1) still verify with the legacy salt", async () => {
    const x = deriveKeys(new Uint8Array(mnemonicToSeedSync(V.mnemonic)), [
      KeyId.X25519,
    ]).get(KeyId.X25519)!;
    const km = await crypto.subtle.importKey(
      "raw",
      enc(V.mnemonic),
      { name: "PBKDF2" },
      false,
      ["deriveKey"],
    );
    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: enc(LEGACY_MAJIK_MNEMONIC_SALT),
        iterations: 200_000,
        hash: "SHA-256",
      },
      km,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
    const iv = generateRandomBytes(IV_LENGTH);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv as BufferSource },
        key,
        x.secretKey as BufferSource,
      ),
    );
    const backup = utf8ToBase64(
      JSON.stringify({
        id: V.fingerprint,
        iv: arrayToBase64(iv),
        ciphertext: arrayToBase64(ct),
        publicKey: arrayToBase64(x.publicKey),
        fingerprint: V.fingerprint,
      }),
    );
    const re = await MajikKey.importFromMnemonicBackup(
      backup,
      V.mnemonic,
      PASS,
    );
    expect(re.fingerprint).toBe(V.fingerprint);
  });
});
