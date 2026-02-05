import { validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

/* -------------------------------
 * Validators
 * ------------------------------- */

import { MajikKeyError } from "./error";
import { MajikKeyJSON } from "./types";

export class MajikKeyValidator {
  static validateMnemonic(mnemonic: string): void {
    if (!mnemonic || typeof mnemonic !== "string") {
      throw new MajikKeyError("Mnemonic must be a non-empty string");
    }

    const trimmed = mnemonic.trim();
    if (!trimmed) {
      throw new MajikKeyError("Mnemonic cannot be empty or whitespace");
    }

    if (!validateMnemonic(trimmed, wordlist)) {
      throw new MajikKeyError("Invalid BIP39 mnemonic phrase");
    }
  }

  static validatePassphrase(
    passphrase: string,
    fieldName = "Passphrase",
  ): void {
    if (!passphrase || typeof passphrase !== "string") {
      throw new MajikKeyError(`${fieldName} must be a non-empty string`);
    }

    if (!passphrase.trim()) {
      throw new MajikKeyError(`${fieldName} cannot be empty or whitespace`);
    }
  }

  static validateLabel(label: string | undefined): void {
    if (label !== undefined && typeof label !== "string") {
      throw new MajikKeyError("Label must be a string if provided");
    }
  }

  static validateId(id: string): void {
    if (!id || typeof id !== "string") {
      throw new MajikKeyError("ID must be a non-empty string");
    }

    if (!id.trim()) {
      throw new MajikKeyError("ID cannot be empty or whitespace");
    }
  }

  static validateJSON(json: unknown): MajikKeyJSON {
    if (!json || typeof json !== "object") {
      throw new MajikKeyError("Invalid JSON: must be an object");
    }

    const obj = json as any;

    if (!obj.id || typeof obj.id !== "string") {
      throw new MajikKeyError("Invalid JSON: missing or invalid 'id' field");
    }

    if (!obj.publicKey || typeof obj.publicKey !== "string") {
      throw new MajikKeyError(
        "Invalid JSON: missing or invalid 'publicKey' field",
      );
    }

    if (!obj.fingerprint || typeof obj.fingerprint !== "string") {
      throw new MajikKeyError(
        "Invalid JSON: missing or invalid 'fingerprint' field",
      );
    }

    if (
      !obj.encryptedPrivateKey ||
      typeof obj.encryptedPrivateKey !== "string"
    ) {
      throw new MajikKeyError(
        "Invalid JSON: missing or invalid 'encryptedPrivateKey' field",
      );
    }

    if (!obj.salt || typeof obj.salt !== "string") {
      throw new MajikKeyError("Invalid JSON: missing or invalid 'salt' field");
    }

    if (!obj.backup || typeof obj.backup !== "string") {
      throw new MajikKeyError(
        "Invalid JSON: missing or invalid 'backup' field",
      );
    }

    if (!obj.timestamp || typeof obj.timestamp !== "string") {
      throw new MajikKeyError(
        "Invalid JSON: missing or invalid 'timestamp' field",
      );
    }

    if (obj.label !== undefined && typeof obj.label !== "string") {
      throw new MajikKeyError(
        "Invalid JSON: 'label' must be a string if provided",
      );
    }

    return obj as MajikKeyJSON;
  }

  static assert(condition: unknown, message: string): asserts condition {
    if (!condition) throw new Error(message);
  }

  static assertString(value: unknown, field: string): asserts value is string {
    this.assert(
      typeof value === "string" && value.trim().length > 0,
      `${field} must be a non-empty string`,
    );
  }
}
