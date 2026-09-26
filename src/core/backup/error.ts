/**
 * All errors this module throws. Typed so callers can branch on
 * `instanceof` instead of string-matching `.message` — and so every
 * failure is loud and specific rather than a generic Error/undefined.
 */
export class MajikKeyBackupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

/** An optional peer dependency (jszip, @majikah/majik-bytes) wasn't resolvable at runtime. */
export class MissingOptionalDependencyError extends MajikKeyBackupError {
  constructor(pkg: string, feature: string) {
    super(
      `"${pkg}" is required to ${feature}. Install it with \`npm install ${pkg}\`.`,
    );
  }
}

/** A JSON payload (bare, or decoded from a PNG/zip) failed shape validation. */
export class InvalidBackupJSONError extends MajikKeyBackupError {
  constructor(reason: string) {
    super(`Invalid backup JSON: ${reason}`);
  }
}

/** A PNG file wasn't a valid MajikByte, or its decoded payload wasn't a valid backup. */
export class InvalidBackupPNGError extends MajikKeyBackupError {
  constructor(reason: string) {
    super(`Invalid backup PNG: ${reason}`);
  }
}

/** A .zip archive contained no valid backup.png or backup.json anywhere inside it. */
export class InvalidBackupZipError extends MajikKeyBackupError {
  constructor(reason: string) {
    super(`Invalid backup archive: ${reason}`);
  }
}

/** A zip contained both a valid PNG backup and a valid JSON backup, but they describe different accounts. */
export class BackupIntegrityMismatchError extends MajikKeyBackupError {
  constructor(details: string) {
    super(`Backup archive contains conflicting payloads: ${details}`);
  }
}