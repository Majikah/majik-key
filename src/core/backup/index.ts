export { MajikKeyBackup } from "./majik-key-backup.js";

export type { BackupSource, CreateBackupParams, ToZipOptions } from "./types.js";
export { BACKUP_FORMAT_VERSION } from "./types.js";

export {
  MajikKeyBackupError,
  MissingOptionalDependencyError,
  InvalidBackupJSONError,
  InvalidBackupPNGError,
  InvalidBackupZipError,
  BackupIntegrityMismatchError,
} from "./error.js";
