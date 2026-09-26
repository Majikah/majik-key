export { MajikKeyBackup } from "./majik-key-backup";

export type { BackupSource, CreateBackupParams, ToZipOptions } from "./types";
export { BACKUP_FORMAT_VERSION } from "./types";

export {
  MajikKeyBackupError,
  MissingOptionalDependencyError,
  InvalidBackupJSONError,
  InvalidBackupPNGError,
  InvalidBackupZipError,
  BackupIntegrityMismatchError,
} from "./error";
