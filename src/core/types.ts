export type ISODateString = string;

export type MajikMessageAccountID = string;

export type MajikMessagePublicKey = string;

export type MajikMessageChatID = string;

export interface MajikKeyJSON {
  id: string;
  label: string;
  publicKey: string; // base64
  fingerprint: string;
  encryptedPrivateKey: string; // base64
  salt: string; // base64
  backup: string; // base64
  timestamp: string; // ISO 8601
  kdfVersion?: number; // undefined → treated as v1 (PBKDF2) for legacy accounts
  mlKemPublicKey?: string;
  encryptedMlKemSecretKey?: string;
}

export interface MajikKeyMetadata {
  id: string;
  fingerprint: string;
  label: string;
  timestamp: Date;
  isLocked: boolean;
  kdfVersion: number;
  hasMlKem: boolean;
}

export interface MnemonicJSON {
  seed: string[];
  id: string;
  phrase?: string;
}
