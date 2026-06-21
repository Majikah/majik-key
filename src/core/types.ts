import { MnemonicLanguage } from "./crypto/wordlist";

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
  kdfVersion?: number;
  mlKemPublicKey?: string;
  encryptedMlKemSecretKey?: string;

  edPublicKey?: string;
  encryptedEdSecretKey?: string;
  mlDsaPublicKey?: string;
  encryptedMlDsaSecretKey?: string;

  mnemonicLanguage?: MnemonicLanguage;
}

export interface MajikKeyMetadata {
  id: string;
  fingerprint: string;
  label: string;
  timestamp: Date;
  isLocked: boolean;
  kdfVersion: number;
  hasMlKem: boolean;
  mnemonicLanguage?: MnemonicLanguage;
}

export interface MnemonicJSON {
  seed: string[];
  id: string;
  phrase?: string;
}
