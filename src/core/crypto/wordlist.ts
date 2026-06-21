export type MnemonicLanguage =
  | "en"
  | "fr"
  | "es"
  | "it"
  | "ja"
  | "ko"
  | "czech"
  | "pt"
  | "zh-cn"
  | "zh-tw";

export const WORDLISTS = {
  en: () => import("@scure/bip39/wordlists/english.js"),
  fr: () => import("@scure/bip39/wordlists/french.js"),
  es: () => import("@scure/bip39/wordlists/spanish.js"),
  it: () => import("@scure/bip39/wordlists/italian.js"),
  ja: () => import("@scure/bip39/wordlists/japanese.js"),
  ko: () => import("@scure/bip39/wordlists/korean.js"),
  pt: () => import("@scure/bip39/wordlists/portuguese.js"),
  czech: () => import("@scure/bip39/wordlists/czech.js"),
  "zh-cn": () => import("@scure/bip39/wordlists/simplified-chinese.js"),
  "zh-tw": () => import("@scure/bip39/wordlists/traditional-chinese.js"),
} as const;
