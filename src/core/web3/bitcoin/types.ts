/**
 * @experimental By default this is Majik's DOMAIN-SEPARATED Bitcoin key
 * (derived via `MAJIK_BITCOIN_DOMAIN_PATH`) — deterministic and fully
 * standard BIP-32, but not the path a generic wallet would derive by
 * default, so it stays effectively private to Majik. Use
 * `MajikKey.getBitcoinKeypairMaterial({ standard: true })` /
 * `getBitcoinWIF({ standard: true })` for the REAL BIP-84 mainnet key —
 * recoverable in any standard wallet from the same mnemonic alone.
 */
export interface MajikKeyBitcoinNamespace {
  /** 33-byte compressed secp256k1 public key. */
  readonly publicKey: Uint8Array;
  /** 32-byte secp256k1 private key. Handle with the same care as any private key. */
  readonly privateKey: Uint8Array;
  /** Native SegWit (bech32) address. Lazily loads @scure/btc-signer — throws if not installed. */
  getBitcoinAddress(): Promise<string>;
  /** WIF string — pastes directly into any standard Bitcoin wallet. */
  getWIF(options?: { compressed?: boolean }): string;
  /** Sign a 32-byte message hash. ECDSA (default) or Schnorr. */
  sign(messageHash: Uint8Array, scheme?: "ecdsa" | "schnorr"): Uint8Array;
}
