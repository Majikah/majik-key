/** @experimental */
export interface EthereumSignature {
  /** 0x-prefixed 32-byte hex. */
  r: string;
  /** 0x-prefixed 32-byte hex (low-s normalized, EIP-2). */
  s: string;
  /** 27 | 28 (Ethereum "v"). */
  v: 27 | 28;
  /** Raw recovery id, 0 | 1. */
  recovery: 0 | 1;
  /** 0x + r || s || v (65 bytes) — what personal_sign / ecrecover consumers expect. */
  serialized: string;
}

/**
 * @experimental Ethereum account derived at the STANDARD path
 * (`m/44'/60'/0'/0/0`): the same address MetaMask and hardware wallets show
 * for this mnemonic. Anyone holding the mnemonic controls the funds.
 */
export interface MajikKeyEthereumNamespace {
  /** 33-byte compressed secp256k1 public key. */
  readonly publicKey: Uint8Array;
  /** 32-byte secp256k1 private key. Handle with the same care as any private key. */
  readonly privateKey: Uint8Array;
  /** EIP-55 checksummed address. Pure computation — needs no extra dependency. */
  readonly address: string;
  /** 0x-prefixed private key hex — pastes directly into any wallet's "import private key". */
  getPrivateKeyHex(): string;
  /** Sign a 32-byte hash (e.g. a tx hash or EIP-712 digest). Returns r/s/v. */
  signHash(hash32: Uint8Array): EthereumSignature;
  /** EIP-191 `personal_sign`: signs keccak256("\x19Ethereum Signed Message:\n" + len + message). */
  signMessage(message: string | Uint8Array): EthereumSignature;
}
