/**
 * @experimental Web3 / blockchain integrations are experimental. This
 * namespace's shape may change without a major version bump.
 */
export interface MajikKeySolanaNamespace {
  /** 32-byte Solana/Ed25519 public key. */
  readonly publicKey: Uint8Array;
  /** 64-byte nacl-format secret key. Handle with the same care as any private key. */
  readonly secretKey: Uint8Array;
  /** Base58 Solana address — does not require @solana/kit. */
  readonly address: string;
  /** Real @solana/kit Keypair. Lazily loads @solana/kit — throws if not installed. */
  getSolanaKeypair(): Promise<any>;
  /** Real @solana/kit PublicKey. Lazily loads @solana/kit — throws if not installed. */
  getSolanaAddress(): Promise<any>;
  /** Sign a message with this Solana keypair's Ed25519 key. No web3.js needed. */
  sign(message: Uint8Array): Uint8Array;
}

