import type { MajikKeyBitcoinNamespace } from "./bitcoin/types.js";
import type { MajikKeyEthereumNamespace } from "./ethereum/types.js";
import type { MajikKeySolanaNamespace } from "./solana/types.js";

/** @experimental */
export interface MajikKeyWeb3Namespace {
  readonly solana: MajikKeySolanaNamespace;
  readonly bitcoin?: MajikKeyBitcoinNamespace;
  readonly ethereum?: MajikKeyEthereumNamespace;
}
