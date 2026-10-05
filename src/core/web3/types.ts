import type { MajikKeyBitcoinNamespace } from "./bitcoin/types";
import type { MajikKeyEthereumNamespace } from "./ethereum/types";
import type { MajikKeySolanaNamespace } from "./solana/types";

/** @experimental */
export interface MajikKeyWeb3Namespace {
  readonly solana: MajikKeySolanaNamespace;
  readonly bitcoin?: MajikKeyBitcoinNamespace;
  readonly ethereum?: MajikKeyEthereumNamespace;
}
