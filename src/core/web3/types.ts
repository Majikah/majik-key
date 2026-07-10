import { MajikKeyBitcoinNamespace } from "./bitcoin/types";
import { MajikKeySolanaNamespace } from "./solana/types";

/** @experimental */
export interface MajikKeyWeb3Namespace {
  readonly solana: MajikKeySolanaNamespace;
  readonly bitcoin?: MajikKeyBitcoinNamespace;
}
