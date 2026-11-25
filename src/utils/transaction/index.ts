export { extractSignatures } from "./signatures.ts";
export { decode } from "./transaction.ts";
export type { Transaction, TransactionInput, TransactionOutput } from "./transaction.ts";
export {
  SIGHASH_ALL,
  SIGHASH_ANYONECANPAY,
  SIGHASH_DEFAULT,
  SIGHASH_NONE,
  SIGHASH_SINGLE,
  legacySighash,
  segwitSighash,
  taprootSighash,
} from "./sighash.ts";
export type {
  LegacySighashOptions,
  SegwitSighashOptions,
  TaprootSighashOptions,
} from "./sighash.ts";
export type { InputSignature, SignatureExtractionOptions, SpentOutput } from "./signatures.ts";
export { recoverSigner } from "./evm.ts";
export type { EvmAccessListEntry, EvmTransactionJson, TransactionSigner } from "./evm.ts";
