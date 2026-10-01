export { AbstractBlockchain, getBlockchainPath, useBlockchain } from "./blockchain.ts";
export { AbstractEVMBlockchain } from "./utils/evm.ts";

// Export lazy-loaded blockchain implementations
export { blockchains } from "./_blockchains.ts";

// Export Signing utilities
export { signMessage, verifyMessage } from "./utils/signing.ts";

export type {
  Blockchain,
  Curve,
  BlockchainImplementation,
  Keys,
  Wallet,
  XpubWallet,
  MessageSigner,
  KeyOptions,
  HDWalletOptions,
  SigningOptions,
  RecoverableSigningOptions,
  Options,
  AddressType,
  NetworkType,
  AddressFormat,
} from "./types.ts";
