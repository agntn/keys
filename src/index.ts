export { AbstractBlockchain, useBlockchain } from "./blockchain.ts";
export { AbstractEVMBlockchain } from "./utils/evm.ts";

// Export lazy-loaded blockchain implementations
export { blockchains } from "./_blockchains.ts";

// Export BIP44 utilities
export {
  BIP44,
  BIP44Change,
  getBIP44Path,
  parseBIP44Path,
  getBlockchainPath,
} from "./utils/bip44/index.ts";

// Export Signing utilities
export { signMessage, verifyMessage, type SigningOptions } from "./utils/signing.ts";

export type {
  Blockchain,
  BlockchainImplementation,
  Keys,
  Wallet,
  KeyOptions,
  AddressType,
  NetworkType,
  AddressFormat,
} from "./types.ts";
