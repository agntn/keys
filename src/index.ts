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
export { signMessage, verifyMessage } from "./utils/signing.ts";

export type {
  Blockchain,
  Curve,
  BlockchainImplementation,
  Keys,
  Wallet,
  KeyOptions,
  SigningOptions,
  Options,
  AddressType,
  NetworkType,
  AddressFormat,
} from "./types.ts";
