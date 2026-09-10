export { convertSecp256k1PublicKey } from "./utils/public-key.ts";
export type { PublicKeyEncodingOptions } from "./utils/public-key.ts";
export { AbstractBlockchain, useBlockchain } from "./blockchain.ts";
export { AbstractEVMBlockchain } from "./utils/evm.ts";
export { encodeWIF, decodeWIF } from "./utils/wif.ts";
export type { WIFChain, WIFNetworkOptions, WIFOptions, DecodedWIF } from "./utils/wif.ts";

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
  HDWalletOptions,
  SigningOptions,
  Options,
  AddressType,
  NetworkType,
  AddressFormat,
} from "./types.ts";
