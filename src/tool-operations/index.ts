/**
 * Tool executors shared by the MCP server and the Pi extension.
 *
 * Inputs may bypass a host schema, so every executor checks its own boundary.
 * Errors never echo secret inputs; conversion results contain the equivalent secret.
 */

export { sanitizeToolText } from "./results.ts";
export type { ToolResult } from "./results.ts";
export { generateWallet, deriveWallet } from "./wallet.ts";
export type { GeneratedWalletDetails, DerivedWalletDetails } from "./wallet.ts";
export { deriveHdWallet, deriveXpubWallet, recoverBip32Parent } from "./hd.ts";
export type { DerivedXpubWalletDetails, RecoveredParentDetails } from "./hd.ts";
export { scanHdWallet } from "./hd-scan.ts";
export type { ScannedWalletDetails } from "./hd-scan.ts";
export { deriveElectrumWallet } from "./electrum.ts";
export type { DerivedOldElectrumWalletDetails } from "./electrum.ts";
export { deriveBrainwallet } from "./brainwallet.ts";
export type { DerivedBrainwalletDetails } from "./brainwallet.ts";
export {
  deriveBip39Seed,
  generateBip39Mnemonic,
  inspectMnemonic,
  encodeBip39Entropy,
} from "./bip39.ts";
export type {
  DerivedBIP39SeedDetails,
  MnemonicInspectionDetails,
  GeneratedMnemonicDetails,
  EncodedEntropyDetails,
} from "./bip39.ts";
export {
  lookupBip39Indices,
  lookupBip39Words,
  orderBip39Words,
  repairBip39Words,
  recoverMnemonicWord,
} from "./bip39-words.ts";
export type {
  BIP39IndexLookupDetails,
  BIP39IndexedWord,
  BIP39WordLookupDetails,
  BIP39WordOrderDetails,
  BIP39WordRepairDetails,
  MnemonicRecoveryDetails,
} from "./bip39-words.ts";
export { getAddress, validateAddress } from "./address.ts";
export type { AddressDetails, AddressValidationDetails } from "./address.ts";
export { signMessage, verifyMessage, recoverMessageSigner } from "./message.ts";
export type {
  SignatureDetails,
  SignatureVerificationDetails,
  MessageSignerDetails,
} from "./message.ts";
export { signBip322, verifyBip322 } from "./bip322.ts";
export type { BIP322SignatureDetails, BIP322VerificationDetails } from "./bip322.ts";
export { inspectOpenpgp, verifyOpenpgp } from "./openpgp.ts";
export type { OpenPGPInspectionDetails, OpenPGPVerificationDetails } from "./openpgp.ts";
export { getScriptAddress, deriveDescriptor } from "./script.ts";
export type { ScriptAddressDetails, DescriptorDetails } from "./script.ts";
export { parseBip44Path, generateBip44Path } from "./bip44.ts";
export type { BIP44PathDetails } from "./bip44.ts";
export { encodeWif, decodeWif } from "./wif.ts";
export type { EncodedWIFDetails } from "./wif.ts";
export { convertPublicKey, recoverSecp256k1Nonce } from "./secp256k1.ts";
export type { ConvertedPublicKeyDetails, RecoveredNonceDetails } from "./secp256k1.ts";
export { extractTransactionSignatures } from "./transaction.ts";
export type { TransactionSignaturesDetails } from "./transaction.ts";
export { inspectBip38, decryptBip38 } from "./bip38.ts";
export type { DecryptedBip38Details } from "./bip38.ts";
export { decryptStore } from "./store.ts";
export type { DecryptedStoreDetails } from "./store.ts";
export { getArweaveAddress } from "./arweave.ts";
export type { ArweaveAddressDetails } from "./arweave.ts";
export {
  MAX_BIP39_LOOKUP_ITEMS,
  BIP39_ENTROPY_BYTE_LENGTHS,
  BIP39_ENTROPY_SCHEMA_PATTERN,
  BIP39_WORD_SCHEMA_PATTERN,
  DERIVATION_PATH_SCHEMA_PATTERN,
} from "../tool-parameters.ts";
