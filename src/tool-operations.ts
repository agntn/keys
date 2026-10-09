/**
 * Tool executors shared by the MCP server and the Pi extension.
 *
 * Inputs may bypass a host schema, so every executor checks its own boundary.
 * Errors never echo secret inputs; conversion results contain the equivalent secret.
 */

import {
  deriveOldMasterPublicKey,
  deriveOldPublicKey,
  deriveSeed as deriveElectrumSeed,
  inspect as inspectElectrumSeed,
} from "./utils/electrum/index.ts";
import {
  BIP32ChildMismatchError,
  deriveHDKey,
  getMasterKeyFromSeed,
  recoverParent,
  type RecoveredParent,
} from "./utils/bip32/index.ts";
import { getMasterKeyFromSeed as getSLIP10MasterKey } from "./utils/slip10/index.ts";
import {
  ELECTRUM_SCHEMES,
  hdAddress,
  nodeWalker,
  scanSchemes,
  walkScheme,
  type ScanAddress,
  type ScanMatch,
  type ScanScheme,
  type ScanTried,
} from "./utils/hd-scan.ts";
import {
  convertPublicKey as convertSecp256k1PublicKey,
  recoverReusedNonce,
} from "./utils/secp256k1/index.ts";
import { extractSignatures, type InputSignature } from "./utils/transaction/index.ts";
import {
  address as scriptAddress,
  multisig,
  MAX_MULTISIG_KEYS,
  type ScriptAddressType,
} from "./utils/script/index.ts";
import { parse as parseDescriptor, type DescriptorOutput } from "./utils/descriptor/index.ts";
import { describeInvalidMnemonic, normalizeMnemonic } from "./utils/hd.ts";
import {
  encode as encodeWIF,
  decode as decodeWIF,
  type DecodedWIF,
  type WIFNetworkOptions,
} from "./utils/wif/index.ts";
import {
  BIP38PassphraseError,
  decrypt as decryptBIP38Key,
  inspect as inspectBIP38,
  type BIP38Inspection,
  type BIP38Mode,
  type DecryptedBIP38,
} from "./utils/bip38/index.ts";
import {
  derive as deriveBrainwalletKey,
  type BrainwalletKDF,
  type BrainwalletRecipe,
  type PlainBrainwalletOptions,
  type WarpWalletOptions,
} from "./utils/brainwallet/index.ts";
import {
  decrypt as decryptStoreKey,
  inspect as inspectStore,
  KeystorePasswordError,
  type KeystoreKDF,
} from "./utils/store/index.ts";
import { getBlockchainPath, useBlockchain, type AbstractBlockchain } from "./blockchain.ts";
import { blockchains } from "./_blockchains.ts";
import { parse as parseBIP44Path } from "./utils/bip44/index.ts";
import type { Curve, MessageSigner, Options } from "./types.ts";
import { hashTypedData, type TypedData } from "./utils/eip712.ts";
import {
  entropyHashAlgorithms,
  profileEntropy,
  BUILT_IN_PREIMAGES,
  ENTROPY_DIGEST_BYTES,
  type EntropyPattern,
  type EntropyPreimage,
  type EntropyProfile,
} from "./utils/entropy-profile.ts";
import {
  MAX_BIP39_LOOKUP_ITEMS,
  MAX_BIP39_CHECKSUM_SEARCH,
  MAX_BIP39_PHRASES_SHOWN,
  MAX_BIP39_PHRASE_LENGTH,
  DEFAULT_BIP39_PHRASES_SHOWN,
  MAX_BIP39_REPAIR_WORDS,
  MAX_BIP39_REPAIR_DISTANCE,
  DEFAULT_BIP39_REPAIR_DISTANCE,
  MAX_ENTROPY_PREIMAGES,
  MAX_ENTROPY_PREIMAGE_LENGTH,
  BIP39_ENTROPY_BYTE_LENGTHS,
  TOOL_ADDRESS_TYPES_BY_CHAIN,
  TOOL_CHAINS,
  TOOL_NETWORKS,
  CHAIN_NETWORKS,
  MAX_WALLET_SECRET_LENGTH,
  TOOL_MNEMONIC_WORD_COUNTS,
  MAX_BIP39_SEED_INPUT_LENGTH,
  MAX_BIP38_ADDRESS_LENGTH,
  MAX_BIP38_PASSPHRASE_LENGTH,
  MAX_EXTENDED_KEY_LENGTH,
  MAX_WIF_LENGTH,
  MAX_KEYSTORE_LENGTH,
  MAX_KEYSTORE_PASSWORD_LENGTH,
  MAX_ADDRESS_LENGTH,
  MAX_SCAN_MNEMONIC_LENGTH,
  SCAN_ACCOUNTS,
  SCAN_INDICES,
  MAX_BRAINWALLET_INPUT_LENGTH,
  MAX_SCRYPT_BLOCKS,
  KDF_COST_LIMITS,
  TOOL_WIF_CHAINS,
  PRIVATE_KEY_SCHEMA_PATTERN,
  FAMILY_SEED_SCHEMA_PATTERN,
  MONERO_SEED_SCHEMA_PATTERN,
  DER_SIGNATURE_SCHEMA_PATTERN,
  PUBLIC_KEY_SCHEMA_PATTERN,
  CHAIN_PUBLIC_KEY_SCHEMA_PATTERN,
  CORE_SIGNATURE_SCHEMA_PATTERN,
  RECOVERABLE_SIGNATURE_SCHEMA_PATTERN,
  DIGEST_SCHEMA_PATTERN,
  MAX_TYPED_DATA_LENGTH,
  SIGNATURE_SCHEMA_PATTERN,
  BIP322_SIGNING_TYPES,
  BIP322_SIGNATURE_SCHEMA_PATTERN,
  MAX_BIP322_SIGNATURE_LENGTH,
  HEX_BYTES_SCHEMA_PATTERN,
  MAX_INPUT_INDEX,
  MAX_SPENT_OUTPUTS,
  MAX_SPENT_SCRIPT_HEX_LENGTH,
  MAX_SPENT_SCRIPTS_HEX_LENGTH,
  MAX_TRANSACTION_HEX_LENGTH,
  NONCE_SCALAR_SCHEMA_PATTERN,
  NONCE_SIGNATURE_TYPES,
  MAX_DESCRIPTOR_ADDRESSES,
  MAX_DESCRIPTOR_LENGTH,
  MAX_SCRIPT_HEX_LENGTH,
  SEC1_PUBLIC_KEY_SCHEMA_PATTERN,
  type ToolChain,
  type ToolNetwork,
} from "./tool-parameters.ts";
import {
  sign as signBIP322Message,
  verify as verifyBIP322Message,
  type BIP322Format,
  type BIP322SigningType,
  type BIP322State,
  type BIP322Verification,
} from "./utils/bip322/index.ts";
import {
  bip39,
  mnemonicToSeed,
  loadWordlist as loadBIP39Wordlist,
  getMnemonicWordCandidates,
  inspect as inspectBIP39Mnemonic,
  lookupIndices as lookupBIP39Indices,
  lookupWords as lookupBIP39Words,
  lookupPrefixes as lookupBIP39Prefixes,
  countWordOrders,
  orderWords,
  repairWords,
  suggestWords,
  type WordSuggestions,
} from "./utils/bip39/index.ts";
import { BIP39_LANGUAGES, isBIP39Language, type BIP39Language } from "./utils/bip39/languages.ts";

export {
  MAX_BIP39_LOOKUP_ITEMS,
  BIP39_ENTROPY_BYTE_LENGTHS,
  BIP39_ENTROPY_SCHEMA_PATTERN,
  BIP39_WORD_SCHEMA_PATTERN,
  DERIVATION_PATH_SCHEMA_PATTERN,
} from "./tool-parameters.ts";

/**
 * Text for the model plus structured details for agent harnesses. A failure throws instead:
 * Pi records every returned value as a successful call.
 */
export interface ToolResult<Details> {
  content: Array<{ type: "text"; text: string }>;
  details: Details;
}

/** Generated wallet material. */
export interface GeneratedWalletDetails {
  chain: string;
  network: string;
  curve: string;
  bip44: number;
  privateKey: string;
  publicKey: string;
  address: string;
}

/** Public wallet material derived from a secret input. */
export interface DerivedWalletDetails {
  chain: string;
  network: string;
  publicKey: string;
  addressType?: string;
  /** The public key form the caller asked for; absent when it was left to the default. */
  compressed?: boolean;
  address: string;
  path?: string;
  warnings?: readonly string[];
}

/** A disposable BIP39 seed, never a BIP32 master private key. */
export interface DerivedBIP39SeedDetails {
  language: BIP39Language;
  seed: string;
}

/** BIP39 inspection result without the supplied mnemonic. */
export interface MnemonicInspectionDetails {
  language: BIP39Language;
  valid: boolean;
  words: number;
  wordCountValid: boolean;
  wordlistValid: boolean;
  checksumValid: boolean | null;
  entropy?: string;
  entropyProfile?: EntropyProfile;
}

/** Fresh disposable mnemonic and its word count. */
export interface GeneratedMnemonicDetails {
  language: BIP39Language;
  words: number;
  mnemonic: string;
}

/** Mnemonic generated from supplied entropy. */
export interface EncodedEntropyDetails {
  language: BIP39Language;
  words: number;
  mnemonic: string;
}

/** Result of a BIP39 index lookup. */
export interface BIP39IndexLookupDetails {
  language: string;
  indexBase: 0 | 1;
  lookups: Array<{ index: number; word: string | null }>;
}

/** A list word with both index conventions. */
export interface BIP39IndexedWord {
  word: string;
  zeroBasedIndex: number;
  oneBasedIndex: number;
}

/** Result of a BIP39 word lookup. */
export interface BIP39WordLookupDetails {
  language: string;
  lookups: Array<{
    word: string;
    zeroBasedIndex: number | null;
    oneBasedIndex: number | null;
    /** Words a missing entry of three or more letters starts, in list order. */
    prefixOf?: BIP39IndexedWord[];
  }>;
}

/** Orders of scattered words that pass the BIP39 checksum. */
export interface BIP39WordOrderDetails {
  language: string;
  checked: number;
  valid: number;
  orders: string[];
}

/** Words close to the ones outside the list and the repaired phrases that pass the checksum. */
export interface BIP39WordRepairDetails {
  language: string;
  maxDistance: number;
  positions: Array<{ position: number; suggestions: Array<{ word: string; distance: number }> }>;
  checked: number;
  valid: number;
  repairs: Array<{ mnemonic: string; distance: number }>;
}

/** Candidate words for one missing mnemonic position. */
export interface MnemonicRecoveryDetails {
  language: string;
  position: number;
  candidates: readonly string[];
}

/** Address derived from a public key. */
export interface AddressDetails {
  chain: string;
  network: string;
  addressType?: string;
  address: string;
}

/** Address format validation result. */
export interface AddressValidationDetails extends AddressDetails {
  valid: boolean;
}

/** Signature generated without retaining the private key or message. */
export interface SignatureDetails {
  chain: string;
  network: string;
  signature: string;
  /** True for the recoverable form: `r||s||v` hex on EVM and TRON, base64 on the Core family. */
  recovered: boolean;
}

/** Signature verification result. */
export interface SignatureVerificationDetails {
  chain: string;
  network: string;
  valid: boolean;
}

/** Recovered signer, compared with an address when one was given. */
export interface MessageSignerDetails {
  chain: string;
  network: string;
  /** What the signature covers. */
  signed: "message" | "typedData" | "digest";
  /** EIP-712 digest the typed data hashed to; only for `typedData`. */
  digest?: string;
  publicKey: string;
  /** Address type the Core signature header names; absent on EVM chains and TRON. */
  addressType?: string;
  /** Address of that type for the recovered key. */
  address: string;
  /** Whether the given address belongs to the recovered key; absent without an address. */
  matches?: boolean;
  /** Address type the given address matched, SegWit included under a P2PKH header. */
  matchedType?: string;
}

/** Parsed or generated BIP44 path. */
export interface BIP44PathDetails {
  path: string;
  chain?: string;
  coinType: number;
  purpose?: number;
  account: number;
  change: number;
  addressIndex: number;
}

const BIP39_ENTROPY_PATTERN = /^[0-9a-f]+$/i;

/**
 * Decodes BIP39 entropy from hex, refusing lengths the standard has no word count for.
 * @param value - Entropy as the caller passed it
 * @returns {Uint8Array} Entropy bytes
 */
function parseBip39Entropy(value: unknown): Uint8Array {
  const entropyText = requiredString(value, "BIP39 entropy");
  if (!BIP39_ENTROPY_PATTERN.test(entropyText)) {
    throw new TypeError("BIP39 entropy must be a hexadecimal string");
  }
  if (!BIP39_ENTROPY_BYTE_LENGTHS.includes(entropyText.length / 2)) {
    throw new RangeError("BIP39 entropy must be 16, 20, 24, 28, or 32 bytes");
  }
  return Uint8Array.fromHex(entropyText);
}

function parseIndexBase(value: unknown): 0 | 1 {
  if (value === undefined || value === 0) return 0;
  if (value === 1) return 1;
  throw new RangeError("BIP39 index base must be 0 or 1");
}

function assertLookupSize(length: number, label: string): void {
  if (length === 0 || length > MAX_BIP39_LOOKUP_ITEMS) {
    throw new RangeError(`Provide between 1 and ${MAX_BIP39_LOOKUP_ITEMS} ${label}`);
  }
}

function assertIndexRange(indices: readonly number[], indexBase: 0 | 1): void {
  const maximumIndex = 2047 + indexBase;
  if (indices.some((index) => index < indexBase || index > maximumIndex)) {
    throw new RangeError(`BIP39 indices must be between ${indexBase} and ${maximumIndex}`);
  }
}
const BIP39_WORD_PATTERN = /^[\p{L}\p{M}]+$/u;
const DERIVATION_PATH_PATTERN = /^m(?:\/\d+['h]?)+$/u;

/** Substrate junctions as `keys_hd_wallet_derive` takes them on polkadot, `m` for the root key. */
const SUBSTRATE_PATH_PATTERN = /^(?:m|(?:\/\/?[^/]+)+)$/u;

/**
 * Refuses a path the chain cannot walk: BIP32 everywhere but polkadot, Substrate junctions there.
 * @param chain - Name of the loaded chain
 * @param path - Derivation path as given
 * @throws {TypeError} When the path has the wrong shape for the chain
 */
function assertHdWalletPath(chain: string, path: string): void {
  if (chain !== "polkadot") {
    if (!DERIVATION_PATH_PATTERN.test(path)) {
      throw new TypeError("Derivation path must look like m/84'/0'/0'/0/0");
    }
    return;
  }
  if (!SUBSTRATE_PATH_PATTERN.test(path)) {
    throw new TypeError(
      "Derivation path on polkadot is hard junctions such as //polkadot//0, or m for the root key",
    );
  }
}

/**
 * Removes terminal and line control bytes from text crossing an agent boundary.
 * @param text - Text to sanitize.
 * @returns {string} Text without control bytes.
 */
export function sanitizeToolText(text: string): string {
  return text.replaceAll(/\p{Cc}/gu, " ");
}

function content(text: string): Array<{ type: "text"; text: string }> {
  return [{ type: "text", text }];
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string`);
  return value;
}

const PRIVATE_KEY_HEX = new RegExp(PRIVATE_KEY_SCHEMA_PATTERN, "u");
const PUBLIC_KEY_HEX = new RegExp(PUBLIC_KEY_SCHEMA_PATTERN, "u");
const CHAIN_PUBLIC_KEY = new RegExp(CHAIN_PUBLIC_KEY_SCHEMA_PATTERN, "u");
const SIGNATURE_HEX = new RegExp(SIGNATURE_SCHEMA_PATTERN, "u");
const DER_SIGNATURE = new RegExp(DER_SIGNATURE_SCHEMA_PATTERN, "u");
const FAMILY_SEED = new RegExp(FAMILY_SEED_SCHEMA_PATTERN, "u");
const MONERO_SEED = new RegExp(MONERO_SEED_SCHEMA_PATTERN, "u");
/** Monero's spend and view pair, the one 64-byte key the tools take. */
const MONERO_PUBLIC_KEY = /^[0-9A-Fa-f]{128}$/u;
const CORE_SIGNATURE = new RegExp(CORE_SIGNATURE_SCHEMA_PATTERN, "u");
const RECOVERABLE_SIGNATURE = new RegExp(RECOVERABLE_SIGNATURE_SCHEMA_PATTERN, "u");
const DIGEST_HEX = new RegExp(DIGEST_SCHEMA_PATTERN, "u");

/**
 * Applies a schema's hex pattern for hosts that skip the schema, so a `0x` prefix fails as input
 * instead of reaching a verifier that reports it as a bad signature. The value is never echoed.
 * @param value - Raw argument.
 * @param name - Argument name for the error.
 * @param pattern - Pattern the shared schema advertises.
 * @param shape - Accepted form, as the error states it.
 * @returns {string} The argument unchanged.
 */
function hexArgument(
  value: unknown,
  name: string,
  pattern: Readonly<RegExp>,
  shape: string,
): string {
  const text = requiredString(value, name);
  if (!pattern.test(text)) throw new TypeError(`${name} must be ${shape} without 0x`);
  return text;
}

/**
 * Reads the key for an address or a signature check, the `ed25519:` form on near only.
 * @param value - Argument as the host passed it.
 * @param chain - Name of the chain that reads the key.
 * @returns {string} The key as given.
 * @throws {TypeError} On a bad shape, or the `ed25519:` form on another chain.
 */
function chainPublicKey(value: unknown, chain: string): string {
  const publicKey = hexArgument(
    value,
    "Public key",
    CHAIN_PUBLIC_KEY,
    "a 32-byte ed25519 key, XRPL's ED form of one, NEAR's ed25519: form, Monero's 64-byte spend and view pair, or a SEC1 secp256k1 key in hex",
  );
  if (chain !== "near" && publicKey.startsWith("ed25519:")) {
    throw new TypeError(
      `ed25519: and base58 is how NEAR writes a key. Give ${chain} the key in hex`,
    );
  }
  if ((chain === "monero") !== MONERO_PUBLIC_KEY.test(publicKey)) {
    throw new TypeError(
      chain === "monero"
        ? "A Monero public key is 64 bytes of hex: the public spend key, then the public view key"
        : `64 bytes of hex is Monero's spend and view pair. Give ${chain} its own public key`,
    );
  }
  return publicKey;
}

function optionalString(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined;
  return requiredString(value, name);
}

/**
 * Tells whether an optional name such as a network or an address type was left out.
 * OMP sends every property of the schema, so an option the model leaves alone arrives as `""`.
 * Passphrases skip this check, because spaces are a passphrase of their own.
 * @param value - Argument as the host passed it.
 * @returns {boolean} True when the argument is missing or a blank string.
 */
function isUnset(value: unknown): boolean {
  return value === undefined || (typeof value === "string" && value.trim() === "");
}

function optionalName(value: unknown, name: string): string | undefined {
  return isUnset(value) ? undefined : requiredString(value, name);
}

function optionalIndex(value: unknown, name: string, maximum = 0x7fffffff): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > maximum) {
    throw new RangeError(`${name} must be an integer between 0 and ${maximum}`);
  }
  return value;
}

function stringArray(value: unknown, name: string): readonly string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new TypeError(`${name} must be an array of strings`);
  }
  return value;
}

function integerArray(value: unknown, name: string): readonly number[] {
  if (!Array.isArray(value)) throw new TypeError(`${name} must be an array of integers`);
  const integers: number[] = [];
  for (const item of value) {
    if (typeof item !== "number" || !Number.isInteger(item)) {
      throw new TypeError(`${name} must be an array of integers`);
    }
    integers.push(item);
  }
  return integers;
}

function parseBIP39Language(value: unknown): BIP39Language {
  const language = optionalString(value, "BIP39 language") ?? "english";
  if (!isBIP39Language(language)) {
    throw new RangeError(`Unknown BIP39 language. Supported: ${BIP39_LANGUAGES.join(", ")}`);
  }
  return language;
}

function normalizedMnemonic(value: unknown): string {
  const mnemonic = requiredString(value, "BIP39 mnemonic").trim().replaceAll(/\s+/gu, " ");
  if (mnemonic === "") throw new TypeError("BIP39 mnemonic must not be empty");
  return mnemonic;
}

function formatCurve(curve: string | readonly string[]): string {
  return typeof curve === "string" ? curve : curve.join(", ");
}

function parseNetwork(value: unknown): ToolNetwork {
  const network = optionalName(value, "Network") ?? "mainnet";
  const matched = TOOL_NETWORKS.find((candidate) => candidate === network);
  if (matched === undefined) {
    throw new RangeError(
      `Unsupported network ${JSON.stringify(network)}. Supported: ${TOOL_NETWORKS.join(", ")}`,
    );
  }
  return matched;
}

/**
 * Reads the network of a chain tool: mainnet or testnet, and stagenet on monero only.
 * @param chain - Chain the call loads
 * @param value - Network as the host passed it
 * @returns {string} The network to construct the chain with
 */
function parseChainNetwork(chain: ToolChain, value: unknown): string {
  if (chain === "monero" && optionalName(value, "Network") === "stagenet") return "stagenet";
  return parseNetwork(value);
}

function parseAddressType(chain: ToolChain, value: unknown): string | undefined {
  const addressType = optionalName(value, "Address type");
  if (addressType === undefined) return undefined;

  const supported = TOOL_ADDRESS_TYPES_BY_CHAIN[chain];
  if (supported.length === 0) {
    throw new RangeError(
      `Address type ${JSON.stringify(addressType)} is not supported for ${chain}, which has one address format. Omit addressType`,
    );
  }
  const matched = supported.find((candidate) => candidate === addressType);
  if (matched === undefined) {
    throw new RangeError(
      `Address type ${JSON.stringify(addressType)} is not supported for ${chain}. Supported: ${supported.join(", ")}`,
    );
  }
  return matched;
}

/**
 * Names the address type in a result, on chains that write more than one.
 * @param addressType - Type the wallet or address was written as
 * @returns {string[]} One `Address type:` line, or none
 */
function addressTypeLines(addressType: string | undefined): string[] {
  return addressType === undefined ? [] : [`Address type: ${addressType}`];
}

/** An SS58 prefix as the tools take it: a decimal number, no sign or leading zero. */
const SS58_PREFIX_TEXT = /^(?:0|[1-9]\d{0,4})$/u;

/**
 * Reads the prefix into the options of the chain that takes one: the bech32 prefix on cosmos, the
 * SS58 network number on polkadot. Blank counts as left out.
 * @param chain - Chain the call loads.
 * @param value - Prefix as the host passed it.
 * @returns {Pick<Options, "prefix" | "ss58Prefix">} The chain's option, empty for its default.
 * @throws {RangeError} When a prefix comes with any other chain, or polkadot gets no number.
 */
function parsePrefix(chain: ToolChain, value: unknown): Pick<Options, "prefix" | "ss58Prefix"> {
  const prefix = optionalName(value, "Prefix");
  if (prefix === undefined) return {};
  if (chain === "cosmos") return { prefix };
  if (chain !== "polkadot") {
    throw new RangeError(
      `prefix picks a Cosmos SDK chain on cosmos and an SS58 network on polkadot. Leave it out on ${chain}`,
    );
  }
  if (!SS58_PREFIX_TEXT.test(prefix)) {
    throw new RangeError("prefix on polkadot is the SS58 network number, such as 2 for Kusama");
  }
  return { ss58Prefix: Number(prefix) };
}

/**
 * Reads the coin type a Cosmos SDK chain's path walks in place of the one its prefix stands for.
 * @param chain - Chain the call loads.
 * @param value - Coin type as the host passed it.
 * @returns {Pick<Options, "coinType">} The option, empty when left out.
 * @throws {RangeError} When it comes with any chain but cosmos, or is no coin type.
 */
function parseCoinType(chain: ToolChain, value: unknown): Pick<Options, "coinType"> {
  const coinType = optionalIndex(value, "coinType");
  if (coinType === undefined) return {};
  if (chain !== "cosmos") {
    throw new RangeError(
      `coinType picks the path of a Cosmos SDK chain. ${chain} has its own, so leave it out`,
    );
  }
  return { coinType };
}

async function getBlockchain(
  chainValue: unknown,
  networkValue?: unknown,
  addressTypeValue?: unknown,
  prefixValue?: unknown,
  coinTypeValue?: unknown,
): Promise<{ readonly blockchain: AbstractBlockchain; readonly addressType: string | undefined }> {
  const name = requiredString(chainValue, "Chain").toLowerCase();
  const chain = TOOL_CHAINS.find((candidate) => candidate === name);
  if (chain === undefined) {
    throw new RangeError(
      `Unknown chain ${JSON.stringify(name)}. Supported: ${TOOL_CHAINS.join(", ")}`,
    );
  }
  const network = parseChainNetwork(chain, networkValue);
  const addressType = parseAddressType(chain, addressTypeValue);
  const prefix = parsePrefix(chain, prefixValue);
  const coinType = parseCoinType(chain, coinTypeValue);
  return {
    blockchain: useBlockchain(await blockchains[chain]({ network, ...prefix, ...coinType })()),
    addressType,
  };
}

/**
 * Generate a disposable wallet for one supported blockchain.
 * @param chainValue - Blockchain name.
 * @param networkValue - Optional network name.
 * @param addressTypeValue - Optional chain-specific address type.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @returns {Promise<ToolResult<GeneratedWalletDetails | undefined>>} Generated key and address material.
 */
export async function generateWallet(
  chainValue: unknown,
  networkValue?: unknown,
  addressTypeValue?: unknown,
  prefixValue?: unknown,
): Promise<ToolResult<GeneratedWalletDetails | undefined>> {
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
    prefixValue,
  );
  const wallet = blockchain.generateWallet({}, addressType);
  const details = {
    chain: blockchain.name,
    network: blockchain.network,
    curve: formatCurve(blockchain.curve),
    bip44: blockchain.coinType,
    privateKey: wallet.keys.private,
    publicKey: wallet.keys.public,
    address: wallet.address,
  };
  return {
    content: content(
      [
        `Chain: ${details.chain} (${details.network})`,
        `Curve: ${details.curve}`,
        `BIP44: ${details.bip44}`,
        ...addressTypeLines(wallet.addressType),
        `Private key: ${details.privateKey}`,
        `Public key: ${details.publicKey}`,
        `Address: ${details.address}`,
      ].join("\n"),
    ),
    details: undefined,
  };
}

/**
 * Reads the public key form, which the chain then checks against its address.
 * @param value - Raw argument
 * @returns {boolean | undefined} The form to derive, undefined when omitted
 */
function walletCompressed(value: unknown): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw new TypeError("compressed must be a boolean");
  return value;
}

/**
 * Derive public wallet material from a private key without echoing the secret.
 * @param chainValue - Blockchain name.
 * @param privateKeyValue - Private key as hexadecimal text.
 * @param addressTypeValue - Optional chain-specific address type.
 * @param networkValue - Optional network name.
 * @param compressedValue - Optional secp256k1 public key form, compressed by default.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @returns {Promise<ToolResult<DerivedWalletDetails>>} Derived public wallet material.
 */
export async function deriveWallet(
  chainValue: unknown,
  privateKeyValue: unknown,
  addressTypeValue?: unknown,
  networkValue?: unknown,
  compressedValue?: unknown,
  prefixValue?: unknown,
): Promise<ToolResult<DerivedWalletDetails>> {
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
    prefixValue,
  );
  const compressed = walletCompressed(compressedValue);
  const options = compressed === undefined ? {} : { compressed };
  const secret = requiredString(privateKeyValue, "Private key");
  if (secret.length > MAX_WALLET_SECRET_LENGTH) {
    throw new RangeError(`Private key must not exceed ${MAX_WALLET_SECRET_LENGTH} characters`);
  }
  if (MONERO_SEED.test(secret) && blockchain.name !== "monero") {
    throw new TypeError(
      `Seed words go to keys_hd_wallet_derive as a BIP39 mnemonic; ${blockchain.name} takes a private key here`,
    );
  }
  const wallet =
    FAMILY_SEED.test(secret) || MONERO_SEED.test(secret)
      ? blockchain.deriveSeedWallet(secret, options, addressType)
      : blockchain.deriveWallet(
          hexArgument(
            secret,
            "Private key",
            PRIVATE_KEY_HEX,
            "64 hex characters, a family seed (s...) on xrpl or the seed words on monero,",
          ),
          options,
          addressType,
        );
  const details = {
    chain: blockchain.name,
    network: blockchain.network,
    ...(wallet.addressType === undefined ? {} : { addressType: wallet.addressType }),
    ...(compressed === undefined ? {} : { compressed }),
    publicKey: wallet.keys.public,
    address: wallet.address,
  };
  return {
    content: content(
      [
        ...addressTypeLines(details.addressType),
        `Public key: ${details.publicKey}`,
        `Address: ${details.address}`,
      ].join("\n"),
    ),
    details,
  };
}

/**
 * Takes the mnemonic as given, or spells the entropy with the word list; exactly one of them.
 * @param mnemonicValue - Mnemonic as the caller passed it
 * @param entropyValue - Entropy hex as the caller passed it
 * @param wordlist - Word list that spells the entropy
 * @returns {string} Mnemonic to derive from
 */
function mnemonicOrEntropy(
  mnemonicValue: unknown,
  entropyValue: unknown,
  wordlist: readonly string[],
): string {
  if (mnemonicValue !== undefined && entropyValue !== undefined) {
    throw new TypeError("Pass either a BIP39 mnemonic or its entropy, not both");
  }
  if (entropyValue === undefined) {
    if (mnemonicValue === undefined) throw new TypeError("Pass a BIP39 mnemonic or its entropy");
    return requiredString(mnemonicValue, "BIP39 mnemonic");
  }
  return bip39.entropyToMnemonic(parseBip39Entropy(entropyValue), [...wordlist]);
}

/**
 * Derive public wallet material from a BIP39 mnemonic or its entropy and a path.
 * @param chainValue - Blockchain name.
 * @param mnemonicValue - BIP39 mnemonic in the selected language, or undefined when entropy is given.
 * @param pathValue - Absolute derivation path.
 * @param passphraseValue - Optional BIP39 passphrase.
 * @param addressTypeValue - Optional chain-specific address type.
 * @param networkValue - Optional network name.
 * @param allowInvalidChecksumValue - Accept a checksum failure for a public puzzle, default false.
 * @param languageValue - Optional official BIP39 language key.
 * @param entropyValue - BIP39 entropy as hex, encoded with the selected list in place of a mnemonic.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @returns {Promise<ToolResult<DerivedWalletDetails>>} Derived public wallet material.
 */
export async function deriveHdWallet(
  chainValue: unknown,
  mnemonicValue: unknown,
  pathValue: unknown,
  passphraseValue?: unknown,
  addressTypeValue?: unknown,
  networkValue?: unknown,
  allowInvalidChecksumValue?: unknown,
  languageValue?: unknown,
  entropyValue?: unknown,
  prefixValue?: unknown,
): Promise<ToolResult<DerivedWalletDetails>> {
  if (allowInvalidChecksumValue !== undefined && typeof allowInvalidChecksumValue !== "boolean") {
    throw new TypeError("allowInvalidChecksum must be a boolean");
  }
  const allowInvalidChecksum = allowInvalidChecksumValue ?? false;
  const path = requiredString(pathValue, "Derivation path");
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
    prefixValue,
  );
  assertHdWalletPath(blockchain.name, path);
  const passphrase = optionalString(passphraseValue, "BIP39 passphrase");
  const language = parseBIP39Language(languageValue);
  const wordlist = await loadBIP39Wordlist(language);
  const mnemonic = mnemonicOrEntropy(mnemonicValue, entropyValue, wordlist);
  const words = normalizeMnemonic(mnemonic);
  const inspection = inspectBIP39Mnemonic(words, wordlist);
  if (inspection.checksumValid === null) {
    throw new TypeError(describeInvalidMnemonic(words, inspection, wordlist, language));
  }
  const wallet = blockchain.deriveHDWallet(
    mnemonic,
    path,
    { passphrase, allowInvalidChecksum, wordlist },
    addressType,
  );
  const details = {
    chain: blockchain.name,
    network: blockchain.network,
    path,
    ...(wallet.addressType === undefined ? {} : { addressType: wallet.addressType }),
    publicKey: wallet.keys.public,
    address: wallet.address,
    ...(wallet.warnings === undefined ? {} : { warnings: wallet.warnings }),
  };
  return {
    content: content(
      [
        `Chain: ${details.chain} (${details.network})`,
        `Path: ${path}`,
        ...addressTypeLines(details.addressType),
        `Public key: ${details.publicKey}`,
        `Address: ${details.address}`,
        ...(details.warnings ?? []).map((warning) => `Warning: ${warning}`),
      ].join("\n"),
    ),
    details,
  };
}

/** A seed family the scan did not walk, such as `electrum`, and why. */
interface ScanSkipped {
  readonly family: string;
  readonly reason: string;
}

/** Where a wallet scan found the target, or everything it checked when it did not. */
export interface ScannedWalletDetails {
  chain: string;
  network: string;
  /** The target address as given. */
  address: string;
  found: boolean;
  /** Addresses derived before the scan stopped. */
  checked: number;
  /** Scheme, path and public key that reached the target. */
  match?: ScanMatch;
  /** Schemes walked, the last one stopped at the match. */
  tried: readonly ScanTried[];
  /** Seed families the phrase is not, or that the scan could not walk, with the reason. */
  skipped: ReadonlyArray<ScanSkipped>;
  warnings?: readonly string[];
}

/**
 * Reads how many accounts or indices the scan walks, refusing 0 and anything above the maximum.
 * @param value - Raw argument
 * @param name - Argument name for the error
 * @param limits - Default and maximum
 * @param limits.default - Count when the argument is left out
 * @param limits.maximum - Highest count
 * @returns {number} The count
 */
function scanCount(
  value: unknown,
  name: string,
  limits: { readonly default: number; readonly maximum: number },
): number {
  if (value === undefined) return limits.default;
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 1 ||
    value > limits.maximum
  ) {
    throw new RangeError(`${name} must be an integer between 1 and ${limits.maximum}`);
  }
  return value;
}

/** A seed the scan walks: its schemes and the address each path reaches. */
interface ScanSource {
  readonly schemes: readonly ScanScheme[];
  readonly addressAt: (scheme: ScanScheme) => (path: string) => ScanAddress;
}

/** How a phrase reads as one seed family: a source to walk, or the reason it is skipped. */
interface ScanRead {
  readonly source?: ScanSource;
  readonly reason?: string;
  readonly warning?: string;
}

/**
 * Reads the phrase as BIP39 words, or says why the BIP39 schemes are skipped.
 * @param blockchain - Chain whose schemes apply
 * @param schemes - BIP39 schemes of the chain
 * @param input - Phrase, passphrase, word list and checksum override
 * @param input.mnemonic - Phrase as given
 * @param input.passphrase - BIP39 passphrase
 * @param input.wordlist - Selected BIP39 word list
 * @param input.language - Its name for the error
 * @param input.allowInvalidChecksum - Whether a checksum failure is scanned
 * @returns {ScanRead} Source, or the reason it is skipped
 */
function bip39ScanSource(
  blockchain: Readonly<AbstractBlockchain>,
  schemes: readonly ScanScheme[],
  {
    mnemonic,
    passphrase,
    wordlist,
    language,
    allowInvalidChecksum,
  }: {
    readonly mnemonic: string;
    readonly passphrase: string;
    readonly wordlist: readonly string[];
    readonly language: BIP39Language;
    readonly allowInvalidChecksum: boolean;
  },
): ScanRead {
  const words = normalizeMnemonic(mnemonic);
  const inspection = inspectBIP39Mnemonic(words, wordlist);
  if (inspection.checksumValid === null) {
    return { reason: describeInvalidMnemonic(words, inspection, wordlist, language) };
  }
  if (!inspection.valid && !allowInvalidChecksum) {
    return {
      reason: "Invalid BIP39 mnemonic: the checksum does not match. allowInvalidChecksum scans it",
    };
  }
  const seed = mnemonicToSeed(words, passphrase);
  const walkers = {
    secp256k1: nodeWalker(getMasterKeyFromSeed(seed)),
    ed25519: nodeWalker(getSLIP10MasterKey(seed)),
  };
  const curveOf = (scheme: ScanScheme): Curve => {
    if (scheme.addressType === "ed25519" || scheme.addressType === "secp256k1") {
      return scheme.addressType;
    }
    return typeof blockchain.curve === "string" ? blockchain.curve : "secp256k1";
  };
  return {
    source: {
      schemes,
      addressAt: (scheme) => hdAddress(blockchain, scheme, walkers[curveOf(scheme)]),
    },
    ...(inspection.valid
      ? {}
      : {
          warning:
            "BIP39 checksum is invalid. Scanned the supplied words without repairing the checksum.",
        }),
  };
}

/**
 * Reads the phrase as a native Electrum seed, or says why the Electrum schemes are skipped.
 * @param blockchain - Bitcoin on the selected network
 * @param mnemonic - Phrase as given
 * @param passphrase - Electrum seed extension
 * @returns {ScanRead} Source, or the reason it is skipped
 */
function electrumScanSource(
  blockchain: Readonly<AbstractBlockchain>,
  mnemonic: string,
  passphrase: string,
): ScanRead {
  const seedType = inspectElectrumSeed(mnemonic);
  if (seedType === "standard" || seedType === "segwit") {
    const nodeAt = nodeWalker(getMasterKeyFromSeed(deriveElectrumSeed(mnemonic, passphrase).seed));
    return {
      source: {
        schemes: [ELECTRUM_SCHEMES[seedType]],
        addressAt: (scheme) => hdAddress(blockchain, scheme, nodeAt),
      },
    };
  }
  if (seedType === "old") {
    if (passphrase !== "") return { reason: "Old Electrum seeds take no passphrase" };
    const masterPublicKey = deriveOldMasterPublicKey(mnemonic);
    return {
      source: {
        schemes: [{ name: "electrum-old", path: "{change}/{index}", addressType: "legacy" }],
        addressAt: () => (path) => {
          const [change = 0, index = 0] = path.split("/").map(Number);
          const publicKey = deriveOldPublicKey(masterPublicKey, change, index).toHex();
          return { publicKey, address: blockchain.getAddress(publicKey, "legacy") };
        },
      },
    };
  }
  if (seedType === "2fa" || seedType === "2fa_segwit") {
    return { reason: "Electrum 2FA seeds are multisig and are not derived" };
  }
  return { reason: "Not an Electrum seed" };
}

/** Scan arguments after the executor's own checks. */
interface ScanArguments {
  readonly mnemonic: string;
  readonly address: string;
  readonly passphrase: string;
  readonly allowInvalidChecksum: boolean;
  readonly ranges: { readonly accounts: number; readonly indices: number };
}

/**
 * Checks the scan arguments for hosts that skip the schema, never echoing the phrase.
 * @param args - Raw arguments
 * @param args.mnemonic - Phrase
 * @param args.address - Target address
 * @param args.passphrase - Passphrase
 * @param args.allowInvalidChecksum - Checksum override
 * @param args.accounts - Account count
 * @param args.indices - Index count
 * @returns {ScanArguments} The checked arguments
 */
function scanArguments(args: Readonly<Record<string, unknown>>): ScanArguments {
  const { allowInvalidChecksum = false } = args;
  if (typeof allowInvalidChecksum !== "boolean") {
    throw new TypeError("allowInvalidChecksum must be a boolean");
  }
  const mnemonic = requiredString(args.mnemonic, "Mnemonic");
  if (mnemonic.length > MAX_SCAN_MNEMONIC_LENGTH) {
    throw new RangeError(`Mnemonic must not exceed ${MAX_SCAN_MNEMONIC_LENGTH} characters`);
  }
  if (mnemonic.trim() === "") throw new TypeError("Mnemonic must not be empty");
  const address = requiredString(args.address, "Address").trim();
  if (address === "" || Array.from(address).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Address must be 1 to ${MAX_ADDRESS_LENGTH} characters`);
  }
  return {
    mnemonic,
    address,
    passphrase: optionalString(args.passphrase, "Passphrase") ?? "",
    allowInvalidChecksum,
    ranges: {
      accounts: scanCount(args.accounts, "accounts", SCAN_ACCOUNTS),
      indices: scanCount(args.indices, "indices", SCAN_INDICES),
    },
  };
}

/** Seeds a phrase opens, with the families it does not open and why. */
interface ScanSources {
  readonly sources: ScanSource[];
  readonly skipped: ScanSkipped[];
  readonly warnings: string[];
}

/**
 * Reads the phrase as BIP39 words and, on Bitcoin, as an Electrum seed; throws when neither works.
 * @param blockchain - Chain on the selected network
 * @param schemes - BIP39 schemes of the chain
 * @param args - Checked scan arguments
 * @param languageValue - Raw BIP39 language
 * @returns {Promise<ScanSources>} Seeds to walk and the families skipped
 */
async function scanSources(
  blockchain: Readonly<AbstractBlockchain>,
  schemes: readonly ScanScheme[],
  args: ScanArguments,
  languageValue: unknown,
): Promise<ScanSources> {
  const language = parseBIP39Language(languageValue);
  const found: ScanSources = { sources: [], skipped: [], warnings: [] };
  const bip39Source = bip39ScanSource(blockchain, schemes, {
    ...args,
    wordlist: await loadBIP39Wordlist(language),
    language,
  });
  const electrum: ScanRead =
    blockchain.name === "bitcoin"
      ? electrumScanSource(blockchain, args.mnemonic, args.passphrase)
      : {};
  for (const [family, read] of [
    ["bip39", bip39Source],
    ["electrum", electrum],
  ] as const) {
    if (read.source) found.sources.push(read.source);
    if (read.reason !== undefined) found.skipped.push({ family, reason: read.reason });
  }
  if (bip39Source.warning !== undefined) found.warnings.push(bip39Source.warning);
  if (found.sources.length === 0) {
    throw new TypeError(
      found.skipped.map(({ family, reason }) => `${family}: ${reason}`).join("; "),
    );
  }
  return found;
}

/**
 * Walks every scheme of every seed in order until one reaches the address.
 * @param sources - Seeds to walk
 * @param args - Checked scan arguments
 * @returns {{ tried: ScanTried[]; match?: ScanMatch }} Schemes walked and the match
 */
function walkSources(
  sources: readonly ScanSource[],
  args: ScanArguments,
): { tried: ScanTried[]; match?: ScanMatch } {
  const tried: ScanTried[] = [];
  for (const source of sources) {
    for (const scheme of source.schemes) {
      const walk = walkScheme(scheme, args.ranges, source.addressAt(scheme), (written) =>
        sameAddress(written, args.address),
      );
      tried.push(walk.tried);
      if (walk.match) return { tried, match: walk.match };
    }
  }
  return { tried };
}

/**
 * Writes a scan result: the match, or every scheme tried and every family skipped.
 * @param details - Scan details
 * @returns {string} Text for the model
 */
function scanText(details: Readonly<ScannedWalletDetails>): string {
  const { match, checked } = details;
  const counted = `${checked} ${checked === 1 ? "address" : "addresses"} checked`;
  const lines = match
    ? [
        `Match: ${match.scheme}, ${counted}`,
        `Path: ${match.path}`,
        ...addressTypeLines(match.addressType),
        `Public key: ${match.publicKey}`,
        `Address: ${match.address}`,
      ]
    : [
        `Match: none, ${counted}`,
        ...details.tried.map(({ scheme, path, addressType }) =>
          [`Tried: ${scheme}`, path, addressType].filter(Boolean).join(" "),
        ),
        ...details.skipped.map(({ family, reason }) => `Skipped: ${family}. ${reason}`),
      ];
  return [
    `Chain: ${details.chain} (${details.network})`,
    ...lines,
    ...(details.warnings ?? []).map((warning) => `Warning: ${warning}`),
  ].join("\n");
}

/** Why a chain with no scan schemes has none, where a generic answer would mislead. */
const SCAN_REFUSALS: Readonly<Record<string, string>> = {
  polkadot:
    "polkadot has no wallet paths to scan: wallets name their own junctions, so derive each one with keys_hd_wallet_derive",
  monero:
    "monero has no wallet paths to scan: a wallet restores from its 25 seed words, so pass them to keys_wallet_derive",
};

/**
 * The error a scan on a chain without schemes answers with.
 * @param chain - Name of the loaded chain
 * @returns {string} The chain's own reason, or the generic one
 */
function scanRefusal(chain: string): string {
  return (
    SCAN_REFUSALS[chain] ??
    `${chain} has no wallet paths to scan: its HD derivation is not supported`
  );
}

/**
 * Scans a fixed, named list of wallet paths for the one that reaches an address.
 * @param chainValue - Blockchain name
 * @param mnemonicValue - Public or disposable BIP39 or Electrum phrase
 * @param addressValue - Target address on the chain and network
 * @param passphraseValue - Optional BIP39 passphrase or Electrum seed extension
 * @param networkValue - Optional network name
 * @param languageValue - Optional BIP39 language key
 * @param allowInvalidChecksumValue - Scan BIP39 words that fail only the checksum, default false
 * @param accountsValue - Accounts from 0, default 3
 * @param indicesValue - Address indices from 0, default 20
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot
 * @param coinTypeValue - Optional coin type on cosmos, in place of the one prefix stands for
 * @returns {Promise<ToolResult<ScannedWalletDetails>>} The match, or every scheme tried
 */
export async function scanHdWallet(
  chainValue: unknown,
  mnemonicValue: unknown,
  addressValue: unknown,
  passphraseValue?: unknown,
  networkValue?: unknown,
  languageValue?: unknown,
  allowInvalidChecksumValue?: unknown,
  accountsValue?: unknown,
  indicesValue?: unknown,
  prefixValue?: unknown,
  coinTypeValue?: unknown,
): Promise<ToolResult<ScannedWalletDetails>> {
  const args = scanArguments({
    mnemonic: mnemonicValue,
    address: addressValue,
    passphrase: passphraseValue,
    allowInvalidChecksum: allowInvalidChecksumValue,
    accounts: accountsValue,
    indices: indicesValue,
  });
  const { blockchain } = await getBlockchain(
    chainValue,
    networkValue,
    undefined,
    prefixValue,
    coinTypeValue,
  );
  const schemes = scanSchemes(blockchain.name, blockchain.network, blockchain.coinType);
  if (schemes === undefined) {
    throw new RangeError(scanRefusal(blockchain.name));
  }
  if (!blockchain.validateAddress(args.address)) {
    throw new TypeError(
      `Address is not a ${blockchain.name} ${blockchain.network} address, so no path can reach it`,
    );
  }
  const { sources, skipped, warnings } = await scanSources(
    blockchain,
    schemes,
    args,
    languageValue,
  );
  const { tried, match } = walkSources(sources, args);
  const details: ScannedWalletDetails = {
    chain: blockchain.name,
    network: blockchain.network,
    address: args.address,
    found: match !== undefined,
    checked: tried.reduce((sum, walk) => sum + walk.addresses, 0),
    ...(match ? { match } : {}),
    tried,
    skipped,
    ...(warnings.length === 0 ? {} : { warnings }),
  };
  return { content: content(scanText(details)), details };
}

/** Watch-only wallet material derived from an extended public key. */
export interface DerivedXpubWalletDetails {
  chain: string;
  network: string;
  prefix: string;
  path: string;
  addressType?: string;
  publicKey: string;
  address: string;
}

/**
 * Derives a watch-only address from an extended public key and normal levels below it.
 * @param chainValue - Blockchain name.
 * @param extendedKeyValue - Extended public key such as an account `xpub`.
 * @param pathValue - Normal levels below the key, such as `m/0/0`.
 * @param addressTypeValue - Optional address type that wins over the one the prefix stands for.
 * @param networkValue - Optional network name.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @returns {Promise<ToolResult<DerivedXpubWalletDetails>>} Public key and address at the path.
 */
export async function deriveXpubWallet(
  chainValue: unknown,
  extendedKeyValue: unknown,
  pathValue: unknown,
  addressTypeValue?: unknown,
  networkValue?: unknown,
  prefixValue?: unknown,
): Promise<ToolResult<DerivedXpubWalletDetails>> {
  const extendedKey = requiredString(extendedKeyValue, "Extended key");
  const path = requiredString(pathValue, "Derivation path");
  if (path.length > 256) throw new TypeError("Invalid derivation path");
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
    prefixValue,
  );
  const wallet = blockchain.deriveXpubWallet(extendedKey, path, addressType);
  const details = {
    chain: blockchain.name,
    network: blockchain.network,
    prefix: wallet.prefix,
    path,
    ...(wallet.addressType === undefined ? {} : { addressType: wallet.addressType }),
    publicKey: wallet.keys.public,
    address: wallet.address,
  };
  return {
    content: content(
      [
        `Chain: ${details.chain} (${details.network})`,
        `Extended key: ${details.prefix}`,
        `Path: ${path}`,
        ...addressTypeLines(details.addressType),
        `Public key: ${details.publicKey}`,
        `Address: ${details.address}`,
      ].join("\n"),
    ),
    details,
  };
}

/** What the parent of a leaked child key gives away, with its xprv only on request. */
export interface RecoveredParentDetails {
  /** Prefix of the extended public key, such as `xpub`. */
  prefix: string;
  /** Index of the child below the parent. */
  index: number;
  /** Whether the child key derives from the extended public key at that index. */
  recovered: boolean;
  /** Parent depth, 0 for a master key. */
  depth?: number;
  /** Parent fingerprint as 8 hex digits, the one its children carry. */
  fingerprint?: string;
  /** Parent extended private key, only when the caller asked for it. */
  extendedPrivateKey?: string;
}

/**
 * Reads a child private key given as an xprv, 64 hex digits or a WIF of any supported chain.
 * Errors name the accepted forms and never echo the value.
 * @param value - Raw child argument
 * @returns {string | Uint8Array} An xprv as is, or the bare private key
 */
function childKeyArgument(value: unknown): string | Uint8Array {
  const child = requiredString(value, "Child key");
  if (PRIVATE_KEY_HEX.test(child)) return Uint8Array.fromHex(child);
  if (child.length > MAX_EXTENDED_KEY_LENGTH) throw new RangeError("Child key is too long");
  if (child.length > MAX_WIF_LENGTH && !/^0x/iu.test(child)) return child;
  for (const chain of TOOL_WIF_CHAINS) {
    for (const network of TOOL_NETWORKS) {
      try {
        return Uint8Array.fromHex(decodeWIF(child, { chain, network }).privateKey);
      } catch {
        continue;
      }
    }
  }
  throw new TypeError("Child key must be an xprv, a WIF or 64 hex digits without 0x");
}

/** Parent recovery arguments after the executor's own checks. */
interface ParentArguments {
  extendedKey: string;
  child: string | Uint8Array;
  requested: number | undefined;
  revealKey: boolean;
}

/**
 * Checks the parent recovery arguments for hosts that skip the schema, never echoing a key.
 * @param extendedKeyValue - Raw extended key argument
 * @param childValue - Raw child argument
 * @param indexValue - Raw index argument
 * @param revealKeyValue - Raw revealKey argument
 * @returns {ParentArguments} The checked arguments
 */
function parentArguments(
  extendedKeyValue: unknown,
  childValue: unknown,
  indexValue: unknown,
  revealKeyValue: unknown,
): ParentArguments {
  const extendedKey = requiredString(extendedKeyValue, "Extended key");
  if (extendedKey.length > MAX_EXTENDED_KEY_LENGTH) {
    throw new RangeError("Extended key is too long");
  }
  const child = childKeyArgument(childValue);
  const requested = optionalIndex(indexValue, "Index");
  const revealKey = revealKeyValue ?? false;
  if (typeof revealKey !== "boolean") throw new TypeError("revealKey must be a boolean");
  if (typeof child !== "string" && requested === undefined) {
    throw new TypeError("Index is required unless the child key is an xprv");
  }
  return { extendedKey, child, requested, revealKey };
}

/**
 * Recovers the parent of a leaked normal child; a child from another xpub is a result, not an error.
 * @param extendedKeyValue - Parent extended public key
 * @param childValue - Child xprv, WIF or hex private key
 * @param indexValue - Child index; required unless the child is an xprv
 * @param revealKeyValue - Whether to return the parent xprv, false by default
 * @returns {ToolResult<RecoveredParentDetails>} Verdict, fingerprint and the xprv on request
 */
export function recoverBip32Parent(
  extendedKeyValue: unknown,
  childValue: unknown,
  indexValue?: unknown,
  revealKeyValue?: unknown,
): ToolResult<RecoveredParentDetails> {
  const { extendedKey, child, requested, revealKey } = parentArguments(
    extendedKeyValue,
    childValue,
    indexValue,
    revealKeyValue,
  );
  const prefix = extendedKey.slice(0, 4);
  let recovered: RecoveredParent;
  try {
    recovered = recoverParent(extendedKey, child, requested);
  } catch (error) {
    if (!(error instanceof BIP32ChildMismatchError)) throw error;
    return {
      content: content(
        [
          `Extended key: ${prefix}`,
          `Child index: ${error.index}`,
          `Parent: not recovered. ${error.message}`,
        ].join("\n"),
      ),
      details: { prefix, index: error.index, recovered: false },
    };
  }
  const fingerprint = recovered.parent.fingerprint.toString(16).padStart(8, "0");
  const details: RecoveredParentDetails = {
    prefix,
    index: recovered.index,
    recovered: true,
    depth: recovered.parent.depth,
    fingerprint,
    ...(revealKey ? { extendedPrivateKey: recovered.parent.privateExtendedKey } : {}),
  };
  return {
    content: content(
      [
        `Extended key: ${prefix}, depth ${details.depth}`,
        `Child index: ${recovered.index}`,
        "Parent: recovered",
        `Fingerprint: ${fingerprint}`,
        ...(revealKey ? [`Extended private key: ${recovered.parent.privateExtendedKey}`] : []),
      ].join("\n"),
    ),
    details,
  };
}

/** Public wallet of an old Electrum seed, which walks a change chain and an index, not a path. */
export interface DerivedOldElectrumWalletDetails {
  chain: "bitcoin";
  network: string;
  scheme: "electrum";
  seedType: "old";
  /** 128 hex digits, x then y, as Electrum shows the MPK of a watching wallet. */
  masterPublicKey: string;
  change: number;
  index: number;
  /** Uncompressed, the key the P2PKH address hashes. */
  publicKey: string;
  address: string;
}

/**
 * Derives public Bitcoin wallet material from a complete Electrum phrase, by path or old index.
 * @param mnemonicValue - Public or disposable Electrum phrase
 * @param pathValue - Exact absolute BIP32 path, for standard and SegWit seeds
 * @param passphraseValue - Electrum passphrase; old seeds take none
 * @param networkValue - Bitcoin network
 * @param changeValue - Old seeds only: 0 for receiving, 1 for change. Default 0
 * @param indexValue - Old seeds only: address index. Default 0
 * @returns {Promise<ToolResult<DerivedWalletDetails | DerivedOldElectrumWalletDetails>>} Public wallet
 */
export async function deriveElectrumWallet(
  mnemonicValue: unknown,
  pathValue: unknown,
  passphraseValue?: unknown,
  networkValue?: unknown,
  changeValue?: unknown,
  indexValue?: unknown,
): Promise<
  ToolResult<
    | (DerivedWalletDetails & { scheme: "electrum"; seedType: "standard" | "segwit" })
    | DerivedOldElectrumWalletDetails
  >
> {
  const mnemonic = requiredString(mnemonicValue, "Electrum mnemonic");
  const passphrase = optionalString(passphraseValue, "Electrum passphrase") ?? "";
  const change = optionalIndex(changeValue, "Change", 1);
  const index = optionalIndex(indexValue, "Index");
  if (inspectElectrumSeed(mnemonic) === "old") {
    return deriveOldElectrumWallet(mnemonic, pathValue, passphrase, {
      change,
      index,
      networkValue,
    });
  }
  const path = electrumPath(pathValue, change !== undefined || index !== undefined);
  const { blockchain } = await getBlockchain("bitcoin", networkValue);
  const { seed, seedType, scheme } = deriveElectrumSeed(mnemonic, passphrase);
  const privateKey = deriveHDKey(getMasterKeyFromSeed(seed), path).privateKey;
  if (!privateKey) throw new Error("No private key at the supplied path");
  const wallet = blockchain.deriveWallet(
    privateKey.toHex(),
    { compressed: true },
    seedType === "segwit" ? "segwit" : "legacy",
  );
  const details = {
    chain: "bitcoin",
    network: blockchain.network,
    scheme,
    seedType,
    path,
    publicKey: wallet.keys.public,
    address: wallet.address,
  };
  return {
    content: content(
      `Scheme: ${scheme}\nSeed type: ${seedType}\nChain: bitcoin (${details.network})\nPath: ${path}\nPublic key: ${details.publicKey}\nAddress: ${details.address}`,
    ),
    details,
  };
}

/**
 * Reads the BIP32 path a standard or SegWit seed needs, refusing the old seed arguments.
 * @param pathValue - Raw path argument
 * @param oldArguments - Whether change or index came along
 * @returns {string} The path
 */
function electrumPath(pathValue: unknown, oldArguments: boolean): string {
  if (oldArguments) {
    throw new TypeError("Change and index apply to old Electrum seeds only; pass a BIP32 path");
  }
  if (isUnset(pathValue))
    throw new TypeError("Standard and SegWit Electrum seeds need a BIP32 path");
  const path = requiredString(pathValue, "Derivation path");
  if (path.length > 256 || !DERIVATION_PATH_PATTERN.test(path)) {
    throw new TypeError("Invalid derivation path");
  }
  return path;
}

/**
 * Derives one P2PKH address of an old seed from its master public key, as Electrum before 2.0 did.
 * @param mnemonic - Old seed words or hex seed
 * @param pathValue - Raw path argument, which an old seed refuses
 * @param passphrase - Electrum passphrase, which an old seed refuses
 * @param options - Change chain and index, 0 when left out, and the Bitcoin network
 * @param options.change - 0 for receiving, 1 for change
 * @param options.index - Address index
 * @param options.networkValue - Bitcoin network
 * @returns {Promise<ToolResult<DerivedOldElectrumWalletDetails>>} MPK, key and address
 */
async function deriveOldElectrumWallet(
  mnemonic: string,
  pathValue: unknown,
  passphrase: string,
  {
    change = 0,
    index = 0,
    networkValue,
  }: { readonly change?: number; readonly index?: number; readonly networkValue: unknown },
): Promise<ToolResult<DerivedOldElectrumWalletDetails>> {
  if (!isUnset(pathValue)) {
    throw new TypeError("Old Electrum seeds have no BIP32 path; pass change and index instead");
  }
  if (passphrase !== "") throw new TypeError("Old Electrum seeds take no passphrase");
  const { blockchain } = await getBlockchain("bitcoin", networkValue);
  const masterPublicKey = deriveOldMasterPublicKey(mnemonic);
  const publicKey = deriveOldPublicKey(masterPublicKey, change, index).toHex();
  const details: DerivedOldElectrumWalletDetails = {
    chain: "bitcoin",
    network: blockchain.network,
    scheme: "electrum",
    seedType: "old",
    masterPublicKey: masterPublicKey.toHex(),
    change,
    index,
    publicKey,
    address: blockchain.getAddress(publicKey, "legacy"),
  };
  return {
    content: content(
      [
        "Scheme: electrum",
        "Seed type: old",
        `Chain: bitcoin (${details.network})`,
        `Master public key: ${details.masterPublicKey}`,
        `Change: ${change}`,
        `Index: ${index}`,
        `Public key: ${publicKey}`,
        `Address: ${details.address}`,
      ].join("\n"),
    ),
    details,
  };
}

/** Public wallet of a brainwallet, with the target verdict when one was given. */
export interface DerivedBrainwalletDetails {
  chain: BrainwalletChain;
  network: string;
  /** Bitcoin only: always P2PKH. */
  addressType?: "legacy";
  /** Bitcoin only: whether the address hashes the compressed key. */
  compressed?: boolean;
  publicKey: string;
  address: string;
  matches?: boolean;
}

const EVEN_HEX = /^(?:[0-9a-f]{2})*$/iu;

/**
 * Picks one value out of a closed set, naming the set when the value is not in it.
 * @param value - Raw argument
 * @param name - Argument name for the error
 * @param allowed - Values the argument takes
 * @returns {Value} The matched value
 */
function oneOf<const Value extends string>(
  value: unknown,
  name: string,
  allowed: readonly Value[],
): Value {
  const matched = allowed.find((candidate) => candidate === value);
  if (matched === undefined) throw new RangeError(`${name} must be one of ${allowed.join(", ")}`);
  return matched;
}

/**
 * Reads one cost parameter against the ceiling the KDF tools set.
 * @param value - Raw argument
 * @param name - Parameter name, a key of `KDF_COST_LIMITS`
 * @param minimum - Smallest value the KDF takes
 * @returns {number} The parameter
 */
function costArgument(value: unknown, name: keyof typeof KDF_COST_LIMITS, minimum = 1): number {
  const maximum = KDF_COST_LIMITS[name];
  if (typeof value !== "number" || !Number.isInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

/**
 * Tells whether a cost was left out. OMP sends 0 for an unused number, which no KDF takes.
 * @param value - Raw argument
 * @returns {boolean} True for a missing, zero or blank value
 */
function isUnsetCost(value: unknown): boolean {
  return value === 0 || isUnset(value);
}

/**
 * Reads the KDF and its costs, refusing the other KDF's so no option drops silently.
 * @param kdf - scrypt or pbkdf2
 * @param args - Tool arguments
 * @returns {BrainwalletKDF} The KDF with its parameters
 */
function brainwalletKDF(
  kdf: BrainwalletKDF["kdf"],
  args: Readonly<Record<string, unknown>>,
): BrainwalletKDF {
  const foreign = (kdf === "scrypt" ? ["iterations", "digest"] : ["N", "r", "p"]).filter(
    (name) => !isUnsetCost(args[name]),
  );
  if (foreign.length > 0) throw new RangeError(`${kdf} does not take ${foreign.join(", ")}`);
  if (kdf === "pbkdf2") {
    const iterations = costArgument(args["iterations"], "iterations");
    return { kdf, iterations, digest: oneOf(args["digest"], "digest", ["sha256", "sha512"]) };
  }
  const N = costArgument(args["N"], "N", 2);
  if ((N & (N - 1)) !== 0) throw new RangeError("N must be a power of 2");
  const r = costArgument(args["r"], "r");
  if (N * r > MAX_SCRYPT_BLOCKS) {
    throw new RangeError(`N * r must not exceed ${MAX_SCRYPT_BLOCKS}`);
  }
  return { kdf, N, r, p: costArgument(args["p"], "p") };
}

/**
 * Reads a passphrase or salt under the tool's length limit.
 * @param value - Raw argument
 * @param name - Argument name for the error
 * @returns {string} The text, untouched
 */
function brainwalletText(value: unknown, name: string): string {
  const text = requiredString(value, name);
  if (Array.from(text).length > MAX_BRAINWALLET_INPUT_LENGTH) {
    throw new RangeError(`${name} must not exceed ${MAX_BRAINWALLET_INPUT_LENGTH} characters`);
  }
  return text;
}

/** Arguments a plain brainwallet has no use for. OMP sends 0 or an empty string for each. */
const SALTED_ONLY_ARGUMENTS = [
  "salt",
  "saltEncoding",
  "hashed",
  "N",
  "r",
  "p",
  "digest",
  "keyLength",
];

/**
 * Reads the rounds of a plain brainwallet, refusing every salted recipe argument.
 * @param kdf - Digest the passphrase goes through
 * @param args - Tool arguments
 * @returns {PlainBrainwalletOptions} The digest with its rounds
 */
function plainBrainwalletRecipe(
  kdf: PlainBrainwalletOptions["kdf"],
  args: Readonly<Record<string, unknown>>,
): PlainBrainwalletOptions {
  const foreign = SALTED_ONLY_ARGUMENTS.filter(
    (name) => args[name] !== undefined && args[name] !== "" && args[name] !== 0,
  );
  if (foreign.length > 0) throw new RangeError(`${kdf} does not take ${foreign.join(", ")}`);
  if (isUnsetCost(args["iterations"])) return { kdf };
  return { kdf, iterations: costArgument(args["iterations"], "iterations") };
}

/**
 * Reads the salt a salted recipe or WarpWallet requires, empty for none.
 * @param kdf - KDF name for the error
 * @param args - Tool arguments
 * @returns {Uint8Array | string} Decoded hex bytes, or the text to read as UTF-8
 */
function brainwalletSalt(
  kdf: string,
  args: Readonly<Record<string, unknown>>,
): Uint8Array | string {
  if (args["salt"] === undefined) throw new TypeError(`${kdf} needs a salt, empty for none`);
  const saltText = brainwalletText(args["salt"], "Salt");
  const saltEncoding = oneOf(args["saltEncoding"], "saltEncoding", ["utf8", "hex"]);
  if (saltEncoding === "hex" && !EVEN_HEX.test(saltText)) {
    throw new TypeError("Salt must be hex digit pairs without 0x when saltEncoding is hex");
  }
  return saltEncoding === "hex" ? Uint8Array.fromHex(saltText) : saltText;
}

/** Arguments WarpWallet fixes for itself. OMP sends 0 or an empty string for each. */
const WARP_FIXED_ARGUMENTS = ["hashed", "N", "r", "p", "iterations", "digest", "keyLength"];

/**
 * Reads the salt of a WarpWallet, refusing every cost it fixes for itself.
 * @param args - Tool arguments
 * @returns {WarpWalletOptions} WarpWallet with its salt
 */
function warpWalletRecipe(args: Readonly<Record<string, unknown>>): WarpWalletOptions {
  const foreign = WARP_FIXED_ARGUMENTS.filter((name) => !isUnsetCost(args[name]));
  if (foreign.length > 0) throw new RangeError(`warpwallet does not take ${foreign.join(", ")}`);
  return { kdf: "warpwallet", salt: brainwalletSalt("warpwallet", args) };
}

/**
 * Reads the passphrase and the full recipe, refusing anything the KDF would not run as given.
 * @param args - Tool arguments
 * @returns {{ passphrase: string; options: BrainwalletRecipe }} Passphrase and recipe
 */
function brainwalletRecipe(args: Readonly<Record<string, unknown>>): {
  passphrase: string;
  options: BrainwalletRecipe;
} {
  const passphrase = brainwalletText(args["passphrase"], "Passphrase");
  const kdf = oneOf(args["kdf"], "kdf", ["scrypt", "pbkdf2", "sha256", "keccak256", "warpwallet"]);
  if (kdf === "sha256" || kdf === "keccak256") {
    return { passphrase, options: plainBrainwalletRecipe(kdf, args) };
  }
  if (kdf === "warpwallet") return { passphrase, options: warpWalletRecipe(args) };
  const salt = brainwalletSalt(kdf, args);
  const stretch = brainwalletKDF(kdf, args);
  const hashed = oneOf(args["hashed"], "hashed", ["bytes", "hex"]);
  const options = { ...stretch, salt, hashed };
  if (isUnsetCost(args["keyLength"])) return { passphrase, options };
  return {
    passphrase,
    options: { ...options, keyLength: costArgument(args["keyLength"], "keyLength") },
  };
}

/** Chains the brainwallet tool writes an address for. */
type BrainwalletChain = "bitcoin" | "ethereum";

/**
 * Reads the Bitcoin key form. Ethereum hashes the uncompressed key, so it refuses only true.
 * @param chain - Chain the address is for
 * @param value - Raw argument
 * @returns {boolean | undefined} The Bitcoin key form, undefined on Ethereum
 */
function brainwalletCompressed(chain: BrainwalletChain, value: unknown): boolean | undefined {
  if (chain === "ethereum") {
    if (value === true) throw new RangeError("ethereum does not take compressed");
    if (value !== undefined && value !== false) throw new TypeError("compressed must be a boolean");
    return undefined;
  }
  if (typeof value !== "boolean") throw new TypeError("compressed must be a boolean");
  return value;
}

/**
 * Reads where the address goes: chain, Bitcoin key form and the optional target.
 * @param args - Tool arguments
 * @returns {{ chain: BrainwalletChain; compressed?: boolean; target?: string }} Address settings
 */
function brainwalletAddressing(args: Readonly<Record<string, unknown>>): {
  chain: BrainwalletChain;
  compressed: boolean | undefined;
  target: string | undefined;
} {
  const chain = isUnset(args["chain"])
    ? "bitcoin"
    : oneOf(args["chain"], "chain", ["bitcoin", "ethereum"]);
  const target = optionalName(args["target"], "Target");
  if (target !== undefined && Array.from(target).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Target must not exceed ${MAX_ADDRESS_LENGTH} characters`);
  }
  return { chain, compressed: brainwalletCompressed(chain, args["compressed"]), target };
}

/**
 * Writes the brainwallet answer, one fact per line.
 * @param details - Public wallet and verdict
 * @returns {string} The text the tool returns
 */
function brainwalletAnswer(details: Readonly<DerivedBrainwalletDetails>): string {
  const { compressed, matches } = details;
  return [
    `Chain: ${details.chain} (${details.network})`,
    ...(compressed === undefined
      ? []
      : [`Address type: legacy, ${compressed ? "compressed" : "uncompressed"}`]),
    `Public key: ${details.publicKey}`,
    `Address: ${details.address}`,
    ...(matches === undefined ? [] : [`Target: ${matches ? "match" : "no match"}`]),
  ].join("\n");
}

/**
 * Derives the public wallet of a brainwallet, never echoing its key or passphrase.
 * @param args - Tool arguments, as `DERIVE_BRAINWALLET_PARAMETERS` names them
 * @returns {Promise<ToolResult<DerivedBrainwalletDetails>>} Public key, address and verdict
 */
export async function deriveBrainwallet(
  args: Readonly<Record<string, unknown>>,
): Promise<ToolResult<DerivedBrainwalletDetails>> {
  const { passphrase, options } = brainwalletRecipe(args);
  const { chain, compressed, target } = brainwalletAddressing(args);
  const { blockchain } = await getBlockchain(chain, args["network"]);
  const privateKey = deriveBrainwalletKey(passphrase, options).toHex();
  const wallet =
    compressed === undefined
      ? blockchain.deriveWallet(privateKey)
      : blockchain.deriveWallet(privateKey, { compressed }, "legacy");
  const matches =
    chain === "ethereum"
      ? wallet.address.toLowerCase() === target?.toLowerCase()
      : wallet.address === target;
  const details: DerivedBrainwalletDetails = {
    chain,
    network: blockchain.network,
    ...(compressed === undefined ? {} : { addressType: "legacy", compressed }),
    publicKey: wallet.keys.public,
    address: wallet.address,
    ...(target === undefined ? {} : { matches }),
  };
  return { content: content(brainwalletAnswer(details)), details };
}

/**
 * Derive a disposable seed after validating the mnemonic against the selected list.
 * @param mnemonicValue - Public or disposable BIP39 mnemonic.
 * @param passphraseValue - BIP39 passphrase, defaulting to empty.
 * @param languageValue - Optional official BIP39 language key.
 * @returns {Promise<ToolResult<DerivedBIP39SeedDetails>>} Seed hex and transcript warning.
 */
export async function deriveBip39Seed(
  mnemonicValue: unknown,
  passphraseValue?: unknown,
  languageValue?: unknown,
): Promise<ToolResult<DerivedBIP39SeedDetails>> {
  const input = requiredString(mnemonicValue, "BIP39 mnemonic");
  const passphrase = optionalString(passphraseValue, "BIP39 passphrase") ?? "";
  if (
    Array.from(input).length > MAX_BIP39_SEED_INPUT_LENGTH ||
    Array.from(passphrase).length > MAX_BIP39_SEED_INPUT_LENGTH
  ) {
    throw new RangeError(
      `BIP39 mnemonic and passphrase must not exceed ${MAX_BIP39_SEED_INPUT_LENGTH} characters each`,
    );
  }
  const mnemonic = normalizedMnemonic(input);
  const language = parseBIP39Language(languageValue);
  const wordlist = await loadBIP39Wordlist(language);
  const inspection = inspectBIP39Mnemonic(mnemonic, wordlist);
  if (!inspection.valid) {
    throw new TypeError(describeInvalidMnemonic(mnemonic, inspection, wordlist, language));
  }
  const seed = Buffer.from(await bip39.mnemonicToSeed(mnemonic, passphrase)).toString("hex");
  return {
    content: content(
      `Language: ${language}\nSeed: ${seed}\nThis seed is saved in the transcript. Never use it for real funds.`,
    ),
    details: { language, seed },
  };
}

/**
 * Generate a disposable mnemonic using the library's cryptographic randomness.
 * @param wordsValue - Word count, defaulting to 12.
 * @param languageValue - Optional official BIP39 language key.
 * @returns {Promise<ToolResult<GeneratedMnemonicDetails>>} Mnemonic and transcript warning.
 */
export async function generateBip39Mnemonic(
  wordsValue: unknown = 12,
  languageValue?: unknown,
): Promise<ToolResult<GeneratedMnemonicDetails>> {
  if (typeof wordsValue !== "number" || !TOOL_MNEMONIC_WORD_COUNTS.includes(wordsValue)) {
    throw new RangeError("BIP39 word count must be 12, 15, 18, 21, or 24");
  }
  const language = parseBIP39Language(languageValue);
  const wordlist = await loadBIP39Wordlist(language);
  const mnemonic = bip39.generateMnemonic(wordlist, (wordsValue / 3) * 32);
  return {
    content: content(
      `Language: ${language}\nMnemonic: ${mnemonic}\nWords: ${wordsValue}\nThis mnemonic is saved in the transcript. Never use it for real funds.`,
    ),
    details: { language, words: wordsValue, mnemonic },
  };
}

/**
 * Quotes text for one result line, escaping every code point that could break or hide it.
 * @param text - Text read from entropy or passed by the caller.
 * @returns {string} The text in double quotes.
 */
function quoteEntropyText(text: string): string {
  const escaped = text.replaceAll(/[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}"\\]/gu, (character) =>
    character === '"' || character === "\\"
      ? `\\${character}`
      : `\\u{${character.codePointAt(0)?.toString(16) ?? ""}}`,
  );
  return `"${escaped}"`;
}

function describeEntropyPattern(pattern: EntropyPattern, length: number): string {
  switch (pattern.kind) {
    case "all-zeros":
      return "all zeros";
    case "all-ones":
      return "all ones (ff)";
    case "repeated-byte":
      return `byte ${pattern.byte} repeated`;
    case "repeated-block":
      return `${pattern.block.length / 2}-byte block ${pattern.block} repeated`;
    case "low-diversity":
      return `only ${pattern.distinct} distinct bytes out of ${length}`;
    case "date":
      return `date ${pattern.date} as ${pattern.encoding.replace("-", " ")}`;
  }
}

function describeEntropyPreimage(preimage: EntropyPreimage, length: number, cut: boolean): string {
  const { algorithm, text, source } = preimage;
  const prefix = cut ? `, first ${length} bytes` : "";
  return `${algorithm} of ${quoteEntropyText(text)} (${source}${prefix})`;
}

interface InspectedEntropy {
  details: { entropy?: string; entropyProfile?: EntropyProfile };
  lines: string[];
}

/**
 * Entropy of a valid mnemonic for the result, with what its bytes look like.
 * @param entropy - Entropy bytes, or undefined for an invalid mnemonic.
 * @param preimages - Caller texts hashed against the entropy.
 * @returns {InspectedEntropy} Detail fields and result lines.
 */
function inspectedEntropy(
  entropy: Uint8Array | undefined,
  preimages: readonly string[],
): InspectedEntropy {
  if (entropy === undefined) return { details: {}, lines: [] };
  const { length } = entropy;
  const profile = profileEntropy(entropy, preimages);
  const matches = profile.preimages.map((preimage) =>
    describeEntropyPreimage(preimage, length, ENTROPY_DIGEST_BYTES[preimage.algorithm] > length),
  );
  const checked = `${BUILT_IN_PREIMAGES.length} built-in, ${preimages.length} given; ${entropyHashAlgorithms(length).join(", ")}`;
  const patterns = profile.patterns.map((pattern) => describeEntropyPattern(pattern, length));
  return {
    details: { entropy: entropy.toHex(), entropyProfile: profile },
    lines: [
      `Entropy: ${entropy.toHex()}`,
      `Entropy text: ${profile.text === null ? "none" : quoteEntropyText(profile.text)}`,
      `Entropy pattern: ${patterns.join("; ") || "none"}`,
      `Entropy preimage: ${matches.join("; ") || `none (${checked})`}`,
    ],
  };
}

function entropyPreimageTexts(value: unknown): readonly string[] {
  if (value === undefined) return [];
  const texts = stringArray(value, "Entropy preimages");
  if (texts.length > MAX_ENTROPY_PREIMAGES) {
    throw new RangeError(`Provide at most ${MAX_ENTROPY_PREIMAGES} entropy preimages`);
  }
  if (texts.some((text) => text.length > MAX_ENTROPY_PREIMAGE_LENGTH)) {
    throw new RangeError(
      `Each entropy preimage must be at most ${MAX_ENTROPY_PREIMAGE_LENGTH} characters`,
    );
  }
  return texts;
}

/**
 * Validate a BIP39 mnemonic against the selected list and recover its entropy when valid.
 * @param mnemonicValue - BIP39 mnemonic candidate.
 * @param languageValue - Optional official BIP39 language key.
 * @param preimagesValue - Optional caller texts hashed against the entropy after the built-in list.
 * @returns {Promise<ToolResult<MnemonicInspectionDetails>>} Validity, entropy and its profile.
 */
export async function inspectMnemonic(
  mnemonicValue: unknown,
  languageValue?: unknown,
  preimagesValue?: unknown,
): Promise<ToolResult<MnemonicInspectionDetails>> {
  const mnemonic = normalizedMnemonic(mnemonicValue);
  const language = parseBIP39Language(languageValue);
  const preimages = entropyPreimageTexts(preimagesValue);
  const wordlist = await loadBIP39Wordlist(language);
  const inspection = inspectBIP39Mnemonic(mnemonic, wordlist);
  const { valid, words, wordCountValid, wordlistValid, checksumValid } = inspection;
  const entropy = inspectedEntropy(
    valid ? bip39.mnemonicToEntropy(mnemonic, wordlist) : undefined,
    preimages,
  );
  return {
    content: content(
      [
        `Language: ${language}`,
        `Valid BIP39: ${valid ? "yes" : "no"}`,
        `Words: ${words}`,
        `Word count valid: ${wordCountValid ? "yes" : "no"}`,
        `Wordlist valid: ${wordlistValid ? "yes" : "no"}`,
        `Checksum valid: ${checksumValid === null ? "not checked" : checksumValid ? "yes" : "no"}`,
        ...entropy.lines,
      ].join("\n"),
    ),
    details: { language, ...inspection, ...entropy.details },
  };
}

/**
 * Encode a supported BIP39 entropy length using the selected word list.
 * @param entropyValue - BIP39 entropy as hexadecimal text.
 * @param languageValue - Optional official BIP39 language key.
 * @returns {Promise<ToolResult<EncodedEntropyDetails>>} Canonical mnemonic and language.
 */
export async function encodeBip39Entropy(
  entropyValue: unknown,
  languageValue?: unknown,
): Promise<ToolResult<EncodedEntropyDetails>> {
  const entropy = parseBip39Entropy(entropyValue);
  const language = parseBIP39Language(languageValue);
  const wordlist = await loadBIP39Wordlist(language);
  const mnemonic = bip39.entropyToMnemonic(entropy, wordlist);
  const words = mnemonic.split(/\s+/u).length;
  return {
    content: content(`Language: ${language}\nWords: ${words}\nMnemonic: ${mnemonic}`),
    details: { language, words, mnemonic },
  };
}

/**
 * Read words at numeric positions in an official BIP39 list.
 * @param indicesValue - Numeric positions to read.
 * @param languageValue - Optional official language key.
 * @param indexBaseValue - Zero-based or one-based convention.
 * @returns {Promise<ToolResult<BIP39IndexLookupDetails>>} Ordered word lookups.
 */
export async function lookupBip39Indices(
  indicesValue: unknown,
  languageValue?: unknown,
  indexBaseValue?: unknown,
): Promise<ToolResult<BIP39IndexLookupDetails>> {
  const indices = integerArray(indicesValue, "BIP39 indices");
  assertLookupSize(indices.length, "indices");
  const indexBase = parseIndexBase(indexBaseValue);
  assertIndexRange(indices, indexBase);
  const language = parseBIP39Language(languageValue);
  const lookups = await lookupBIP39Indices(indices, language, indexBase);
  return {
    content: content(
      [
        `Language: ${language}`,
        `Index base: ${indexBase}`,
        ...lookups.map((lookup) => `${lookup.index}: ${lookup.word ?? "not in range"}`),
      ].join("\n"),
    ),
    details: { language, indexBase, lookups: lookups.map((lookup) => ({ ...lookup })) },
  };
}

/**
 * Look up word membership and both index conventions in an official BIP39 list.
 * @param wordsValue - Words to find.
 * @param languageValue - Optional official language key.
 * @returns {Promise<ToolResult<BIP39WordLookupDetails>>} Membership and indices.
 */
export async function lookupBip39Words(
  wordsValue: unknown,
  languageValue?: unknown,
): Promise<ToolResult<BIP39WordLookupDetails>> {
  const words = stringArray(wordsValue, "BIP39 lookup words");
  assertLookupSize(words.length, "words");
  if (words.some((word) => !BIP39_WORD_PATTERN.test(word))) {
    throw new TypeError("BIP39 lookup words must contain letters and combining marks only");
  }
  const language = parseBIP39Language(languageValue);
  const found = await lookupBIP39Words(words, language);
  const missing = found.flatMap((lookup) => (lookup.zeroBasedIndex === null ? [lookup.word] : []));
  const expanded = new Map(
    (await lookupBIP39Prefixes(missing, language)).map(({ prefix, matches }) => [
      prefix,
      matches.map(({ word, zeroBasedIndex }) => ({
        word,
        zeroBasedIndex,
        oneBasedIndex: zeroBasedIndex + 1,
      })),
    ]),
  );
  const lookups = found.map((lookup) => {
    const prefixOf = expanded.get(lookup.word) ?? [];
    return {
      word: lookup.word,
      zeroBasedIndex: lookup.zeroBasedIndex,
      oneBasedIndex: lookup.zeroBasedIndex === null ? null : lookup.zeroBasedIndex + 1,
      ...(prefixOf.length === 0 ? {} : { prefixOf }),
    };
  });
  return {
    content: content(
      [
        `Language: ${language}`,
        "Indices: zero-based, one-based",
        ...lookups.map((lookup) => {
          if (lookup.zeroBasedIndex !== null) {
            return `${lookup.word}: ${lookup.zeroBasedIndex}, ${lookup.oneBasedIndex}`;
          }
          if (lookup.prefixOf === undefined) return `${lookup.word}: not in BIP39`;
          const matches = lookup.prefixOf.map(
            (match) => `${match.word} (${match.zeroBasedIndex}, ${match.oneBasedIndex})`,
          );
          return `${lookup.word}: not in BIP39, prefix of ${matches.join(", ")}`;
        }),
      ].join("\n"),
    ),
    details: { language, lookups },
  };
}

/**
 * Applies the word count and letter rules of the order schema for hosts that skip it.
 * @param value - Raw words argument.
 * @returns {ReadonlyArray<string>} The words unchanged.
 */
function orderWordsArgument(value: unknown): readonly string[] {
  const words = stringArray(value, "BIP39 words");
  if (words.length === 0 || words.length > 24) {
    throw new RangeError("Provide between 1 and 24 words");
  }
  if (words.some((word) => !BIP39_WORD_PATTERN.test(word))) {
    throw new TypeError("BIP39 words must contain letters and combining marks only");
  }
  return words;
}

/**
 * Reads how many valid orders to list, the default when it is left out.
 * @param value - Raw limit argument.
 * @returns {number} An integer from 1 to the listing cap.
 */
function phraseLimit(value: unknown): number {
  const limit = value ?? DEFAULT_BIP39_PHRASES_SHOWN;
  if (
    typeof limit !== "number" ||
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > MAX_BIP39_PHRASES_SHOWN
  ) {
    throw new RangeError(`Limit must be an integer between 1 and ${MAX_BIP39_PHRASES_SHOWN}`);
  }
  return limit;
}

/**
 * Put scattered words in every order the open positions allow and keep the checksum passes.
 * @param wordsValue - Words without a known position.
 * @param templateValue - Optional phrase with known words and one ? per loose word.
 * @param languageValue - Optional official BIP39 language key.
 * @param limitValue - Optional count of valid orders to list.
 * @returns {Promise<ToolResult<BIP39WordOrderDetails>>} Orders checked, passed and listed.
 */
export async function orderBip39Words(
  wordsValue: unknown,
  templateValue?: unknown,
  languageValue?: unknown,
  limitValue?: unknown,
): Promise<ToolResult<BIP39WordOrderDetails>> {
  const words = orderWordsArgument(wordsValue);
  const template = optionalName(templateValue, "Template");
  if (template !== undefined && template.length > MAX_BIP39_PHRASE_LENGTH) {
    throw new RangeError(`Template must be at most ${MAX_BIP39_PHRASE_LENGTH} characters`);
  }
  const language = parseBIP39Language(languageValue);
  const limit = phraseLimit(limitValue);
  const options = { template, wordlist: await loadBIP39Wordlist(language), listName: language };
  const total = countWordOrders(words, options);
  if (total > BigInt(MAX_BIP39_CHECKSUM_SEARCH)) {
    throw new RangeError(
      `These words have ${total} orders, over the ${MAX_BIP39_CHECKSUM_SEARCH} one call checks. Fix more positions in template, or search with orderWords from @agntn/keys/bip39`,
    );
  }
  const orders: string[] = [];
  let valid = 0;
  for (const order of orderWords(words, options)) {
    valid++;
    if (orders.length < limit) orders.push(order.join(" "));
  }
  const checked = Number(total);
  return {
    content: content(
      [
        `Language: ${language}`,
        `Orders checked: ${checked}`,
        `Valid checksum: ${valid}`,
        ...(valid === 0
          ? []
          : [`First ${orders.length}, sorted by the list index of the loose words:`, ...orders]),
      ].join("\n"),
    ),
    details: { language, checked, valid, orders },
  };
}

/** Suggestions per word the repair text lists, the rest only counted. */
const SUGGESTIONS_SHOWN = 10;

/**
 * Reads how many edits a suggestion may be away, the default when it is left out.
 * @param value - Raw maxDistance argument.
 * @returns {number} An integer from 1 to the repair cap.
 */
function repairDistance(value: unknown): number {
  if (value === undefined) return DEFAULT_BIP39_REPAIR_DISTANCE;
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 1 ||
    value > MAX_BIP39_REPAIR_DISTANCE
  ) {
    throw new RangeError(
      `maxDistance must be an integer between 1 and ${MAX_BIP39_REPAIR_DISTANCE}`,
    );
  }
  return value;
}

/**
 * Refuses a phrase with too many words outside the list or too many combinations to check.
 * @param positions - Suggestions per word outside the list.
 * @param language - List name for the error.
 * @returns {number} Combinations the repair checks.
 */
function repairCombinations(positions: readonly WordSuggestions[], language: string): number {
  if (positions.length > MAX_BIP39_REPAIR_WORDS) {
    throw new RangeError(
      `Words ${positions.map(({ position }) => position).join(", ")} are not in the ${language} list, and one call repairs ${MAX_BIP39_REPAIR_WORDS} at most. Correct the others first`,
    );
  }
  const total = positions.reduce((product, { suggestions }) => product * suggestions.length, 1);
  if (total > MAX_BIP39_CHECKSUM_SEARCH) {
    throw new RangeError(
      `These suggestions make ${total} combinations, over the ${MAX_BIP39_CHECKSUM_SEARCH} one call checks. Lower maxDistance`,
    );
  }
  return total;
}

/**
 * Writes an edit count as words.
 * @param count - Number of edits.
 * @returns {string} "1 edit" or "N edits".
 */
function edits(count: number): string {
  return count === 1 ? "1 edit" : `${count} edits`;
}

/**
 * Lists the nearest words for one position, the rest only counted.
 * @param entry - Position and its suggestions.
 * @param maxDistance - Edits the search allowed.
 * @returns {string} One line of the repair text.
 */
function suggestionLine(entry: WordSuggestions, maxDistance: number): string {
  const { position, suggestions } = entry;
  if (suggestions.length === 0) return `Word ${position}: nothing within ${edits(maxDistance)}`;
  const shown = suggestions
    .slice(0, SUGGESTIONS_SHOWN)
    .map(({ word, distance }) => `${word} (${distance})`);
  const more = suggestions.length - shown.length;
  return `Word ${position}, ${suggestions.length} within ${edits(maxDistance)}: ${shown.join(", ")}${more > 0 ? `, ${more} more` : ""}`;
}

/**
 * Suggest list words for the words of a phrase outside the list and keep the checksum passes.
 * @param mnemonicValue - Phrase with mistyped words.
 * @param languageValue - Optional official BIP39 language key.
 * @param maxDistanceValue - Optional most edits per word.
 * @param limitValue - Optional count of repaired phrases to list.
 * @returns {Promise<ToolResult<BIP39WordRepairDetails>>} Suggestions, combinations and repairs.
 */
export async function repairBip39Words(
  mnemonicValue: unknown,
  languageValue?: unknown,
  maxDistanceValue?: unknown,
  limitValue?: unknown,
): Promise<ToolResult<BIP39WordRepairDetails>> {
  const mnemonic = normalizedMnemonic(mnemonicValue);
  if (mnemonic.length > MAX_BIP39_PHRASE_LENGTH) {
    throw new RangeError(`BIP39 mnemonic must be at most ${MAX_BIP39_PHRASE_LENGTH} characters`);
  }
  const language = parseBIP39Language(languageValue);
  const maxDistance = repairDistance(maxDistanceValue);
  const limit = phraseLimit(limitValue);
  const options = { wordlist: await loadBIP39Wordlist(language), maxDistance };
  const positions = suggestWords(mnemonic, options);
  const checked = repairCombinations(positions, language);
  const repairs = repairWords(mnemonic, options).map(({ words, distance }) => ({
    mnemonic: words.join(" "),
    distance,
  }));
  const listed = repairs.slice(0, limit);
  const outside = positions.map(({ position }) => position);
  return {
    content: content(
      [
        `Language: ${language}`,
        `Not in the list: ${outside.length === 0 ? "none" : `${outside.length === 1 ? "word" : "words"} ${outside.join(", ")}`}`,
        ...positions.map((entry) => suggestionLine(entry, maxDistance)),
        `Combinations checked: ${checked}`,
        `Valid checksum: ${repairs.length}`,
        ...(listed.length === 0 ? [] : [`First ${listed.length}, fewest edits first:`]),
        ...listed.map(({ mnemonic: phrase, distance }) => `${edits(distance)}: ${phrase}`),
        "A wrong word that is in the list stays as written. If no phrase here opens the wallet, put ? in its place and use keys_bip39_word_recover.",
      ].join("\n"),
    ),
    details: {
      language,
      maxDistance,
      positions: positions.map(({ position, suggestions }) => ({
        position,
        suggestions: suggestions.map(({ word, distance }) => ({ word, distance })),
      })),
      checked,
      valid: repairs.length,
      repairs: listed,
    },
  };
}

/**
 * List the words of one BIP39 list that satisfy one missing checksum position.
 * @param mnemonicValue - Mnemonic template containing one question mark.
 * @param languageValue - Optional official BIP39 language key.
 * @returns {Promise<ToolResult<MnemonicRecoveryDetails>>} Language, position and candidate words.
 */
export async function recoverMnemonicWord(
  mnemonicValue: unknown,
  languageValue?: unknown,
): Promise<ToolResult<MnemonicRecoveryDetails>> {
  const mnemonic = normalizedMnemonic(mnemonicValue);
  const language = parseBIP39Language(languageValue);
  const wordlist = await loadBIP39Wordlist(language);
  const position = mnemonic.normalize("NFKD").split(" ").indexOf("?") + 1;
  const candidates = getMnemonicWordCandidates(mnemonic, wordlist, language);
  return {
    content: content(
      `Language: ${language}\nPosition: ${position}\nCandidates (${candidates.length}): ${candidates.length === 0 ? "none" : candidates.join(", ")}`,
    ),
    details: { language, position, candidates },
  };
}

/**
 * Derive an address from a public key.
 * @param chainValue - Blockchain name.
 * @param publicKeyValue - Public key as hexadecimal text.
 * @param addressTypeValue - Optional chain-specific address type.
 * @param networkValue - Optional network name.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @returns {Promise<ToolResult<AddressDetails>>} Derived address.
 */
export async function getAddress(
  chainValue: unknown,
  publicKeyValue: unknown,
  addressTypeValue?: unknown,
  networkValue?: unknown,
  prefixValue?: unknown,
): Promise<ToolResult<AddressDetails>> {
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
    prefixValue,
  );
  const publicKey = chainPublicKey(publicKeyValue, blockchain.name);
  const type = addressType ?? blockchain.defaultAddressType;
  const address = blockchain.getAddress(publicKey, type);
  return {
    content: content([...addressTypeLines(type), `Address: ${address}`].join("\n")),
    details: {
      chain: blockchain.name,
      network: blockchain.network,
      ...(type === undefined ? {} : { addressType: type }),
      address,
    },
  };
}

/**
 * Check whether an address matches one chain's format.
 * @param chainValue - Blockchain name.
 * @param addressValue - Address to validate.
 * @param networkValue - Optional network name.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @returns {Promise<ToolResult<AddressValidationDetails>>} Address format verdict.
 */
export async function validateAddress(
  chainValue: unknown,
  addressValue: unknown,
  networkValue?: unknown,
  prefixValue?: unknown,
): Promise<ToolResult<AddressValidationDetails>> {
  const { blockchain } = await getBlockchain(chainValue, networkValue, undefined, prefixValue);
  const address = requiredString(addressValue, "Address");
  if (Array.from(address).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Address must not exceed ${MAX_ADDRESS_LENGTH} characters`);
  }
  const valid = blockchain.validateAddress(address);
  const renderedAddress = sanitizeToolText(address);
  const otherNetwork = valid
    ? undefined
    : await otherNetworkOf(blockchain.name, blockchain.network, address, prefixValue);
  return {
    content: content(
      valid
        ? `${renderedAddress} is a valid ${blockchain.name} address`
        : otherNetwork === undefined
          ? `${renderedAddress} is not a valid ${blockchain.name} address`
          : `${renderedAddress} is not a valid ${blockchain.name} address on ${blockchain.network}, but it is valid on ${otherNetwork}`,
    ),
    details: { chain: blockchain.name, network: blockchain.network, address, valid },
  };
}

/**
 * Finds another network an address is valid on, so a testnet address checked against
 * mainnet is not reported as simply broken.
 * @param chain - Blockchain name, already accepted by `getBlockchain`.
 * @param network - Network the address failed on.
 * @param address - Address that failed.
 * @param prefixValue - Prefix the first check used, cosmos and polkadot only.
 * @returns {Promise<string | undefined>} The other network, when the address passes there.
 */
async function otherNetworkOf(
  chain: string,
  network: string,
  address: string,
  prefixValue: unknown,
): Promise<string | undefined> {
  const networks = chain === "monero" ? CHAIN_NETWORKS : TOOL_NETWORKS;
  for (const other of networks.filter((candidate) => candidate !== network)) {
    const { blockchain } = await getBlockchain(chain, other, undefined, prefixValue);
    if (blockchain.validateAddress(address)) return other;
  }
  return undefined;
}

/**
 * Sign a message without retaining the private key or message in result details.
 * @param chainValue - Blockchain name.
 * @param messageValue - Message to sign.
 * @param privateKeyValue - Private key as hexadecimal text.
 * @param networkValue - Optional network name.
 * @param recoveredValue - Append the recovery byte as `v`, default false.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @returns {Promise<ToolResult<SignatureDetails>>} Generated signature.
 */
export async function signMessage(
  chainValue: unknown,
  messageValue: unknown,
  privateKeyValue: unknown,
  networkValue?: unknown,
  recoveredValue?: unknown,
  prefixValue?: unknown,
): Promise<ToolResult<SignatureDetails>> {
  if (recoveredValue !== undefined && typeof recoveredValue !== "boolean") {
    throw new TypeError("recovered must be a boolean");
  }
  const recovered = recoveredValue ?? false;
  const { blockchain } = await getBlockchain(chainValue, networkValue, undefined, prefixValue);
  const message = requiredString(messageValue, "Message");
  const privateKey = hexArgument(
    privateKeyValue,
    "Private key",
    PRIVATE_KEY_HEX,
    "64 hex characters",
  );
  /** Only pass options when the flag is set, so every other chain keeps its current defaults. */
  const signature = recovered
    ? blockchain.signMessage(message, privateKey, { recovered })
    : blockchain.signMessage(message, privateKey);
  return {
    content: content(`Signature: ${signature}`),
    details: { chain: blockchain.name, network: blockchain.network, signature, recovered },
  };
}

/**
 * Refuse a base64 signature the chain never writes or whose header is out of range, so neither
 * reads as invalid. One that recovers no key stays a verdict, as in Core.
 * @param blockchain - Chain the signature is checked on.
 * @param message - Signed message.
 * @param signature - Base64 signature.
 * @returns {void} Nothing; it throws on unreadable input.
 */
function assertReadableSignature(
  blockchain: Readonly<AbstractBlockchain>,
  message: string,
  signature: string,
): void {
  try {
    blockchain.recoverMessageSigner(message, signature);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
  }
}

/**
 * Verify a signature against a message and public key.
 * @param chainValue - Blockchain name.
 * @param messageValue - Original message.
 * @param signatureValue - Signature as hexadecimal text.
 * @param publicKeyValue - Public key as hexadecimal text.
 * @param networkValue - Optional network name.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @returns {Promise<ToolResult<SignatureVerificationDetails>>} Signature verdict.
 */
export async function verifyMessage(
  chainValue: unknown,
  messageValue: unknown,
  signatureValue: unknown,
  publicKeyValue: unknown,
  networkValue?: unknown,
  prefixValue?: unknown,
): Promise<ToolResult<SignatureVerificationDetails>> {
  const { blockchain } = await getBlockchain(chainValue, networkValue, undefined, prefixValue);
  const message = requiredString(messageValue, "Message");
  const signatureText = requiredString(signatureValue, "Signature");
  const core = CORE_SIGNATURE.test(signatureText);
  const signature = core
    ? signatureText
    : hexArgument(
        signatureText,
        "Signature",
        DER_SIGNATURE.test(signatureText) ? DER_SIGNATURE : SIGNATURE_HEX,
        "64 or 65 bytes of hex, or DER on xrpl,",
      );
  const publicKey = chainPublicKey(publicKeyValue, blockchain.name);
  if (core) assertReadableSignature(blockchain, message, signature);
  const valid = blockchain.verifyMessage(message, signature, publicKey);
  return {
    content: content(valid ? "Signature is valid" : "Signature is invalid"),
    details: { chain: blockchain.name, network: blockchain.network, valid },
  };
}

/** Bech32 as an encoder writes it: a BIP-173 prefix without uppercase, `1`, then the data. */
const BECH32_WRITTEN = /^[\x21-\x40\x5B-\x7E]{1,83}1[02-9ac-hj-np-z]{6,}$/u;

/**
 * Compare a written address with a typed one: bech32 and CashAddr ignore case, base58 doesn't.
 * @param written - Address from `getAddress`
 * @param given - Address the caller passed, already validated for the chain
 * @returns {boolean} True when both name the same address
 */
function sameAddress(written: string, given: string): boolean {
  if (written === given) return true;
  if (written.startsWith("0x")) return written.toLowerCase() === given.toLowerCase();
  if (!written.includes(":") && !BECH32_WRITTEN.test(written)) return false;
  const lower = given.toLowerCase();
  return lower === written || lower === written.slice(written.indexOf(":") + 1);
}

/**
 * Read the optional address a recovered signer is compared with.
 * @param value - Raw argument.
 * @returns {string | undefined} The address, or undefined when it was left out.
 */
function expectedAddress(value: unknown): string | undefined {
  const address = optionalName(value, "Address");
  if (address !== undefined && Array.from(address).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Address must not exceed ${MAX_ADDRESS_LENGTH} characters`);
  }
  return address;
}

/**
 * Address types a signer may hold, as Electrum checks them for the header.
 * @param signer - Key and header type from the signature.
 * @returns {(string | undefined)[]} Types to compare, `[undefined]` on EVM and TRON.
 */
function signerAddressTypes(signer: Readonly<MessageSigner>): (string | undefined)[] {
  if (signer.addressType !== "legacy" || signer.publicKey.length !== 66)
    return [signer.addressType];
  return ["legacy", "p2sh", "segwit"];
}

/**
 * Line that reports the comparison, empty when no address was given.
 * @param expected - Address the caller passed.
 * @param matches - Whether it belongs to the recovered key.
 * @param matchedType - Address type it matched, if the chain has types.
 * @returns {string[]} Zero or one line.
 */
function comparisonLines(
  expected: string | undefined,
  matches: boolean,
  matchedType: string | undefined,
): string[] {
  if (expected === undefined) return [];
  if (!matches) return ["Given address: no match"];
  return [
    matchedType === undefined ? "Given address: match" : `Given address: match (${matchedType})`,
  ];
}

/** What a recover call checks the signature against: the message, or a digest it hashed to. */
type SignedInput =
  | { signed: "message"; message: string }
  | { signed: "typedData" | "digest"; digest: Uint8Array };

/**
 * Tell typed data from any other JSON before hashing, so `hashTypedData` gets its own shape.
 * @param value - Parsed JSON.
 * @returns {boolean} True for an object with types, primaryType, domain and message.
 */
function isTypedData(value: unknown): value is TypedData {
  if (typeof value !== "object" || value === null) return false;
  const shape = (key: string): unknown =>
    Object.hasOwn(value, key) ? Reflect.get(value, key) : undefined;
  const isObject = (field: unknown): boolean =>
    typeof field === "object" && field !== null && !Array.isArray(field);
  return (
    isObject(shape("types")) &&
    typeof shape("primaryType") === "string" &&
    isObject(shape("domain")) &&
    isObject(shape("message"))
  );
}

/**
 * Take exactly one of the message, the typed data and the digest.
 * @param messageValue - Message as the caller passed it.
 * @param typedDataValue - EIP-712 JSON as the caller passed it.
 * @param digestValue - Digest hex as the caller passed it.
 * @returns {SignedInput} The message, or the digest to recover against.
 */
function signedInput(
  messageValue: unknown,
  typedDataValue: unknown,
  digestValue: unknown,
): SignedInput {
  const given = [messageValue, typedDataValue, digestValue].filter((value) => value !== undefined);
  if (given.length !== 1) {
    throw new TypeError("Pass exactly one of message, typedData and digest");
  }
  if (messageValue !== undefined) {
    return { signed: "message", message: requiredString(messageValue, "Message") };
  }
  if (digestValue !== undefined) {
    const digest = hexArgument(digestValue, "Digest", DIGEST_HEX, "32 bytes of hex");
    return { signed: "digest", digest: Uint8Array.fromHex(digest) };
  }
  const text = requiredString(typedDataValue, "Typed data");
  if (text.length > MAX_TYPED_DATA_LENGTH) {
    throw new RangeError(`Typed data must not exceed ${MAX_TYPED_DATA_LENGTH} characters`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError("Typed data must be JSON");
  }
  if (!isTypedData(parsed)) {
    throw new TypeError(
      "Typed data must be a JSON object with types, primaryType, domain and message",
    );
  }
  return { signed: "typedData", digest: hashTypedData(parsed) };
}

/**
 * Find the address type of the recovered key that the given address names.
 * @param blockchain - Chain the signature was recovered on.
 * @param signer - The recovered key and header type.
 * @param expected - Address the caller passed.
 * @returns {{ matches: boolean; matchedType?: string }} The verdict and the matched type.
 */
function matchSigner(
  blockchain: Readonly<AbstractBlockchain>,
  signer: Readonly<MessageSigner>,
  expected: string,
): { matches: boolean; matchedType?: string } {
  const types = signerAddressTypes(signer);
  const index = types.findIndex((type) => {
    try {
      return sameAddress(blockchain.getAddress(signer.publicKey, type), expected);
    } catch {
      return false;
    }
  });
  if (index === -1) return { matches: false };
  const matchedType = types[index];
  return matchedType === undefined ? { matches: true } : { matches: true, matchedType };
}

/**
 * Text lines of a recovered signer.
 * @param details - The signer and the comparison.
 * @param expected - Address the caller passed, if any.
 * @returns {string[]} One line per fact.
 */
function signerLines(
  details: Readonly<MessageSignerDetails>,
  expected: string | undefined,
): string[] {
  return [
    `Chain: ${details.chain} (${details.network})`,
    ...(details.digest === undefined ? [] : [`EIP-712 digest: ${details.digest}`]),
    `Public key: ${details.publicKey}`,
    details.addressType === undefined
      ? `Address: ${details.address}`
      : `Address: ${details.address} (${details.addressType})`,
    ...comparisonLines(expected, details.matches === true, details.matchedType),
  ];
}

/**
 * Recover the signer of a message, EIP-712 typed data or a digest, and say whether it holds a
 * given address. The Bitcoin family and Decred read Core's base64, EVM chains and TRON `r||s||v`.
 * @param chainValue - Blockchain name.
 * @param messageValue - Message that was signed, or undefined beside typed data or a digest.
 * @param signatureValue - Base64 of the header byte, then `r` and `s`, or `r||s||v` hex.
 * @param addressValue - Optional address to compare with.
 * @param networkValue - Optional network name.
 * @param typedDataValue - EIP-712 typed data as JSON, in place of the message.
 * @param digestValue - 32-byte digest as hex, in place of the message.
 * @returns {Promise<ToolResult<MessageSignerDetails>>} The signer and the comparison.
 */
export async function recoverMessageSigner(
  chainValue: unknown,
  messageValue: unknown,
  signatureValue: unknown,
  addressValue?: unknown,
  networkValue?: unknown,
  typedDataValue?: unknown,
  digestValue?: unknown,
): Promise<ToolResult<MessageSignerDetails>> {
  const { blockchain } = await getBlockchain(chainValue, networkValue);
  const input = signedInput(messageValue, typedDataValue, digestValue);
  const signature = requiredString(signatureValue, "Signature");
  if (!RECOVERABLE_SIGNATURE.test(signature)) {
    throw new TypeError(
      "Signature must be 65 bytes: r||s||v as 130 hex characters without 0x, or signmessage's base64",
    );
  }
  const expected = expectedAddress(addressValue);
  if (expected !== undefined && !blockchain.validateAddress(expected)) {
    throw new TypeError(`Address is not a valid ${blockchain.name} ${blockchain.network} address`);
  }
  const signer =
    input.signed === "message"
      ? blockchain.recoverMessageSigner(input.message, signature)
      : blockchain.recoverDigestSigner(input.digest, signature);
  const details: MessageSignerDetails = {
    chain: blockchain.name,
    network: blockchain.network,
    signed: input.signed,
    ...(input.signed === "typedData" ? { digest: input.digest.toHex() } : {}),
    publicKey: signer.publicKey,
    ...(signer.addressType === undefined ? {} : { addressType: signer.addressType }),
    address: blockchain.getAddress(signer.publicKey, signer.addressType),
    ...(expected === undefined ? {} : matchSigner(blockchain, signer, expected)),
  };
  return { content: content(signerLines(details, expected).join("\n")), details };
}

/** A BIP322 signature written for a key's address. */
export interface BIP322SignatureDetails {
  chain: "bitcoin";
  network: string;
  addressType: BIP322SigningType;
  address: string;
  format: "simple" | "full";
  signature: string;
}

/** The verdict on a BIP322 signature. */
export interface BIP322VerificationDetails {
  chain: "bitcoin";
  network: string;
  state: BIP322State;
  format: BIP322Format;
  addressType: string;
  reason?: string;
  publicKey?: string;
  lockTime?: number;
  sequence?: number;
}

const BIP322_SIGNATURE = new RegExp(BIP322_SIGNATURE_SCHEMA_PATTERN, "u");

/**
 * Read the address type a BIP322 signature is written for.
 * @param value - Raw argument.
 * @returns {BIP322SigningType} legacy, p2sh, segwit or taproot.
 */
function bip322SigningType(value: unknown): BIP322SigningType {
  const type = BIP322_SIGNING_TYPES.find((candidate) => candidate === value);
  if (type === undefined) {
    throw new RangeError(`Address type must be one of ${BIP322_SIGNING_TYPES.join(", ")}`);
  }
  return type;
}

/**
 * Sign a message by BIP322 for the Bitcoin address of a private key.
 * @param messageValue - Message to sign.
 * @param privateKeyValue - Private key as 64 hex characters.
 * @param addressTypeValue - legacy, p2sh, segwit or taproot.
 * @param networkValue - Optional network name.
 * @param compressedValue - Legacy only: whether the address takes the compressed key.
 * @returns {Promise<ToolResult<BIP322SignatureDetails>>} The signature and the address it proves.
 */
export async function signBip322(
  messageValue: unknown,
  privateKeyValue: unknown,
  addressTypeValue: unknown,
  networkValue?: unknown,
  compressedValue?: unknown,
): Promise<ToolResult<BIP322SignatureDetails>> {
  const message = requiredString(messageValue, "Message");
  const privateKey = hexArgument(
    privateKeyValue,
    "Private key",
    PRIVATE_KEY_HEX,
    "64 hex characters",
  );
  const addressType = bip322SigningType(addressTypeValue);
  const network = parseNetwork(networkValue);
  if (compressedValue !== undefined && typeof compressedValue !== "boolean") {
    throw new TypeError("compressed must be a boolean");
  }
  if (compressedValue !== undefined && addressType !== "legacy") {
    throw new TypeError(
      "compressed applies to legacy only; the other types take the compressed key",
    );
  }
  const signature = signBIP322Message(message, privateKey, addressType, {
    network,
    ...(compressedValue === undefined ? {} : { compressed: compressedValue }),
  });
  const { blockchain } = await getBlockchain("bitcoin", network);
  const publicKey = blockchain.getKeyPublic(privateKey, { compressed: compressedValue !== false });
  const address = blockchain.getAddress(publicKey, addressType);
  const format = signature.startsWith("ful") ? "full" : "simple";
  return {
    content: content(`Signature: ${signature}\nAddress: ${address} (${addressType}, ${format})`),
    details: { chain: "bitcoin", network, addressType, address, format, signature },
  };
}

/**
 * First line of a BIP322 verdict, with the format and the address type.
 * @param verdict - The verification.
 * @returns {string} One line, the reason after a colon when the signature is not valid.
 */
function bip322VerdictLine(verdict: Readonly<BIP322Verification>): string {
  const head = `Signature is ${verdict.state} (${verdict.format}, ${verdict.addressType})`;
  return verdict.reason === undefined ? head : `${head}: ${verdict.reason}`;
}

/**
 * Verify a BIP322 signature of a message by a Bitcoin address.
 * @param addressValue - Address that signed.
 * @param messageValue - Message that was signed.
 * @param signatureValue - Prefixed base64, unprefixed base64, or signmessage's base64.
 * @param networkValue - Optional network name.
 * @returns {ToolResult<BIP322VerificationDetails>} Valid, invalid or inconclusive, with the reason.
 */
export function verifyBip322(
  addressValue: unknown,
  messageValue: unknown,
  signatureValue: unknown,
  networkValue?: unknown,
): ToolResult<BIP322VerificationDetails> {
  const address = requiredString(addressValue, "Address");
  if (Array.from(address).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Address must not exceed ${MAX_ADDRESS_LENGTH} characters`);
  }
  const message = requiredString(messageValue, "Message");
  const signature = requiredString(signatureValue, "Signature");
  if (signature.length > MAX_BIP322_SIGNATURE_LENGTH || !BIP322_SIGNATURE.test(signature)) {
    throw new TypeError(
      `Signature must be base64 of at most ${MAX_BIP322_SIGNATURE_LENGTH} characters, after an optional smp, ful or pof`,
    );
  }
  const network = parseNetwork(networkValue);
  const verdict = verifyBIP322Message(address, message, signature, { network });
  const lines = [bip322VerdictLine(verdict)];
  if (verdict.publicKey !== undefined) lines.push(`Public key: ${verdict.publicKey}`);
  if ((verdict.lockTime ?? 0) > 0 || (verdict.sequence ?? 0) > 0) {
    lines.push(`Valid from lock time ${verdict.lockTime} and sequence ${verdict.sequence}`);
  }
  return {
    content: content(lines.join("\n")),
    details: { chain: "bitcoin", network, ...verdict },
  };
}

/** Addresses that pay to one script, with the reason a wrapper refuses it. */
export interface ScriptAddressDetails {
  chain: "bitcoin";
  network: string;
  /** The script hashed, written out when the tool built it from keys. */
  script: string;
  addresses: Partial<Record<ScriptAddressType, string>>;
  refused?: Partial<Record<ScriptAddressType, string>>;
  warnings?: string[];
}

const SCRIPT_ADDRESS_TYPES = ["p2sh", "p2wsh", "p2sh-p2wsh"] as const;

/** Labels of the wrappers in the tool text. */
const SCRIPT_ADDRESS_LABELS: Readonly<Record<ScriptAddressType, string>> = {
  p2sh: "P2SH",
  p2wsh: "P2WSH",
  "p2sh-p2wsh": "P2SH-P2WSH",
};

const SEC1_PUBLIC_KEY = new RegExp(SEC1_PUBLIC_KEY_SCHEMA_PATTERN, "u");

/**
 * Reads an optional count that starts at 1, unlike an index.
 * @param value - Raw argument
 * @param name - Argument name for the error
 * @param maximum - Largest value it takes
 * @returns {number | undefined} The count, undefined when left out
 */
function optionalCount(value: unknown, name: string, maximum: number): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${name} must be an integer from 1 to ${maximum}`);
  }
  return value;
}

/**
 * Reads the script argument, a hex script without the multisig arguments.
 * @param scriptValue - Raw script
 * @param thresholdValue - Raw threshold, which must be absent
 * @param sortedValue - Raw sorted flag, which must be absent
 * @returns {Uint8Array} The script bytes
 */
function givenScript(
  scriptValue: unknown,
  thresholdValue: unknown,
  sortedValue: unknown,
): Uint8Array {
  const script = requiredString(scriptValue, "Script");
  if (script.length > MAX_SCRIPT_HEX_LENGTH || !HEX_BYTES.test(script)) {
    throw new TypeError(`Script must be hex without 0x, at most ${MAX_SCRIPT_HEX_LENGTH} digits`);
  }
  if (thresholdValue !== undefined || sortedValue !== undefined) {
    throw new TypeError("threshold and sorted go with publicKeys, not with script");
  }
  return Uint8Array.fromHex(script);
}

/**
 * Reads the multisig arguments into their keys and script.
 * @param thresholdValue - Raw threshold
 * @param publicKeysValue - Raw keys
 * @param sortedValue - Raw sorted flag
 * @returns {[readonly string[], Uint8Array]} The keys and the multisig script
 */
function multisigArgument(
  thresholdValue: unknown,
  publicKeysValue: unknown,
  sortedValue: unknown,
): [readonly string[], Uint8Array] {
  const keys = stringArray(publicKeysValue, "publicKeys");
  if (keys.length > MAX_MULTISIG_KEYS || !keys.every((key) => SEC1_PUBLIC_KEY.test(key))) {
    throw new TypeError(
      `publicKeys must be 1 to ${MAX_MULTISIG_KEYS} compressed or uncompressed SEC1 keys as hex without 0x`,
    );
  }
  const threshold = optionalCount(thresholdValue, "threshold", keys.length);
  if (threshold === undefined) throw new TypeError("publicKeys need a threshold");
  if (sortedValue !== undefined && typeof sortedValue !== "boolean") {
    throw new TypeError("sorted must be a boolean");
  }
  return [keys, multisig(threshold, keys, { sorted: sortedValue === true })];
}

/**
 * Writes the address of each wrapper, or the reason it refuses the script.
 * @param script - Redeem or witness script
 * @param network - Network of the addresses
 * @returns {Pick<ScriptAddressDetails, "addresses" | "refused"> & { lines: string[] }} One per type
 */
function wrapperAddresses(
  script: Uint8Array,
  network: ToolNetwork,
): Pick<ScriptAddressDetails, "addresses" | "refused"> & { lines: string[] } {
  const addresses: Partial<Record<ScriptAddressType, string>> = {};
  const refused: Partial<Record<ScriptAddressType, string>> = {};
  const lines = SCRIPT_ADDRESS_TYPES.map((type) => {
    try {
      addresses[type] = scriptAddress(script, type, { network });
      return `${SCRIPT_ADDRESS_LABELS[type]}: ${addresses[type]}`;
    } catch (error) {
      if (!(error instanceof RangeError)) throw error;
      refused[type] = error.message;
      return `${SCRIPT_ADDRESS_LABELS[type]}: none, ${error.message}`;
    }
  });
  return { addresses, ...(Object.keys(refused).length === 0 ? {} : { refused }), lines };
}

/**
 * Get the P2SH, P2WSH and P2SH-P2WSH addresses of a script or of an m-of-n multisig.
 * @param scriptValue - Redeem or witness script as hex
 * @param thresholdValue - Signatures the multisig needs
 * @param publicKeysValue - Multisig keys
 * @param sortedValue - Whether to sort the keys
 * @param networkValue - Optional network name
 * @returns {ToolResult<ScriptAddressDetails>} An address per wrapper, or why it refuses the script
 */
export function getScriptAddress(
  scriptValue: unknown,
  thresholdValue: unknown,
  publicKeysValue: unknown,
  sortedValue: unknown,
  networkValue?: unknown,
): ToolResult<ScriptAddressDetails> {
  const network = parseNetwork(networkValue);
  const hasScript = !isUnset(scriptValue);
  const hasKeys = Array.isArray(publicKeysValue)
    ? publicKeysValue.length > 0
    : publicKeysValue !== undefined;
  if (hasScript === hasKeys)
    throw new TypeError("Pass either script, or publicKeys with threshold");
  const [keys, script] = hasScript
    ? [[], givenScript(scriptValue, thresholdValue, sortedValue)]
    : multisigArgument(thresholdValue, publicKeysValue, sortedValue);
  const { lines, ...wrapped } = wrapperAddresses(script, network);
  const warnings = keys.some((key) => key.length === 130)
    ? ["Uncompressed keys make P2WSH and P2SH-P2WSH spends non-standard, so nodes don't relay them"]
    : [];
  const shownScript = hasKeys ? [`Script: ${script.toHex()} (${script.length} bytes)`] : [];
  return {
    content: content([...shownScript, ...lines, ...warnings].join("\n")),
    details: {
      chain: "bitcoin",
      network,
      script: script.toHex(),
      ...wrapped,
      ...(warnings.length === 0 ? {} : { warnings }),
    },
  };
}

/** Outputs of an output descriptor and the checksum it sums to. */
export interface DescriptorDetails {
  chain: "bitcoin";
  network: string;
  checksum: string;
  /** Whether the descriptor carried that checksum after #. */
  checksumGiven: boolean;
  ranged: boolean;
  outputs: Array<{ index?: number; address: string; script: string }>;
}

/**
 * Reads where a ranged descriptor starts and how many addresses it lists.
 * @param ranged - Whether the descriptor has a /* step
 * @param indexValue - Raw first index
 * @param countValue - Raw count
 * @returns {number[]} The indices to derive, empty for a descriptor without /*
 */
function descriptorIndices(ranged: boolean, indexValue: unknown, countValue: unknown): number[] {
  const start = optionalIndex(indexValue, "index");
  const count = optionalCount(countValue, "count", MAX_DESCRIPTOR_ADDRESSES);
  if (!ranged) {
    if (start !== undefined || count !== undefined) {
      throw new TypeError("Descriptor has no /* step; leave index and count out");
    }
    return [];
  }
  const first = start ?? 0;
  const length = count ?? 1;
  if (first + length - 1 > 0x7fffffff)
    throw new RangeError("index plus count must stay below 2^31");
  return Array.from({ length }, (_, offset) => first + offset);
}

/**
 * Derive the addresses of a Bitcoin output descriptor and check or compute its checksum.
 * @param descriptorValue - The descriptor, with or without #checksum
 * @param indexValue - First index of a ranged descriptor
 * @param countValue - Addresses of a ranged descriptor to list
 * @param networkValue - Optional network name
 * @returns {ToolResult<DescriptorDetails>} The checksum and the addresses
 */
export function deriveDescriptor(
  descriptorValue: unknown,
  indexValue: unknown,
  countValue: unknown,
  networkValue?: unknown,
): ToolResult<DescriptorDetails> {
  const text = requiredString(descriptorValue, "Descriptor");
  if (text.length === 0 || text.length > MAX_DESCRIPTOR_LENGTH) {
    throw new RangeError(`Descriptor must be 1 to ${MAX_DESCRIPTOR_LENGTH} characters`);
  }
  const network = parseNetwork(networkValue);
  const descriptor = parseDescriptor(text, { network });
  const indices = descriptorIndices(descriptor.ranged, indexValue, countValue);
  const shown = (output: DescriptorOutput, index?: number) => ({
    ...(index === undefined ? {} : { index }),
    address: output.address,
    script: output.script.toHex(),
  });
  const outputs = descriptor.ranged
    ? indices.map((index) => shown(descriptor.derive(index), index))
    : [shown(descriptor.derive())];
  const checksumGiven = text.includes("#");
  const lines = [
    `Checksum: ${descriptor.checksum}${checksumGiven ? ", matches the one given" : ""}`,
    ...outputs.map((output) =>
      output.index === undefined
        ? `Address: ${output.address}`
        : `Index ${output.index}: ${output.address}`,
    ),
  ];
  return {
    content: content(lines.join("\n")),
    details: {
      chain: "bitcoin",
      network,
      checksum: descriptor.checksum,
      checksumGiven,
      ranged: descriptor.ranged,
      outputs,
    },
  };
}

/**
 * Parse a BIP44 path into its levels.
 * @param pathValue - BIP44 path, hardened levels marked with ' or h.
 * @returns {ToolResult<BIP44PathDetails>} The path and its levels.
 */
export function parseBip44Path(pathValue: unknown): ToolResult<BIP44PathDetails> {
  const path = requiredString(pathValue, "BIP44 path");
  const parsed = parseBIP44Path(path);
  if (!parsed) throw new Error(`Invalid BIP44 path: ${JSON.stringify(path)}`);
  return {
    content: content(
      [
        `Path: ${path}`,
        `Purpose: ${parsed.purpose}`,
        `Coin type: ${parsed.coinType}`,
        `Account: ${parsed.account}`,
        `Change: ${parsed.change}`,
        `Address index: ${parsed.addressIndex}`,
      ].join("\n"),
    ),
    details: { path, ...parsed },
  };
}

/**
 * Generate the path a chain's wallets use, with the change range and Sui scheme the chain sets.
 * @param chainValue - Blockchain name.
 * @param accountValue - Account index.
 * @param changeValue - External or internal branch, or the CIP-1852 role on Cardano.
 * @param addressIndexValue - Address index.
 * @param addressTypeValue - Signature scheme on Sui, ed25519 by default.
 * @param networkValue - Network, which picks the coin type on the UTXO chains.
 * @param prefixValue - Bech32 prefix on cosmos, which picks the coin type there.
 * @param coinTypeValue - Coin type on cosmos, in place of the one prefix stands for.
 * @returns {Promise<ToolResult<BIP44PathDetails>>} The generated path.
 */
export async function generateBip44Path(
  chainValue: unknown,
  accountValue?: unknown,
  changeValue?: unknown,
  addressIndexValue?: unknown,
  addressTypeValue?: unknown,
  networkValue?: unknown,
  prefixValue?: unknown,
  coinTypeValue?: unknown,
): Promise<ToolResult<BIP44PathDetails>> {
  const account = optionalIndex(accountValue, "Account") ?? 0;
  const change = optionalIndex(changeValue, "Change") ?? 0;
  const addressIndex = optionalIndex(addressIndexValue, "Address index") ?? 0;
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
    prefixValue,
    coinTypeValue,
  );
  if (addressType !== undefined && !Array.isArray(blockchain.curve)) {
    throw new RangeError(`addressType names a scheme, and ${blockchain.name} has one curve`);
  }
  const options = addressType === undefined ? undefined : { scheme: addressType };
  const generated = getBlockchainPath(blockchain, account, change, addressIndex, options);
  return {
    content: content(
      `Chain: ${blockchain.name} (BIP44 coin type: ${blockchain.coinType})\nPath: ${generated}`,
    ),
    details: {
      path: generated,
      chain: blockchain.name,
      coinType: blockchain.coinType,
      account,
      change,
      addressIndex,
    },
  };
}

/** Exported WIF and the effective wallet options, without the input hex key. */
export interface EncodedWIFDetails {
  wif: string;
  chain: DecodedWIF["chain"];
  network: DecodedWIF["network"];
  compressed: boolean;
}

function parseWIFContext(chainValue: unknown, networkValue: unknown): WIFNetworkOptions {
  const chain = TOOL_WIF_CHAINS.find((candidate) => candidate === chainValue);
  if (chain === undefined)
    throw new Error(`Unsupported WIF chain. Use ${TOOL_WIF_CHAINS.join(", ")}`);
  const network = isUnset(networkValue) ? "mainnet" : networkValue;
  if (network !== "mainnet" && network !== "testnet")
    throw new Error("Unsupported WIF network. Use mainnet or testnet");
  return { chain, network };
}

/**
 * Export a disposable key as native WIF without echoing the supplied hex.
 * @param chainValue - Native WIF chain.
 * @param privateKeyValue - Disposable private key as hex.
 * @param networkValue - Optional network.
 * @param compressedValue - Optional compression flag.
 * @returns {ToolResult<EncodedWIFDetails>} WIF and effective wallet options.
 */
export function encodeWif(
  chainValue: unknown,
  privateKeyValue: unknown,
  networkValue?: unknown,
  compressedValue?: unknown,
): ToolResult<EncodedWIFDetails> {
  const options = parseWIFContext(chainValue, networkValue);
  const compressed = compressedValue === undefined ? true : compressedValue;
  if (typeof compressed !== "boolean") throw new TypeError("WIF compressed must be a boolean");
  const wif = encodeWIF(requiredString(privateKeyValue, "Private key"), { ...options, compressed });
  const details = { wif, chain: options.chain, network: options.network ?? "mainnet", compressed };
  return { content: content(JSON.stringify(details)), details };
}

/**
 * Read native WIF into hex and wallet options; both representations are secrets.
 * @param chainValue - Expected native WIF chain.
 * @param wifValue - Public or disposable WIF.
 * @param networkValue - Optional expected network.
 * @returns {ToolResult<DecodedWIF>} Private key and effective wallet options.
 */
export function decodeWif(
  chainValue: unknown,
  wifValue: unknown,
  networkValue?: unknown,
): ToolResult<DecodedWIF> {
  const options = parseWIFContext(chainValue, networkValue);
  const details = decodeWIF(requiredString(wifValue, "WIF"), options);
  return { content: content(JSON.stringify(details)), details };
}

/** Output from a SEC1 public key conversion. */
export interface ConvertedPublicKeyDetails {
  publicKey: string;
  compressed: boolean;
}

/**
 * Convert a public secp256k1 point between SEC1 encodings.
 * @param publicKeyValue - SEC1 hex input.
 * @param compressedValue - Optional output compression flag.
 * @returns {ToolResult<ConvertedPublicKeyDetails>} Converted public key and output encoding.
 */
export function convertPublicKey(
  publicKeyValue: unknown,
  compressedValue?: unknown,
): ToolResult<ConvertedPublicKeyDetails> {
  const compressed = compressedValue === undefined ? true : compressedValue;
  if (typeof compressed !== "boolean") throw new TypeError("Compressed must be a boolean");
  const publicKey = convertSecp256k1PublicKey(requiredString(publicKeyValue, "Public key"), {
    compressed,
  });
  const details = { publicKey, compressed };
  return { content: content(JSON.stringify(details)), details };
}

/** What the nonce tool answers; the private key stays in the library. */
export interface RecoveredNonceDetails {
  type: (typeof NONCE_SIGNATURE_TYPES)[number];
  publicKey: string;
}

const NONCE_SCALAR = new RegExp(NONCE_SCALAR_SCHEMA_PATTERN, "u");
const HEX_BYTES = new RegExp(HEX_BYTES_SCHEMA_PATTERN, "u");

/**
 * Reads an object argument, refusing any key the schema does not list.
 * @param value - Raw argument
 * @param name - Argument name for the error
 * @param keys - Keys the schema lists
 * @returns {Readonly<Record<string, unknown>>} The object
 */
function closedObject(
  value: unknown,
  name: string,
  keys: readonly string[],
): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object with ${keys.join(", ")}`);
  }
  if (Object.keys(value).some((key) => !keys.includes(key))) {
    throw new TypeError(`${name} takes only ${keys.join(", ")}`);
  }
  return Object.fromEntries(Object.entries(value));
}

/**
 * Reads an array argument with a length range.
 * @param value - Raw argument
 * @param name - Argument name for the error
 * @param minimum - Fewest items
 * @param maximum - Most items
 * @returns {readonly unknown[]} The items
 */
function boundedArray(
  value: unknown,
  name: string,
  minimum: number,
  maximum: number,
): readonly unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    const count = minimum === maximum ? `${minimum}` : `${minimum} to ${maximum}`;
    throw new RangeError(`${name} must be an array of ${count} items`);
  }
  return value;
}

/**
 * Reads one signature of the nonce tool.
 * @param value - Raw item
 * @param position - Its place, for the error
 * @returns {{ r: string; s: string; z: string }} Its hex parts
 */
function nonceSignature(value: unknown, position: number): { r: string; s: string; z: string } {
  const item = closedObject(value, `signatures[${position}]`, ["r", "s", "z"]);
  const [r, s, z] = ["r", "s", "z"].map((key) =>
    hexArgument(item[key], `signatures[${position}].${key}`, NONCE_SCALAR, "1 to 64 hex digits"),
  );
  return { r: r ?? "", s: s ?? "", z: z ?? "" };
}

/**
 * Recover the key behind two signatures that share a nonce and answer with its public key only.
 * @param typeValue - ecdsa or schnorr, ecdsa when blank.
 * @param signaturesValue - Two signatures with r, s and z.
 * @param publicKeyValue - Optional key the result must match.
 * @returns {ToolResult<RecoveredNonceDetails>} The public key both signatures verify under.
 */
export function recoverSecp256k1Nonce(
  typeValue: unknown,
  signaturesValue: unknown,
  publicKeyValue?: unknown,
): ToolResult<RecoveredNonceDetails> {
  const type = isUnset(typeValue) ? "ecdsa" : oneOf(typeValue, "type", NONCE_SIGNATURE_TYPES);
  const [first, second] = boundedArray(signaturesValue, "signatures", 2, 2).map((item, position) =>
    nonceSignature(item, position),
  );
  const publicKey = isUnset(publicKeyValue)
    ? undefined
    : hexArgument(publicKeyValue, "Public key", PUBLIC_KEY_HEX, "SEC1 or x-only hex");
  const recovered = recoverReusedNonce(
    { type, ...(first ?? { r: "", s: "", z: "" }) },
    { type, ...(second ?? { r: "", s: "", z: "" }) },
    publicKey === undefined ? {} : { publicKey },
  );
  const lines = [
    `Recovered the private key of ${recovered.publicKey}: both signatures verify under it${publicKey === undefined ? "" : ", and it matches publicKey"}.`,
    "The key stays out of this answer; recoverReusedNonce from @agntn/keys/secp256k1 returns it with the nonce.",
  ];
  return {
    content: content(lines.join("\n")),
    details: { type, publicKey: recovered.publicKey },
  };
}

/** What the transaction tool reads from one input. */
export interface TransactionSignaturesDetails {
  index: number;
  signatures: InputSignature[];
}

const HASH_TYPE_NAMES: Readonly<Record<number, string>> = {
  0: "SIGHASH_DEFAULT",
  1: "SIGHASH_ALL",
  2: "SIGHASH_NONE",
  3: "SIGHASH_SINGLE",
};

/**
 * Names a hash type byte.
 * @param hashType - The byte
 * @returns {string} Its name, with |ANYONECANPAY when that bit is set, or the hex of an unknown one
 */
function hashTypeName(hashType: number): string {
  const base = hashType & 0x7f;
  const name = Object.hasOwn(HASH_TYPE_NAMES, base) ? HASH_TYPE_NAMES[base] : undefined;
  if (name === undefined) return `hash type 0x${hashType.toString(16).padStart(2, "0")}`;
  return (hashType & 0x80) === 0 ? name : `${name}|ANYONECANPAY`;
}

/**
 * Reads one spent output of the transaction tool.
 * @param value - Raw item
 * @param position - Its place, for the error
 * @returns {{ script: string; value: number }} The script hex and the value
 */
function spentOutput(value: unknown, position: number): { script: string; value: number } {
  const item = closedObject(value, `spent[${position}]`, ["script", "value"]);
  const script = requiredString(item["script"], `spent[${position}].script`);
  if (script.length > MAX_SPENT_SCRIPT_HEX_LENGTH || !HEX_BYTES.test(script)) {
    throw new TypeError(
      `spent[${position}].script must be hex without 0x, at most ${MAX_SPENT_SCRIPT_HEX_LENGTH} digits`,
    );
  }
  const amount = optionalIndex(item["value"], `spent[${position}].value`, Number.MAX_SAFE_INTEGER);
  if (amount === undefined) throw new TypeError(`spent[${position}].value must be satoshis`);
  return { script, value: amount };
}

/**
 * One signature as the transaction tool writes it.
 * @param signature - The signature
 * @param position - Its place in the input, from 1
 * @returns {string} Its lines
 */
function signatureText(signature: Readonly<InputSignature>, position: number): string {
  const key =
    signature.publicKey ?? "none of the keys in the input or the spent script verifies it";
  return [
    `${position}. ${signature.type} ${hashTypeName(signature.hashType)}`,
    `   r: ${signature.r}`,
    `   s: ${signature.s}`,
    `   z: ${signature.z}`,
    `   key: ${key}`,
  ].join("\n");
}

/**
 * Read the signatures of one transaction input with the sighash each one signs.
 * @param transactionValue - Raw signed transaction hex.
 * @param indexValue - Input to read.
 * @param spentValue - Outputs the input spends, one or one per input.
 * @returns {ToolResult<TransactionSignaturesDetails>} r, s, z, hash type and key of each signature.
 */
export function extractTransactionSignatures(
  transactionValue: unknown,
  indexValue: unknown,
  spentValue: unknown,
): ToolResult<TransactionSignaturesDetails> {
  const transaction = requiredString(transactionValue, "Transaction");
  if (transaction.length > MAX_TRANSACTION_HEX_LENGTH || !HEX_BYTES.test(transaction)) {
    throw new TypeError(
      `Transaction must be hex without 0x, at most ${MAX_TRANSACTION_HEX_LENGTH} digits`,
    );
  }
  const index = optionalIndex(indexValue, "Index", MAX_INPUT_INDEX);
  if (index === undefined) throw new TypeError("Index must be the input to read");
  const spent = boundedArray(spentValue, "spent", 1, MAX_SPENT_OUTPUTS).map((item, position) =>
    spentOutput(item, position),
  );
  if (
    spent.reduce((total, output) => total + output.script.length, 0) > MAX_SPENT_SCRIPTS_HEX_LENGTH
  ) {
    throw new RangeError(
      `spent scripts together take at most ${MAX_SPENT_SCRIPTS_HEX_LENGTH} hex digits`,
    );
  }
  const signatures = extractSignatures(transaction, index, spent);
  const text =
    signatures.length === 0
      ? `Input ${index} carries no signature, or none this tool reads`
      : [
          `Input ${index}: ${signatures.length} signature${signatures.length === 1 ? "" : "s"}`,
          ...signatures.map((signature, position) => signatureText(signature, position + 1)),
        ].join("\n");
  return { content: content(text), details: { index, signatures } };
}

/**
 * Read the public header of a BIP38 key and optionally check an address against it.
 * No passphrase is taken and nothing is decrypted.
 * @param encryptedValue - BIP38 key starting with `6P`.
 * @param addressValue - Optional address to compare with the stored address hash.
 * @returns {ToolResult<BIP38Inspection>} Mode, flags, address hash and owner entropy.
 */
export function inspectBip38(
  encryptedValue: unknown,
  addressValue?: unknown,
): ToolResult<BIP38Inspection> {
  const address = optionalName(addressValue, "Address");
  if (address !== undefined && Array.from(address).length > MAX_BIP38_ADDRESS_LENGTH) {
    throw new RangeError(`Address must not exceed ${MAX_BIP38_ADDRESS_LENGTH} characters`);
  }
  const details = inspectBIP38(
    requiredString(encryptedValue, "BIP38 key"),
    address === undefined ? {} : { address },
  );
  return { content: content(JSON.stringify(details)), details };
}

/** A BIP38 key's header, and its public wallet when the passphrase opens it. */
export interface DecryptedBip38Details {
  mode: BIP38Mode;
  compressed: boolean;
  lot?: number;
  sequence?: number;
  /** Whether the passphrase gives an address with the stored address hash. */
  unlocked: boolean;
  chain?: "bitcoin";
  publicKey?: string;
  address?: string;
  /** Mainnet WIF, only when the caller asked for it. */
  wif?: string;
}

/**
 * Checks the BIP38 decrypt arguments for hosts that skip the schema, never echoing a value.
 * @param encryptedValue - Raw key argument
 * @param passphraseValue - Raw passphrase argument
 * @param revealKeyValue - Raw revealKey argument
 * @returns {{ encrypted: string; passphrase: string; revealKey: boolean }} The checked arguments
 */
function bip38Arguments(
  encryptedValue: unknown,
  passphraseValue: unknown,
  revealKeyValue: unknown,
): { encrypted: string; passphrase: string; revealKey: boolean } {
  const encrypted = requiredString(encryptedValue, "BIP38 key");
  const passphrase = requiredString(passphraseValue, "Passphrase");
  if (Array.from(passphrase).length > MAX_BIP38_PASSPHRASE_LENGTH) {
    throw new RangeError(`Passphrase must not exceed ${MAX_BIP38_PASSPHRASE_LENGTH} characters`);
  }
  const revealKey = revealKeyValue ?? false;
  if (typeof revealKey !== "boolean") throw new TypeError("revealKey must be a boolean");
  return { encrypted, passphrase, revealKey };
}

/**
 * Reads what a BIP38 key shows without its passphrase, as a text line and details.
 * @param encrypted - BIP38 key starting with `6P`
 * @returns {{ header: string[]; base: Omit<DecryptedBip38Details, "unlocked"> }} The header
 */
function bip38Summary(encrypted: string): {
  header: string[];
  base: Omit<DecryptedBip38Details, "unlocked">;
} {
  const { mode, compressed, lot, sequence } = inspectBIP38(encrypted);
  const lotSequence = lot === undefined ? "" : `, lot ${lot}, sequence ${sequence}`;
  return {
    header: [`BIP38: ${mode}, ${compressed ? "compressed" : "uncompressed"}${lotSequence}`],
    base: { mode, compressed, ...(lot === undefined ? {} : { lot, sequence }) },
  };
}

/**
 * Opens a BIP38 key with its passphrase and gives its Bitcoin wallet, with the WIF only on request.
 * A wrong passphrase is a result, not an error.
 * @param encryptedValue - BIP38 key starting with `6P`
 * @param passphraseValue - Passphrase
 * @param revealKeyValue - Whether to return the WIF, false by default
 * @returns {Promise<ToolResult<DecryptedBip38Details>>} Mode, verdict, public key, address, WIF
 */
export async function decryptBip38(
  encryptedValue: unknown,
  passphraseValue: unknown,
  revealKeyValue?: unknown,
): Promise<ToolResult<DecryptedBip38Details>> {
  const { encrypted, passphrase, revealKey } = bip38Arguments(
    encryptedValue,
    passphraseValue,
    revealKeyValue,
  );
  const { header, base } = bip38Summary(encrypted);
  const { compressed } = base;
  let decrypted: DecryptedBIP38;
  try {
    decrypted = decryptBIP38Key(encrypted, passphrase);
  } catch (error) {
    if (!(error instanceof BIP38PassphraseError)) throw error;
    return {
      content: content(
        [...header, "Passphrase: wrong, the address hash does not match"].join("\n"),
      ),
      details: { ...base, unlocked: false },
    };
  }
  const { blockchain } = await getBlockchain("bitcoin");
  const wallet = blockchain.deriveWallet(decrypted.privateKey.toHex(), { compressed }, "legacy");
  const details: DecryptedBip38Details = {
    ...base,
    unlocked: true,
    chain: "bitcoin",
    publicKey: wallet.keys.public,
    address: wallet.address,
    ...(revealKey ? { wif: decrypted.wif } : {}),
  };
  return {
    content: content(
      [
        ...header,
        "Passphrase: correct",
        `Public key: ${wallet.keys.public}`,
        `Address: ${wallet.address}`,
        ...(revealKey ? [`WIF: ${decrypted.wif}`] : []),
      ].join("\n"),
    ),
    details,
  };
}

/** Keystore parameters, and the public wallet when the password opens it. */
export interface DecryptedStoreDetails {
  version: 3;
  id?: string;
  kdf: KeystoreKDF & { dklen: number };
  /** The address the file stores, EIP-55, when it stores one. */
  storedAddress?: string;
  /** Whether the password gives the stored MAC. */
  unlocked: boolean;
  chain?: "ethereum";
  publicKey?: string;
  address?: string;
}

/**
 * Refuses keystore costs above the ceilings the KDF tools set, before the KDF runs.
 * @param kdf - KDF, costs and derived key length the file names
 */
function checkStoreCost(kdf: Readonly<KeystoreKDF & { dklen: number }>): void {
  costArgument(kdf.dklen, "keyLength");
  if (kdf.kdf === "pbkdf2") {
    costArgument(kdf.c, "iterations");
    return;
  }
  costArgument(kdf.n, "N", 2);
  costArgument(kdf.r, "r");
  costArgument(kdf.p, "p");
  if (kdf.n * kdf.r > MAX_SCRYPT_BLOCKS) {
    throw new RangeError(`N * r must not exceed ${MAX_SCRYPT_BLOCKS}`);
  }
}

/**
 * Reads a keystore's parameters under the cost ceilings, as text lines and details.
 * @param keystore - Keystore JSON text
 * @returns {{ header: string[]; base: Omit<DecryptedStoreDetails, "unlocked"> }} What the file shows
 */
function storeSummary(keystore: string): {
  header: string[];
  base: Omit<DecryptedStoreDetails, "unlocked">;
} {
  const file = inspectStore(keystore);
  const kdf: KeystoreKDF & { dklen: number } =
    file.kdf === "scrypt"
      ? { kdf: "scrypt", n: file.n, r: file.r, p: file.p, dklen: file.dklen }
      : { kdf: "pbkdf2", c: file.c, dklen: file.dklen };
  checkStoreCost(kdf);
  const costs =
    kdf.kdf === "scrypt" ? `n ${kdf.n}, r ${kdf.r}, p ${kdf.p}` : `c ${kdf.c}, hmac-sha256`;
  const stored = file.address === undefined ? {} : { storedAddress: file.address };
  return {
    header: [
      `Keystore: version 3, ${kdf.kdf} (${costs}), aes-128-ctr`,
      ...(file.address === undefined ? [] : [`Stored address: ${file.address}`]),
    ],
    base: { version: 3, ...(file.id === undefined ? {} : { id: file.id }), kdf, ...stored },
  };
}

/**
 * Opens a version 3 keystore and gives its public Ethereum wallet, never its private key. A wrong
 * password is a result, not an error.
 * @param keystoreValue - Keystore JSON text
 * @param passwordValue - Password
 * @returns {Promise<ToolResult<DecryptedStoreDetails>>} Parameters, verdict, public key and address
 */
export async function decryptStore(
  keystoreValue: unknown,
  passwordValue: unknown,
): Promise<ToolResult<DecryptedStoreDetails>> {
  const keystore = requiredString(keystoreValue, "Keystore");
  if (keystore.length > MAX_KEYSTORE_LENGTH) {
    throw new RangeError(`Keystore must not exceed ${MAX_KEYSTORE_LENGTH} characters`);
  }
  const password = requiredString(passwordValue, "Password");
  if (Array.from(password).length > MAX_KEYSTORE_PASSWORD_LENGTH) {
    throw new RangeError(`Password must not exceed ${MAX_KEYSTORE_PASSWORD_LENGTH} characters`);
  }
  const { header, base } = storeSummary(keystore);
  let privateKey: Uint8Array;
  try {
    privateKey = decryptStoreKey(keystore, password);
  } catch (error) {
    if (!(error instanceof KeystorePasswordError)) throw error;
    return {
      content: content([...header, "Password: wrong, the MAC does not match"].join("\n")),
      details: { ...base, unlocked: false },
    };
  }
  const { blockchain } = await getBlockchain("ethereum");
  const wallet = blockchain.deriveWallet(privateKey.toHex());
  const details: DecryptedStoreDetails = {
    ...base,
    unlocked: true,
    chain: "ethereum",
    publicKey: wallet.keys.public,
    address: wallet.address,
  };
  return {
    content: content(
      [
        ...header,
        "Password: correct",
        `Public key: ${wallet.keys.public}`,
        `Address: ${wallet.address}`,
      ].join("\n"),
    ),
    details,
  };
}
