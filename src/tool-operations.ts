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
import { deriveHDKey, getMasterKeyFromSeed } from "./utils/bip32/index.ts";
import { convertPublicKey as convertSecp256k1PublicKey } from "./utils/secp256k1/index.ts";
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
import type { MessageSigner } from "./types.ts";
import { hashTypedData, type TypedData } from "./utils/eip712.ts";
import {
  MAX_BIP39_LOOKUP_ITEMS,
  BIP39_ENTROPY_BYTE_LENGTHS,
  TOOL_ADDRESS_TYPES_BY_CHAIN,
  TOOL_CHAINS,
  TOOL_NETWORKS,
  TOOL_MNEMONIC_WORD_COUNTS,
  MAX_BIP39_SEED_INPUT_LENGTH,
  MAX_BIP38_ADDRESS_LENGTH,
  MAX_BIP38_PASSPHRASE_LENGTH,
  MAX_KEYSTORE_LENGTH,
  MAX_KEYSTORE_PASSWORD_LENGTH,
  MAX_ADDRESS_LENGTH,
  MAX_BRAINWALLET_INPUT_LENGTH,
  MAX_SCRYPT_BLOCKS,
  KDF_COST_LIMITS,
  TOOL_WIF_CHAINS,
  PRIVATE_KEY_SCHEMA_PATTERN,
  PUBLIC_KEY_SCHEMA_PATTERN,
  CORE_SIGNATURE_SCHEMA_PATTERN,
  RECOVERABLE_SIGNATURE_SCHEMA_PATTERN,
  DIGEST_SCHEMA_PATTERN,
  MAX_TYPED_DATA_LENGTH,
  SIGNATURE_SCHEMA_PATTERN,
  type ToolChain,
  type ToolNetwork,
} from "./tool-parameters.ts";
import {
  bip39,
  loadWordlist as loadBIP39Wordlist,
  getMnemonicWordCandidates,
  inspect as inspectBIP39Mnemonic,
  lookupIndices as lookupBIP39Indices,
  lookupWords as lookupBIP39Words,
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

/** Result of a BIP39 word lookup. */
export interface BIP39WordLookupDetails {
  language: string;
  lookups: Array<{ word: string; zeroBasedIndex: number | null; oneBasedIndex: number | null }>;
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
const SIGNATURE_HEX = new RegExp(SIGNATURE_SCHEMA_PATTERN, "u");
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

async function getBlockchain(
  chainValue: unknown,
  networkValue?: unknown,
  addressTypeValue?: unknown,
): Promise<{ readonly blockchain: AbstractBlockchain; readonly addressType: string | undefined }> {
  const name = requiredString(chainValue, "Chain").toLowerCase();
  const chain = TOOL_CHAINS.find((candidate) => candidate === name);
  if (chain === undefined) {
    throw new RangeError(
      `Unknown chain ${JSON.stringify(name)}. Supported: ${TOOL_CHAINS.join(", ")}`,
    );
  }
  const network = parseNetwork(networkValue);
  const addressType = parseAddressType(chain, addressTypeValue);
  return { blockchain: useBlockchain(await blockchains[chain]({ network })()), addressType };
}

/**
 * Generate a disposable wallet for one supported blockchain.
 * @param chainValue - Blockchain name.
 * @param networkValue - Optional network name.
 * @param addressTypeValue - Optional chain-specific address type.
 * @returns {Promise<ToolResult<GeneratedWalletDetails | undefined>>} Generated key and address material.
 */
export async function generateWallet(
  chainValue: unknown,
  networkValue?: unknown,
  addressTypeValue?: unknown,
): Promise<ToolResult<GeneratedWalletDetails | undefined>> {
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
  );
  const wallet = blockchain.generateWallet({}, addressType);
  const details = {
    chain: blockchain.name,
    network: blockchain.network,
    curve: formatCurve(blockchain.curve),
    bip44: blockchain.bip44,
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

/** Chains whose address hashes the uncompressed secp256k1 key whatever form it is given in. */
const UNCOMPRESSED_ADDRESS_CHAINS: ReadonlySet<string> = new Set(["ethereum", "base", "tron"]);

/**
 * Reads the public key form, refusing one the chain's address would ignore.
 * @param blockchain - Chain the wallet is for
 * @param addressType - Parsed address type, which picks the curve on Sui
 * @param value - Raw argument
 * @returns {boolean | undefined} The form to derive, undefined when omitted
 */
function walletCompressed(
  blockchain: Readonly<AbstractBlockchain>,
  addressType: string | undefined,
  value: unknown,
): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw new TypeError("compressed must be a boolean");
  const { name, curve } = blockchain;
  if (curve !== "secp256k1" && addressType !== "secp256k1") {
    throw new RangeError(`${name} ed25519 keys take no compressed`);
  }
  if (value && UNCOMPRESSED_ADDRESS_CHAINS.has(name)) {
    throw new RangeError(
      `${name} addresses hash the uncompressed key, so compressed: true does not apply`,
    );
  }
  if (!value && name === "sui") {
    throw new RangeError(
      "sui secp256k1 addresses hash the compressed key, so compressed: false does not apply",
    );
  }
  return value;
}

/**
 * Derive public wallet material from a private key without echoing the secret.
 * @param chainValue - Blockchain name.
 * @param privateKeyValue - Private key as hexadecimal text.
 * @param addressTypeValue - Optional chain-specific address type.
 * @param networkValue - Optional network name.
 * @param compressedValue - Optional secp256k1 public key form, compressed by default.
 * @returns {Promise<ToolResult<DerivedWalletDetails>>} Derived public wallet material.
 */
export async function deriveWallet(
  chainValue: unknown,
  privateKeyValue: unknown,
  addressTypeValue?: unknown,
  networkValue?: unknown,
  compressedValue?: unknown,
): Promise<ToolResult<DerivedWalletDetails>> {
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
  );
  const compressed = walletCompressed(blockchain, addressType, compressedValue);
  const privateKey = hexArgument(
    privateKeyValue,
    "Private key",
    PRIVATE_KEY_HEX,
    "64 hex characters",
  );
  const wallet = blockchain.deriveWallet(
    privateKey,
    compressed === undefined ? {} : { compressed },
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
): Promise<ToolResult<DerivedWalletDetails>> {
  if (allowInvalidChecksumValue !== undefined && typeof allowInvalidChecksumValue !== "boolean") {
    throw new TypeError("allowInvalidChecksum must be a boolean");
  }
  const allowInvalidChecksum = allowInvalidChecksumValue ?? false;
  const path = requiredString(pathValue, "Derivation path");
  if (!DERIVATION_PATH_PATTERN.test(path)) {
    throw new TypeError("Derivation path must look like m/84'/0'/0'/0/0");
  }
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
  );
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
 * @returns {Promise<ToolResult<DerivedXpubWalletDetails>>} Public key and address at the path.
 */
export async function deriveXpubWallet(
  chainValue: unknown,
  extendedKeyValue: unknown,
  pathValue: unknown,
  addressTypeValue?: unknown,
  networkValue?: unknown,
): Promise<ToolResult<DerivedXpubWalletDetails>> {
  const extendedKey = requiredString(extendedKeyValue, "Extended key");
  const path = requiredString(pathValue, "Derivation path");
  if (path.length > 256) throw new TypeError("Invalid derivation path");
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
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
 * Validate a BIP39 mnemonic against the selected list and recover its entropy when valid.
 * @param mnemonicValue - BIP39 mnemonic candidate.
 * @param languageValue - Optional official BIP39 language key.
 * @returns {Promise<ToolResult<MnemonicInspectionDetails>>} Validity and optional entropy.
 */
export async function inspectMnemonic(
  mnemonicValue: unknown,
  languageValue?: unknown,
): Promise<ToolResult<MnemonicInspectionDetails>> {
  const mnemonic = normalizedMnemonic(mnemonicValue);
  const language = parseBIP39Language(languageValue);
  const wordlist = await loadBIP39Wordlist(language);
  const inspection = inspectBIP39Mnemonic(mnemonic, wordlist);
  const { valid, words, wordCountValid, wordlistValid, checksumValid } = inspection;
  const entropy = valid
    ? Buffer.from(bip39.mnemonicToEntropy(mnemonic, wordlist)).toString("hex")
    : undefined;
  const details = { language, ...inspection, ...(entropy === undefined ? {} : { entropy }) };
  return {
    content: content(
      [
        `Language: ${language}`,
        `Valid BIP39: ${valid ? "yes" : "no"}`,
        `Words: ${words}`,
        `Word count valid: ${wordCountValid ? "yes" : "no"}`,
        `Wordlist valid: ${wordlistValid ? "yes" : "no"}`,
        `Checksum valid: ${checksumValid === null ? "not checked" : checksumValid ? "yes" : "no"}`,
        entropy === undefined ? undefined : `Entropy: ${entropy}`,
      ]
        .filter((line) => line !== undefined)
        .join("\n"),
    ),
    details,
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
  const lookups = found.map((lookup) => ({
    word: lookup.word,
    zeroBasedIndex: lookup.zeroBasedIndex,
    oneBasedIndex: lookup.zeroBasedIndex === null ? null : lookup.zeroBasedIndex + 1,
  }));
  return {
    content: content(
      [
        `Language: ${language}`,
        "Indices: zero-based, one-based",
        ...lookups.map((lookup) =>
          lookup.zeroBasedIndex === null
            ? `${lookup.word}: not in BIP39`
            : `${lookup.word}: ${lookup.zeroBasedIndex}, ${lookup.oneBasedIndex}`,
        ),
      ].join("\n"),
    ),
    details: { language, lookups },
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
 * @returns {Promise<ToolResult<AddressDetails>>} Derived address.
 */
export async function getAddress(
  chainValue: unknown,
  publicKeyValue: unknown,
  addressTypeValue?: unknown,
  networkValue?: unknown,
): Promise<ToolResult<AddressDetails>> {
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
  );
  const publicKey = hexArgument(
    publicKeyValue,
    "Public key",
    PUBLIC_KEY_HEX,
    "a 32-byte ed25519 or SEC1 secp256k1 key in hex",
  );
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
 * @returns {Promise<ToolResult<AddressValidationDetails>>} Address format verdict.
 */
export async function validateAddress(
  chainValue: unknown,
  addressValue: unknown,
  networkValue?: unknown,
): Promise<ToolResult<AddressValidationDetails>> {
  const { blockchain } = await getBlockchain(chainValue, networkValue);
  const address = requiredString(addressValue, "Address");
  if (Array.from(address).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Address must not exceed ${MAX_ADDRESS_LENGTH} characters`);
  }
  const valid = blockchain.validateAddress(address);
  const renderedAddress = sanitizeToolText(address);
  const otherNetwork = valid
    ? undefined
    : await otherNetworkOf(chainValue, blockchain.network, address);
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
 * Finds the other network an address is valid on, so a testnet address checked against
 * mainnet is not reported as simply broken.
 * @param chainValue - Blockchain name, already accepted by `getBlockchain`.
 * @param network - Network the address failed on.
 * @param address - Address that failed.
 * @returns {Promise<ToolNetwork | undefined>} The other network, when the address passes there.
 */
async function otherNetworkOf(
  chainValue: unknown,
  network: string,
  address: string,
): Promise<ToolNetwork | undefined> {
  const other = TOOL_NETWORKS.find((candidate) => candidate !== network);
  if (other === undefined) return undefined;
  const { blockchain } = await getBlockchain(chainValue, other);
  return blockchain.validateAddress(address) ? other : undefined;
}

/**
 * Sign a message without retaining the private key or message in result details.
 * @param chainValue - Blockchain name.
 * @param messageValue - Message to sign.
 * @param privateKeyValue - Private key as hexadecimal text.
 * @param networkValue - Optional network name.
 * @param recoveredValue - Append the recovery byte as `v`, default false.
 * @returns {Promise<ToolResult<SignatureDetails>>} Generated signature.
 */
export async function signMessage(
  chainValue: unknown,
  messageValue: unknown,
  privateKeyValue: unknown,
  networkValue?: unknown,
  recoveredValue?: unknown,
): Promise<ToolResult<SignatureDetails>> {
  if (recoveredValue !== undefined && typeof recoveredValue !== "boolean") {
    throw new TypeError("recovered must be a boolean");
  }
  const recovered = recoveredValue ?? false;
  const { blockchain } = await getBlockchain(chainValue, networkValue);
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
 * @returns {Promise<ToolResult<SignatureVerificationDetails>>} Signature verdict.
 */
export async function verifyMessage(
  chainValue: unknown,
  messageValue: unknown,
  signatureValue: unknown,
  publicKeyValue: unknown,
  networkValue?: unknown,
): Promise<ToolResult<SignatureVerificationDetails>> {
  const { blockchain } = await getBlockchain(chainValue, networkValue);
  const message = requiredString(messageValue, "Message");
  const signatureText = requiredString(signatureValue, "Signature");
  const core = CORE_SIGNATURE.test(signatureText);
  const signature = core
    ? signatureText
    : hexArgument(signatureText, "Signature", SIGNATURE_HEX, "64 or 65 bytes of hex");
  const publicKey = hexArgument(
    publicKeyValue,
    "Public key",
    PUBLIC_KEY_HEX,
    "a 32-byte ed25519 or SEC1 secp256k1 key in hex",
  );
  if (core) assertReadableSignature(blockchain, message, signature);
  const valid = blockchain.verifyMessage(message, signature, publicKey);
  return {
    content: content(valid ? "Signature is valid" : "Signature is invalid"),
    details: { chain: blockchain.name, network: blockchain.network, valid },
  };
}

/**
 * Compare a written address with a typed one: bech32 and CashAddr ignore case, base58 doesn't.
 * @param written - Address from `getAddress`
 * @param given - Address the caller passed, already validated for the chain
 * @returns {boolean} True when both name the same address
 */
function sameAddress(written: string, given: string): boolean {
  if (written === given) return true;
  if (written.startsWith("0x")) return written.toLowerCase() === given.toLowerCase();
  if (!written.includes(":") && !/^[a-z]+1[02-9ac-hj-np-z]+$/u.test(written)) return false;
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
 * @returns {Promise<ToolResult<BIP44PathDetails>>} The generated path.
 */
export async function generateBip44Path(
  chainValue: unknown,
  accountValue?: unknown,
  changeValue?: unknown,
  addressIndexValue?: unknown,
  addressTypeValue?: unknown,
): Promise<ToolResult<BIP44PathDetails>> {
  const account = optionalIndex(accountValue, "Account") ?? 0;
  const change = optionalIndex(changeValue, "Change") ?? 0;
  const addressIndex = optionalIndex(addressIndexValue, "Address index") ?? 0;
  const { blockchain, addressType } = await getBlockchain(chainValue, undefined, addressTypeValue);
  if (addressType !== undefined && !Array.isArray(blockchain.curve)) {
    throw new RangeError(`addressType names a scheme, and ${blockchain.name} has one curve`);
  }
  const options = addressType === undefined ? undefined : { scheme: addressType };
  const generated = getBlockchainPath(blockchain, account, change, addressIndex, options);
  return {
    content: content(
      `Chain: ${blockchain.name} (BIP44 coin type: ${blockchain.bip44})\nPath: ${generated}`,
    ),
    details: {
      path: generated,
      chain: blockchain.name,
      coinType: blockchain.bip44,
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
