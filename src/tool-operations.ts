/**
 * Tool executors shared by the MCP server and the Pi extension.
 *
 * Inputs may bypass a host schema, so every executor checks its own boundary.
 * Errors never echo secret inputs; conversion results contain the equivalent secret.
 */

import { bytesToHex } from "@noble/hashes/utils.js";
import { deriveElectrumSeed } from "./utils/electrum.ts";
import { getMasterKeyFromSeed } from "./utils/bip32/index.ts";
import { convertSecp256k1PublicKey } from "./utils/public-key.ts";
import { encodeWIF, decodeWIF, type DecodedWIF, type WIFNetworkOptions } from "./utils/wif.ts";
import type { AbstractBlockchain } from "./blockchain.ts";
import { blockchains, getBlockchainPath, parseBIP44Path, useBlockchain } from "./index.ts";
import {
  MAX_BIP39_LOOKUP_ITEMS,
  BIP39_ENTROPY_BYTE_LENGTHS,
  TOOL_ADDRESS_TYPES_BY_CHAIN,
  TOOL_CHAINS,
  TOOL_NETWORKS,
  TOOL_MNEMONIC_WORD_COUNTS,
  MAX_BIP39_SEED_INPUT_LENGTH,
  TOOL_WIF_CHAINS,
  type ToolChain,
  type ToolNetwork,
} from "./tool-parameters.ts";
import {
  bip39,
  loadBIP39Wordlist,
  getMnemonicWordCandidates,
  inspectBIP39Mnemonic,
  lookupBIP39Indices,
  lookupBIP39Words,
} from "./utils/bip39/index.ts";
import { BIP39_LANGUAGES, isBIP39Language, type BIP39Language } from "./utils/bip39/languages.ts";

export {
  MAX_BIP39_LOOKUP_ITEMS,
  BIP39_ENTROPY_BYTE_LENGTHS,
  BIP39_ENTROPY_SCHEMA_PATTERN,
  BIP39_WORD_SCHEMA_PATTERN,
  DERIVATION_PATH_SCHEMA_PATTERN,
} from "./tool-parameters.ts";

/** Text for the model plus structured details for agent harnesses. */
export interface ToolResult<Details> {
  content: Array<{ type: "text"; text: string }>;
  details: Details;
  /** Set when the tool could not perform the requested operation. */
  isError?: boolean;
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
  position: number;
  candidates: readonly string[];
}

/** Address derived from a public key. */
export interface AddressDetails {
  chain: string;
  network: string;
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
}

/** Signature verification result. */
export interface SignatureVerificationDetails {
  chain: string;
  network: string;
  valid: boolean;
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
const DERIVATION_PATH_PATTERN = /^m(?:\/\d+'?)+$/u;

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

function optionalString(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined;
  return requiredString(value, name);
}

function optionalIndex(value: unknown, name: string, maximum = 0x7fffffff): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > maximum) {
    throw new RangeError(`${name} must be an integer between 0 and ${maximum}`);
  }
  return value;
}

function assertBip44PathMode(
  chainValue: unknown,
  pathValue: unknown,
  generationOptions: readonly unknown[],
): void {
  if (pathValue === undefined) {
    if (chainValue !== undefined) return;
  } else if (chainValue === undefined && generationOptions.every((value) => value === undefined)) {
    return;
  }
  throw new TypeError(
    "Provide path by itself, or chain with optional account, change, addressIndex, and addressType",
  );
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

const BLOCKCHAIN_LOADERS: ReadonlyArray<{
  name: ToolChain;
  load(network: ToolNetwork): Promise<AbstractBlockchain>;
}> = [
  {
    name: "bitcoin",
    load: async (network) => useBlockchain(await blockchains.bitcoin({ network })()),
  },
  {
    name: "litecoin",
    load: async (network) => useBlockchain(await blockchains.litecoin({ network })()),
  },
  {
    name: "decred",
    load: async (network) => useBlockchain(await blockchains.decred({ network })()),
  },
  {
    name: "ethereum",
    load: async (network) => useBlockchain(await blockchains.ethereum({ network })()),
  },
  { name: "base", load: async (network) => useBlockchain(await blockchains.base({ network })()) },
  {
    name: "solana",
    load: async (network) => useBlockchain(await blockchains.solana({ network })()),
  },
  {
    name: "stellar",
    load: async (network) => useBlockchain(await blockchains.stellar({ network })()),
  },
  { name: "aptos", load: async (network) => useBlockchain(await blockchains.aptos({ network })()) },
  { name: "tron", load: async (network) => useBlockchain(await blockchains.tron({ network })()) },
  { name: "sui", load: async (network) => useBlockchain(await blockchains.sui({ network })()) },
  {
    name: "cardano",
    load: async (network) => useBlockchain(await blockchains.cardano({ network })()),
  },
];

function parseNetwork(value: unknown): ToolNetwork {
  const network = optionalString(value, "Network") ?? "mainnet";
  const matched = TOOL_NETWORKS.find((candidate) => candidate === network);
  if (matched === undefined) {
    throw new RangeError(
      `Unsupported network ${JSON.stringify(network)}. Supported: ${TOOL_NETWORKS.join(", ")}`,
    );
  }
  return matched;
}

function parseAddressType(chain: ToolChain, value: unknown): string | undefined {
  const addressType = optionalString(value, "Address type");
  if (addressType === undefined) return undefined;

  const supported = TOOL_ADDRESS_TYPES_BY_CHAIN[chain];
  if (supported.length === 0) {
    throw new RangeError(`Address type is not supported for ${chain}`);
  }
  const matched = supported.find((candidate) => candidate === addressType);
  if (matched === undefined) {
    throw new RangeError(
      `Address type ${JSON.stringify(addressType)} is not supported for ${chain}. Supported: ${supported.join(", ")}`,
    );
  }
  return matched;
}

async function getBlockchain(
  chainValue: unknown,
  networkValue?: unknown,
  addressTypeValue?: unknown,
): Promise<{ readonly blockchain: AbstractBlockchain; readonly addressType: string | undefined }> {
  const chain = requiredString(chainValue, "Chain").toLowerCase();
  const loader = BLOCKCHAIN_LOADERS.find((candidate) => candidate.name === chain);
  if (!loader) {
    throw new RangeError(
      `Unknown chain ${JSON.stringify(chain)}. Supported: ${TOOL_CHAINS.join(", ")}`,
    );
  }
  const network = parseNetwork(networkValue);
  const addressType = parseAddressType(loader.name, addressTypeValue);
  return { blockchain: await loader.load(network), addressType };
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
        `Private key: ${details.privateKey}`,
        `Public key: ${details.publicKey}`,
        `Address: ${details.address}`,
      ].join("\n"),
    ),
    details: undefined,
  };
}

/**
 * Derive public wallet material from a private key without echoing the secret.
 * @param chainValue - Blockchain name.
 * @param privateKeyValue - Private key as hexadecimal text.
 * @param addressTypeValue - Optional chain-specific address type.
 * @param networkValue - Optional network name.
 * @returns {Promise<ToolResult<DerivedWalletDetails>>} Derived public wallet material.
 */
export async function deriveWallet(
  chainValue: unknown,
  privateKeyValue: unknown,
  addressTypeValue?: unknown,
  networkValue?: unknown,
): Promise<ToolResult<DerivedWalletDetails>> {
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
  );
  const privateKey = requiredString(privateKeyValue, "Private key");
  const wallet = blockchain.deriveWallet(privateKey, {}, addressType);
  const details = {
    chain: blockchain.name,
    network: blockchain.network,
    publicKey: wallet.keys.public,
    address: wallet.address,
  };
  return {
    content: content(`Public key: ${details.publicKey}\nAddress: ${details.address}`),
    details,
  };
}

/**
 * Derive public wallet material from a BIP39 mnemonic and path.
 * @param chainValue - Blockchain name.
 * @param mnemonicValue - English BIP39 mnemonic.
 * @param pathValue - Absolute derivation path.
 * @param passphraseValue - Optional BIP39 passphrase.
 * @param addressTypeValue - Optional chain-specific address type.
 * @param networkValue - Optional network name.
 * @param allowInvalidChecksumValue - Accept a checksum failure for a public puzzle, default false.
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
  const mnemonic = requiredString(mnemonicValue, "BIP39 mnemonic");
  const passphrase = optionalString(passphraseValue, "BIP39 passphrase");
  const wallet = blockchain.deriveHDWallet(
    mnemonic,
    path,
    { passphrase, allowInvalidChecksum },
    addressType,
  );
  const details = {
    chain: blockchain.name,
    network: blockchain.network,
    path,
    publicKey: wallet.keys.public,
    address: wallet.address,
    ...(wallet.warnings === undefined ? {} : { warnings: wallet.warnings }),
  };
  return {
    content: content(
      [
        `Chain: ${details.chain} (${details.network})`,
        `Path: ${path}`,
        `Public key: ${details.publicKey}`,
        `Address: ${details.address}`,
        ...(details.warnings ?? []).map((warning) => `Warning: ${warning}`),
      ].join("\n"),
    ),
    details,
  };
}

/**
 * Derives public Bitcoin wallet material from a complete Electrum phrase and exact path.
 * @param mnemonicValue - Public or disposable Electrum phrase
 * @param pathValue - Exact absolute BIP32 path
 * @param passphraseValue - Electrum passphrase
 * @param networkValue - Bitcoin network
 * @returns {Promise<ToolResult<DerivedWalletDetails & { scheme: "electrum"; seedType: "standard" | "segwit" }>>} Public wallet and seed version
 */
export async function deriveElectrumWallet(
  mnemonicValue: unknown,
  pathValue: unknown,
  passphraseValue?: unknown,
  networkValue?: unknown,
): Promise<
  ToolResult<DerivedWalletDetails & { scheme: "electrum"; seedType: "standard" | "segwit" }>
> {
  const path = requiredString(pathValue, "Derivation path");
  if (path.length > 256 || !DERIVATION_PATH_PATTERN.test(path))
    throw new TypeError("Invalid derivation path");
  const mnemonic = requiredString(mnemonicValue, "Electrum mnemonic");
  const passphrase = optionalString(passphraseValue, "Electrum passphrase") ?? "";
  const { blockchain } = await getBlockchain("bitcoin", networkValue);
  const { seed, seedType, scheme } = deriveElectrumSeed(mnemonic, passphrase);
  const privateKey = getMasterKeyFromSeed(seed).derive(path).privateKey;
  if (!privateKey) throw new Error("No private key at the supplied path");
  const wallet = blockchain.deriveWallet(
    bytesToHex(privateKey),
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
  if (!inspectBIP39Mnemonic(mnemonic, wordlist).valid) {
    throw new TypeError("Invalid BIP39 mnemonic for the selected language");
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
  const entropyText = requiredString(entropyValue, "BIP39 entropy");
  if (!BIP39_ENTROPY_PATTERN.test(entropyText)) {
    throw new TypeError("BIP39 entropy must be a hexadecimal string");
  }
  if (!BIP39_ENTROPY_BYTE_LENGTHS.includes(entropyText.length / 2)) {
    throw new RangeError("BIP39 entropy must be 16, 20, 24, 28, or 32 bytes");
  }
  const language = parseBIP39Language(languageValue);
  const wordlist = await loadBIP39Wordlist(language);
  const mnemonic = bip39.entropyToMnemonic(Buffer.from(entropyText, "hex"), wordlist);
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
 * List English BIP39 words that satisfy one missing checksum position.
 * @param mnemonicValue - Mnemonic template containing one question mark.
 * @returns {ToolResult<MnemonicRecoveryDetails>} Position and candidate words.
 */
export function recoverMnemonicWord(mnemonicValue: unknown): ToolResult<MnemonicRecoveryDetails> {
  const mnemonic = normalizedMnemonic(mnemonicValue);
  const position = mnemonic.split(" ").indexOf("?") + 1;
  const candidates = getMnemonicWordCandidates(mnemonic);
  return {
    content: content(
      `Position: ${position}\nCandidates (${candidates.length}): ${candidates.length === 0 ? "none" : candidates.join(", ")}`,
    ),
    details: { position, candidates },
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
  const publicKey = requiredString(publicKeyValue, "Public key");
  const address = blockchain.getAddress(publicKey, addressType);
  return {
    content: content(`Address: ${address}`),
    details: { chain: blockchain.name, network: blockchain.network, address },
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
  const valid = blockchain.validateAddress(address);
  const renderedAddress = sanitizeToolText(address);
  return {
    content: content(
      valid
        ? `${renderedAddress} is a valid ${blockchain.name} address`
        : `${renderedAddress} is not a valid ${blockchain.name} address`,
    ),
    details: { chain: blockchain.name, network: blockchain.network, address, valid },
  };
}

/**
 * Sign a message without retaining the private key or message in result details.
 * @param chainValue - Blockchain name.
 * @param messageValue - Message to sign.
 * @param privateKeyValue - Private key as hexadecimal text.
 * @param networkValue - Optional network name.
 * @returns {Promise<ToolResult<SignatureDetails>>} Generated signature.
 */
export async function signMessage(
  chainValue: unknown,
  messageValue: unknown,
  privateKeyValue: unknown,
  networkValue?: unknown,
): Promise<ToolResult<SignatureDetails>> {
  const { blockchain } = await getBlockchain(chainValue, networkValue);
  const message = requiredString(messageValue, "Message");
  const privateKey = requiredString(privateKeyValue, "Private key");
  const signature = blockchain.signMessage(message, privateKey);
  return {
    content: content(`Signature: ${signature}`),
    details: { chain: blockchain.name, network: blockchain.network, signature },
  };
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
  const signature = requiredString(signatureValue, "Signature");
  const publicKey = requiredString(publicKeyValue, "Public key");
  const valid = blockchain.verifyMessage(message, signature, publicKey);
  return {
    content: content(valid ? "Signature is valid" : "Signature is invalid"),
    details: { chain: blockchain.name, network: blockchain.network, valid },
  };
}

/**
 * Parse a BIP44 path or generate the one a chain's wallets use. The chain checks the change value,
 * Cardano up to the CIP-1852 roles, and the address type names the scheme where two curves exist.
 * @param chainValue - Blockchain name for generation mode.
 * @param pathValue - Existing BIP44 path for parse mode.
 * @param accountValue - Account index.
 * @param changeValue - External or internal branch, or the CIP-1852 role on Cardano.
 * @param addressIndexValue - Address index.
 * @param addressTypeValue - Signature scheme on Sui, ed25519 by default.
 * @returns {Promise<ToolResult<BIP44PathDetails>>} Parsed or generated path.
 */
export async function bip44Path(
  chainValue?: unknown,
  pathValue?: unknown,
  accountValue?: unknown,
  changeValue?: unknown,
  addressIndexValue?: unknown,
  addressTypeValue?: unknown,
): Promise<ToolResult<BIP44PathDetails>> {
  assertBip44PathMode(chainValue, pathValue, [
    accountValue,
    changeValue,
    addressIndexValue,
    addressTypeValue,
  ]);
  const path = optionalString(pathValue, "BIP44 path");
  if (path !== undefined) {
    const parsed = parseBIP44Path(path);
    if (!parsed) {
      return {
        content: content(`Invalid BIP44 path: ${JSON.stringify(path)}`),
        details: { path, coinType: -1, account: -1, change: -1, addressIndex: -1 },
        isError: true,
      };
    }
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
    throw new Error("Unsupported WIF chain. Use bitcoin, litecoin or decred");
  const network = networkValue === undefined ? "mainnet" : networkValue;
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
