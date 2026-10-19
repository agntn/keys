import {
  MAX_EXTENDED_KEY_LENGTH,
  MAX_WIF_LENGTH,
  TOOL_WIF_CHAINS,
  TOOL_NETWORKS,
} from "../tool-parameters.ts";
import {
  type RecoveredParent,
  recoverParent,
  BIP32ChildMismatchError,
} from "../utils/bip32/index.ts";
import {
  entropyToMnemonic,
  loadWordlist as loadBIP39Wordlist,
  inspect as inspectBIP39Mnemonic,
} from "../utils/bip39/index.ts";
import { normalizeMnemonic, describeInvalidMnemonic } from "../utils/hd.ts";
import { decode as decodeWIF } from "../utils/wif/index.ts";
import { requiredString, optionalString, PRIVATE_KEY_HEX, optionalIndex } from "./arguments.ts";
import {
  type Bip39ListArguments,
  parseBip39Entropy,
  colemanFlag,
  parseBIP39Language,
} from "./bip39.ts";
import { type ChainArguments, getBlockchain, addressTypeLines } from "./blockchain.ts";
import { type ToolResult, content } from "./results.ts";
import type { DerivedWalletDetails } from "./wallet.ts";

export const DERIVATION_PATH_PATTERN = /^m(?:\/\d+['h]?)+$/u;

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

/** The mnemonic or its entropy hex, each as the caller passed it. */
interface MnemonicSource {
  readonly mnemonic?: unknown;
  readonly entropy?: unknown;
}

/** Word list that spells the entropy, and whether to take Coleman's entropy lengths. */
interface EntropySpelling {
  readonly wordlist: readonly string[];
  readonly coleman: boolean;
}

/**
 * Takes the mnemonic as given, or spells the entropy with the word list; exactly one of them.
 * @param source - Mnemonic or entropy as the caller passed it
 * @param spelling - Word list and Coleman flag that spell the entropy
 * @returns {string} Mnemonic to derive from
 */
function mnemonicOrEntropy(source: MnemonicSource, spelling: EntropySpelling): string {
  const { wordlist, coleman } = spelling;
  const { mnemonic: mnemonicValue, entropy: entropyValue } = source;
  if (mnemonicValue !== undefined && entropyValue !== undefined) {
    throw new TypeError("Pass either a BIP39 mnemonic or its entropy, not both");
  }
  if (entropyValue === undefined) {
    if (mnemonicValue === undefined) throw new TypeError("Pass a BIP39 mnemonic or its entropy");
    return requiredString(mnemonicValue, "BIP39 mnemonic");
  }
  return entropyToMnemonic(parseBip39Entropy(entropyValue, coleman), wordlist, { coleman });
}

/** HD wallet tool arguments besides the chain, raw until the executor checks them. */
export interface HdWalletArguments
  extends Omit<ChainArguments, "coinType">, Bip39ListArguments, MnemonicSource {
  /** Absolute derivation path. */
  readonly path?: unknown;
  readonly passphrase?: unknown;
  /** Accept a checksum failure for a public puzzle, default false. */
  readonly allowInvalidChecksum?: unknown;
}

/**
 * Derive public wallet material from a BIP39 mnemonic or its entropy and a path.
 * @param chainValue - Blockchain name.
 * @param options - Mnemonic or entropy, path, passphrase, word list and network options.
 * @returns {Promise<ToolResult<DerivedWalletDetails>>} Derived public wallet material.
 */
export async function deriveHdWallet(
  chainValue: unknown,
  options: HdWalletArguments,
): Promise<ToolResult<DerivedWalletDetails>> {
  const allowInvalidChecksumValue = options.allowInvalidChecksum;
  if (allowInvalidChecksumValue !== undefined && typeof allowInvalidChecksumValue !== "boolean") {
    throw new TypeError("allowInvalidChecksum must be a boolean");
  }
  const allowInvalidChecksum = allowInvalidChecksumValue ?? false;
  const coleman = colemanFlag(options.coleman);
  const path = requiredString(options.path, "Derivation path");
  const { blockchain, addressType } = await getBlockchain(chainValue, {
    network: options.network,
    addressType: options.addressType,
    prefix: options.prefix,
  });
  assertHdWalletPath(blockchain.name, path);
  const passphrase = optionalString(options.passphrase, "BIP39 passphrase");
  const language = parseBIP39Language(options.language);
  const wordlist = await loadBIP39Wordlist(language);
  const mnemonic = mnemonicOrEntropy(options, { wordlist, coleman });
  const words = normalizeMnemonic(mnemonic);
  const inspection = inspectBIP39Mnemonic(words, wordlist, { coleman });
  if (inspection.checksumValid === null) {
    throw new TypeError(describeInvalidMnemonic(words, inspection, wordlist, language));
  }
  const wallet = blockchain.deriveHDWallet(mnemonic, {
    path,
    passphrase,
    allowInvalidChecksum,
    wordlist,
    ...(coleman ? { coleman } : {}),
    addressType,
  });
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

/** Watch-only tool arguments besides the chain, raw until the executor checks them. */
export interface XpubWalletArguments extends Omit<ChainArguments, "coinType"> {
  /** Extended public key such as an account `xpub`. */
  readonly extendedKey?: unknown;
  /** Normal levels below the key, such as `m/0/0`. */
  readonly path?: unknown;
}

/**
 * Derives a watch-only address from an extended public key and normal levels below it.
 * @param chainValue - Blockchain name.
 * @param options - Extended key and path, with an address type that wins over the key's prefix.
 * @returns {Promise<ToolResult<DerivedXpubWalletDetails>>} Public key and address at the path.
 */
export async function deriveXpubWallet(
  chainValue: unknown,
  options: XpubWalletArguments,
): Promise<ToolResult<DerivedXpubWalletDetails>> {
  const extendedKey = requiredString(options.extendedKey, "Extended key");
  const path = requiredString(options.path, "Derivation path");
  if (path.length > 256) throw new TypeError("Invalid derivation path");
  const { blockchain, addressType } = await getBlockchain(chainValue, {
    network: options.network,
    addressType: options.addressType,
    prefix: options.prefix,
  });
  const wallet = blockchain.deriveXpubWallet(extendedKey, { path, addressType });
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

/** Parent recovery arguments besides the extended key, raw until the executor checks them. */
export interface ParentRecoveryArguments {
  /** Child xprv, WIF or hex private key. */
  readonly child?: unknown;
  /** Child index; required unless the child is an xprv. */
  readonly index?: unknown;
  /** Whether to return the parent xprv, false by default. */
  readonly revealKey?: unknown;
}

/**
 * Checks the parent recovery arguments for hosts that skip the schema, never echoing a key.
 * @param extendedKeyValue - Raw extended key argument
 * @param options - Raw child, index and revealKey arguments
 * @returns {ParentArguments} The checked arguments
 */
function parentArguments(
  extendedKeyValue: unknown,
  options: ParentRecoveryArguments,
): ParentArguments {
  const extendedKey = requiredString(extendedKeyValue, "Extended key");
  if (extendedKey.length > MAX_EXTENDED_KEY_LENGTH) {
    throw new RangeError("Extended key is too long");
  }
  const child = childKeyArgument(options.child);
  const requested = optionalIndex(options.index, { name: "Index" });
  const revealKey = options.revealKey ?? false;
  if (typeof revealKey !== "boolean") throw new TypeError("revealKey must be a boolean");
  if (typeof child !== "string" && requested === undefined) {
    throw new TypeError("Index is required unless the child key is an xprv");
  }
  return { extendedKey, child, requested, revealKey };
}

/**
 * Recovers the parent of a leaked normal child; a child from another xpub is a result, not an error.
 * @param extendedKeyValue - Parent extended public key
 * @param options - Child key, its index and whether to return the parent xprv
 * @returns {ToolResult<RecoveredParentDetails>} Verdict, fingerprint and the xprv on request
 */
export function recoverBip32Parent(
  extendedKeyValue: unknown,
  options: ParentRecoveryArguments,
): ToolResult<RecoveredParentDetails> {
  const { extendedKey, child, requested, revealKey } = parentArguments(extendedKeyValue, options);
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
