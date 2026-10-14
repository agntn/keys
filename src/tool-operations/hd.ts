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
import { parseBip39Entropy, colemanFlag, parseBIP39Language } from "./bip39.ts";
import { getBlockchain, addressTypeLines } from "./blockchain.ts";
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

/**
 * Takes the mnemonic as given, or spells the entropy with the word list; exactly one of them.
 * @param mnemonicValue - Mnemonic as the caller passed it
 * @param entropyValue - Entropy hex as the caller passed it
 * @param wordlist - Word list that spells the entropy
 * @param coleman - Take Coleman's entropy lengths
 * @returns {string} Mnemonic to derive from
 */
function mnemonicOrEntropy(
  mnemonicValue: unknown,
  entropyValue: unknown,
  wordlist: readonly string[],
  coleman: boolean,
): string {
  if (mnemonicValue !== undefined && entropyValue !== undefined) {
    throw new TypeError("Pass either a BIP39 mnemonic or its entropy, not both");
  }
  if (entropyValue === undefined) {
    if (mnemonicValue === undefined) throw new TypeError("Pass a BIP39 mnemonic or its entropy");
    return requiredString(mnemonicValue, "BIP39 mnemonic");
  }
  return entropyToMnemonic(parseBip39Entropy(entropyValue, coleman), wordlist, { coleman });
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
 * @param colemanValue - Take Ian Coleman's lengths too, default false.
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
  colemanValue?: unknown,
): Promise<ToolResult<DerivedWalletDetails>> {
  if (allowInvalidChecksumValue !== undefined && typeof allowInvalidChecksumValue !== "boolean") {
    throw new TypeError("allowInvalidChecksum must be a boolean");
  }
  const allowInvalidChecksum = allowInvalidChecksumValue ?? false;
  const coleman = colemanFlag(colemanValue);
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
  const mnemonic = mnemonicOrEntropy(mnemonicValue, entropyValue, wordlist, coleman);
  const words = normalizeMnemonic(mnemonic);
  const inspection = inspectBIP39Mnemonic(words, wordlist, { coleman });
  if (inspection.checksumValid === null) {
    throw new TypeError(describeInvalidMnemonic(words, inspection, wordlist, language));
  }
  const wallet = blockchain.deriveHDWallet(
    mnemonic,
    path,
    { passphrase, allowInvalidChecksum, wordlist, ...(coleman ? { coleman } : {}) },
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
