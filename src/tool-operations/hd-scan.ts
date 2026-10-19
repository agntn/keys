import type { AbstractBlockchain } from "../blockchain.ts";
import {
  MAX_MNEMONIC_LENGTH,
  MAX_ADDRESS_LENGTH,
  SCAN_ACCOUNTS,
  SCAN_INDICES,
} from "../tool-parameters.ts";
import type { Curve } from "../types.ts";
import { getMasterKeyFromSeed } from "../utils/bip32/index.ts";
import {
  inspect as inspectBIP39Mnemonic,
  mnemonicToSeed,
  loadWordlist as loadBIP39Wordlist,
} from "../utils/bip39/index.ts";
import type { BIP39Language } from "../utils/bip39/languages.ts";
import {
  inspect as inspectElectrumSeed,
  deriveSeed as deriveElectrumSeed,
  deriveOldMasterPublicKey,
  deriveOldPublicKey,
} from "../utils/electrum/index.ts";
import { MAX_ELECTRUM_TEXT_LENGTH } from "../utils/electrum/normalize.ts";
import {
  type ScanMatch,
  type ScanTried,
  type ScanScheme,
  type ScanAddress,
  nodeWalker,
  hdAddress,
  ELECTRUM_SCHEMES,
  walkScheme,
  scanSchemes,
} from "../utils/hd-scan.ts";
import { normalizeMnemonic, describeInvalidMnemonic } from "../utils/hd.ts";
import { getMasterKeyFromSeed as getSLIP10MasterKey } from "../utils/slip10/index.ts";
import { sameAddress } from "./address.ts";
import { requiredString, optionalString } from "./arguments.ts";
import {
  type Bip39ListArguments,
  NONSTANDARD_LENGTH_WARNING,
  colemanFlag,
  parseBIP39Language,
} from "./bip39.ts";
import { type ChainArguments, addressTypeLines, getBlockchain } from "./blockchain.ts";
import { type ToolResult, content } from "./results.ts";

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
 * @param limits - Argument name for the error, default and maximum
 * @param limits.name - Argument name for the error
 * @param limits.default - Count when the argument is left out
 * @param limits.maximum - Highest count
 * @returns {number} The count
 */
function scanCount(
  value: unknown,
  limits: { readonly name: string; readonly default: number; readonly maximum: number },
): number {
  if (value === undefined) return limits.default;
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 1 ||
    value > limits.maximum
  ) {
    throw new RangeError(`${limits.name} must be an integer between 1 and ${limits.maximum}`);
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
  readonly warnings?: readonly string[];
}

/**
 * Reads the phrase as BIP39 words, or says why the BIP39 schemes are skipped.
 * @param blockchain - Chain whose schemes apply
 * @param input - Schemes, phrase, passphrase, word list and checksum override
 * @param input.schemes - BIP39 schemes of the chain
 * @param input.mnemonic - Phrase as given
 * @param input.passphrase - BIP39 passphrase
 * @param input.wordlist - Selected BIP39 word list
 * @param input.language - Its name for the error
 * @param input.allowInvalidChecksum - Whether a checksum failure is scanned
 * @param input.coleman - Whether Ian Coleman's lengths are read
 * @returns {ScanRead} Source, or the reason it is skipped
 */
function bip39ScanSource(
  blockchain: Readonly<AbstractBlockchain>,
  {
    schemes,
    mnemonic,
    passphrase,
    wordlist,
    language,
    allowInvalidChecksum,
    coleman,
  }: {
    readonly schemes: readonly ScanScheme[];
    readonly mnemonic: string;
    readonly passphrase: string;
    readonly wordlist: readonly string[];
    readonly language: BIP39Language;
    readonly allowInvalidChecksum: boolean;
    readonly coleman: boolean;
  },
): ScanRead {
  const words = normalizeMnemonic(mnemonic);
  const inspection = inspectBIP39Mnemonic(words, { wordlist, coleman });
  if (inspection.checksumValid === null) {
    return { reason: describeInvalidMnemonic(words, { inspection, wordlist, listName: language }) };
  }
  if (!inspection.valid && !allowInvalidChecksum) {
    return {
      reason: "Invalid BIP39 mnemonic: the checksum does not match. allowInvalidChecksum scans it",
    };
  }
  const seed = mnemonicToSeed(words, { passphrase, coleman });
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
      addressAt: (scheme) => hdAddress(blockchain, { scheme, nodeAt: walkers[curveOf(scheme)] }),
    },
    warnings: [
      ...(inspection.valid
        ? []
        : [
            "BIP39 checksum is invalid. Scanned the supplied words without repairing the checksum.",
          ]),
      ...(inspection.standardLength === false ? [NONSTANDARD_LENGTH_WARNING] : []),
    ],
  };
}

/**
 * Reads the phrase as a native Electrum seed, or says why the Electrum schemes are skipped.
 * @param blockchain - Bitcoin on the selected network
 * @param seed - Phrase as given and its Electrum seed extension
 * @param seed.mnemonic - Phrase as given
 * @param seed.passphrase - Electrum seed extension
 * @returns {ScanRead} Source, or the reason it is skipped
 */
function electrumScanSource(
  blockchain: Readonly<AbstractBlockchain>,
  { mnemonic, passphrase }: { readonly mnemonic: string; readonly passphrase: string },
): ScanRead {
  if (Array.from(mnemonic).length > MAX_ELECTRUM_TEXT_LENGTH) {
    return { reason: "Longer than any Electrum seed" };
  }
  const seedType = inspectElectrumSeed(mnemonic);
  if (seedType === "standard" || seedType === "segwit") {
    const nodeAt = nodeWalker(getMasterKeyFromSeed(deriveElectrumSeed(mnemonic, passphrase).seed));
    return {
      source: {
        schemes: [ELECTRUM_SCHEMES[seedType]],
        addressAt: (scheme) => hdAddress(blockchain, { scheme, nodeAt }),
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
          const publicKey = deriveOldPublicKey(masterPublicKey, { change, index }).toHex();
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
  readonly coleman: boolean;
  readonly ranges: { readonly accounts: number; readonly indices: number };
}

/**
 * Checks the scan arguments for hosts that skip the schema, never echoing the phrase.
 * @param args - Raw arguments
 * @param args.mnemonic - Phrase
 * @param args.address - Target address
 * @param args.passphrase - Passphrase
 * @param args.allowInvalidChecksum - Checksum override
 * @param args.coleman - Length mode
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
  if (mnemonic.length > MAX_MNEMONIC_LENGTH) {
    throw new RangeError(`Mnemonic must not exceed ${MAX_MNEMONIC_LENGTH} characters`);
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
    coleman: colemanFlag(args.coleman),
    ranges: {
      accounts: scanCount(args.accounts, { name: "accounts", ...SCAN_ACCOUNTS }),
      indices: scanCount(args.indices, { name: "indices", ...SCAN_INDICES }),
    },
  };
}

/** Seeds a phrase opens, with the families it does not open and why. */
interface ScanSources {
  readonly sources: ScanSource[];
  readonly skipped: ScanSkipped[];
  readonly warnings: string[];
}

/** Checked scan arguments with the chain's BIP39 schemes and the raw BIP39 language. */
interface ScanRequest extends ScanArguments {
  readonly schemes: readonly ScanScheme[];
  readonly language: unknown;
}

/**
 * Reads the phrase as BIP39 words and, on Bitcoin, as an Electrum seed; throws when neither works.
 * @param blockchain - Chain on the selected network
 * @param request - Checked scan arguments, the chain's schemes and the raw language
 * @returns {Promise<ScanSources>} Seeds to walk and the families skipped
 */
async function scanSources(
  blockchain: Readonly<AbstractBlockchain>,
  request: ScanRequest,
): Promise<ScanSources> {
  const language = parseBIP39Language(request.language);
  const found: ScanSources = { sources: [], skipped: [], warnings: [] };
  const bip39Source = bip39ScanSource(blockchain, {
    ...request,
    wordlist: await loadBIP39Wordlist(language),
    language,
  });
  const electrum: ScanRead =
    blockchain.name === "bitcoin" ? electrumScanSource(blockchain, request) : {};
  for (const [family, read] of [
    ["bip39", bip39Source],
    ["electrum", electrum],
  ] as const) {
    if (read.source) found.sources.push(read.source);
    if (read.reason !== undefined) found.skipped.push({ family, reason: read.reason });
  }
  found.warnings.push(...(bip39Source.warnings ?? []));
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
      const walk = walkScheme(scheme, {
        ranges: args.ranges,
        addressAt: source.addressAt(scheme),
        matches: (written) => sameAddress(written, args.address),
      });
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

/** Scan tool arguments besides the chain, raw until the executor checks them. */
export interface HdScanArguments extends Omit<ChainArguments, "addressType">, Bip39ListArguments {
  /** Public or disposable BIP39 or Electrum phrase. */
  readonly mnemonic?: unknown;
  /** Target address on the chain and network. */
  readonly address?: unknown;
  /** BIP39 passphrase or Electrum seed extension. */
  readonly passphrase?: unknown;
  /** Scan BIP39 words that fail only the checksum, default false. */
  readonly allowInvalidChecksum?: unknown;
  /** Accounts from 0, default 3. */
  readonly accounts?: unknown;
  /** Address indices from 0, default 20. */
  readonly indices?: unknown;
}

/**
 * Scans a fixed, named list of wallet paths for the one that reaches an address.
 * @param chainValue - Blockchain name
 * @param options - Phrase, target address, ranges, word list and the chain's network options
 * @returns {Promise<ToolResult<ScannedWalletDetails>>} The match, or every scheme tried
 */
export async function scanHdWallet(
  chainValue: unknown,
  options: HdScanArguments,
): Promise<ToolResult<ScannedWalletDetails>> {
  const args = scanArguments({
    coleman: options.coleman,
    mnemonic: options.mnemonic,
    address: options.address,
    passphrase: options.passphrase,
    allowInvalidChecksum: options.allowInvalidChecksum,
    accounts: options.accounts,
    indices: options.indices,
  });
  const { blockchain } = await getBlockchain(chainValue, {
    network: options.network,
    prefix: options.prefix,
    coinType: options.coinType,
  });
  const schemes = scanSchemes(blockchain.name, {
    network: blockchain.network,
    coinType: blockchain.coinType,
  });
  if (schemes === undefined) {
    throw new RangeError(scanRefusal(blockchain.name));
  }
  if (!blockchain.validateAddress(args.address)) {
    throw new TypeError(
      `Address is not a ${blockchain.name} ${blockchain.network} address, so no path can reach it`,
    );
  }
  const { sources, skipped, warnings } = await scanSources(blockchain, {
    ...args,
    schemes,
    language: options.language,
  });
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
