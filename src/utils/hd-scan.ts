import type { AbstractBlockchain } from "../blockchain.ts";
import type { AddressType } from "../types.ts";
import { HARDENED_OFFSET } from "./hd-index.ts";

/** A named wallet path; `{account}`, `{change}` and `{index}` walk their ranges. */
export interface ScanScheme {
  /** Name the result reports, such as `bip84` or `ledger-live`. */
  readonly name: string;
  /** Path template, such as `m/84'/0'/{account}'/{change}/{index}`. */
  readonly path: string;
  /** Address type the wallet writes, or the Sui signature scheme. */
  readonly addressType?: AddressType;
}

/** How far the scan walks each placeholder. */
export interface ScanRanges {
  /** Accounts from 0. */
  readonly accounts: number;
  /** Address indices from 0. */
  readonly indices: number;
}

/** A child node of either HD flavour, BIP32 or SLIP-10. */
export interface ScanNode {
  readonly privateKey: Uint8Array | null;
  deriveChild(index: number): ScanNode;
}

/** The address one path reaches. */
export interface ScanAddress {
  readonly publicKey: string;
  readonly address: string;
  readonly addressType?: string;
}

/** A scheme the scan walked and how many addresses it checked there. */
export interface ScanTried {
  readonly scheme: string;
  /** Template with the walked ranges filled in, such as `m/44'/0'/{0..2}'/{0,1}/{0..19}`. */
  readonly path: string;
  readonly addressType?: string;
  readonly addresses: number;
}

/** The scheme and path that reached the target. */
export interface ScanMatch extends ScanAddress {
  readonly scheme: string;
  readonly path: string;
}

/** Testnet coin type of SLIP-0044, which every UTXO chain shares. */
const TESTNET_COIN = 1;

const UTXO_PURPOSES = [
  ["bip44", 44, "legacy"],
  ["bip49", 49, "p2sh"],
  ["bip84", 84, "segwit"],
  ["bip86", 86, "taproot"],
] as const;

/**
 * BIP44, BIP49, BIP84 and BIP86 on one coin type, limited to the address types the chain writes.
 * @param coin - Mainnet coin type
 * @param purposes - Purpose names the chain's wallets use
 * @returns {ScanScheme[]} One scheme per purpose
 */
function utxo(coin: number, purposes: readonly string[]): ScanScheme[] {
  return UTXO_PURPOSES.filter(([name]) => purposes.includes(name)).map(
    ([name, purpose, addressType]) => ({
      name,
      path: `m/${purpose}'/${coin}'/{account}'/{change}/{index}`,
      addressType,
    }),
  );
}

/**
 * BIP44 legacy paths on a chain's own coin type plus the other coin types its wallets used.
 * @param coins - Scheme name and mainnet coin type, the chain's own first
 * @returns {ScanScheme[]} One legacy scheme per coin type
 */
function legacy(...coins: ReadonlyArray<readonly [string, number]>): ScanScheme[] {
  return coins.map(([name, coin]) => ({
    name,
    path: `m/44'/${coin}'/{account}'/{change}/{index}`,
    addressType: "legacy",
  }));
}

const EVM_SCHEMES: readonly ScanScheme[] = [
  { name: "bip44", path: "m/44'/60'/{account}'/0/{index}" },
  { name: "ledger-live", path: "m/44'/60'/{index}'/0/0" },
  { name: "ledger-legacy", path: "m/44'/60'/0'/{index}" },
];

/** Wallet paths per chain, in the order the scan walks them; the UTXO coin types are mainnet. */
const CHAIN_SCHEMES: Readonly<Record<string, readonly ScanScheme[]>> = {
  bitcoin: utxo(0, ["bip44", "bip49", "bip84", "bip86"]),
  litecoin: utxo(2, ["bip44", "bip49", "bip84", "bip86"]),
  bitcoingold: utxo(156, ["bip44", "bip49", "bip84"]),
  bitcoincash: legacy(["bip44", 145]),
  bitcoinsv: legacy(["bip44", 236], ["electrumsv", 0]),
  dash: legacy(["bip44", 5]),
  dogecoin: legacy(["bip44", 3]),
  zcash: legacy(["bip44", 133]),
  ecash: legacy(["bip44", 899], ["cashtab", 1899], ["bitcoincash", 145]),
  ethereum: EVM_SCHEMES,
  base: EVM_SCHEMES,
  tron: [{ name: "bip44", path: "m/44'/195'/{account}'/0/{index}" }],
  solana: [
    { name: "bip44", path: "m/44'/501'/{index}'/0'" },
    { name: "bip44-account", path: "m/44'/501'/{index}'" },
  ],
  stellar: [{ name: "sep5", path: "m/44'/148'/{index}'" }],
  aptos: [{ name: "bip44", path: "m/44'/637'/{index}'/0'/0'" }],
  sui: [
    { name: "bip44", path: "m/44'/784'/{index}'/0'/0'", addressType: "ed25519" },
    { name: "bip54", path: "m/54'/784'/{index}'/0/0", addressType: "secp256k1" },
  ],
  xrpl: [{ name: "bip44", path: "m/44'/144'/{account}'/0/{index}" }],
  near: [
    { name: "bip44", path: "m/44'/397'/{index}'" },
    { name: "ledger", path: "m/44'/397'/0'/0'/{index}'" },
  ],
  cosmos: [{ name: "bip44", path: "m/44'/118'/{account}'/0/{index}" }],
};

/** UTXO chains, whose testnet wallets take coin type 1. */
const UTXO_CHAINS: ReadonlySet<string> = new Set([
  "bitcoin",
  "litecoin",
  "bitcoingold",
  "bitcoincash",
  "bitcoinsv",
  "dash",
  "dogecoin",
  "zcash",
  "ecash",
]);

/** Paths of a native Electrum seed, by seed type. */
export const ELECTRUM_SCHEMES: Readonly<Record<"standard" | "segwit", ScanScheme>> = {
  standard: { name: "electrum-standard", path: "m/{change}/{index}", addressType: "legacy" },
  segwit: { name: "electrum-segwit", path: "m/0'/{change}/{index}", addressType: "segwit" },
};

/**
 * Lists the BIP39 wallet paths of a chain; a UTXO testnet walks coin type 1 as `-testnet` first.
 * @param chain - Tool chain name
 * @param network - Network name
 * @returns {ScanScheme[] | undefined} Schemes, or undefined for a chain without BIP39 derivation
 */
export function scanSchemes(chain: string, network: string): ScanScheme[] | undefined {
  const schemes = CHAIN_SCHEMES[chain];
  if (schemes === undefined) return undefined;
  if (network !== "testnet" || !UTXO_CHAINS.has(chain)) return [...schemes];
  const testnet = new Map<string, ScanScheme>();
  for (const scheme of schemes) {
    const path = scheme.path.replace(/^(m\/\d+'\/)\d+'/u, `$1${TESTNET_COIN}'`);
    if (!testnet.has(path)) testnet.set(path, { ...scheme, name: `${scheme.name}-testnet`, path });
  }
  return [...testnet.values(), ...schemes];
}

/**
 * Lists the values a range walks.
 * @param count - How many values from 0
 * @returns {number[]} 0 up to count - 1
 */
function range(count: number): number[] {
  return Array.from({ length: count }, (_, value) => value);
}

/**
 * Writes a walked range as the result shows it: `0`, `{0,1}` or `{0..19}`.
 * @param values - Walked values in order
 * @returns {string} The range
 */
function formatRange(values: readonly number[]): string {
  if (values.length === 1) return String(values[0]);
  if (values.length === 2) return `{${values.join(",")}}`;
  return `{${values[0]}..${values.at(-1)}}`;
}

/** Placeholder values one template walks. */
interface Placeholders {
  readonly account: readonly number[];
  readonly change: readonly number[];
  readonly index: readonly number[];
}

/**
 * Fills a template with one value per placeholder, or with the ranges it walks.
 * @param template - Path template
 * @param values - Value or range text per placeholder
 * @returns {string} The filled path
 */
function fill(template: string, values: Readonly<Record<keyof Placeholders, string>>): string {
  return template.replaceAll(
    /\{(account|change|index)\}/gu,
    (_, name: keyof Placeholders) => values[name],
  );
}

/**
 * Every path a template reaches over the ranges, account first, then change, then index.
 * @param template - Path template
 * @param placeholders - Values per placeholder
 * @yields {string} Each concrete path
 * @returns {Generator<string>} Concrete paths
 */
function* paths(template: string, placeholders: Placeholders): Generator<string> {
  const used = (name: keyof Placeholders): readonly number[] =>
    template.includes(`{${name}}`) ? placeholders[name] : [0];
  for (const account of used("account")) {
    for (const change of used("change")) {
      for (const index of used("index")) {
        yield fill(template, {
          account: String(account),
          change: String(change),
          index: String(index),
        });
      }
    }
  }
}

/**
 * Walks paths below one master node, deriving every parent once.
 * @param master - Master node of the seed
 * @returns {(path: string) => ScanNode} Node at an absolute path such as `m/44'/0'/0'/0/5`
 */
export function nodeWalker(master: Readonly<ScanNode>): (path: string) => ScanNode {
  const nodes = new Map<string, ScanNode>([["m", master]]);
  const nodeAt = (path: string): ScanNode => {
    const cached = nodes.get(path);
    if (cached !== undefined) return cached;
    const cut = path.lastIndexOf("/");
    const level = path.slice(cut + 1);
    const index = Number.parseInt(level, 10) + (level.endsWith("'") ? HARDENED_OFFSET : 0);
    const node = nodeAt(path.slice(0, cut)).deriveChild(index);
    nodes.set(path, node);
    return node;
  };
  return nodeAt;
}

/** What one scheme walk reports. */
export interface SchemeWalk {
  readonly tried: ScanTried;
  readonly match?: ScanMatch;
}

/**
 * Walks one scheme until the target turns up or the ranges run out.
 * @param scheme - Scheme to walk
 * @param ranges - Accounts and indices
 * @param addressAt - Address one concrete path reaches
 * @param matches - Whether an address is the target
 * @returns {SchemeWalk} The walk, with the match when there is one
 */
export function walkScheme(
  scheme: ScanScheme,
  ranges: ScanRanges,
  addressAt: (path: string) => ScanAddress,
  matches: (address: string) => boolean,
): SchemeWalk {
  const placeholders = {
    account: range(ranges.accounts),
    change: [0, 1],
    index: range(ranges.indices),
  };
  const shown = fill(scheme.path, {
    account: formatRange(placeholders.account),
    change: formatRange(placeholders.change),
    index: formatRange(placeholders.index),
  });
  let addresses = 0;
  for (const path of paths(scheme.path, placeholders)) {
    const reached = addressAt(path);
    addresses += 1;
    if (matches(reached.address)) {
      return {
        tried: { scheme: scheme.name, path: shown, ...typeOf(scheme), addresses },
        match: { scheme: scheme.name, path, ...reached },
      };
    }
  }
  return { tried: { scheme: scheme.name, path: shown, ...typeOf(scheme), addresses } };
}

/**
 * The address type field of a scheme, when it names one.
 * @param scheme - Scheme
 * @returns {{ addressType?: string }} The field or nothing
 */
function typeOf(scheme: ScanScheme): { addressType?: string } {
  return scheme.addressType === undefined ? {} : { addressType: scheme.addressType };
}

/**
 * Builds the address reader for a BIP39 or Electrum seed on one chain.
 * @param blockchain - Chain that writes the address
 * @param scheme - Scheme whose address type applies
 * @param nodeAt - Node walker over the right master key
 * @returns {(path: string) => ScanAddress} Address one path reaches
 */
export function hdAddress(
  blockchain: Readonly<AbstractBlockchain>,
  scheme: ScanScheme,
  nodeAt: (path: string) => ScanNode,
): (path: string) => ScanAddress {
  return (path) => {
    const privateKey = nodeAt(path).privateKey;
    if (!privateKey) throw new Error(`No private key at ${path}`);
    const wallet = blockchain.deriveWallet(privateKey.toHex(), undefined, scheme.addressType);
    return {
      publicKey: wallet.keys.public,
      address: wallet.address,
      ...(wallet.addressType === undefined ? {} : { addressType: wallet.addressType }),
    };
  };
}
