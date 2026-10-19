import { blockchains } from "../_blockchains.ts";
import { type AbstractBlockchain, useBlockchain } from "../blockchain.ts";
import {
  type ToolNetwork,
  TOOL_NETWORKS,
  type ToolChain,
  TOOL_ADDRESS_TYPES_BY_CHAIN,
  TOOL_CHAINS,
} from "../tool-parameters.ts";
import type { Options } from "../types.ts";
import { optionalName, optionalIndex, requiredString } from "./arguments.ts";

export function parseNetwork(value: unknown): ToolNetwork {
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
export function addressTypeLines(addressType: string | undefined): string[] {
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
  const coinType = optionalIndex(value, { name: "coinType" });
  if (coinType === undefined) return {};
  if (chain !== "cosmos") {
    throw new RangeError(
      `coinType picks the path of a Cosmos SDK chain. ${chain} has its own, so leave it out`,
    );
  }
  return { coinType };
}

/** How a chain tool loads its chain, each field as the host passed it. */
export interface ChainArguments {
  readonly network?: unknown;
  readonly addressType?: unknown;
  readonly prefix?: unknown;
  readonly coinType?: unknown;
}

export async function getBlockchain(
  chainValue: unknown,
  options: ChainArguments = {},
): Promise<{ readonly blockchain: AbstractBlockchain; readonly addressType: string | undefined }> {
  const name = requiredString(chainValue, "Chain").toLowerCase();
  const chain = TOOL_CHAINS.find((candidate) => candidate === name);
  if (chain === undefined) {
    throw new RangeError(
      `Unknown chain ${JSON.stringify(name)}. Supported: ${TOOL_CHAINS.join(", ")}`,
    );
  }
  const network = parseChainNetwork(chain, options.network);
  const addressType = parseAddressType(chain, options.addressType);
  const prefix = parsePrefix(chain, options.prefix);
  const coinType = parseCoinType(chain, options.coinType);
  return {
    blockchain: useBlockchain(await blockchains[chain]({ network, ...prefix, ...coinType })()),
    addressType,
  };
}
