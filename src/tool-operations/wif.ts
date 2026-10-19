import { TOOL_WIF_CHAINS } from "../tool-parameters.ts";
import {
  type DecodedWIF,
  type WIFNetworkOptions,
  encode as encodeWIF,
  decode as decodeWIF,
} from "../utils/wif/index.ts";
import { isUnset, requiredString } from "./arguments.ts";
import { type ToolResult, content } from "./results.ts";

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

/** What the WIF encoder takes past the chain, as the host passed it. */
export interface WifEncodeArguments {
  readonly privateKey?: unknown;
  readonly network?: unknown;
  readonly compressed?: unknown;
}

/**
 * Export a disposable key as native WIF without echoing the supplied hex.
 * @param chainValue - Native WIF chain.
 * @param args - Disposable private key as hex, with optional network and compression flag.
 * @returns {ToolResult<EncodedWIFDetails>} WIF and effective wallet options.
 */
export function encodeWif(
  chainValue: unknown,
  args: WifEncodeArguments,
): ToolResult<EncodedWIFDetails> {
  const { privateKey, network, compressed: compressedValue } = args;
  const options = parseWIFContext(chainValue, network);
  const compressed = compressedValue === undefined ? true : compressedValue;
  if (typeof compressed !== "boolean") throw new TypeError("WIF compressed must be a boolean");
  const wif = encodeWIF(requiredString(privateKey, "Private key"), { ...options, compressed });
  const details = { wif, chain: options.chain, network: options.network ?? "mainnet", compressed };
  return { content: content(JSON.stringify(details)), details };
}

/** What the WIF decoder takes past the chain, as the host passed it. */
export interface WifDecodeArguments {
  readonly wif?: unknown;
  readonly network?: unknown;
}

/**
 * Read native WIF into hex and wallet options; both representations are secrets.
 * @param chainValue - Expected native WIF chain.
 * @param args - Public or disposable WIF, with the optional expected network.
 * @returns {ToolResult<DecodedWIF>} Private key and effective wallet options.
 */
export function decodeWif(chainValue: unknown, args: WifDecodeArguments): ToolResult<DecodedWIF> {
  const { wif, network } = args;
  const options = parseWIFContext(chainValue, network);
  const details = decodeWIF(requiredString(wif, "WIF"), options);
  return { content: content(JSON.stringify(details)), details };
}
