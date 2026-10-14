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
