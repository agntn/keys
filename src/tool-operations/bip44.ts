import { getBlockchainPath } from "../blockchain.ts";
import { parse as parseBIP44Path } from "../utils/bip44/index.ts";
import { requiredString, optionalIndex } from "./arguments.ts";
import { type ChainArguments, getBlockchain } from "./blockchain.ts";
import { type ToolResult, content } from "./results.ts";

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

/** Path levels past the chain, plus the network, Sui scheme, prefix and coin type that shape it. */
export interface Bip44GenerateArguments extends ChainArguments {
  readonly account?: unknown;
  /** External or internal branch, or the CIP-1852 role on Cardano. */
  readonly change?: unknown;
  readonly addressIndex?: unknown;
}

/**
 * Generate the path a chain's wallets use, with the change range and Sui scheme the chain sets.
 * @param chainValue - Blockchain name.
 * @param options - Account, change and address index, with the chain's network, scheme and prefix.
 * @returns {Promise<ToolResult<BIP44PathDetails>>} The generated path.
 */
export async function generateBip44Path(
  chainValue: unknown,
  options: Bip44GenerateArguments = {},
): Promise<ToolResult<BIP44PathDetails>> {
  const account = optionalIndex(options.account, { name: "Account" }) ?? 0;
  const change = optionalIndex(options.change, { name: "Change" }) ?? 0;
  const addressIndex = optionalIndex(options.addressIndex, { name: "Address index" }) ?? 0;
  const { blockchain, addressType } = await getBlockchain(chainValue, options);
  if (addressType !== undefined && !Array.isArray(blockchain.curve)) {
    throw new RangeError(`addressType names a scheme, and ${blockchain.name} has one curve`);
  }
  const generated = getBlockchainPath(blockchain, {
    account,
    change,
    addressIndex,
    scheme: addressType,
  });
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
