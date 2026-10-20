import { blockchains } from "../_blockchains.ts";
import type { AbstractBlockchain } from "../blockchain.ts";
import {
  MONERO_PAYMENT_ID_SCHEMA_PATTERN,
  MAX_ADDRESS_LENGTH,
  CHAIN_NETWORKS,
  TOOL_NETWORKS,
} from "../tool-parameters.ts";
import { decodeTonAddress } from "../utils/ton-address.ts";
import { hexArgument, chainPublicKey, requiredString } from "./arguments.ts";
import { type ChainArguments, addressTypeLines, getBlockchain } from "./blockchain.ts";
import { type ToolResult, content, sanitizeToolText } from "./results.ts";

/** Address derived from a public key. */
export interface AddressDetails {
  chain: string;
  network: string;
  addressType?: string;
  /** Payment ID inside a Monero integrated address. */
  paymentId?: string;
  address: string;
}

/** Address format validation result. */
export interface AddressValidationDetails extends AddressDetails {
  valid: boolean;
}

const MONERO_PAYMENT_ID = new RegExp(MONERO_PAYMENT_ID_SCHEMA_PATTERN, "u");

/** Key pair, raw payment ID, and the address type the caller asked for, which must stay unset. */
interface IntegratedAddressRequest {
  /** The public spend key then the public view key, as hex. */
  readonly publicKey: string;
  readonly paymentId: unknown;
  readonly addressType: string | undefined;
}

/**
 * Writes the Monero integrated address of a key pair and a payment ID.
 * @param blockchain - The chain the caller named
 * @param request - Key pair, raw payment ID and the address type the caller asked for
 * @returns {Promise<ToolResult<AddressDetails>>} The integrated address
 * @throws {RangeError} When the chain is not monero, a type is given or the ID is not 8 bytes
 */
async function integratedAddress(
  blockchain: Readonly<AbstractBlockchain>,
  request: IntegratedAddressRequest,
): Promise<ToolResult<AddressDetails>> {
  const { publicKey, paymentId: paymentIdValue, addressType } = request;
  if (blockchain.name !== "monero") {
    throw new RangeError(
      `paymentId makes a Monero integrated address; ${blockchain.name} has none`,
    );
  }
  if (addressType !== undefined) {
    throw new RangeError("An integrated address holds the standard keys, so leave addressType out");
  }
  const paymentId = hexArgument(paymentIdValue, {
    name: "paymentId",
    pattern: MONERO_PAYMENT_ID,
    shape: "16 hex characters",
  }).toLowerCase();
  const monero = await blockchains.monero({ network: blockchain.network })();
  const address = monero.getIntegratedAddress(publicKey, paymentId);
  return {
    content: content(
      [...addressTypeLines("integrated"), `Payment ID: ${paymentId}`, `Address: ${address}`].join(
        "\n",
      ),
    ),
    details: {
      chain: blockchain.name,
      network: blockchain.network,
      addressType: "integrated",
      paymentId,
      address,
    },
  };
}

/** Address tool arguments besides the chain, raw until the executor checks them. */
export interface AddressArguments extends Omit<ChainArguments, "coinType"> {
  /** Public key as hexadecimal text. */
  readonly publicKey?: unknown;
  /** Payment ID of a Monero integrated address. */
  readonly paymentId?: unknown;
}

/**
 * Derive an address from a public key.
 * @param chainValue - Blockchain name.
 * @param options - Public key, address type, network, prefix and a Monero payment ID.
 * @returns {Promise<ToolResult<AddressDetails>>} Derived address.
 */
export async function getAddress(
  chainValue: unknown,
  options: AddressArguments,
): Promise<ToolResult<AddressDetails>> {
  const { blockchain, addressType } = await getBlockchain(chainValue, {
    network: options.network,
    addressType: options.addressType,
    prefix: options.prefix,
  });
  const publicKey = chainPublicKey(options.publicKey, blockchain.name);
  if (options.paymentId !== undefined) {
    return integratedAddress(blockchain, { publicKey, paymentId: options.paymentId, addressType });
  }
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

/** Validation tool arguments besides the chain, raw until the executor checks them. */
export interface AddressValidationArguments {
  readonly address?: unknown;
  readonly network?: unknown;
  /** Bech32 prefix on cosmos, SS58 number on polkadot. */
  readonly prefix?: unknown;
}

/**
 * Check whether an address matches one chain's format.
 * @param chainValue - Blockchain name.
 * @param options - Address to validate, with an optional network and prefix.
 * @returns {Promise<ToolResult<AddressValidationDetails>>} Address format verdict.
 */
export async function validateAddress(
  chainValue: unknown,
  options: AddressValidationArguments,
): Promise<ToolResult<AddressValidationDetails>> {
  const { prefix } = options;
  const { blockchain } = await getBlockchain(chainValue, { network: options.network, prefix });
  const address = requiredString(options.address, "Address");
  if (Array.from(address).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Address must not exceed ${MAX_ADDRESS_LENGTH} characters`);
  }
  const valid = blockchain.validateAddress(address);
  const renderedAddress = sanitizeToolText(address);
  const otherNetwork = valid ? undefined : await otherNetworkOf(blockchain, { address, prefix });
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
 * Finds another network an address is valid on, so a testnet address checked against
 * mainnet is not reported as simply broken.
 * @param failed - Chain and network the address failed on.
 * @param check - Address that failed and the prefix the first check used, cosmos and polkadot only.
 * @returns {Promise<string | undefined>} The other network, when the address passes there.
 */
async function otherNetworkOf(
  failed: Readonly<Pick<AbstractBlockchain, "name" | "network">>,
  check: { readonly address: string; readonly prefix: unknown },
): Promise<string | undefined> {
  const { address, prefix } = check;
  const { name: chain, network } = failed;
  const networks = chain === "monero" ? CHAIN_NETWORKS : TOOL_NETWORKS;
  for (const other of networks.filter((candidate) => candidate !== network)) {
    const { blockchain } = await getBlockchain(chain, { network: other, prefix });
    if (blockchain.validateAddress(address)) return other;
  }
  return undefined;
}

/** Bech32 as an encoder writes it: a BIP-173 prefix without uppercase, `1`, then the data. */
const BECH32_WRITTEN = /^[\x21-\x40\x5B-\x7E]{1,83}1[02-9ac-hj-np-z]{6,}$/u;

/** A user-friendly TON address as `getAddress` writes it, bounceable or not, on either network. */
const TON_WRITTEN = /^[UEk0]Q[A-Za-z0-9_-]{46}$/u;

/**
 * Tells whether two TON addresses name one account, whatever form each is in.
 * @param written - User-friendly address from `getAddress`
 * @param given - Raw or user-friendly address the caller passed
 * @returns {boolean} True when workchain and account ID agree
 */
function sameTonAccount(written: string, given: string): boolean {
  const left = decodeTonAddress(written);
  const right = decodeTonAddress(given);
  if (left === undefined || right === undefined) return false;
  return left.workchain === right.workchain && left.hash.toHex() === right.hash.toHex();
}

/**
 * Compare a written address with a typed one: bech32 and CashAddr ignore case, base58 doesn't,
 * and TON's forms of one account all match.
 * @param written - Address from `getAddress`
 * @param given - Address the caller passed, already validated for the chain
 * @returns {boolean} True when both name the same address
 */
export function sameAddress(written: string, given: string): boolean {
  if (written === given) return true;
  if (TON_WRITTEN.test(written)) return sameTonAccount(written, given);
  if (written.startsWith("0x")) return written.toLowerCase() === given.toLowerCase();
  if (!written.includes(":") && !BECH32_WRITTEN.test(written)) return false;
  const lower = given.toLowerCase();
  return lower === written || lower === written.slice(written.indexOf(":") + 1);
}
