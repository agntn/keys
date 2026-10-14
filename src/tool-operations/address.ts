import { blockchains } from "../_blockchains.ts";
import type { AbstractBlockchain } from "../blockchain.ts";
import {
  MONERO_PAYMENT_ID_SCHEMA_PATTERN,
  MAX_ADDRESS_LENGTH,
  CHAIN_NETWORKS,
  TOOL_NETWORKS,
} from "../tool-parameters.ts";
import { hexArgument, chainPublicKey, requiredString } from "./arguments.ts";
import { addressTypeLines, getBlockchain } from "./blockchain.ts";
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

/**
 * Writes the Monero integrated address of a key pair and a payment ID.
 * @param blockchain - The chain the caller named
 * @param publicKey - The public spend key then the public view key, as hex
 * @param paymentIdValue - Raw payment ID argument
 * @param addressType - The address type the caller asked for, which must be left out
 * @returns {Promise<ToolResult<AddressDetails>>} The integrated address
 * @throws {RangeError} When the chain is not monero, a type is given or the ID is not 8 bytes
 */
async function integratedAddress(
  blockchain: Readonly<AbstractBlockchain>,
  publicKey: string,
  paymentIdValue: unknown,
  addressType: string | undefined,
): Promise<ToolResult<AddressDetails>> {
  if (blockchain.name !== "monero") {
    throw new RangeError(
      `paymentId makes a Monero integrated address; ${blockchain.name} has none`,
    );
  }
  if (addressType !== undefined) {
    throw new RangeError("An integrated address holds the standard keys, so leave addressType out");
  }
  const paymentId = hexArgument(
    paymentIdValue,
    "paymentId",
    MONERO_PAYMENT_ID,
    "16 hex characters",
  ).toLowerCase();
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

/**
 * Derive an address from a public key.
 * @param chainValue - Blockchain name.
 * @param publicKeyValue - Public key as hexadecimal text.
 * @param addressTypeValue - Optional chain-specific address type.
 * @param networkValue - Optional network name.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @param paymentIdValue - Optional payment ID of a Monero integrated address.
 * @returns {Promise<ToolResult<AddressDetails>>} Derived address.
 */
export async function getAddress(
  chainValue: unknown,
  publicKeyValue: unknown,
  addressTypeValue?: unknown,
  networkValue?: unknown,
  prefixValue?: unknown,
  paymentIdValue?: unknown,
): Promise<ToolResult<AddressDetails>> {
  const { blockchain, addressType } = await getBlockchain(
    chainValue,
    networkValue,
    addressTypeValue,
    prefixValue,
  );
  const publicKey = chainPublicKey(publicKeyValue, blockchain.name);
  if (paymentIdValue !== undefined) {
    return integratedAddress(blockchain, publicKey, paymentIdValue, addressType);
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

/**
 * Check whether an address matches one chain's format.
 * @param chainValue - Blockchain name.
 * @param addressValue - Address to validate.
 * @param networkValue - Optional network name.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @returns {Promise<ToolResult<AddressValidationDetails>>} Address format verdict.
 */
export async function validateAddress(
  chainValue: unknown,
  addressValue: unknown,
  networkValue?: unknown,
  prefixValue?: unknown,
): Promise<ToolResult<AddressValidationDetails>> {
  const { blockchain } = await getBlockchain(chainValue, networkValue, undefined, prefixValue);
  const address = requiredString(addressValue, "Address");
  if (Array.from(address).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Address must not exceed ${MAX_ADDRESS_LENGTH} characters`);
  }
  const valid = blockchain.validateAddress(address);
  const renderedAddress = sanitizeToolText(address);
  const otherNetwork = valid
    ? undefined
    : await otherNetworkOf(blockchain.name, blockchain.network, address, prefixValue);
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
 * @param chain - Blockchain name, already accepted by `getBlockchain`.
 * @param network - Network the address failed on.
 * @param address - Address that failed.
 * @param prefixValue - Prefix the first check used, cosmos and polkadot only.
 * @returns {Promise<string | undefined>} The other network, when the address passes there.
 */
async function otherNetworkOf(
  chain: string,
  network: string,
  address: string,
  prefixValue: unknown,
): Promise<string | undefined> {
  const networks = chain === "monero" ? CHAIN_NETWORKS : TOOL_NETWORKS;
  for (const other of networks.filter((candidate) => candidate !== network)) {
    const { blockchain } = await getBlockchain(chain, other, undefined, prefixValue);
    if (blockchain.validateAddress(address)) return other;
  }
  return undefined;
}

/** Bech32 as an encoder writes it: a BIP-173 prefix without uppercase, `1`, then the data. */
const BECH32_WRITTEN = /^[\x21-\x40\x5B-\x7E]{1,83}1[02-9ac-hj-np-z]{6,}$/u;

/**
 * Compare a written address with a typed one: bech32 and CashAddr ignore case, base58 doesn't.
 * @param written - Address from `getAddress`
 * @param given - Address the caller passed, already validated for the chain
 * @returns {boolean} True when both name the same address
 */
export function sameAddress(written: string, given: string): boolean {
  if (written === given) return true;
  if (written.startsWith("0x")) return written.toLowerCase() === given.toLowerCase();
  if (!written.includes(":") && !BECH32_WRITTEN.test(written)) return false;
  const lower = given.toLowerCase();
  return lower === written || lower === written.slice(written.indexOf(":") + 1);
}
