/**
 * BIP44 implementation
 * Hierarchical Deterministic Wallets
 *
 * BIP44 defines a logical hierarchy for deterministic wallets based on BIP32.
 * This structure helps organize and derive keys for multiple blockchains
 * and accounts from a single seed.
 *
 * Format: m / purpose' / coin_type' / account' / change / address_index
 *
 * Where:
 * - purpose: always 44' (hardened) for BIP44
 * - coin_type: registered blockchain type (https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
 * - account: account index, starting from 0'
 * - change: 0 for external (receiving), 1 for internal (change)
 * - address_index: address index, starting from 0
 */

import { HARDENED_OFFSET, formatIndex } from "../bip32/index.ts";

// BIP44 path levels
export enum BIP44Levels {
  PURPOSE = 1,
  COIN_TYPE = 2,
  ACCOUNT = 3,
  CHANGE = 4,
  ADDRESS_INDEX = 5,
}

// BIP44 purpose is always 44'
export const BIP44_PURPOSE = HARDENED_OFFSET + 44;

/** Highest value a path level holds before the hardened offset applies. */
const MAX_LEVEL_INDEX = HARDENED_OFFSET - 1;

function assertLevelIndex(name: string, value: number, maximum = MAX_LEVEL_INDEX): void {
  if (!Number.isInteger(value) || value < 0 || value > maximum) {
    throw new RangeError(`${name} must be an integer between 0 and ${maximum}`);
  }
}

// BIP44 change level values
export enum BIP44Change {
  EXTERNAL = 0, // Receiving addresses
  INTERNAL = 1, // Change addresses
}

// SLIP-0044 registered blockchain types
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
export const BIP44 = {
  BITCOIN: 0,
  TESTNET: 1,
  LITECOIN: 2,
  DECRED: 42,
  ETHEREUM: 60,
  SOLANA: 501,
  CARDANO: 1815,
  TRON: 195,
  APTOS: 637,
  SUI: 784,
} as const;

/**
 * Creates a BIP44 derivation path
 *
 * @param coinType - Coin type (from SLIP-0044)
 * @param account - Account index (defaults to 0)
 * @param change - 0 for external chain (receive addresses), 1 for internal chain (change addresses)
 * @param addressIndex - Address index (defaults to 0)
 * @returns {string} BIP44 derivation path string
 */
export function getBIP44Path(
  coinType: number,
  account = 0,
  change = BIP44Change.EXTERNAL,
  addressIndex = 0,
): string {
  assertLevelIndex("coinType", coinType);
  assertLevelIndex("account", account);
  assertLevelIndex("change", change, BIP44Change.INTERNAL);
  assertLevelIndex("addressIndex", addressIndex);

  // Harden purpose, coin type, and account
  const purposeStr = formatIndex(BIP44_PURPOSE);
  const coinTypeStr = formatIndex(HARDENED_OFFSET + coinType);
  const accountStr = formatIndex(HARDENED_OFFSET + account);

  // Change and address index are not hardened
  return `m/${purposeStr}/${coinTypeStr}/${accountStr}/${change}/${addressIndex}`;
}

/**
 * Parse a BIP44 path string into its components
 *
 * @param path - BIP44 path string (e.g., "m/44'/0'/0'/0/0")
 * @returns {{ purpose: number; coinType: number; account: number; change: number; addressIndex: number } | undefined} Object with parsed components or undefined if invalid BIP44 path
 */
export function parseBIP44Path(path: string):
  | {
      purpose: number;
      coinType: number;
      account: number;
      change: number;
      addressIndex: number;
    }
  | undefined {
  // Check if the path starts with 'm/'
  if (!path.startsWith("m/")) {
    return undefined;
  }

  // Remove 'm/' and split the path
  const segments = path.slice(2).split("/");

  // BIP44 requires exactly 5 segments
  if (segments.length !== 5) {
    return undefined;
  }

  // Parse each segment (length verified === 5 above)
  const purpose = parseSegment(segments[0]!);
  const coinType = parseSegment(segments[1]!);
  const account = parseSegment(segments[2]!);
  const change = parseSegment(segments[3]!);
  const addressIndex = parseSegment(segments[4]!);

  if (
    purpose === undefined ||
    coinType === undefined ||
    account === undefined ||
    change === undefined ||
    addressIndex === undefined ||
    !isValidBIP44Components(purpose, coinType, account, change, addressIndex)
  ) {
    return undefined;
  }

  return {
    purpose: purpose - HARDENED_OFFSET,
    coinType: coinType - HARDENED_OFFSET,
    account: account - HARDENED_OFFSET,
    change,
    addressIndex,
  };
}

/**
 * Validate parsed BIP44 path components
 *
 * @param purpose - Parsed purpose segment (hardened offset included)
 * @param coinType - Parsed coin type segment (hardened offset included)
 * @param account - Parsed account segment (hardened offset included)
 * @param change - Parsed change segment
 * @param addressIndex - Parsed address index segment
 * @returns {boolean} True if the components form a valid BIP44 path
 */
function isValidBIP44Components(
  purpose: number,
  coinType: number,
  account: number,
  change: number,
  addressIndex: number,
): boolean {
  // Validate purpose is 44'
  if (purpose !== BIP44_PURPOSE) {
    return false;
  }

  // Validate hardened status: purpose, coin_type, account should be hardened
  if (purpose < HARDENED_OFFSET || coinType < HARDENED_OFFSET || account < HARDENED_OFFSET) {
    return false;
  }

  // Validate change is 0 or 1 and not hardened
  if ((change !== 0 && change !== 1) || change >= HARDENED_OFFSET) {
    return false;
  }

  // Validate address index is not hardened
  if (addressIndex >= HARDENED_OFFSET) {
    return false;
  }

  return true;
}

/**
 * Parse a path segment, hardened or not, rejecting what `parseInt` reads loosely.
 *
 * @param segment - Path segment string (e.g., "44'" or "0")
 * @returns {number | undefined} Parsed number value, or undefined when the segment is not a level index
 */
function parseSegment(segment: string): number | undefined {
  const hardened = segment.endsWith("'");
  const digits = hardened ? segment.slice(0, -1) : segment;

  if (!/^\d+$/.test(digits)) {
    return undefined;
  }

  const value = Number.parseInt(digits, 10);
  if (value > MAX_LEVEL_INDEX) {
    return undefined;
  }

  return hardened ? value + HARDENED_OFFSET : value;
}

/**
 * Get derivation path for a specific blockchain
 *
 * @param blockchain - The blockchain implementation interface
 * @param account - Account index (defaults to 0)
 * @param change - 0 for external chain (receive addresses), 1 for internal chain (change addresses)
 * @param addressIndex - Address index (defaults to 0)
 * @returns {string} BIP44 derivation path string
 */
export function getBlockchainPath(
  blockchain: { readonly bip44: number },
  account = 0,
  change = BIP44Change.EXTERNAL,
  addressIndex = 0,
): string {
  return getBIP44Path(blockchain.bip44, account, change, addressIndex);
}
