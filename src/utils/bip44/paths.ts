import { HARDENED_OFFSET, formatIndex } from "../bip32/index.ts";

/** BIP44 purpose, hardened. */
export const BIP44_PURPOSE = HARDENED_OFFSET + 44;

/** Highest value a path level holds before the hardened offset applies. */
export const MAX_LEVEL_INDEX = HARDENED_OFFSET - 1;

/** Change level: external for receiving addresses, internal for change. */
export const BIP44Change = {
  EXTERNAL: 0,
  INTERNAL: 1,
} as const;
export type BIP44Change = (typeof BIP44Change)[keyof typeof BIP44Change];

/** The account, branch and address a path points at, each from 0. */
export interface PathLevels {
  /** Account index. Default: 0 */
  readonly account?: number;
  /** 0 for the external branch, 1 for the internal one. Default: 0 */
  readonly change?: number;
  /** Address index. Default: 0 */
  readonly addressIndex?: number;
}

/** The coin type and the levels under it, where BIP44, BIP49, BIP84 and CIP-1852 paths agree. */
export interface BIP32PathLevels extends PathLevels {
  /** Coin type (from SLIP-0044). */
  readonly coinType: number;
  /** Highest change value the purpose allows, 1 for BIP44 and 5 for CIP-1852 roles. Default: 1 */
  readonly maxChange?: number;
}

/** Names of the levels below the coin type, in path order. */
const LEVEL_NAMES = ["account", "change", "addressIndex"] as const;

/**
 * Refuses a level that is not an integer from 0 up to its ceiling.
 * @param value - The level
 * @param level - Its name for the error and its ceiling, the hardened offset minus one by default
 * @throws {RangeError} When the level is out of range
 */
function assertLevelIndex(
  value: number,
  level: { readonly name: string; readonly maximum?: number },
): void {
  const { name, maximum = MAX_LEVEL_INDEX } = level;
  if (!Number.isInteger(value) || value < 0 || value > maximum) {
    throw new RangeError(`${name} must be an integer between 0 and ${maximum}`);
  }
}

/**
 * Creates the path of five levels that BIP44, BIP49, BIP84 and CIP-1852 share: purpose, coin type
 * and account hardened, change and index plain.
 *
 * @param purpose - Purpose level, 44 for BIP44
 * @param levels - Coin type, then account, change branch (the role on CIP-1852) and address index,
 * each 0 by default, and the highest change the purpose allows
 * @returns {string} Derivation path string
 */
export function getBIP32Path(purpose: number, levels: BIP32PathLevels): string {
  const {
    coinType,
    account = 0,
    change = 0,
    addressIndex = 0,
    maxChange = BIP44Change.INTERNAL,
  } = levels;
  assertLevelIndex(purpose, { name: "purpose" });
  assertLevelIndex(coinType, { name: "coinType" });
  assertLevelIndex(account, { name: "account" });
  assertLevelIndex(maxChange, { name: "maxChange" });
  assertLevelIndex(change, { name: "change", maximum: maxChange });
  assertLevelIndex(addressIndex, { name: "addressIndex" });

  const purposeStr = formatIndex(HARDENED_OFFSET + purpose);
  const coinTypeStr = formatIndex(HARDENED_OFFSET + coinType);
  const accountStr = formatIndex(HARDENED_OFFSET + account);

  return `m/${purposeStr}/${coinTypeStr}/${accountStr}/${change}/${addressIndex}`;
}

/**
 * Creates the path SLIP-10 wallets use, `m/44'/coinType'/account'/change'/index'` with every
 * level hardened, cut where the chain stops: Stellar after the account, Solana after the change.
 *
 * @param coinType - Coin type (from SLIP-0044)
 * @param levels - Account first, then the change branch and the address index if the chain has them
 * @returns {string} Derivation path with every level hardened
 */
export function getHardenedPath(coinType: number, levels: readonly number[]): string {
  assertLevelIndex(coinType, { name: "coinType" });
  if (levels.length === 0 || levels.length > LEVEL_NAMES.length) {
    throw new RangeError(`levels must carry 1 to ${LEVEL_NAMES.length} entries`);
  }
  const hardened = levels.map((level, position) => {
    const maximum = position === 1 ? BIP44Change.INTERNAL : MAX_LEVEL_INDEX;
    assertLevelIndex(level, { name: LEVEL_NAMES[position] ?? "level", maximum });
    return formatIndex(HARDENED_OFFSET + level);
  });

  const purposeStr = formatIndex(BIP44_PURPOSE);
  const coinTypeStr = formatIndex(HARDENED_OFFSET + coinType);

  return `m/${purposeStr}/${coinTypeStr}/${hardened.join("/")}`;
}
