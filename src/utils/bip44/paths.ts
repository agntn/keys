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

/** Names of the levels below the coin type, in path order. */
const LEVEL_NAMES = ["account", "change", "addressIndex"] as const;

function assertLevelIndex(name: string, value: number, maximum = MAX_LEVEL_INDEX): void {
  if (!Number.isInteger(value) || value < 0 || value > maximum) {
    throw new RangeError(`${name} must be an integer between 0 and ${maximum}`);
  }
}

/**
 * Creates the path of five levels that BIP44, BIP49, BIP84 and CIP-1852 share: purpose, coin type
 * and account hardened, change and index plain.
 *
 * @param purpose - Purpose level, 44 for BIP44
 * @param coinType - Coin type (from SLIP-0044)
 * @param account - Account index (defaults to 0)
 * @param change - Change branch, or the role on CIP-1852
 * @param addressIndex - Address index (defaults to 0)
 * @param maxChange - Highest change value the purpose allows, 1 for BIP44 and 5 for CIP-1852 roles
 * @returns {string} Derivation path string
 */
export function getBIP32Path(
  purpose: number,
  coinType: number,
  account = 0,
  change = 0,
  addressIndex = 0,
  maxChange: number = BIP44Change.INTERNAL,
): string {
  assertLevelIndex("purpose", purpose);
  assertLevelIndex("coinType", coinType);
  assertLevelIndex("account", account);
  assertLevelIndex("maxChange", maxChange);
  assertLevelIndex("change", change, maxChange);
  assertLevelIndex("addressIndex", addressIndex);

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
  assertLevelIndex("coinType", coinType);
  if (levels.length === 0 || levels.length > LEVEL_NAMES.length) {
    throw new RangeError(`levels must carry 1 to ${LEVEL_NAMES.length} entries`);
  }
  const hardened = levels.map((level, position) => {
    const maximum = position === 1 ? BIP44Change.INTERNAL : MAX_LEVEL_INDEX;
    assertLevelIndex(LEVEL_NAMES[position] ?? "level", level, maximum);
    return formatIndex(HARDENED_OFFSET + level);
  });

  const purposeStr = formatIndex(BIP44_PURPOSE);
  const coinTypeStr = formatIndex(HARDENED_OFFSET + coinType);

  return `m/${purposeStr}/${coinTypeStr}/${hardened.join("/")}`;
}
