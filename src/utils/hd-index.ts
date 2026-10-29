/** BIP32 and SLIP-0010 reserve the high bit of a 32-bit child index for hardening. */
export const HARDENED_OFFSET = 0x80_00_00_00;

/**
 * Creates a hardened child index
 * @param index - Integer from 0 through 2147483647
 * @returns {number} Hardened index
 */
export function hardenedIndex(index: number): number {
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
    throw new RangeError("Index must be an integer between 0 and 2147483647");
  }
  return index + HARDENED_OFFSET;
}

/**
 * Checks if an index is hardened
 * @param index - Index to check
 * @returns {boolean} True if index is hardened
 */
export function isHardenedIndex(index: number): boolean {
  return index >= HARDENED_OFFSET;
}

/**
 * Rewrites the `h` hardened marker of BIP380 descriptors as the `'` the BIP32 libraries read.
 * @param path - Derivation path such as `m/84h/0h/0h/0/0`
 * @returns {string} The path with `'` on every hardened level
 */
export function normalizeHardenedMarkers(path: string): string {
  return path.replaceAll(/(?<=\d)h(?=\/|$)/gu, "'");
}

/** What a derivation path has to hold on top of the BIP32 grammar. */
export interface DerivationPathRules {
  /** Refuse normal levels, since SLIP-10 walks ed25519 down hardened levels only. Default: false */
  readonly hardenedOnly?: boolean;
}

/** One level below `m`: the index in digits, then `'` when it is hardened. */
const LEVEL = /^(\d+)(')?$/u;

/**
 * Reads a path the way BIP32 and SLIP-10 walk it, but names the level it refuses and the rule.
 * @param path - Derivation path such as `m/84h/0h/0h/0/0`
 * @param rules - Whether every level has to be hardened
 * @returns {string} The path with `'` on every hardened level
 * @throws {RangeError} For a path the BIP32 and SLIP-10 libraries would refuse with their own text
 * @throws {TypeError} For a path that is not a string
 */
export function normalizeDerivationPath(path: string, rules: DerivationPathRules = {}): string {
  if (typeof path !== "string") {
    throw new TypeError("Derivation path must be a string, such as m/84'/0'/0'/0/0");
  }
  const normalized = normalizeHardenedMarkers(path);
  const root = /^[mM]'?(?=\/|$)/u.exec(normalized)?.[0];
  if (root === undefined) {
    throw new RangeError("Derivation path must be m or start with m/, such as m/84'/0'/0'/0/0");
  }
  if (normalized !== root) {
    assertLevels(normalized.slice(root.length + 1).split("/"), rules);
  }
  return normalized;
}

/**
 * Checks each level below `m` for digits, the 31-bit index range and, on ed25519, the marker.
 * @param levels - Levels below `m`, split on `/`
 * @param rules - Whether a normal level is refused
 * @returns {void} Nothing; it throws on the first level that breaks a rule
 */
function assertLevels(levels: readonly string[], rules: DerivationPathRules): void {
  for (const [offset, level] of levels.entries()) {
    const match = LEVEL.exec(level);
    const name = `Level ${offset + 1} of the derivation path`;
    if (match === null) {
      throw new RangeError(`${name} must be digits, with ' or h for a hardened level`);
    }
    const [, digits, hardened] = match;
    if (Number(digits) >= HARDENED_OFFSET) {
      throw new RangeError(
        `${name} is above 2147483647; mark a hardened level with ' or h instead of adding 2^31`,
      );
    }
    if (rules.hardenedOnly === true && hardened === undefined) {
      throw new RangeError(
        `SLIP-10 walks ed25519 down hardened levels only, so ${name.toLowerCase()} needs ' or h`,
      );
    }
  }
}

/**
 * Formats an index to a string representation, appending ' to hardened indices
 * @param index - Index to format
 * @returns {string} Formatted string representation
 */
export function formatIndex(index: number): string {
  return isHardenedIndex(index) ? `${index - HARDENED_OFFSET}'` : `${index}`;
}
