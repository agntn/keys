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

/**
 * Formats an index to a string representation, appending ' to hardened indices
 * @param index - Index to format
 * @returns {string} Formatted string representation
 */
export function formatIndex(index: number): string {
  return isHardenedIndex(index) ? `${index - HARDENED_OFFSET}'` : `${index}`;
}
