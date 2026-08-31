import { HDKey } from "@scure/bip32";
export { HDKey };

// BIP32 hardened offset constant
export const HARDENED_OFFSET = 0x80_00_00_00;

/**
 * Creates a BIP32 master key from seed bytes
 * @param seed - A seed byte array
 * @returns {HDKey} HDKey instance for the master key
 */
export function getMasterKeyFromSeed(seed: Uint8Array): HDKey {
  return HDKey.fromMasterSeed(seed);
}

/**
 * Creates a BIP32 HDKey from extended key string
 * @param xkey - Extended private or public key in base58 format
 * @returns {HDKey} HDKey instance
 */
export function getHDKeyFromExtended(xkey: string): HDKey {
  return HDKey.fromExtendedKey(xkey);
}

/**
 * Derives a child key from a parent key using a derivation path
 * @param parent - Parent HDKey instance
 * @param path - Derivation path (e.g., "m/44'/0'/0'/0/0")
 * @returns {HDKey} Derived HDKey instance
 */
export function deriveHDKey(parent: HDKey, path: string): HDKey {
  return parent.derive(path);
}

/**
 * Derives a child key at a specific index from a parent key
 * @param parent - Parent HDKey instance
 * @param index - Child index (use index + HARDENED_OFFSET for hardened keys)
 * @returns {HDKey} Derived HDKey child
 */
export function deriveHDChild(parent: HDKey, index: number): HDKey {
  return parent.deriveChild(index);
}

/**
 * Creates a hardened child index
 * @param index - Non-hardened index
 * @returns {number} Hardened index
 */
export function hardenedIndex(index: number): number {
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
 * Formats an index to a string representation, appending ' to hardened indices
 * @param index - Index to format
 * @returns {string} Formatted string representation
 */
export function formatIndex(index: number): string {
  return isHardenedIndex(index) ? `${index - HARDENED_OFFSET}'` : `${index}`;
}
