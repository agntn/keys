import { HDKey } from "micro-key-producer/slip10.js";

// Reexport the SLIP10 implementation
export { HDKey };

// SLIP-0010 hardened offset constant - same as BIP32
export const HARDENED_OFFSET = 0x80_00_00_00;

/**
 * Creates a SLIP-0010 master key from seed bytes
 * @param seed - A seed byte array
 * @returns HDKey instance for the master key
 */
export function getMasterKeyFromSeed(seed: Uint8Array): HDKey {
  return HDKey.fromMasterSeed(seed);
}

/**
 * Derives a child key from a parent key using a derivation path
 * @param parent - Parent HDKey instance
 * @param path - Derivation path (e.g., "m/44'/0'/0'/0/0")
 * @param forceHardened - Whether to force hardened derivation for ed25519
 * @returns Derived HDKey instance
 */
export function deriveHDKey(parent: HDKey, path: string, forceHardened = true): HDKey {
  return parent.derive(path, forceHardened);
}

/**
 * Derives a child key at a specific index from a parent key
 * @param parent - Parent HDKey instance
 * @param index - Child index (use index + HARDENED_OFFSET for hardened keys)
 * @returns Derived HDKey child
 */
export function deriveHDChild(parent: HDKey, index: number): HDKey {
  return parent.deriveChild(index);
}

/**
 * Creates a hardened child index
 * @param index - Non-hardened index
 * @returns Hardened index
 */
export function hardenedIndex(index: number): number {
  return index + HARDENED_OFFSET;
}

/**
 * Checks if an index is hardened
 * @param index - Index to check
 * @returns True if index is hardened
 */
export function isHardenedIndex(index: number): boolean {
  return index >= HARDENED_OFFSET;
}

/**
 * Formats an index to a string representation, appending ' to hardened indices
 * @param index - Index to format
 * @returns Formatted string representation
 */
export function formatIndex(index: number): string {
  return isHardenedIndex(index) ? `${index - HARDENED_OFFSET}'` : `${index}`;
}
