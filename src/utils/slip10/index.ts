import { HDKey } from "micro-key-producer/slip10.js";

// Reexport the SLIP10 implementation
export { HDKey };

export { HARDENED_OFFSET, hardenedIndex, isHardenedIndex, formatIndex } from "../hd-index.ts";

/**
 * Creates a SLIP-0010 master key from seed bytes
 * @param seed - A seed byte array
 * @returns {HDKey} HDKey instance for the master key
 */
export function getMasterKeyFromSeed(seed: Uint8Array): HDKey {
  return HDKey.fromMasterSeed(seed);
}

/**
 * Derives a child key from a parent key using a derivation path
 * @param parent - Parent HDKey instance
 * @param path - Derivation path (e.g., "m/44'/0'/0'/0/0")
 * @param forceHardened - Whether to force hardened derivation for ed25519
 * @returns {HDKey} Derived HDKey instance
 */
export function deriveHDKey(parent: HDKey, path: string, forceHardened = true): HDKey {
  return parent.derive(path, forceHardened);
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
