import { HDKey } from "@scure/bip32";
export { HDKey };

export { HARDENED_OFFSET, hardenedIndex, isHardenedIndex, formatIndex } from "../hd-index.ts";

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
