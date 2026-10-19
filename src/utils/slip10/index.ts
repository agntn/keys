import { HDKey } from "micro-key-producer/slip10.js";

// Reexport the SLIP10 implementation
export { HDKey };

import { normalizeHardenedMarkers } from "../hd-index.ts";
import { assertOptions } from "../options.ts";

export { HARDENED_OFFSET, hardenedIndex, isHardenedIndex, formatIndex } from "../hd-index.ts";

/**
 * Creates a SLIP-0010 master key from seed bytes
 * @param seed - A seed byte array
 * @returns {HDKey} HDKey instance for the master key
 */
export function getMasterKeyFromSeed(seed: Uint8Array): HDKey {
  return HDKey.fromMasterSeed(seed);
}

/** Where `deriveHDKey` walks and whether it hardens every level on the way. */
export interface SLIP10PathOptions {
  /** Derivation path (e.g., "m/44'/0'/0'/0/0"), with `'` or `h` marking hardened levels. */
  readonly path: string;
  /** Harden every level, as ed25519 needs. Default: true */
  readonly forceHardened?: boolean;
}

/**
 * Derives a child key from a parent key using a derivation path
 * @param parent - Parent HDKey instance
 * @param options - Derivation path and whether to force hardened derivation for ed25519
 * @returns {HDKey} Derived HDKey instance
 */
export function deriveHDKey(parent: HDKey, options: SLIP10PathOptions): HDKey {
  assertOptions(options, "deriveHDKey(parent, { path, forceHardened })");
  const { path, forceHardened = true } = options;
  return parent.derive(normalizeHardenedMarkers(path), forceHardened);
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
