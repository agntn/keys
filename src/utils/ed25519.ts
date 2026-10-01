import { ed25519 } from "@noble/curves/ed25519.js";

/**
 * Generates a public key from a private key using Ed25519 elliptic curve
 * Used by Solana, Aptos and other blockchains
 *
 * @param keyPrivate - The private key as a hex string
 * @returns {string} The public key as a hex string
 */
export function generateKeyPublic(keyPrivate: string): string {
  const keyPrivateBytes = Uint8Array.fromHex(keyPrivate);
  const keyPublic = ed25519.getPublicKey(keyPrivateBytes);
  return keyPublic.toHex();
}

/**
 * Refuses any length but 32 bytes, so a SEC1 key never hashes into an ed25519 address.
 *
 * @param keyPublic - The public key as hex
 * @param label - Chain name for the error message
 * @returns {Uint8Array} The 32 key bytes
 * @throws {RangeError} When the key is not 32 bytes
 */
export function decodeKeyPublic(keyPublic: string, label: string): Uint8Array {
  const keyPublicBytes = Uint8Array.fromHex(keyPublic);
  if (keyPublicBytes.length !== 32) {
    throw new RangeError(`${label} public key must be 32 bytes`);
  }
  return keyPublicBytes;
}
