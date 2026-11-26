import { verify } from "@agntn/curves/ed25519";
import { ed25519 } from "@noble/curves/ed25519.js";

/** What an Ed25519 signature is checked against. */
interface Ed25519Check {
  readonly message: Uint8Array;
  /** 32 bytes. */
  readonly publicKey: Uint8Array;
  /** ZIP 215's rules unless false, which wants RFC 8032 strict. */
  readonly zip215?: boolean;
}

/**
 * Check plain Ed25519 over the raw bytes.
 * @param signature - 64 bytes, R then S
 * @param check - Message, key and rules
 * @returns {boolean} Whether the key signed it
 * @throws {RangeError} When a length is off
 */
export function verifyBytes(signature: Uint8Array, check: Readonly<Ed25519Check>): boolean {
  const { message, publicKey, zip215 } = check;
  return verify(signature.toHex(), {
    message: message.toHex(),
    publicKey: publicKey.toHex(),
    ...(zip215 === undefined ? {} : { zip215 }),
  });
}

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
