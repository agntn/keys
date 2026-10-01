import { secp256k1 } from "@noble/curves/secp256k1.js";

/** The one refusal for a public key that isn't a SEC1 point, shared with `convertPublicKey`. */
export const INVALID_PUBLIC_KEY = "Invalid SEC1 secp256k1 public key";

/**
 * Decode a private key with an error that names it, in place of the curve library's own.
 * @param keyPrivate - The private key as hex
 * @returns {Uint8Array} The 32 key bytes
 * @throws {RangeError} When the key is not hex or not a scalar from 1 to the curve order minus 1
 */
export function decodeKeyPrivate(keyPrivate: string): Uint8Array {
  if (typeof keyPrivate === "string" && /^[0-9a-f]{64}$/iu.test(keyPrivate)) {
    const keyPrivateBytes = Uint8Array.fromHex(keyPrivate);
    if (secp256k1.utils.isValidSecretKey(keyPrivateBytes)) return keyPrivateBytes;
  }
  throw new RangeError(
    "secp256k1 private key must be 32 bytes of hex, above zero and below the curve order",
  );
}

/**
 * Decode a SEC1 public key into its point, with one error in place of the curve library's own.
 * @param keyPublic - Compressed or uncompressed SEC1 public key as hex
 * @returns {ReturnType<typeof secp256k1.Point.fromBytes>} The point the key encodes
 * @throws {Error} When the key is not hex, not SEC1 or not on the curve
 */
export function decodePublicPoint(keyPublic: string): ReturnType<typeof secp256k1.Point.fromBytes> {
  try {
    return secp256k1.Point.fromBytes(Uint8Array.fromHex(keyPublic));
  } catch {
    throw new Error(INVALID_PUBLIC_KEY);
  }
}
