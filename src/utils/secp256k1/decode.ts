import { secp256k1 } from "@noble/curves/secp256k1.js";

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
