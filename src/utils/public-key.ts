import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

/** SEC1 output encoding; this does not change the curve point. */
export interface PublicKeyEncodingOptions {
  readonly compressed?: boolean;
}

/**
 * Convert a SEC1 secp256k1 public key without needing a private key.
 * @param publicKey - Compressed or uncompressed SEC1 hex, without 0x.
 * @param options - Output encoding; compressed by default.
 * @returns {string} Canonical lowercase SEC1 hex.
 */
export function convertSecp256k1PublicKey(
  publicKey: string,
  options: PublicKeyEncodingOptions = {},
): string {
  const { compressed = true } = options;
  if (typeof compressed !== "boolean") throw new TypeError("Compressed must be a boolean");
  try {
    if (
      typeof publicKey !== "string" ||
      !/^(?:0[23][0-9a-f]{64}|04[0-9a-f]{128})$/iu.test(publicKey)
    ) {
      throw new Error("Invalid encoding");
    }
    const point = secp256k1.Point.fromBytes(hexToBytes(publicKey));
    return bytesToHex(point.toBytes(compressed));
  } catch {
    throw new Error("Invalid SEC1 secp256k1 public key");
  }
}
