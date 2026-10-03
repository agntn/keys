import { secp256k1 } from "@noble/curves/secp256k1.js";
import { INVALID_PUBLIC_KEY } from "./decode.ts";

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
export function convertPublicKey(
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
    const point = secp256k1.Point.fromBytes(Uint8Array.fromHex(publicKey));
    return point.toBytes(compressed).toHex();
  } catch {
    throw new Error(INVALID_PUBLIC_KEY);
  }
}

export {
  addPoints,
  addScalars,
  invertScalar,
  isOnCurve,
  liftX,
  multiplyGenerator,
  multiplyPoint,
  multiplyScalars,
  negatePoint,
  subtractPoints,
  subtractScalars,
} from "./math.ts";
export type { LiftedPoints, Scalar } from "./math.ts";
export { recoverReusedNonce } from "./nonce.ts";
export type { NonceRecoveryOptions, NonceSignature, RecoveredNonceKey } from "./nonce.ts";
