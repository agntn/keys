import { decodePublicKey, INVALID_PUBLIC_KEY } from "./public.ts";

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
  if (
    typeof publicKey !== "string" ||
    !/^(?:0[23][0-9a-f]{64}|04[0-9a-f]{128})$/iu.test(publicKey)
  ) {
    throw new Error(INVALID_PUBLIC_KEY);
  }
  return decodePublicKey(publicKey, { compressed }).toHex();
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
} from "@agntn/curves/secp256k1";
export type { LiftedPoints, Scalar } from "@agntn/curves/secp256k1";
export { recoverKnownNonce, recoverReusedNonce } from "./nonce.ts";
export type {
  KnownNonceKey,
  KnownNonceOptions,
  NonceRecoveryOptions,
  NonceSignature,
  NonceSignaturePair,
  RecoveredNonceKey,
} from "./nonce.ts";
