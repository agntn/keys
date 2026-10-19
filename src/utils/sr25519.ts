import { expandSeed, getPublicKey, sign, verify } from "@agntn/curves/sr25519";

/** Hex digits of a mini secret, the 32 bytes Substrate expands into a key. */
const MINI_SECRET_DIGITS = 64;

/** Hex digits of a schnorrkel secret: the key, then its nonce. */
const SECRET_DIGITS = 128;

/**
 * Reads an sr25519 private key: a mini secret gets expanded, a full secret passes as it is.
 * @param keyPrivate - 32-byte mini secret or 64-byte schnorrkel secret, as hex
 * @returns {string} The 64-byte secret as hex
 * @throws {RangeError} When the key is neither length
 */
export function readSecret(keyPrivate: string): string {
  if (keyPrivate.length === MINI_SECRET_DIGITS) return expandSeed(keyPrivate);
  if (keyPrivate.length === SECRET_DIGITS) return keyPrivate.toLowerCase();
  throw new RangeError(
    "An sr25519 private key is a 32-byte mini secret or the 64-byte secret of a derived account",
  );
}

/**
 * The ristretto255 public key of an sr25519 private key.
 * @param keyPrivate - 32-byte mini secret or 64-byte schnorrkel secret, as hex
 * @returns {string} The 32-byte public key as hex
 */
export function generateKeyPublic(keyPrivate: string): string {
  return getPublicKey(readSecret(keyPrivate));
}

/**
 * Signs the bytes under schnorrkel's `substrate` context, with a random nonce every time.
 * @param message - The bytes to sign
 * @param keyPrivate - 32-byte mini secret or 64-byte schnorrkel secret, as hex
 * @returns {string} The 64-byte signature as hex
 */
export function signBytes(message: Uint8Array, keyPrivate: string): string {
  return sign(readSecret(keyPrivate), message);
}

/**
 * Checks an sr25519 signature under the `substrate` context, where bad hex is a failed check.
 * @param signature - Signature as hex
 * @param check - The signed bytes and the public key as hex
 * @param check.message - The signed bytes
 * @param check.publicKey - The 32-byte public key as hex
 * @returns {boolean} Whether the signature matches the key
 */
export function verifyBytes(
  signature: string,
  check: { readonly message: Uint8Array; readonly publicKey: string },
): boolean {
  try {
    return verify(signature, check.message, check.publicKey);
  } catch {
    return false;
  }
}
