import { verify as verifyBip340 } from "@agntn/curves/bip340";
import {
  addPoints,
  convertPoint,
  multiplyGenerator,
  recoverPublicKey,
  verify,
} from "@agntn/curves/secp256k1";

/** The one refusal for a public key that isn't a SEC1 point, shared with `convertPublicKey`. */
export const INVALID_PUBLIC_KEY = "Invalid SEC1 secp256k1 public key";

/** DER tags BIP66 allows: one sequence of two integers. */
const DER_SEQUENCE = 0x30;
const DER_INTEGER = 0x02;

/** SEC1 output form; the point stays the same. */
interface PointEncoding {
  readonly compressed?: boolean;
}

/** What an ECDSA signature is checked against. */
interface EcdsaCheck {
  readonly digest: Uint8Array;
  /** SEC1, compressed or not. */
  readonly publicKey: Uint8Array;
  /** Refuse s above n / 2, as BIP 62 and BIP 146 do. */
  readonly lowS: boolean;
}

/** What an ECDSA key comes back from. */
interface EcdsaRecovery extends PointEncoding {
  readonly digest: Uint8Array;
  /** 0 to 3, as Core and Ethereum carry it. */
  readonly recovery: number;
}

/** What a BIP340 signature is checked against. */
interface SchnorrCheck {
  readonly message: Uint8Array;
  /** 32 bytes, x-only. */
  readonly publicKey: Uint8Array;
}

/**
 * Trim a digest to what ECDSA reads, as noble did: 32 bytes, zero when empty.
 * @param digest - The signed digest
 * @returns {string} Hex for curves
 */
function digestHex(digest: Uint8Array): string {
  return digest.length === 0 ? "00" : digest.subarray(0, 32).toHex();
}

/**
 * Decode a SEC1 public key under one error.
 * @param keyPublic - SEC1 hex, compressed or not
 * @param encoding - Output form, compressed by default
 * @returns {Uint8Array} The same point as SEC1 bytes
 * @throws {Error} When the key is no SEC1 point
 */
export function decodePublicKey(keyPublic: string, encoding: PointEncoding = {}): Uint8Array {
  try {
    return Uint8Array.fromHex(convertPoint(keyPublic, encoding));
  } catch {
    throw new Error(INVALID_PUBLIC_KEY);
  }
}

/**
 * Add tweak times G to a key, as Taproot and old Electrum do. Zero leaves it be, as BIP341 allows.
 * @param publicKey - SEC1 bytes
 * @param options - Tweak from 0 to n minus 1, and the output form
 * @returns {Uint8Array} The tweaked key, compressed by default
 * @throws {RangeError} When the tweak is out of range or the sum is infinity
 */
export function tweakPublicKey(
  publicKey: Uint8Array,
  options: PointEncoding & { readonly tweak: bigint },
): Uint8Array {
  const { tweak, compressed } = options;
  const key = publicKey.toHex();
  if (tweak === 0n) return Uint8Array.fromHex(convertPoint(key, { compressed }));
  return Uint8Array.fromHex(addPoints(key, multiplyGenerator(tweak), { compressed }));
}

/**
 * Check ECDSA over a digest that's already hashed.
 * @param signature - 64 bytes, r then s
 * @param check - Digest, key and the low-S rule
 * @returns {boolean} False for any unreadable input too
 */
export function verifyEcdsaDigest(signature: Uint8Array, check: Readonly<EcdsaCheck>): boolean {
  const { digest, publicKey, lowS } = check;
  try {
    return verify(signature.toHex(), {
      digest: digestHex(digest),
      publicKey: publicKey.toHex(),
      lowS,
    });
  } catch {
    return false;
  }
}

/**
 * Recover the key behind ECDSA. Every well formed signature gives one, so compare it.
 * @param signature - 64 bytes, r then s
 * @param options - Digest, recovery id and output form
 * @returns {Uint8Array} SEC1 bytes, compressed by default
 * @throws {RangeError} When r and s recover no key
 */
export function recoverEcdsaKey(
  signature: Uint8Array,
  options: Readonly<EcdsaRecovery>,
): Uint8Array {
  const { digest, recovery, compressed } = options;
  return Uint8Array.fromHex(
    recoverPublicKey(signature.toHex(), { digest: digestHex(digest), recovery, compressed }),
  );
}

/**
 * Check a BIP340 signature.
 * @param signature - 64 bytes, x of R then s
 * @param check - Message and x-only key
 * @returns {boolean} Whether the key signed it
 * @throws {RangeError} When a length is off
 */
export function verifySchnorr(signature: Uint8Array, check: Readonly<SchnorrCheck>): boolean {
  return verifyBip340(signature.toHex(), {
    message: check.message.toHex(),
    publicKey: check.publicKey.toHex(),
  });
}

/**
 * Drop the sign byte, refusing empty, negative and needlessly padded integers.
 * @param value - Content bytes of one DER integer
 * @returns {Uint8Array | undefined} At most 32 unsigned bytes
 */
function unsignedDigits(value: Uint8Array): Uint8Array | undefined {
  const [first, second = 0] = value;
  if (first === undefined || first >= 0x80) return undefined;
  if (first === 0 && value.length > 1 && second < 0x80) return undefined;
  const digits = value.subarray(first === 0 ? 1 : 0);
  return digits.length > 32 ? undefined : digits;
}

/**
 * Read one DER integer with a short length.
 * @param der - DER signature
 * @param offset - Where its tag sits
 * @returns {[Uint8Array, number] | undefined} 32 bytes and the offset after it
 */
function readStrictInteger(der: Uint8Array, offset: number): [Uint8Array, number] | undefined {
  const length = der[offset + 1] ?? 0;
  const start = offset + 2;
  const value = der.subarray(start, start + length);
  if (der[offset] !== DER_INTEGER || value.length !== length) return undefined;
  const digits = unsignedDigits(value);
  if (digits === undefined) return undefined;
  const padded = new Uint8Array(32);
  padded.set(digits, 32 - digits.length);
  return [padded, start + length];
}

/**
 * Read r and s from DER as strict as BIP66, no byte to spare.
 * @param der - DER signature without the hash type
 * @returns {Uint8Array | undefined} r then s, undefined for anything looser
 */
export function readStrictDer(der: Uint8Array): Uint8Array | undefined {
  if (der[0] !== DER_SEQUENCE || der[1] !== der.length - 2) return undefined;
  const r = readStrictInteger(der, 2);
  const s = r === undefined ? undefined : readStrictInteger(der, r[1]);
  if (r === undefined || s === undefined || s[1] !== der.length) return undefined;
  const signature = new Uint8Array(64);
  signature.set(r[0]);
  signature.set(s[0], 32);
  return signature;
}
