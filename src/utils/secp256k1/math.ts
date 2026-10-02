import { secp256k1 } from "@noble/curves/secp256k1.js";
import { decodePublicPoint, INVALID_PUBLIC_KEY } from "./decode.ts";
import type { PublicKeyEncodingOptions } from "./index.ts";

type Point = ReturnType<typeof secp256k1.Point.fromBytes>;

const { Point: CurvePoint } = secp256k1;
const { Fn } = CurvePoint;

/** A scalar as hex without 0x, up to 64 digits, or as a bigint. */
export type Scalar = string | bigint;

/** The two points above one x coordinate, as SEC1 hex. */
export interface LiftedPoints {
  /** Even y, the point a BIP340 x-only key stands for. */
  readonly even: string;
  readonly odd: string;
}

const INFINITY = "The result is the point at infinity, which is no public key, as with P minus P";

/**
 * Read a scalar and check it against the range the operation allows.
 * @param value - Hex without 0x, up to 64 digits, or a bigint
 * @param name - What the error calls the value
 * @param minimum - 0 for scalar arithmetic, 1 where zero would give the point at infinity
 * @returns {bigint} The scalar
 * @throws {RangeError} When the value is not hex or a bigint, or falls outside minimum to n minus 1
 */
function decodeScalar(value: unknown, name: string, minimum: 0n | 1n): bigint {
  let scalar: bigint | undefined;
  if (typeof value === "bigint") scalar = value;
  else if (typeof value === "string" && /^[0-9a-f]{1,64}$/iu.test(value)) {
    scalar = BigInt(`0x${value}`);
  }
  if (scalar === undefined || scalar < minimum || scalar >= Fn.ORDER) {
    throw new RangeError(
      `${name} must be hex without 0x or a bigint, from ${minimum} to the curve order minus 1`,
    );
  }
  return scalar;
}

function encodeScalar(scalar: bigint): string {
  return scalar.toString(16).padStart(64, "0");
}

function encodePoint(point: Point, options: PublicKeyEncodingOptions): string {
  const { compressed = true } = options;
  if (typeof compressed !== "boolean") throw new TypeError("Compressed must be a boolean");
  if (point.is0()) throw new RangeError(INFINITY);
  return point.toBytes(compressed).toHex();
}

/**
 * Add two points, as in a split key vanity address.
 * @param a - SEC1 hex, compressed or uncompressed
 * @param b - SEC1 hex, compressed or uncompressed
 * @param options - Output encoding; compressed by default
 * @returns {string} The sum as SEC1 hex
 * @throws {RangeError} When b is the negation of a, since the sum is the point at infinity
 */
export function addPoints(a: string, b: string, options: PublicKeyEncodingOptions = {}): string {
  return encodePoint(decodePublicPoint(a).add(decodePublicPoint(b)), options);
}

/**
 * Subtract point b from point a, as when checking the offset between two known keys.
 * @param a - SEC1 hex, compressed or uncompressed
 * @param b - SEC1 hex, compressed or uncompressed
 * @param options - Output encoding; compressed by default
 * @returns {string} The difference as SEC1 hex
 * @throws {RangeError} When a equals b, since the difference is the point at infinity
 */
export function subtractPoints(
  a: string,
  b: string,
  options: PublicKeyEncodingOptions = {},
): string {
  return encodePoint(decodePublicPoint(a).subtract(decodePublicPoint(b)), options);
}

/**
 * Negate a point: same x, the other y.
 * @param point - SEC1 hex, compressed or uncompressed
 * @param options - Output encoding; compressed by default
 * @returns {string} The negated point as SEC1 hex
 */
export function negatePoint(point: string, options: PublicKeyEncodingOptions = {}): string {
  return encodePoint(decodePublicPoint(point).negate(), options);
}

/**
 * Multiply a point by a scalar.
 * @param point - SEC1 hex, compressed or uncompressed
 * @param scalar - From 1 to the curve order minus 1
 * @param options - Output encoding; compressed by default
 * @returns {string} The product as SEC1 hex
 */
export function multiplyPoint(
  point: string,
  scalar: Scalar,
  options: PublicKeyEncodingOptions = {},
): string {
  return encodePoint(
    decodePublicPoint(point).multiply(decodeScalar(scalar, "Scalar", 1n)),
    options,
  );
}

/**
 * Multiply the generator by a scalar, which for a private key is its public key.
 * @param scalar - From 1 to the curve order minus 1
 * @param options - Output encoding; compressed by default
 * @returns {string} The product as SEC1 hex
 */
export function multiplyGenerator(scalar: Scalar, options: PublicKeyEncodingOptions = {}): string {
  return encodePoint(CurvePoint.BASE.multiply(decodeScalar(scalar, "Scalar", 1n)), options);
}

/**
 * Add two scalars mod the curve order.
 * @param a - From 0 to the curve order minus 1
 * @param b - From 0 to the curve order minus 1
 * @returns {string} The sum as 64 hex digits
 */
export function addScalars(a: Scalar, b: Scalar): string {
  return encodeScalar(Fn.add(decodeScalar(a, "Scalar a", 0n), decodeScalar(b, "Scalar b", 0n)));
}

/**
 * Subtract scalar b from scalar a mod the curve order.
 * @param a - From 0 to the curve order minus 1
 * @param b - From 0 to the curve order minus 1
 * @returns {string} The difference as 64 hex digits
 */
export function subtractScalars(a: Scalar, b: Scalar): string {
  return encodeScalar(Fn.sub(decodeScalar(a, "Scalar a", 0n), decodeScalar(b, "Scalar b", 0n)));
}

/**
 * Multiply two scalars mod the curve order.
 * @param a - From 0 to the curve order minus 1
 * @param b - From 0 to the curve order minus 1
 * @returns {string} The product as 64 hex digits
 */
export function multiplyScalars(a: Scalar, b: Scalar): string {
  return encodeScalar(Fn.mul(decodeScalar(a, "Scalar a", 0n), decodeScalar(b, "Scalar b", 0n)));
}

/**
 * Invert a scalar mod the curve order.
 * @param scalar - From 1 to the curve order minus 1, since zero has no inverse
 * @returns {string} The inverse as 64 hex digits
 */
export function invertScalar(scalar: Scalar): string {
  return encodeScalar(Fn.inv(decodeScalar(scalar, "Scalar", 1n)));
}

/**
 * Find both points above an x coordinate. An x-only BIP340 key is the even one.
 * @param x - 64 hex digits without 0x
 * @param options - Output encoding; compressed by default
 * @returns {LiftedPoints} The even and odd point as SEC1 hex
 * @throws {RangeError} When x is not 64 hex digits, or no point of the curve has it
 */
export function liftX(x: string, options: PublicKeyEncodingOptions = {}): LiftedPoints {
  if (typeof x !== "string" || !/^[0-9a-f]{64}$/iu.test(x)) {
    throw new RangeError("x must be 64 hex digits without 0x");
  }
  let even: Point;
  try {
    even = CurvePoint.fromBytes(Uint8Array.fromHex(`02${x}`));
  } catch {
    throw new RangeError("No point of secp256k1 has this x");
  }
  return { even: encodePoint(even, options), odd: encodePoint(even.negate(), options) };
}

/**
 * Check that a SEC1 point lies on the curve.
 * @param point - Compressed or uncompressed SEC1 hex
 * @returns {boolean} False for a point off the curve, or a compressed x that no point has
 * @throws {Error} When the value is not SEC1 hex at all, since there is no point to check
 */
export function isOnCurve(point: string): boolean {
  if (typeof point !== "string" || !/^(?:0[23][0-9a-f]{64}|04[0-9a-f]{128})$/iu.test(point)) {
    throw new Error(INVALID_PUBLIC_KEY);
  }
  try {
    decodePublicPoint(point);
    return true;
  } catch {
    return false;
  }
}
