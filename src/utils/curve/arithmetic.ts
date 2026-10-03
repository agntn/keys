import { invert, isPrime, mod } from "./field.ts";

/** A short Weierstrass curve y^2 = x^3 + ax + b over the prime field of p. */
export interface WeierstrassCurve {
  readonly a: bigint;
  readonly b: bigint;
  readonly p: bigint;
}

/** A point with both coordinates from 0 to p minus 1. */
export interface AffinePoint {
  readonly x: bigint;
  readonly y: bigint;
}

/** A point of the curve, where null stands for the point at infinity. */
export type CurvePoint = AffinePoint | null;

const checked = new WeakSet<WeierstrassCurve>();

/**
 * Check a curve and bring a and b into 0 to p minus 1.
 * @param parameters - a and b as any integers, p a prime above 3
 * @returns {WeierstrassCurve} A frozen curve the other functions take without checking it again
 * @throws {RangeError} When p is not a prime above 3, or 4a^3 + 27b^2 is 0 mod p
 */
export function defineCurve(parameters: Readonly<WeierstrassCurve>): WeierstrassCurve {
  const { p } = parameters;
  if (typeof p !== "bigint" || p <= 3n || !isPrime(p)) {
    throw new RangeError("p must be a prime above 3");
  }
  if (typeof parameters.a !== "bigint" || typeof parameters.b !== "bigint") {
    throw new TypeError("a and b must be bigints");
  }
  const a = mod(parameters.a, p);
  const b = mod(parameters.b, p);
  if (mod(4n * a * a * a + 27n * b * b, p) === 0n) {
    throw new RangeError("The curve is singular: 4a^3 + 27b^2 is 0 mod p");
  }
  const curve = Object.freeze({ a, b, p });
  checked.add(curve);
  return curve;
}

/**
 * Take a curve from `defineCurve` as it is, and check any other object first.
 * @param curve - The curve a caller passed
 * @returns {WeierstrassCurve} A checked curve
 */
export function checkedCurve(curve: Readonly<WeierstrassCurve>): WeierstrassCurve {
  return checked.has(curve) ? curve : defineCurve(curve);
}

/**
 * Tell whether a point satisfies the curve equation, without checking the curve.
 * @param curve - A checked curve
 * @param point - A point or null for infinity
 * @returns {boolean} True for infinity and for a point on the curve
 */
export function satisfies(curve: Readonly<WeierstrassCurve>, point: Readonly<CurvePoint>): boolean {
  if (point === null) return true;
  const { a, b, p } = curve;
  const { x, y } = point;
  if (typeof x !== "bigint" || typeof y !== "bigint" || x < 0n || y < 0n || x >= p || y >= p) {
    return false;
  }
  return mod(y * y - x * x * x - a * x - b, p) === 0n;
}

/**
 * Refuse a point off the curve before any arithmetic runs on it.
 * @param curve - A checked curve
 * @param point - The point a caller passed
 * @param name - What the error calls the point
 * @returns {CurvePoint} The point
 */
export function onCurve(
  curve: Readonly<WeierstrassCurve>,
  point: Readonly<CurvePoint>,
  name = "The point",
): CurvePoint {
  if (!satisfies(curve, point)) {
    throw new RangeError(`${name} is not on the curve; coordinates run from 0 to p minus 1`);
  }
  return point;
}

/**
 * Double a point on a checked curve.
 * @param curve - A checked curve
 * @param point - A point of the curve
 * @returns {CurvePoint} Twice the point
 */
export function double(curve: Readonly<WeierstrassCurve>, point: Readonly<CurvePoint>): CurvePoint {
  if (point === null || point.y === 0n) return null;
  const { a, p } = curve;
  const { x, y } = point;
  const slope = mod((3n * x * x + a) * invert(2n * y, p), p);
  const sumX = mod(slope * slope - 2n * x, p);
  return { x: sumX, y: mod(slope * (x - sumX) - y, p) };
}

/**
 * Add two points of a checked curve.
 * @param curve - A checked curve
 * @param left - A point of the curve
 * @param right - A point of the curve
 * @returns {CurvePoint} The sum
 */
export function add(
  curve: Readonly<WeierstrassCurve>,
  left: Readonly<CurvePoint>,
  right: Readonly<CurvePoint>,
): CurvePoint {
  if (left === null) return right;
  if (right === null) return left;
  const { p } = curve;
  if (left.x === right.x) return left.y === right.y ? double(curve, left) : null;
  const slope = mod((right.y - left.y) * invert(right.x - left.x, p), p);
  const sumX = mod(slope * slope - left.x - right.x, p);
  return { x: sumX, y: mod(slope * (left.x - sumX) - left.y, p) };
}

/**
 * Negate a point of a checked curve: same x, y becomes p minus y.
 * @param curve - A checked curve
 * @param point - A point of the curve
 * @returns {CurvePoint} The negation
 */
export function negate(curve: Readonly<WeierstrassCurve>, point: Readonly<CurvePoint>): CurvePoint {
  return point === null ? null : { x: point.x, y: mod(-point.y, curve.p) };
}

/**
 * Multiply a point of a checked curve by double and add.
 * @param curve - A checked curve
 * @param point - A point of the curve
 * @param scalar - Any integer; a negative one multiplies the negation
 * @returns {CurvePoint} The product
 */
export function multiply(
  curve: Readonly<WeierstrassCurve>,
  point: Readonly<CurvePoint>,
  scalar: bigint,
): CurvePoint {
  if (scalar < 0n) return multiply(curve, negate(curve, point), -scalar);
  let result: CurvePoint = null;
  let addend = point;
  for (let rest = scalar; rest > 0n; rest >>= 1n) {
    if ((rest & 1n) === 1n) result = add(curve, result, addend);
    addend = double(curve, addend);
  }
  return result;
}

/**
 * Tell whether a point lies on the curve.
 * @param curve - From `defineCurve`, or parameters it accepts
 * @param point - A point, or null for infinity, which always lies on it
 * @returns {boolean} False for a point off the curve or coordinates outside 0 to p minus 1
 */
export function isOnCurve(curve: Readonly<WeierstrassCurve>, point: Readonly<CurvePoint>): boolean {
  return satisfies(checkedCurve(curve), point);
}

/**
 * Add two points.
 * @param curve - From `defineCurve`, or parameters it accepts
 * @param left - A point of the curve, or null for infinity
 * @param right - A point of the curve, or null for infinity
 * @returns {CurvePoint} The sum, null when it is the point at infinity
 * @throws {RangeError} When a point is not on the curve
 */
export function addPoints(
  curve: Readonly<WeierstrassCurve>,
  left: Readonly<CurvePoint>,
  right: Readonly<CurvePoint>,
): CurvePoint {
  const checkedOne = checkedCurve(curve);
  return add(checkedOne, onCurve(checkedOne, left, "left"), onCurve(checkedOne, right, "right"));
}

/**
 * Double a point.
 * @param curve - From `defineCurve`, or parameters it accepts
 * @param point - A point of the curve, or null for infinity
 * @returns {CurvePoint} Twice the point, null for a point with y = 0
 * @throws {RangeError} When the point is not on the curve
 */
export function doublePoint(
  curve: Readonly<WeierstrassCurve>,
  point: Readonly<CurvePoint>,
): CurvePoint {
  const checkedOne = checkedCurve(curve);
  return double(checkedOne, onCurve(checkedOne, point));
}

/**
 * Negate a point.
 * @param curve - From `defineCurve`, or parameters it accepts
 * @param point - A point of the curve, or null for infinity
 * @returns {CurvePoint} The point with the other y
 * @throws {RangeError} When the point is not on the curve
 */
export function negatePoint(
  curve: Readonly<WeierstrassCurve>,
  point: Readonly<CurvePoint>,
): CurvePoint {
  const checkedOne = checkedCurve(curve);
  return negate(checkedOne, onCurve(checkedOne, point));
}

/**
 * Multiply a point by a scalar.
 * @param curve - From `defineCurve`, or parameters it accepts
 * @param point - A point of the curve, or null for infinity
 * @param scalar - Any integer: zero gives infinity, a negative one multiplies the negation
 * @returns {CurvePoint} The product
 * @throws {RangeError} When the point is not on the curve
 */
export function multiplyPoint(
  curve: Readonly<WeierstrassCurve>,
  point: Readonly<CurvePoint>,
  scalar: bigint,
): CurvePoint {
  if (typeof scalar !== "bigint") throw new TypeError("The scalar must be a bigint");
  const checkedOne = checkedCurve(curve);
  return multiply(checkedOne, onCurve(checkedOne, point), scalar);
}
