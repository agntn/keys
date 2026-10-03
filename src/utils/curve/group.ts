import {
  add,
  checkedCurve,
  multiply,
  negate,
  onCurve,
  type AffinePoint,
  type CurvePoint,
  type WeierstrassCurve,
} from "./arithmetic.ts";
import { primeFactors, squareRoot } from "./field.ts";

/** Largest p whose points are counted or listed one x at a time. */
export const MAX_COUNTED_PRIME = 1n << 20n;

/** Largest p for listing the points of one order, which multiplies every point. */
export const MAX_FILTERED_PRIME = 1n << 16n;

/** Largest p for the order of a point, found by baby step giant step over the Hasse interval. */
export const MAX_ORDER_PRIME = 1n << 48n;

/** Largest order of the base point a discrete log is searched in. */
export const MAX_LOG_ORDER = 1n << 36n;

/** Which points `listPoints` returns. */
export interface ListPointsOptions {
  /** Only the points of exactly this order. */
  readonly order?: bigint;
  /** Stop after this many points, 1 or more, instead of building the whole list. */
  readonly limit?: number;
}

/**
 * Refuse a field too large to walk one x at a time.
 * @param curve - A checked curve
 * @returns {number} p as a Number
 */
function countedPrime(curve: Readonly<WeierstrassCurve>): number {
  if (curve.p > MAX_COUNTED_PRIME) {
    throw new RangeError(`Counting and listing points takes p up to ${MAX_COUNTED_PRIME}`);
  }
  return Number(curve.p);
}

/**
 * Map every square mod p to its smaller root, in Number arithmetic.
 * @param p - A prime up to the counting limit
 * @returns {Int32Array} The root of each residue, -1 where there is none
 */
function squareRoots(p: number): Int32Array {
  const roots = new Int32Array(p).fill(-1);
  for (let y = (p - 1) / 2; y >= 0; y -= 1) roots[(y * y) % p] = y;
  return roots;
}

/**
 * Walk x from 0 to p minus 1 and hand each x with a point to the visitor, until it answers true.
 * @param curve - A checked curve
 * @param visit - Takes x and the smaller y above it, and answers true to stop
 */
function walkPoints(
  curve: Readonly<WeierstrassCurve>,
  visit: (x: number, y: number, p: number) => boolean,
): void {
  const p = countedPrime(curve);
  const a = Number(curve.a);
  const b = Number(curve.b);
  const roots = squareRoots(p);
  for (let x = 0; x < p; x += 1) {
    const y = roots[(((((x * x) % p) * x) % p) + ((a * x) % p) + b) % p] ?? -1;
    if (y >= 0 && visit(x, y, p)) return;
  }
}

/**
 * Count the points of the curve, the point at infinity included, which is the group order.
 * @param curve - From `defineCurve`, or parameters it accepts
 * @returns {bigint} The number of points
 * @throws {RangeError} When p is above `MAX_COUNTED_PRIME`
 */
export function countPoints(curve: Readonly<WeierstrassCurve>): bigint {
  let count = 1;
  walkPoints(checkedCurve(curve), (_x, y) => {
    count += y === 0 ? 1 : 2;
    return false;
  });
  return BigInt(count);
}

/**
 * Build the check for points of exactly one order, refusing what the walk cannot afford.
 * @param curve - A checked curve
 * @param order - The order asked for, or undefined for every point
 * @returns {(point: Readonly<AffinePoint>) => boolean} True for a point to keep
 */
function orderFilter(
  curve: Readonly<WeierstrassCurve>,
  order: bigint | undefined,
): (point: Readonly<AffinePoint>) => boolean {
  if (order === undefined) return () => true;
  if (typeof order !== "bigint" || order < 1n) {
    throw new RangeError("The order must be a bigint of 1 or more");
  }
  if (curve.p > MAX_FILTERED_PRIME) {
    throw new RangeError(`Listing the points of one order takes p up to ${MAX_FILTERED_PRIME}`);
  }
  if (countPoints(curve) % order !== 0n) return () => false;
  const primes = primeFactors(order);
  return (point) =>
    multiply(curve, point, order) === null &&
    primes.every((prime) => multiply(curve, point, order / prime) !== null);
}

/**
 * Read the most points a listing returns.
 * @param limit - An integer of 1 or more, or undefined for no limit
 * @returns {number} The limit, Infinity when there is none
 */
function pointLimit(limit: number | undefined): number {
  if (limit === undefined) return Number.POSITIVE_INFINITY;
  if (!Number.isInteger(limit) || limit < 1) {
    throw new RangeError("The limit must be an integer of 1 or more");
  }
  return limit;
}

/**
 * List the points of the curve by x, then y, without the point at infinity.
 * @param curve - From `defineCurve`, or parameters it accepts
 * @param options - `order` keeps only the points of exactly that order
 * @returns {AffinePoint[]} The points
 * @throws {RangeError} When p passes its listing limit, or the order or the limit is below 1
 */
export function listPoints(
  curve: Readonly<WeierstrassCurve>,
  options: ListPointsOptions = {},
): AffinePoint[] {
  const checkedOne = checkedCurve(curve);
  const keep = orderFilter(checkedOne, options.order);
  const limit = pointLimit(options.limit);
  const points: AffinePoint[] = [];
  walkPoints(checkedOne, (x, y, p) => {
    for (const one of y === 0 ? [y] : [y, p - y]) {
      const point = { x: BigInt(x), y: BigInt(one) };
      if (keep(point)) points.push(point);
      if (points.length >= limit) return true;
    }
    return false;
  });
  return points;
}

/**
 * Key a point for the baby step table.
 * @param point - A point or null for infinity
 * @returns {string} A key two points share only when they are equal
 */
function key(point: Readonly<CurvePoint>): string {
  return point === null ? "infinity" : `${point.x},${point.y}`;
}

/**
 * Tabulate i times the point for i from 0 to steps minus 1, keeping the first i of each point.
 * @param curve - A checked curve
 * @param point - A point of the curve
 * @param steps - How many baby steps
 * @returns {Map<string, bigint>} i by point
 */
function babySteps(
  curve: Readonly<WeierstrassCurve>,
  point: Readonly<CurvePoint>,
  steps: bigint,
): Map<string, bigint> {
  const table = new Map<string, bigint>();
  let current: CurvePoint = null;
  for (let index = 0n; index < steps; index += 1n) {
    const name = key(current);
    if (!table.has(name)) table.set(name, index);
    current = add(curve, current, point);
  }
  return table;
}

/**
 * Find the smallest j from 0 to steps^2 minus 1 with target equal to j times the point.
 * @param curve - A checked curve
 * @param point - A point of the curve
 * @param target - A point of the curve
 * @param steps - Baby steps, and as many giant steps
 * @returns {bigint | undefined} j, or undefined when no j in range gives the target
 */
function stepSearch(
  curve: Readonly<WeierstrassCurve>,
  point: Readonly<CurvePoint>,
  target: Readonly<CurvePoint>,
  steps: bigint,
): bigint | undefined {
  const table = babySteps(curve, point, steps);
  const giant = negate(curve, multiply(curve, point, steps));
  let current = target;
  for (let round = 0n; round < steps; round += 1n) {
    const index = table.get(key(current));
    if (index !== undefined) return round * steps + index;
    current = add(curve, current, giant);
  }
  return undefined;
}

/**
 * Find the order of a point: the smallest n above 0 with n times the point at infinity.
 * @param curve - From `defineCurve`, or parameters it accepts
 * @param point - A point of the curve, or null for infinity, whose order is 1
 * @returns {bigint} The order
 * @throws {RangeError} When the point is not on the curve, or p is above `MAX_ORDER_PRIME`
 */
export function pointOrder(curve: Readonly<WeierstrassCurve>, point: Readonly<CurvePoint>): bigint {
  const checkedOne = checkedCurve(curve);
  onCurve(checkedOne, point);
  if (checkedOne.p > MAX_ORDER_PRIME) {
    throw new RangeError(`The order of a point takes p up to ${MAX_ORDER_PRIME}`);
  }
  if (point === null) return 1n;
  const bound = squareRoot(4n * checkedOne.p);
  const low = checkedOne.p + 1n - bound;
  const lowPoint = multiply(checkedOne, point, low);
  const offset = stepSearch(
    checkedOne,
    point,
    negate(checkedOne, lowPoint),
    squareRoot(2n * bound) + 1n,
  );
  if (offset === undefined) throw new Error("No multiple of the point inside the Hasse interval");
  let order = low + offset;
  for (const prime of primeFactors(order)) {
    while (order % prime === 0n && multiply(checkedOne, point, order / prime) === null) {
      order /= prime;
    }
  }
  return order;
}

/**
 * Find k with k times the base equal to the target, by baby step giant step.
 * @param curve - From `defineCurve`, or parameters it accepts
 * @param base - A point of the curve
 * @param target - A point of the curve
 * @returns {bigint | undefined} The smallest k below the order of the base, or undefined
 * @throws {RangeError} When a point is off the curve, or the base has order above `MAX_LOG_ORDER`
 */
export function discreteLog(
  curve: Readonly<WeierstrassCurve>,
  base: Readonly<CurvePoint>,
  target: Readonly<CurvePoint>,
): bigint | undefined {
  const checkedOne = checkedCurve(curve);
  onCurve(checkedOne, target, "The target");
  const order = pointOrder(checkedOne, onCurve(checkedOne, base, "The base"));
  if (order > MAX_LOG_ORDER) {
    throw new RangeError(`The base has order ${order}, above the ${MAX_LOG_ORDER} a search takes`);
  }
  return stepSearch(checkedOne, base, target, squareRoot(order - 1n) + 1n);
}
