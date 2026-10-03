import { describe, expect, it } from "vite-plus/test";
import {
  addPoints,
  countPoints,
  defineCurve,
  discreteLog,
  doublePoint,
  isOnCurve,
  listPoints,
  multiplyPoint,
  negatePoint,
  pointOrder,
  MAX_COUNTED_PRIME,
  MAX_FILTERED_PRIME,
  MAX_ORDER_PRIME,
  type AffinePoint,
  type CurvePoint,
} from "../../src/utils/curve/index.ts";
import { curveVectors } from "../fixtures.ts";

const { paar, f23, secp256k1 } = curveVectors;
const paarCurve = defineCurve(paar);
const f23Curve = defineCurve(f23);
const paarMultiples: AffinePoint[] = paar.multiples.map(([x, y]) => ({ x, y }));
const [base] = paarMultiples;
if (base === undefined) throw new Error("Missing the Paar base point");

/* Every point of a small curve, found by trying each x and y, as an oracle for the walk. */
function bruteForcePoints(a: bigint, b: bigint, p: bigint): AffinePoint[] {
  const points: AffinePoint[] = [];
  for (let x = 0n; x < p; x += 1n) {
    for (let y = 0n; y < p; y += 1n) {
      if ((((y * y - x * x * x - a * x - b) % p) + p) % p === 0n) points.push({ x, y });
    }
  }
  return points;
}

/* The order of a point by adding it to itself until infinity. */
function bruteForceOrder(curve: ReturnType<typeof defineCurve>, point: AffinePoint): bigint {
  let order = 1n;
  let current: CurvePoint = point;
  while (current !== null) {
    current = addPoints(curve, current, point);
    order += 1n;
  }
  return order;
}

describe("Curve definition", () => {
  it("reduces a and b mod p, so a = -3 is p - 3", () => {
    expect(defineCurve({ a: -3n, b: 20n, p: 17n })).toEqual({ a: 14n, b: 3n, p: 17n });
  });

  it("refuses a field that is not a prime above 3, and a singular curve", () => {
    for (const p of [15n, 3n, 2n, 1n, 0n, -17n]) {
      expect(() => defineCurve({ a: 2n, b: 2n, p })).toThrow("p must be a prime above 3");
    }
    expect(() => defineCurve({ a: 0n, b: 0n, p: 17n })).toThrow("singular");
    expect(() => defineCurve({ a: -3n, b: 2n, p: 17n })).toThrow("singular");
  });

  it("checks plain parameters too, not only curves from defineCurve", () => {
    expect(() => addPoints({ a: 2n, b: 2n, p: 21n }, base, base)).toThrow("p must be a prime");
    expect(addPoints({ a: 2n, b: 2n, p: 17n }, base, base)).toEqual(paarMultiples[1]);
  });
});

describe("Curve arithmetic", () => {
  it("walks the multiples of (5, 1) in the Paar textbook curve", () => {
    for (const [index, expected] of paarMultiples.entries()) {
      expect(multiplyPoint(paarCurve, base, BigInt(index + 1))).toEqual(expected);
    }
    expect(multiplyPoint(paarCurve, base, paar.order)).toBeNull();
    expect(doublePoint(paarCurve, base)).toEqual({ x: 6n, y: 3n });
    expect(addPoints(paarCurve, base, { x: 6n, y: 3n })).toEqual({ x: 10n, y: 6n });
  });

  it("negates, multiplies by zero and by negative scalars", () => {
    expect(negatePoint(paarCurve, base)).toEqual({ x: 5n, y: 16n });
    expect(addPoints(paarCurve, base, { x: 5n, y: 16n })).toBeNull();
    expect(multiplyPoint(paarCurve, base, 0n)).toBeNull();
    expect(multiplyPoint(paarCurve, base, -2n)).toEqual({ x: 6n, y: 14n });
    expect(addPoints(paarCurve, null, base)).toEqual(base);
    expect(negatePoint(paarCurve, null)).toBeNull();
  });

  it("doubles a point with y = 0 to infinity", () => {
    expect(doublePoint(f23Curve, f23.orderTwo)).toBeNull();
  });

  it("computes 3G on secp256k1 given as plain parameters", () => {
    const curve = defineCurve(secp256k1);
    expect(multiplyPoint(curve, secp256k1.g, 3n)).toEqual(secp256k1.threeG);
    expect(addPoints(curve, doublePoint(curve, secp256k1.g), secp256k1.g)).toEqual(
      secp256k1.threeG,
    );
  });

  it("checks points against the curve and refuses arithmetic on one off it", () => {
    expect(isOnCurve(paarCurve, base)).toBe(true);
    expect(isOnCurve(paarCurve, null)).toBe(true);
    for (const point of [
      { x: 5n, y: 2n },
      { x: 22n, y: 1n },
      { x: -12n, y: 1n },
    ]) {
      expect(isOnCurve(paarCurve, point)).toBe(false);
      expect(() => doublePoint(paarCurve, point)).toThrow("not on the curve");
    }
    expect(() => addPoints(paarCurve, base, { x: 5n, y: 2n })).toThrow("right is not on the curve");
  });
});

describe("Curve group", () => {
  it("counts and lists the points of small curves the same way trying every pair does", () => {
    for (const [a, b, p] of [
      [2n, 2n, 17n],
      [1n, 1n, 23n],
      [0n, 7n, 97n],
      [-3n, 5n, 101n],
    ] as const) {
      const curve = defineCurve({ a, b, p });
      const expected = bruteForcePoints(curve.a, curve.b, p);
      expect(listPoints(curve)).toEqual(expected);
      expect(countPoints(curve)).toBe(BigInt(expected.length + 1));
    }
    expect(countPoints(paarCurve)).toBe(paar.order);
    expect(countPoints(f23Curve)).toBe(f23.count);
    expect(listPoints(f23Curve, { limit: 3 })).toEqual(listPoints(f23Curve).slice(0, 3));
    expect(listPoints(f23Curve, { order: 7n, limit: 1 })).toEqual([{ x: 5n, y: 4n }]);
    for (const limit of [0, 1.5, Number.NaN]) {
      expect(() => listPoints(f23Curve, { limit })).toThrow("The limit must be an integer");
    }
  });

  it("finds the order of every point, as adding one at a time does", () => {
    for (const curve of [paarCurve, f23Curve, defineCurve({ a: -3n, b: 5n, p: 101n })]) {
      for (const point of listPoints(curve)) {
        expect(pointOrder(curve, point)).toBe(bruteForceOrder(curve, point));
      }
    }
    expect(pointOrder(f23Curve, f23.orderTwo)).toBe(2n);
    expect(pointOrder(paarCurve, null)).toBe(1n);
  });

  it("lists the points of one order", () => {
    expect(listPoints(f23Curve, { order: 7n })).toEqual(f23.orderSeven.map(([x, y]) => ({ x, y })));
    expect(listPoints(f23Curve, { order: 2n })).toEqual([f23.orderTwo]);
    const orderFourteen = listPoints(f23Curve, { order: 14n });
    expect(orderFourteen).toHaveLength(6);
    for (const point of orderFourteen) expect(pointOrder(f23Curve, point)).toBe(14n);
    expect(listPoints(f23Curve, { order: 1n })).toEqual([]);
    expect(listPoints(f23Curve, { order: 5n })).toEqual([]);
    expect(listPoints(f23Curve, { order: 2n ** 80n })).toEqual([]);
    expect(listPoints(paarCurve, { order: 19n })).toHaveLength(18);
  });

  it("finds discrete logs, the smallest k, and answers undefined outside the subgroup", () => {
    for (const [index, target] of paarMultiples.entries()) {
      expect(discreteLog(paarCurve, base, target)).toBe(BigInt(index + 1));
    }
    expect(discreteLog(paarCurve, base, null)).toBe(0n);
    const [orderSeven] = f23.orderSeven;
    if (orderSeven === undefined) throw new Error("Missing a point of order 7");
    const generator = { x: orderSeven[0], y: orderSeven[1] };
    expect(discreteLog(f23Curve, generator, f23.orderTwo)).toBeUndefined();
    expect(discreteLog(f23Curve, generator, multiplyPoint(f23Curve, generator, 5n))).toBe(5n);
  });

  it("finds an order over a 40-bit field and a log over a 32-bit one", () => {
    const wide = defineCurve({ a: 2n, b: 3n, p: 1099511627563n });
    const point = { x: 1n, y: 727918651225n };
    const order = pointOrder(wide, point);
    expect(order).toBe(1099513053442n);
    expect(multiplyPoint(wide, point, order)).toBeNull();
    for (const prime of [2n, 103n, 2917n, 1829771n]) {
      expect(order % prime).toBe(0n);
      expect(multiplyPoint(wide, point, order / prime)).not.toBeNull();
    }
    expect(() => discreteLog(wide, point, point)).toThrow("above the");
    const narrow = defineCurve({ a: 2n, b: 3n, p: 4294967291n });
    const generator = { x: 2n, y: 1005604009n };
    const scalar = 1234567890n;
    expect(discreteLog(narrow, generator, multiplyPoint(narrow, generator, scalar))).toBe(scalar);
  });

  it("refuses fields and orders past the limits instead of running for ever", () => {
    const large = defineCurve({ a: 2n, b: 3n, p: 1048583n });
    expect(large.p > MAX_COUNTED_PRIME).toBe(true);
    expect(() => countPoints(large)).toThrow(`takes p up to ${MAX_COUNTED_PRIME}`);
    const filtered = defineCurve({ a: 2n, b: 3n, p: 65537n });
    expect(filtered.p > MAX_FILTERED_PRIME).toBe(true);
    expect(() => listPoints(filtered, { order: 2n })).toThrow(
      `takes p up to ${MAX_FILTERED_PRIME}`,
    );
    const curve = defineCurve(secp256k1);
    expect(curve.p > MAX_ORDER_PRIME).toBe(true);
    expect(() => pointOrder(curve, secp256k1.g)).toThrow(`takes p up to ${MAX_ORDER_PRIME}`);
    expect(() => discreteLog(curve, secp256k1.g, secp256k1.threeG)).toThrow(
      `takes p up to ${MAX_ORDER_PRIME}`,
    );
    expect(() => listPoints(paarCurve, { order: 0n })).toThrow("1 or more");
  });
});
