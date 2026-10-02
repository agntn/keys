import { describe, expect, it } from "vite-plus/test";
import {
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
} from "../../src/utils/secp256k1/index.ts";
import { publicKeyEncodingVector, secp256k1MathVectors } from "../fixtures.ts";

const { g, minusG, twoG, threeG, threeGUncompressed, orderMinusOne, inverseOfTwo, xWithoutPoint } =
  secp256k1MathVectors;
const infinity = "The result is the point at infinity";
const invalidPoint = "Invalid SEC1 secp256k1 public key";

describe("secp256k1 point math", () => {
  it("adds, subtracts and negates points", () => {
    expect(addPoints(g, g)).toBe(twoG);
    expect(subtractPoints(threeG, g)).toBe(twoG);
    expect(addPoints(publicKeyEncodingVector.uncompressed, twoG, { compressed: false })).toBe(
      threeGUncompressed,
    );
    expect(negatePoint(g)).toBe(minusG);
    expect(addPoints(twoG, minusG)).toBe(g);
  });

  it("multiplies a point and the generator by a scalar", () => {
    expect(multiplyPoint(g, "3")).toBe(threeG);
    expect(multiplyPoint(g, 3n, { compressed: false })).toBe(threeGUncompressed);
    expect(multiplyGenerator("03")).toBe(threeG);
    expect(multiplyGenerator(orderMinusOne)).toBe(minusG);
  });

  it("refuses the point at infinity instead of encoding it", () => {
    expect(() => addPoints(g, minusG)).toThrow(infinity);
    expect(() => subtractPoints(g, g)).toThrow(infinity);
  });

  it("refuses scalars outside 1 to n minus 1 and encodings that are not SEC1", () => {
    for (const scalar of ["0", 0n, "0x03", "", "f".repeat(65)]) {
      expect(() => multiplyPoint(g, scalar)).toThrow(RangeError);
    }
    const order = (BigInt(`0x${orderMinusOne}`) + 1n).toString(16);
    expect(() => multiplyGenerator(order)).toThrow("from 1 to the curve order minus 1");
    expect(() => multiplyGenerator(-1n)).toThrow(RangeError);
    for (const point of [`06${threeGUncompressed.slice(2)}`, g.slice(2), `0x${g}`]) {
      expect(() => negatePoint(point)).toThrow(invalidPoint);
    }
  });
});

describe("secp256k1 scalar math", () => {
  it("adds, subtracts, multiplies and inverts mod n", () => {
    expect(addScalars(orderMinusOne, "2")).toBe("1".padStart(64, "0"));
    expect(subtractScalars("0", 1n)).toBe(orderMinusOne);
    expect(multiplyScalars("2", inverseOfTwo)).toBe("1".padStart(64, "0"));
    expect(invertScalar(2n)).toBe(inverseOfTwo);
    expect(multiplyScalars(orderMinusOne, orderMinusOne)).toBe("1".padStart(64, "0"));
  });

  it("refuses zero as an inverse and values at or above n", () => {
    expect(() => invertScalar("0")).toThrow(RangeError);
    const order = (BigInt(`0x${orderMinusOne}`) + 1n).toString(16);
    expect(() => addScalars(order, "1")).toThrow("Scalar a must be hex");
    expect(() => subtractScalars("1", order)).toThrow("Scalar b must be hex");
  });
});

describe("secp256k1 x coordinates", () => {
  it("lifts x to both points, the even one being the BIP340 key", () => {
    expect(liftX(g.slice(2))).toEqual({ even: g, odd: minusG });
    expect(liftX(threeG.slice(2), { compressed: false }).even).toBe(threeGUncompressed);
  });

  it("refuses an x without a point and an x that is not 64 hex digits", () => {
    expect(() => liftX(xWithoutPoint)).toThrow("No point of secp256k1 has this x");
    expect(() => liftX("f".repeat(64))).toThrow("No point of secp256k1 has this x");
    expect(() => liftX(g)).toThrow("x must be 64 hex digits");
  });

  it("checks points against the curve and refuses what is not SEC1", () => {
    expect(isOnCurve(g)).toBe(true);
    expect(isOnCurve(threeGUncompressed)).toBe(true);
    const offCurve = `${threeGUncompressed.slice(0, -1)}3`;
    expect(isOnCurve(offCurve)).toBe(false);
    expect(isOnCurve(`02${xWithoutPoint}`)).toBe(false);
    expect(() => isOnCurve(g.slice(2))).toThrow(invalidPoint);
  });
});
