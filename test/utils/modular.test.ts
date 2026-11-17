import { describe, expect, it } from "vite-plus/test";
import { invert, pow } from "../../src/utils/modular.ts";

/* The secp256k1 field prime, big enough to leave the native `**` behind. */
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

describe("pow", () => {
  it("agrees with native exponentiation on small numbers", () => {
    for (const [base, exponent, modulus] of [
      [2n, 10n, 1000n],
      [7n, 0n, 13n],
      [7n, 1n, 13n],
      [0n, 5n, 13n],
      [12345n, 67n, 89n],
    ] as const) {
      expect(pow(base, exponent, modulus)).toBe(base ** exponent % modulus);
    }
  });

  it("holds Fermat's little theorem on a 256-bit prime", () => {
    expect(pow(2n, P - 1n, P)).toBe(1n);
    expect(pow(P - 1n, 2n, P)).toBe(1n);
  });

  it("reduces a negative base into the ring", () => {
    expect(pow(-2n, 3n, 13n)).toBe(5n);
  });

  it("refuses a modulus of 1 or less and a negative exponent", () => {
    expect(() => pow(2n, 2n, 1n)).toThrow(RangeError);
    expect(() => pow(2n, 2n, 0n)).toThrow(RangeError);
    expect(() => pow(2n, -1n, 13n)).toThrow(RangeError);
  });
});

describe("invert", () => {
  it("finds the inverse", () => {
    expect(invert(3n, 7n)).toBe(5n);
    expect(invert(-3n, 7n)).toBe(2n);
    expect(invert(10n, 7n)).toBe(5n);
  });

  it("agrees with Fermat on a 256-bit prime", () => {
    const value = 0x1234567890abcdef1234567890abcdefn;
    const inverse = invert(value, P);
    expect(inverse).toBe(pow(value, P - 2n, P));
    expect((value * inverse) % P).toBe(1n);
  });

  it("refuses zero, a shared factor and a modulus of 1 or less", () => {
    expect(() => invert(0n, 7n)).toThrow(RangeError);
    expect(() => invert(4n, 8n)).toThrow(RangeError);
    expect(() => invert(3n, 1n)).toThrow(RangeError);
  });
});
