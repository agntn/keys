import { describe, expect, it } from "vite-plus/test";
import { convertSecp256k1PublicKey } from "../../src/index.ts";
import { publicKeyEncodingVector } from "../fixtures.ts";

describe("convertSecp256k1PublicKey", () => {
  it("converts the SEC 2 generator in both directions without a private key", () => {
    const { compressed, uncompressed } = publicKeyEncodingVector;
    expect(convertSecp256k1PublicKey(uncompressed)).toBe(compressed);
    expect(convertSecp256k1PublicKey(compressed, { compressed: false })).toBe(uncompressed);
    expect(convertSecp256k1PublicKey(compressed)).toBe(compressed);
    expect(convertSecp256k1PublicKey(uncompressed.toUpperCase(), { compressed: false })).toBe(
      uncompressed,
    );
  });

  it("preserves the odd y coordinate instead of silently choosing the even point", () => {
    const x = publicKeyEncodingVector.compressed.slice(2);
    const field = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
    const oddY = (field - BigInt("0x" + publicKeyEncodingVector.uncompressed.slice(66)))
      .toString(16)
      .padStart(64, "0");
    expect(convertSecp256k1PublicKey("03" + x, { compressed: false })).toBe("04" + x + oddY);
    expect(convertSecp256k1PublicKey("04" + x + oddY)).toBe("03" + x);
  });

  it("rejects a non-boolean output encoding at the library boundary", () => {
    expect(() =>
      /** @ts-expect-error Exercise callers that bypass TypeScript. */
      convertSecp256k1PublicKey(publicKeyEncodingVector.compressed, { compressed: "false" }),
    ).toThrow("Compressed must be a boolean");
  });

  it.each([
    "",
    "00",
    "00".repeat(32),
    "02" + "ff".repeat(32),
    "04" + "00".repeat(64),
    "06" + publicKeyEncodingVector.uncompressed.slice(2),
    "0x" + publicKeyEncodingVector.compressed,
    publicKeyEncodingVector.compressed + "\n",
    publicKeyEncodingVector.compressed.slice(0, -1) + "z",
  ])("rejects malformed, hybrid, x-only and off-curve inputs: %s", (key) => {
    expect(() => convertSecp256k1PublicKey(key)).toThrow("Invalid SEC1 secp256k1 public key");
  });
});
