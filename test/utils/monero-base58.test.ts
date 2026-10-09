import { describe, expect, it } from "vite-plus/test";
import { hex } from "@agntn/encodings/hex";
import { decodeMoneroBase58, encodeMoneroBase58 } from "../../src/utils/monero-base58.ts";

describe("Monero block base58", () => {
  it.each([
    [1, 2],
    [5, 7],
    [8, 11],
    [9, 13],
    [69, 95],
  ])("writes %i bytes in %i characters, zeros included", (bytes, characters) => {
    const zeros = new Uint8Array(bytes);
    const text = encodeMoneroBase58(zeros);
    expect(text).toBe("1".repeat(characters));
    expect(decodeMoneroBase58(text)).toEqual(zeros);
  });

  it("round trips a full block of ones", () => {
    const bytes = hex.decode("ffffffffffffffff");
    expect(encodeMoneroBase58(bytes)).toBe("jpXCZedGfVQ");
    expect(decodeMoneroBase58("jpXCZedGfVQ")).toEqual(bytes);
  });

  it("refuses a block that overflows its bytes", () => {
    expect(() => decodeMoneroBase58("jpXCZedGfVR")).toThrow("overflows");
    expect(() => decodeMoneroBase58("zz")).toThrow("overflows");
  });

  it("refuses a last block no byte count writes", () => {
    expect(() => decodeMoneroBase58("1111")).toThrow("no block of this length");
    expect(() => decodeMoneroBase58("1")).toThrow("no block of this length");
  });
});
