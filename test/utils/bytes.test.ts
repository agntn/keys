import { describe, expect, it } from "vite-plus/test";
import { hex } from "@agntn/encodings/hex";
import {
  bytesToNumberBE,
  bytesToNumberLE,
  equalBytes,
  numberToBytesBE,
  randomBytes,
} from "../../src/utils/bytes.ts";

describe("equalBytes", () => {
  it("accepts the same bytes, empty arrays included", () => {
    expect(equalBytes(hex.decode("00ff10"), hex.decode("00ff10"))).toBe(true);
    expect(equalBytes(new Uint8Array(), new Uint8Array())).toBe(true);
  });

  it.each([
    ["the first byte", "01ff10"],
    ["the last byte", "00ff11"],
    ["a prefix", "00ff"],
    ["a longer array", "00ff1000"],
  ])("refuses a difference in %s", (_, other) => {
    expect(equalBytes(hex.decode("00ff10"), hex.decode(other))).toBe(false);
  });
});

describe("byte and number conversion", () => {
  it("reads both byte orders", () => {
    expect(bytesToNumberBE(hex.decode("0102ff"))).toBe(0x0102ffn);
    expect(bytesToNumberLE(hex.decode("0102ff"))).toBe(0xff0201n);
  });

  it("reads no bytes as zero and keeps leading zeros harmless", () => {
    expect(bytesToNumberBE(new Uint8Array())).toBe(0n);
    expect(bytesToNumberLE(new Uint8Array())).toBe(0n);
    expect(bytesToNumberBE(hex.decode("000001"))).toBe(1n);
  });

  it("leaves the input of a little endian read alone", () => {
    const bytes = hex.decode("0102");
    bytesToNumberLE(bytes);
    expect(hex.encode(bytes)).toBe("0102");
  });

  it("pads a number to the asked length", () => {
    expect(hex.encode(numberToBytesBE(0x1ffn, 4))).toBe("000001ff");
    expect(hex.encode(numberToBytesBE(0n, 2))).toBe("0000");
    expect(hex.encode(numberToBytesBE(0xffffn, 2))).toBe("ffff");
  });

  it("refuses a number that does not fit, and a negative one", () => {
    expect(() => numberToBytesBE(0x10000n, 2)).toThrow(RangeError);
    expect(() => numberToBytesBE(-1n, 2)).toThrow(RangeError);
  });
});

describe("randomBytes", () => {
  it("draws the asked length, fresh each time", () => {
    const first = randomBytes(32);
    expect(first).toHaveLength(32);
    expect(hex.encode(randomBytes(32))).not.toBe(hex.encode(first));
    expect(randomBytes(0)).toHaveLength(0);
  });
});
