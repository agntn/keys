import { describe, expect, it } from "vitest";
import {
  parseDecimalKey,
  parseHexKey,
  SECP256K1_ORDER,
  stepKey,
} from "../docs/app/utils/parse-key";

describe("keyspace parse-key", () => {
  it("pads hex 1 to 32 bytes", () => {
    expect(parseHexKey("1")).toEqual({
      hex: "1".padStart(64, "0"),
      decimal: 1n,
    });
  });

  it("accepts a 0x prefix", () => {
    expect(parseHexKey("0x02")).toEqual({
      hex: "2".padStart(64, "0"),
      decimal: 2n,
    });
  });

  it("rejects 0", () => {
    expect(parseDecimalKey("0")).toEqual({ error: "Private key must be at least 1." });
  });

  it("rejects the secp256k1 group order", () => {
    expect(parseDecimalKey(SECP256K1_ORDER.toString())).toEqual({
      error: "Private key must be less than the secp256k1 group order n.",
    });
  });

  it("wraps next after n - 1 back to 1", () => {
    expect(stepKey(SECP256K1_ORDER - 1n, 1n).decimal).toBe(1n);
  });

  it("wraps previous before 1 to n - 1", () => {
    expect(stepKey(1n, -1n).decimal).toBe(SECP256K1_ORDER - 1n);
  });
});
