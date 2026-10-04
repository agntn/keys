import { hex } from "@agntn/encodings/hex";
import { describe, expect, it } from "vite-plus/test";
import { address, multisig } from "../../src/utils/script/index.ts";
import { multisigVector } from "../fixtures.ts";

const [g, double] = multisigVector.keys;
const types = ["p2sh", "p2wsh", "p2sh-p2wsh"] as const;
const uncompressedKey =
  "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235";

describe("Multisig scripts", () => {
  it("writes the 2-of-2 of G and 2G that Core decodes", () => {
    expect(hex.encode(multisig(2, [g, double]))).toBe(multisigVector.script);
  });

  it("keeps the given order unless sorted, then sorts as BIP67 does", () => {
    expect(hex.encode(multisig(2, [double, g]))).not.toBe(multisigVector.script);
    expect(hex.encode(multisig(2, [double, g], { sorted: true }))).toBe(multisigVector.script);
  });

  it("takes uncompressed keys and 20 keys, the most OP_CHECKMULTISIG counts", () => {
    const uncompressed = multisig(1, [uncompressedKey]);
    expect(uncompressed.length).toBe(1 + 66 + 1 + 1);
    const twenty = multisig(
      20,
      Array.from({ length: 20 }, () => g),
    );
    expect(hex.encode(twenty.subarray(0, 2))).toBe("0114");
    expect(hex.encode(twenty.subarray(-3))).toBe("0114ae");
  });

  it("refuses a threshold or key count out of range and a key off the curve", () => {
    expect(() => multisig(0, [g])).toThrow("threshold must be an integer from 1 to 1");
    expect(() => multisig(3, [g, double])).toThrow("threshold must be an integer from 1 to 2");
    expect(() => multisig(1.5, [g, double])).toThrow("threshold");
    expect(() => multisig(1, [])).toThrow("Multisig takes 1 to 20 keys");
    expect(() =>
      multisig(
        1,
        Array.from({ length: 21 }, () => g),
      ),
    ).toThrow("1 to 20 keys");
    expect(() => multisig(1, [`02${"00".repeat(32)}`])).toThrow("Invalid SEC1");
  });
});

describe("Script addresses", () => {
  it.each(["mainnet", "testnet"] as const)("matches Core for the 2-of-2 on %s", (network) => {
    const script = hex.decode(multisigVector.script);
    for (const type of types) {
      expect(address(script, type, { network })).toBe(multisigVector[network][type]);
    }
  });

  it("refuses a P2SH script over 520 bytes but hashes it into P2WSH", () => {
    expect(address(new Uint8Array(520).fill(0x51), "p2sh")).toMatch(/^3/u);
    const large = new Uint8Array(521).fill(0x51);
    expect(() => address(large, "p2sh")).toThrow("P2SH takes a script of at most 520 bytes");
    expect(address(large, "p2wsh")).toMatch(/^bc1q/u);
    expect(() => address(new Uint8Array(10_001), "p2sh-p2wsh")).toThrow("at most 10000 bytes");
  });

  it("refuses an empty script, an unknown type and an unknown network", () => {
    expect(() => address(new Uint8Array(), "p2wsh")).toThrow("Script must not be empty");
    /* @ts-expect-error An address type outside the union. */
    expect(() => address(Uint8Array.of(0x51), "p2tr")).toThrow("p2sh, p2wsh or p2sh-p2wsh");
    /* @ts-expect-error A network outside the union. */
    expect(() => address(Uint8Array.of(0x51), "p2sh", { network: "regtest" })).toThrow(
      "Network must be mainnet or testnet",
    );
  });
});
