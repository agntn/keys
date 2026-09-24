import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";
import { decodeCashAddr, encodeCashAddr } from "../../src/utils/cashaddr.ts";
import { bitcoinCashTestVectors } from "../fixtures.ts";

const ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

describe("CashAddr", () => {
  it.each(bitcoinCashTestVectors.spec)(
    "encodes and decodes type %i as %s",
    (type, address, hash) => {
      const prefix = address.slice(0, address.indexOf(":"));
      expect(encodeCashAddr(prefix, type, hexToBytes(hash))).toBe(address);
      const content = decodeCashAddr(address, prefix);
      expect(content?.type).toBe(type);
      expect(bytesToHex(content?.hash ?? new Uint8Array())).toBe(hash);
    },
  );

  it("reads the payload bare and in either case, never in mixed case", () => {
    const { address, publicKeyHash } = bitcoinCashTestVectors.prize;
    const payload = address.slice("bitcoincash:".length);
    for (const candidate of [payload, address.toUpperCase(), payload.toUpperCase()]) {
      expect(bytesToHex(decodeCashAddr(candidate, "bitcoincash")?.hash ?? new Uint8Array())).toBe(
        publicKeyHash,
      );
    }
    expect(decodeCashAddr(`Bitcoincash:${payload}`, "bitcoincash")).toBeUndefined();
    expect(decodeCashAddr(payload.replace("q", "Q"), "bitcoincash")).toBeUndefined();
  });

  it("rejects the checksum under another prefix and a substitution at every position", () => {
    const { address } = bitcoinCashTestVectors.prize;
    expect(decodeCashAddr(address, "bchtest")).toBeUndefined();
    expect(decodeCashAddr(address.replace("bitcoincash:", "ecash:"), "ecash")).toBeUndefined();
    const payload = address.slice("bitcoincash:".length);
    for (let index = 0; index < payload.length; index++) {
      const digit = ALPHABET.indexOf(payload[index] ?? "");
      const corrupted =
        payload.slice(0, index) + ALPHABET[(digit + 1) % 32] + payload.slice(index + 1);
      expect(decodeCashAddr(corrupted, "bitcoincash"), corrupted).toBeUndefined();
    }
  });

  it.each([
    ["no payload", "bitcoincash:"],
    ["a character outside the alphabet", "bitcoincash:qz3yjg59ypg6jqpwhaxgvjj44jm4hdx0w5wsxw2qeb"],
    ["a double prefix", `bitcoincash:${bitcoinCashTestVectors.prize.address}`],
    ["more digits than a 64-byte hash takes", `bitcoincash:${"q".repeat(113)}`],
  ])("rejects %s", (_, address) => {
    expect(decodeCashAddr(address, "bitcoincash")).toBeUndefined();
  });

  it("refuses to encode a hash length the version byte cannot express", () => {
    expect(() => encodeCashAddr("bitcoincash", 0, new Uint8Array(21))).toThrow(RangeError);
    expect(() => encodeCashAddr("bitcoincash", 16, new Uint8Array(20))).toThrow(RangeError);
  });
});
