import { describe, expect, it } from "vite-plus/test";
import { blake256 } from "@noble/hashes/blake1.js";
import { concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { base58 } from "@scure/base";
import { decodeWIF, encodeWIF } from "../../src/index.ts";
import { encodeBase58Check } from "../../src/utils/encoding.ts";
import { wifTestVectors } from "../fixtures.ts";

const keyOne = "00".repeat(31) + "01";
const order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const bitcoin = { chain: "bitcoin" } as const;
const decred = { chain: "decred" } as const;

/* Build malformed Decred payloads with a valid native checksum. */
function decredWIF(hex: string): string {
  const payload = hexToBytes(hex);
  return base58.encode(concatBytes(payload, blake256(payload).slice(0, 4)));
}

describe("WIF", () => {
  it.each(wifTestVectors)("matches $chain $network vector $wif", (vector) => {
    expect(encodeWIF(vector.privateKey, vector)).toBe(vector.wif);
    expect(decodeWIF(vector.wif, vector)).toEqual({
      privateKey: vector.privateKey,
      chain: vector.chain,
      network: vector.network,
      compressed: vector.compressed,
    });
  });

  it.each(["bitcoin", "litecoin", "decred"] as const)(
    "defaults to compressed mainnet for %s and preserves leading zeros",
    (chain) => {
      expect(decodeWIF(encodeWIF(keyOne, { chain }), { chain })).toEqual({
        privateKey: keyOne,
        chain,
        network: "mainnet",
        compressed: true,
      });
      expect(
        decodeWIF(encodeWIF(keyOne, { chain, network: "testnet" }), { chain, network: "testnet" }),
      ).toEqual({
        privateKey: keyOne,
        chain,
        network: "testnet",
        compressed: true,
      });
    },
  );

  it("enforces chain/network while acknowledging shared testnet prefixes", () => {
    const wif = encodeWIF(keyOne, { chain: "litecoin" });
    expect(() => decodeWIF(wif, bitcoin)).toThrow("expected chain/network");
    for (const chain of ["bitcoin", "litecoin", "decred"] as const) {
      const testnet = encodeWIF(keyOne, { chain, network: "testnet" });
      expect(() => decodeWIF(testnet, { chain })).toThrow("expected chain/network");
    }
    const shared = encodeWIF(keyOne, { chain: "bitcoin", network: "testnet" });
    expect(shared).toBe(encodeWIF(keyOne, { chain: "litecoin", network: "testnet" }));
    expect(decodeWIF(shared, { chain: "litecoin", network: "testnet" }).chain).toBe("litecoin");
    expect(() => decodeWIF(wif, decred)).toThrow();
    expect(() => decodeWIF(encodeWIF(keyOne, decred), bitcoin)).toThrow();
  });

  it.each(["00".repeat(32), order, "ff".repeat(32)])("rejects invalid scalar %s", (key) => {
    for (const chain of ["bitcoin", "litecoin", "decred"] as const) {
      expect(() => encodeWIF(key, { chain })).toThrow("Invalid WIF private key scalar");
    }
    for (const suffix of ["", "01"]) {
      expect(() => decodeWIF(encodeBase58Check(hexToBytes("80" + key + suffix)), bitcoin)).toThrow(
        "Invalid WIF private key scalar",
      );
      expect(() =>
        decodeWIF(encodeBase58Check(hexToBytes("b0" + key + suffix)), { chain: "litecoin" }),
      ).toThrow("Invalid WIF private key scalar");
    }
    expect(() => decodeWIF(decredWIF("22de00" + key), decred)).toThrow(
      "Invalid WIF private key scalar",
    );
  });

  it.each([
    "",
    "01",
    "00".repeat(31),
    "00".repeat(33),
    "0x" + keyOne,
    "g".repeat(64),
    keyOne + "\n",
  ])("rejects malformed hex without echoing it", (key) => {
    expect(() => encodeWIF(key, bitcoin)).toThrow(
      "WIF private key must be 32 bytes of hex without a prefix",
    );
  });

  it("rejects malformed Bitcoin payloads with valid checksums", () => {
    for (const length of [31, 35]) {
      const payload = new Uint8Array(length);
      payload[0] = 128;
      expect(() => decodeWIF(encodeBase58Check(payload), bitcoin)).toThrow(
        "Invalid WIF payload length",
      );
    }
    for (const flag of ["00", "02", "ff"]) {
      expect(() => decodeWIF(encodeBase58Check(hexToBytes("80" + keyOne + flag)), bitcoin)).toThrow(
        "Invalid WIF compression flag",
      );
    }
  });

  it("rejects unsupported Decred schemes and uncompressed exports", () => {
    for (const scheme of ["01", "02", "ff"]) {
      expect(() => decodeWIF(decredWIF("22de" + scheme + keyOne), decred)).toThrow(
        "Decred WIF supports ECDSA secp256k1 only",
      );
    }
    expect(() => encodeWIF(keyOne, { chain: "decred", compressed: false })).toThrow(
      "Decred WIF requires a compressed public key",
    );
    expect(() => decodeWIF(decredWIF("22de00" + keyOne + "01"), decred)).toThrow();
    expect(() => decodeWIF(encodeBase58Check(hexToBytes("22de00" + keyOne)), decred)).toThrow(
      "Invalid WIF encoding or checksum",
    );
  });

  it.each(["bitcoin", "litecoin", "decred"] as const)("rejects corrupted %s WIF", (chain) => {
    const wif = encodeWIF(keyOne, { chain });
    const last = wif.endsWith("1") ? "2" : "1";
    for (const input of [wif.slice(0, -1) + last, " " + wif, wif + "\n", "0".repeat(51)]) {
      expect(() => decodeWIF(input, { chain })).toThrow("Invalid WIF encoding or checksum");
    }
    expect(() => decodeWIF("1".repeat(100_000), { chain })).toThrow("Invalid WIF length");
    expect(() => decodeWIF("", { chain })).toThrow("Invalid WIF length");
  });

  it("rejects unsupported chains, networks and JavaScript inputs without coercion", () => {
    for (const chain of [
      "ethereum",
      "base",
      "solana",
      "aptos",
      "sui",
      "cardano",
      "tron",
      "toString",
      "__proto__",
    ]) {
      /* @ts-expect-error Deliberately unsupported chain. */
      expect(() => encodeWIF(keyOne, { chain })).toThrow("Unsupported WIF chain");
      /* @ts-expect-error Deliberately unsupported chain. */
      expect(() => decodeWIF("invalid", { chain })).toThrow("Unsupported WIF chain");
    }
    /* @ts-expect-error Deliberately invalid JavaScript input. */
    expect(() => encodeWIF(keyOne, { chain: "bitcoin", compressed: "false" })).toThrow(
      "WIF compressed",
    );
    /* @ts-expect-error Deliberately unsupported network. */
    expect(() => decodeWIF("invalid", { chain: "bitcoin", network: "regtest" })).toThrow(
      "Unsupported WIF network",
    );
    /* @ts-expect-error Deliberately invalid JavaScript input. */
    expect(() => encodeWIF(123, bitcoin)).toThrow("WIF private key");
    /* @ts-expect-error Deliberately invalid JavaScript input. */
    expect(() => decodeWIF(123, bitcoin)).toThrow("Invalid WIF length");
  });
});
