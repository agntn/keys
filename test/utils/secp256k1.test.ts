import { describe, expect, it } from "vite-plus/test";
import { generateKeyPublic } from "../../src/utils/secp256k1/keys.ts";
import { blockchains } from "../../src/_blockchains.ts";
import { secp256k1TestVectors } from "../fixtures.ts";

describe("secp256k1 utilities", () => {
  const validPrivateKey = "1111111111111111111111111111111111111111111111111111111111111111";

  describe("generateKeyPublic", () => {
    it("should generate a compressed public key by default", () => {
      const publicKey = generateKeyPublic(validPrivateKey);

      // Compressed public key should be 33 bytes (66 hex chars)
      expect(publicKey.length).toBe(66);

      // Compressed keys start with 02 or 03
      expect(publicKey.startsWith("02") || publicKey.startsWith("03")).toBe(true);
    });

    it("should generate an uncompressed public key when specified", () => {
      const publicKey = generateKeyPublic(validPrivateKey, { compressed: false });

      // Uncompressed public key should be 65 bytes (130 hex chars)
      expect(publicKey.length).toBe(130);

      // Uncompressed keys start with 04
      expect(publicKey.startsWith("04")).toBe(true);
    });

    it("should generate deterministic public keys", () => {
      const publicKey1 = generateKeyPublic(validPrivateKey);
      const publicKey2 = generateKeyPublic(validPrivateKey);

      expect(publicKey1).toBe(publicKey2);
    });

    it("should throw an error for invalid private keys", () => {
      // Private key too short
      expect(() => generateKeyPublic("abcdef")).toThrow();

      // Private key with invalid characters
      expect(() => generateKeyPublic("Z".padEnd(64, "0"))).toThrow();
    });
  });
});

describe("secp256k1 key errors on every chain", () => {
  const { curveOrder } = secp256k1TestVectors;
  const privateKeyError =
    "secp256k1 private key must be 32 bytes of hex, above zero and below the curve order";
  const publicKeyError = "Invalid SEC1 secp256k1 public key";

  it.each(Object.entries(blockchains).map(([name, load]) => [name, load] as const))(
    "%s names the key it cannot use",
    async (_name, load) => {
      const chain = await load()();
      if (chain.curve !== "secp256k1") return;
      for (const keyPrivate of ["00".repeat(32), curveOrder, "abcdef"]) {
        expect(() => chain.getKeyPublic(keyPrivate)).toThrow(privateKeyError);
        expect(() => chain.signMessage("hello", keyPrivate)).toThrow(privateKeyError);
      }
      for (const keyPublic of [`02${"00".repeat(32)}`, `04${"00".repeat(64)}`, "zz"]) {
        expect(() => chain.getAddress(keyPublic)).toThrow(publicKeyError);
      }
    },
  );

  it("names the key on Sui's secp256k1 scheme", async () => {
    const chain = await blockchains.sui()();
    expect(() => chain.getKeyPublic(curveOrder, { scheme: "secp256k1" })).toThrow(privateKeyError);
    expect(() => chain.signMessage("hello", curveOrder, { scheme: "secp256k1" })).toThrow(
      privateKeyError,
    );
  });
});
