import { describe, expect, it } from "vite-plus/test";
import { generateKeyPublic } from "../../src/utils/secp256k1";

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
