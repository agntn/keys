import { describe, expect, it } from "vitest";
import {
  hash160,
  generateAddressLegacy,
  validateAddressLegacy,
  generateAddressP2SH,
  validateAddressP2SH,
  generateAddressSegWit,
} from "../../src/utils/address";
import { secp256k1TestVectors } from "../fixtures";

describe("Address utilities", () => {
  const testPublicKey = secp256k1TestVectors.publicKeyCompressed;

  describe("hash160", () => {
    it("should hash data properly", () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const hash = hash160(data);

      // Result should be 20 bytes (RIPEMD160 output)
      expect(hash.length).toBe(20);
    });
  });

  describe("Legacy addresses (P2PKH)", () => {
    it("should generate a valid Legacy address with correct version byte", () => {
      const address = generateAddressLegacy(testPublicKey, { bytesVersion: 0x00 });

      // Should start with '1' (for Bitcoin mainnet)
      expect(address.startsWith("1")).toBe(true);
      expect(address.length).toBeGreaterThanOrEqual(26);
      expect(address.length).toBeLessThanOrEqual(35);
    });

    it("should validate a correct address", () => {
      const address = generateAddressLegacy(testPublicKey, { bytesVersion: 0x00 });
      const isValid = validateAddressLegacy(address, { bytesVersion: 0x00 });

      expect(isValid).toBe(true);
    });

    it("should reject an address with wrong version byte", () => {
      const address = generateAddressLegacy(testPublicKey, { bytesVersion: 0x00 });
      const isValid = validateAddressLegacy(address, { bytesVersion: 0x05 });

      expect(isValid).toBe(false);
    });

    it("should reject invalid addresses", () => {
      expect(validateAddressLegacy("1INVALID$ADDRESS", { bytesVersion: 0x00 })).toBe(false);
      expect(validateAddressLegacy("1Ax", { bytesVersion: 0x00 })).toBe(false);
    });
  });

  describe("P2SH addresses", () => {
    it("should generate correct P2SH address for known public key", () => {
      // Generator point G - known P2SH-P2WPKH address
      const generatorKey = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
      const address = generateAddressP2SH(generatorKey, { bytesVersion: 0x05 });
      expect(address).toBe("3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN");
    });

    it("should generate a valid P2SH address with correct version byte", () => {
      const address = generateAddressP2SH(testPublicKey, { bytesVersion: 0x05 });

      // Should start with '3' (for Bitcoin mainnet)
      expect(address.startsWith("3")).toBe(true);
      expect(address.length).toBeGreaterThanOrEqual(26);
      expect(address.length).toBeLessThanOrEqual(35);
    });

    it("should validate a correct P2SH address", () => {
      const address = generateAddressP2SH(testPublicKey, { bytesVersion: 0x05 });
      const isValid = validateAddressP2SH(address, { bytesVersion: 0x05 });

      expect(isValid).toBe(true);
    });

    it("should reject a P2SH address with wrong version byte", () => {
      const address = generateAddressP2SH(testPublicKey, { bytesVersion: 0x05 });
      const isValid = validateAddressP2SH(address, { bytesVersion: 0x00 });

      expect(isValid).toBe(false);
    });
  });

  describe("public key checks", () => {
    const segwit = { hrp: "bc", witnessVersion: 0 };
    /* G uncompressed. bitcoinjs-lib 6.1.8 hashes it for p2pkh and refuses it for p2wpkh. */
    const uncompressedKey =
      "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    it.each([
      ["empty", ""],
      ["20 bytes", "ab".repeat(20)],
      ["33 zero bytes", "00".repeat(33)],
      ["x outside the field", `02${"ff".repeat(32)}`],
      ["x with no point", `02${"05".padStart(64, "0")}`],
    ])("throws for %s instead of hashing it", (_label, keyPublic) => {
      expect(() => generateAddressLegacy(keyPublic, { bytesVersion: 0x00 })).toThrow();
      expect(() => generateAddressP2SH(keyPublic, { bytesVersion: 0x05 })).toThrow();
      expect(() => generateAddressSegWit(keyPublic, segwit)).toThrow();
      expect(() => generateAddressSegWit(keyPublic, segwit, "p2wsh")).toThrow();
    });

    it("takes an uncompressed key for legacy and taproot, not for SegWit v0", () => {
      expect(generateAddressLegacy(uncompressedKey, { bytesVersion: 0x00 })).toBe(
        "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
      );
      expect(generateAddressSegWit(uncompressedKey, { hrp: "bc", witnessVersion: 1 })).toBe(
        "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
      );
      expect(() => generateAddressP2SH(uncompressedKey, { bytesVersion: 0x05 })).toThrow(
        "compressed",
      );
      expect(() => generateAddressSegWit(uncompressedKey, segwit)).toThrow("compressed");
      expect(() => generateAddressSegWit(uncompressedKey, segwit, "p2wsh")).toThrow("compressed");
    });
  });
});
