import { describe, it, expect } from "vite-plus/test";
import { generateAddressLegacy, validateAddressLegacy } from "../../src/utils/address";

describe("Bitcoin-like utils", () => {
  describe("generateAddressLegacy", () => {
    // Test pubkey (compressed format)
    const pubKey = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

    it("should generate a Bitcoin mainnet address with correct version byte", () => {
      const options = { bytesVersion: 0x00 }; // Bitcoin mainnet
      const address = generateAddressLegacy(pubKey, options);

      // Known correct address for this pubkey
      expect(address).toBe("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    });

    it("should generate a Testnet address with correct version byte", () => {
      const options = { bytesVersion: 0x6f }; // Bitcoin testnet
      const address = generateAddressLegacy(pubKey, options);

      // Known correct testnet address for this pubkey
      expect(address).toBe("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r");
    });
  });

  describe("validateAddressLegacy", () => {
    it("should validate a correct Bitcoin mainnet address", () => {
      const options = { bytesVersion: 0x00 }; // Bitcoin mainnet
      const address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

      expect(validateAddressLegacy(address, options)).toBe(true);
    });

    it("should validate a correct Bitcoin testnet address", () => {
      const options = { bytesVersion: 0x6f }; // Bitcoin testnet
      const address = "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r";

      expect(validateAddressLegacy(address, options)).toBe(true);
    });

    it("should reject an invalid address", () => {
      const options = { bytesVersion: 0x00 }; // Bitcoin mainnet
      const address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMS"; // Changed last character

      expect(validateAddressLegacy(address, options)).toBe(false);
    });

    it("should reject addresses with incorrect version byte", () => {
      const options = { bytesVersion: 0x00 }; // Bitcoin mainnet
      // This is a testnet address, not mainnet
      const address = "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r";

      expect(validateAddressLegacy(address, options)).toBe(false);
    });

    it("should reject addresses with incorrect length", () => {
      const options = { bytesVersion: 0x00 }; // Bitcoin mainnet
      const address = "1BgGZ9tcN4rm9KBzDn7K"; // Too short

      expect(validateAddressLegacy(address, options)).toBe(false);
    });

    it("should reject corrupted Base58Check encoding", () => {
      const options = { bytesVersion: 0x00 }; // Bitcoin mainnet

      // This should cause the Base58Check decoding to fail
      const address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH".replace("B", "X");

      expect(validateAddressLegacy(address, options)).toBe(false);
    });

    it("should reject non-string inputs", () => {
      const options = { bytesVersion: 0x00 }; // Bitcoin mainnet

      // @ts-expect-error Testing with invalid input
      expect(validateAddressLegacy(undefined, options)).toBe(false);
      // @ts-expect-error Testing with invalid input
      expect(validateAddressLegacy(123, options)).toBe(false);
      // @ts-expect-error Testing with invalid input
      expect(validateAddressLegacy({}, options)).toBe(false);
    });
  });
});
