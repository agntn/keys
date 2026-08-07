import { describe, expect, it } from "vitest";
import { useBlockchain } from "../../src";
import Base from "../../src/blockchains/base";

describe("Base blockchain", () => {
  const blockchain = useBlockchain(new Base());

  it("should have a name", () => {
    expect(blockchain.name).toBe("base");
  });

  it("should use secp256k1 curve", () => {
    expect(blockchain.curve).toBe("secp256k1");
  });

  it("should generate a private key", () => {
    const keyPrivate = blockchain.generateKeyPrivate();

    // Private key should be a 64-character hex string (32 bytes)
    expect(keyPrivate).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should generate different private keys each time", () => {
    const keyPrivate1 = blockchain.generateKeyPrivate();
    const keyPrivate2 = blockchain.generateKeyPrivate();

    expect(keyPrivate1).not.toBe(keyPrivate2);
  });

  it("should generate a public key from a private key", () => {
    const keyPrivate = blockchain.generateKeyPrivate();
    const keyPublic = blockchain.getKeyPublic(keyPrivate);

    // Compressed public key should be a 66-character hex string (33 bytes)
    expect(keyPublic).toMatch(/^[0-9a-f]{66}$/);

    // Should start with 02 or 03 (compressed key)
    expect(keyPublic.startsWith("02") || keyPublic.startsWith("03")).toBe(true);
  });

  it("should generate an uncompressed public key", () => {
    const keyPrivate = blockchain.generateKeyPrivate();
    const keyPublic = blockchain.getKeyPublic(keyPrivate, { compressed: false });

    // Uncompressed public key should be a 130-character hex string (65 bytes)
    expect(keyPublic).toMatch(/^[0-9a-f]{130}$/);

    // Should start with 04 (uncompressed key)
    expect(keyPublic.startsWith("04")).toBe(true);
  });

  describe("Base addresses", () => {
    it("should generate a Base address from a compressed public key", () => {
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic);

      // Base address should start with 0x
      expect(address.startsWith("0x")).toBe(true);

      // Base address should be 42 characters (0x + 40 hex chars)
      expect(address.length).toBe(42);

      // Should contain hex characters (potentially mixed case due to EIP-55 checksum)
      expect(address.slice(2)).toMatch(/^[0-9a-fA-F]{40}$/);

      // Validate address using validateAddress
      expect(blockchain.validateAddress?.(address)).toBe(true);
    });

    it("should generate a Base address from an uncompressed public key", () => {
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate, { compressed: false });
      const address = blockchain.getAddress(keyPublic);

      // Base address should start with 0x
      expect(address.startsWith("0x")).toBe(true);

      // Base address should be 42 characters (0x + 40 hex chars)
      expect(address.length).toBe(42);
    });

    it("should validate a valid Base address", () => {
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic);

      // Generated address with EIP-55 checksum should be valid
      expect(blockchain.validateAddress?.(address)).toBe(true);

      // Lowercase address should also be valid (pre-EIP-55 compatibility)
      const lowercaseAddress = address.toLowerCase();
      expect(blockchain.validateAddress?.(lowercaseAddress)).toBe(true);

      // Uppercase address should also be valid (backward compatibility)
      const uppercaseAddress = "0x" + address.slice(2).toUpperCase();
      expect(blockchain.validateAddress?.(uppercaseAddress)).toBe(true);
    });

    it("should correctly implement EIP-55 checksum", () => {
      // Test with a known address and its EIP-55 checksum version
      // Example from EIP-55 specification
      const _lowerCaseAddress = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
      const checksumAddress = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const generatedAddress = blockchain.getAddress(keyPublic);

      // Verify our implementation correctly validates EIP-55 addresses
      expect(blockchain.validateAddress?.(checksumAddress)).toBe(true);

      // Invalid checksum should fail if address has mixed case
      const invalidChecksumAddress = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
      expect(blockchain.validateAddress?.(invalidChecksumAddress)).toBe(false);

      // Our generated address should have correct checksum
      expect(blockchain.validateAddress?.(generatedAddress)).toBe(true);
    });

    it("should reject an invalid Base address", () => {
      // Missing 0x prefix
      expect(blockchain.validateAddress?.("71C7656EC7ab88b098defB751B7401B5f6d8976F")).toBe(false);

      // Too short
      expect(blockchain.validateAddress?.("0x71C7656EC7ab88b098defB751B7401B5f6d8976")).toBe(false);

      // Too long
      expect(blockchain.validateAddress?.("0x71C7656EC7ab88b098defB751B7401B5f6d8976Fa")).toBe(
        false,
      );

      // Invalid characters
      expect(blockchain.validateAddress?.("0x71C7656EC7ab88b098defB751B7401B5f6d8976Z")).toBe(
        false,
      );
    });

    it("should generate the correct known address", () => {
      // Base uses the same address format as Ethereum
      // Test with a known private key and expected address

      // Use a known test key with decimal value 1
      const testKey = "0000000000000000000000000000000000000000000000000000000000000001";

      // Generate public key and address
      const publicKey = blockchain.getKeyPublic(testKey);
      const address = blockchain.getAddress(publicKey);

      // The known address for private key 1 in EVM chains
      expect(address).toBe("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    });
  });
});
