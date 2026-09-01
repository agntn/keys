import { webcrypto } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it, vi } from "vitest";
import { bip39TestVectors } from "../fixtures";
import { useBlockchain } from "../../src";
import Bitcoin from "../../src/blockchains/bitcoin";
import type { Options } from "../../src/types";

describe("Bitcoin blockchain", () => {
  const blockchain = useBlockchain(new Bitcoin());

  it("should have a name", () => {
    expect(blockchain.name).toBe("bitcoin");
  });

  it("should generate a private key", () => {
    const keyPrivate = blockchain.generateKeyPrivate();

    // Private key should be a 64-character hex string (32 bytes)
    expect(keyPrivate).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should generate a private key from a 48-byte secp256k1 seed", () => {
    const seed = new Uint8Array(48);
    const getRandomValues = vi.spyOn(webcrypto, "getRandomValues").mockImplementation((array) => {
      const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
      bytes.set(seed.subarray(0, bytes.byteLength));
      return array;
    });

    try {
      const keyPrivate = blockchain.generateKeyPrivate();

      expect(getRandomValues).toHaveBeenCalledOnce();
      expect(getRandomValues.mock.calls[0]?.[0].byteLength).toBe(seed.byteLength);
      expect(keyPrivate).toBe(bytesToHex(secp256k1.utils.randomSecretKey(seed)));
    } finally {
      getRandomValues.mockRestore();
    }
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

  describe("Legacy addresses (P2PKH)", () => {
    it("should generate a legacy address from a public key", () => {
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic, "legacy");

      // Legacy address should start with 1
      expect(address.startsWith("1")).toBe(true);

      // Legacy address should be 26-35 characters
      expect(address.length).toBeGreaterThanOrEqual(26);
      expect(address.length).toBeLessThanOrEqual(35);
    });

    it("should validate a valid legacy address", () => {
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic, "legacy");

      expect(blockchain.validateAddress!(address)).toBe(true);
    });

    it("should reject an invalid legacy address", () => {
      // Invalid characters
      expect(blockchain.validateAddress!("1INVALID$ADDRESS")).toBe(false);

      // Legacy format but with invalid checksum
      expect(blockchain.validateAddress!("1BvBMSEYstWQtqTFn5Au4m4GFg7xJaNVN2")).toBe(false);

      // Too short
      expect(blockchain.validateAddress!("1Ax")).toBe(false);
    });
  });

  describe("P2SH addresses", () => {
    it("should generate a P2SH address from a public key", () => {
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic, "p2sh");

      // P2SH address should start with 3
      expect(address.startsWith("3")).toBe(true);

      // P2SH address should be 26-35 characters
      expect(address.length).toBeGreaterThanOrEqual(26);
      expect(address.length).toBeLessThanOrEqual(35);
    });

    it("should validate a valid P2SH address", () => {
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic, "p2sh");

      expect(blockchain.validateAddress!(address)).toBe(true);
    });

    it("should reject an invalid P2SH address", () => {
      // P2SH format but with invalid checksum
      expect(blockchain.validateAddress!("3MbYQMMmSkC3AgWkj9FMo5LsPTW1zBTwX1")).toBe(false);
    });
  });

  describe("SegWit v0 (bech32) addresses", () => {
    // Known test vector for SegWit v0
    const segwitTestVector = {
      privateKey: "0000000000000000000000000000000000000000000000000000000000000001",
      publicKey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      segwitAddress: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    };

    it("should generate a SegWit v0 address from a public key", () => {
      const address = blockchain.getAddress(segwitTestVector.publicKey, "segwit");

      // SegWit address should match expected value
      expect(address).toBe(segwitTestVector.segwitAddress);

      // SegWit address should start with bc1
      expect(address.startsWith("bc1")).toBe(true);
    });

    it("should generate a valid SegWit v0 address from any key", () => {
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic, "segwit");

      // SegWit address should start with bc1q (q is part of the encoding, indicating v0)
      expect(address.startsWith("bc1q")).toBe(true);

      // Should be a valid address
      expect(blockchain.validateAddress!(address)).toBe(true);
    });

    it("should generate a P2WSH address from a public key", () => {
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic, "p2wsh");

      // P2WSH address should start with bc1q
      expect(address.startsWith("bc1q")).toBe(true);

      // Should be a valid address
      expect(blockchain.validateAddress!(address)).toBe(true);

      // P2WSH should be different from P2WPKH for the same key
      const p2wpkhAddress = blockchain.getAddress(keyPublic, "segwit");
      expect(address).not.toBe(p2wpkhAddress);

      // P2WSH addresses are longer than P2WPKH addresses because they use a 32-byte hash
      expect(address.length).toBeGreaterThan(p2wpkhAddress.length);
    });

    it("should validate valid SegWit v0 addresses", () => {
      // Test known valid SegWit addresses
      const validAddresses = [
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // P2WPKH
        "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", // P2WSH
      ];

      for (const address of validAddresses) {
        expect(blockchain.validateAddress!(address)).toBe(true);
      }
    });

    it("should reject invalid SegWit v0 addresses", () => {
      // Test known invalid SegWit addresses
      const invalidAddresses = [
        "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", // Wrong hrp
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // Invalid checksum
        "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6q", // Invalid witness version
        "bC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", // Invalid program length
        "bc1q", // Too short
      ];

      for (const address of invalidAddresses) {
        expect(blockchain.validateAddress!(address)).toBe(false);
      }
    });

    it("should generate different P2WPKH and P2WSH addresses from the same key", () => {
      for (let i = 0; i < 5; i++) {
        const keyPrivate = blockchain.generateKeyPrivate();
        const keyPublic = blockchain.getKeyPublic(keyPrivate);

        const p2wpkhAddress = blockchain.getAddress(keyPublic, "segwit");
        const p2wshAddress = blockchain.getAddress(keyPublic, "p2wsh");

        // Addresses should be different
        expect(p2wpkhAddress).not.toBe(p2wshAddress);

        // Both should be valid
        expect(blockchain.validateAddress!(p2wpkhAddress)).toBe(true);
        expect(blockchain.validateAddress!(p2wshAddress)).toBe(true);

        // Both should start with bc1q (SegWit v0)
        expect(p2wpkhAddress.startsWith("bc1q")).toBe(true);
        expect(p2wshAddress.startsWith("bc1q")).toBe(true);
      }
    });
  });

  describe("SegWit v1 (bech32m/Taproot) addresses", () => {
    it("should generate the BIP341 Taproot address for a known public key", () => {
      const address = blockchain.getAddress(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "taproot",
      );

      expect(address).toBe("bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9");
      expect(blockchain.validateAddress!(address)).toBe(true);
    });

    it("should generate different addresses for same key with different types", () => {
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);

      const legacyAddress = blockchain.getAddress(keyPublic, "legacy");
      const p2shAddress = blockchain.getAddress(keyPublic, "p2sh");
      const segwitAddress = blockchain.getAddress(keyPublic, "segwit");
      const taprootAddress = blockchain.getAddress(keyPublic, "taproot");

      // All addresses should be different
      expect(new Set([legacyAddress, p2shAddress, segwitAddress, taprootAddress]).size).toBe(4);

      // Each address should start with the correct prefix
      expect(legacyAddress.startsWith("1")).toBe(true);
      expect(p2shAddress.startsWith("3")).toBe(true);
      expect(segwitAddress.startsWith("bc1q")).toBe(true);
      expect(taprootAddress.startsWith("bc1p")).toBe(true);
    });

    it("should validate a Taproot address", () => {
      // Generate a Taproot address
      const keyPrivate = blockchain.generateKeyPrivate();
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic, "taproot");

      // Should be valid
      expect(blockchain.validateAddress!(address)).toBe(true);

      // Slightly modifying the address should make it invalid
      const invalidAddress = address.slice(0, -1) + (address.at(-1) === "a" ? "b" : "a");
      expect(blockchain.validateAddress!(invalidAddress)).toBe(false);
    });
  });

  it.each([
    ["Bech32", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"],
    ["Bech32m", "BC1P0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQZK5JJ0"],
  ])("should validate an uppercase %s address", (_encoding, address) => {
    expect(blockchain.validateAddress!(address)).toBe(true);
  });

  describe("Message signing", () => {
    it("should sign a message and return a hex string", () => {
      const wallet = blockchain.generateWallet();
      const signature = blockchain.signMessage("Test message", wallet.keys.private);

      expect(signature).toBeTypeOf("string");
      expect(signature).toMatch(/^[0-9a-f]+$/);
    });

    it("should produce different signatures than EVM for the same key and message", async () => {
      const { default: Ethereum } = await import("../../src/blockchains/ethereum");
      const ethBlockchain = useBlockchain(new Ethereum());

      const wallet = blockchain.generateWallet();
      const message = "Test message";

      const btcSig = blockchain.signMessage(message, wallet.keys.private);
      const ethSig = ethBlockchain.signMessage(message, wallet.keys.private);

      expect(btcSig).not.toBe(ethSig);
    });
  });

  describe("Testnet addresses", () => {
    // Create bitcoin blockchain with testnet network option
    const options: Options = { network: "testnet" };
    const testnetBlockchain = useBlockchain(new Bitcoin(options));

    it("should have a network property set to testnet", () => {
      expect(testnetBlockchain.network).toBe("testnet");
    });

    it("should generate testnet addresses with proper prefixes", () => {
      const keyPrivate = testnetBlockchain.generateKeyPrivate();
      const keyPublic = testnetBlockchain.getKeyPublic(keyPrivate);

      // Generate addresses for different types
      const legacyAddress = testnetBlockchain.getAddress(keyPublic, "legacy");
      const p2shAddress = testnetBlockchain.getAddress(keyPublic, "p2sh");
      const segwitAddress = testnetBlockchain.getAddress(keyPublic, "segwit");
      const p2wshAddress = testnetBlockchain.getAddress(keyPublic, "p2wsh");
      const taprootAddress = testnetBlockchain.getAddress(keyPublic, "taproot");

      // Testnet legacy addresses start with 'm' or 'n'
      expect(legacyAddress.startsWith("m") || legacyAddress.startsWith("n")).toBe(true);

      // Testnet P2SH addresses start with '2'
      expect(p2shAddress.startsWith("2")).toBe(true);

      // Testnet SegWit addresses start with 'tb1'
      expect(segwitAddress.startsWith("tb1q")).toBe(true);
      expect(p2wshAddress.startsWith("tb1q")).toBe(true);
      expect(taprootAddress.startsWith("tb1p")).toBe(true);

      // All generated addresses should be valid
      expect(testnetBlockchain.validateAddress!(legacyAddress)).toBe(true);
      expect(testnetBlockchain.validateAddress!(p2shAddress)).toBe(true);
      expect(testnetBlockchain.validateAddress!(segwitAddress)).toBe(true);
      expect(testnetBlockchain.validateAddress!(p2wshAddress)).toBe(true);
      expect(testnetBlockchain.validateAddress!(taprootAddress)).toBe(true);
    });

    it("should validate testnet addresses but reject mainnet addresses", () => {
      const keyPrivate = testnetBlockchain.generateKeyPrivate();
      const keyPublic = testnetBlockchain.getKeyPublic(keyPrivate);

      // Generate a testnet address
      const testnetAddress = testnetBlockchain.getAddress(keyPublic, "legacy");

      // Generate a mainnet address using the same key
      const mainnetAddress = blockchain.getAddress(keyPublic, "legacy");

      // Testnet blockchain should validate testnet address
      expect(testnetBlockchain.validateAddress!(testnetAddress)).toBe(true);

      // Testnet blockchain should reject mainnet address
      expect(testnetBlockchain.validateAddress!(mainnetAddress)).toBe(false);

      // Mainnet blockchain should validate mainnet address
      expect(blockchain.validateAddress!(mainnetAddress)).toBe(true);

      // Mainnet blockchain should reject testnet address
      expect(blockchain.validateAddress!(testnetAddress)).toBe(false);
    });
  });

  /** Addresses computed independently with bip_utils 2.9.3 for the BIP39 reference mnemonic. */
  describe("HD wallets from mnemonics", () => {
    const { mnemonic } = bip39TestVectors;

    it.each([
      ["m/44'/0'/0'/0/0", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"],
      ["m/49'/0'/0'/0/0", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"],
      ["m/84'/0'/0'/0/0", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"],
      ["m/84'/0'/0'/0/1", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"],
      ["m/86'/0'/0'/0/0", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"],
    ])("picks the address type from the purpose of %s", (path, address) => {
      expect(blockchain.deriveHDWallet(mnemonic, path).address).toBe(address);
    });

    it("keeps an explicit address type over the purpose", () => {
      const wallet = blockchain.deriveHDWallet(mnemonic, "m/84'/0'/0'/0/0", {}, "legacy");

      expect(wallet.keys.private).toBe(
        "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3",
      );
      expect(wallet.address).toBe(blockchain.getAddress(wallet.keys.public, "legacy"));
    });

    it("falls back to legacy for paths without a known purpose", () => {
      const wallet = blockchain.deriveHDWallet(mnemonic, "m/0/0");

      expect(wallet.address).toBe(blockchain.getAddress(wallet.keys.public, "legacy"));
    });

    it("derives testnet addresses on the testnet coin type", () => {
      const testnet = useBlockchain(new Bitcoin({ network: "testnet" }));

      expect(testnet.deriveHDWallet(mnemonic, "m/44'/1'/0'/0/0").address).toBe(
        "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
      );
    });
  });
});
