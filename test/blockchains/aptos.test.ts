import { expect, describe, it } from "vitest";
import { bip39TestVectors } from "../fixtures";
import Aptos from "../../src/blockchains/aptos";
import { useBlockchain } from "../../src/blockchain";
import type { Options } from "../../src/types";

describe("Aptos Blockchain", () => {
  describe("Mainnet", () => {
    const blockchain = useBlockchain(new Aptos());

    // Test private key generation
    it("generates a valid private key", () => {
      const keyPrivate = blockchain.generateKeyPrivate();

      expect(keyPrivate).toBeDefined();
      expect(keyPrivate.length).toBe(64); // 32 bytes as hex
      expect(/^[0-9a-f]{64}$/i.test(keyPrivate)).toBe(true);
    });

    // Test public key generation
    it("generates a valid public key from a private key", () => {
      const keyPrivate = "0000000000000000000000000000000000000000000000000000000000000001";
      const keyPublic = blockchain.getKeyPublic(keyPrivate);

      expect(keyPublic).toBeDefined();
      expect(/^[0-9a-f]+$/i.test(keyPublic)).toBe(true);
    });

    // Test address generation
    it("generates a valid Aptos address from a public key", () => {
      const keyPrivate = "0000000000000000000000000000000000000000000000000000000000000001";
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic);

      expect(address).toBeDefined();
      expect(address.startsWith("0x")).toBe(true);
      expect(blockchain.validateAddress?.(address)).toBe(true);
    });

    // Test address validation
    it("validates Aptos addresses correctly", () => {
      // Use the address generated in the previous test
      const keyPrivate = "0000000000000000000000000000000000000000000000000000000000000001";
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const validAddress = blockchain.getAddress(keyPublic);

      expect(blockchain.validateAddress?.(validAddress)).toBe(true);

      // Invalid addresses
      expect(blockchain.validateAddress?.("not-a-valid-address")).toBe(false);
      expect(blockchain.validateAddress?.("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")).toBe(false); // Bitcoin address
      expect(blockchain.validateAddress?.("0x1234")).toBe(false); // Too short
      expect(blockchain.validateAddress?.("")).toBe(false);
    });

    it.each(["0x0", "0x1", "0xa", "0xF"])("accepts canonical short address %s", (address) => {
      expect(blockchain.validateAddress(address)).toBe(true);
    });

    it.each(["0x01", "0x10"])("rejects noncanonical short address %s", (address) => {
      expect(blockchain.validateAddress(address)).toBe(false);
    });
  });

  describe("Testnet", () => {
    const options: Options = { network: "testnet" };
    const testnetBlockchain = useBlockchain(new Aptos(options));

    describe("blockchain interface", () => {
      it("has correct name", () => {
        expect(testnetBlockchain.name).toBe("aptos");
      });

      it("uses Ed25519 curve", () => {
        expect(testnetBlockchain.curve).toBe("ed25519");
      });

      it("has network property set to testnet", () => {
        expect(testnetBlockchain.network).toBe("testnet");
      });
    });

    describe("address generation", () => {
      it("generates identical addresses for testnet and mainnet", () => {
        // Aptos uses the same address format for both networks
        const mainnetBlockchain = useBlockchain(new Aptos());
        const keyPrivate = "0000000000000000000000000000000000000000000000000000000000000001";

        const testnetPublicKey = testnetBlockchain.getKeyPublic(keyPrivate);
        const mainnetPublicKey = mainnetBlockchain.getKeyPublic(keyPrivate);

        // Public keys should be identical
        expect(testnetPublicKey).toBe(mainnetPublicKey);

        // Addresses should be identical
        const testnetAddress = testnetBlockchain.getAddress(testnetPublicKey);
        const mainnetAddress = mainnetBlockchain.getAddress(mainnetPublicKey);

        expect(testnetAddress).toBe(mainnetAddress);
        expect(testnetBlockchain.validateAddress?.(testnetAddress)).toBe(true);
      });
    });
  });

  /** Address computed independently with bip_utils 2.9.3 for the BIP39 reference mnemonic. */
  describe("HD wallets from mnemonics", () => {
    const blockchain = useBlockchain(new Aptos());

    it("derives the first account address over SLIP-10", () => {
      expect(
        blockchain.deriveHDWallet(bip39TestVectors.mnemonic, "m/44'/637'/0'/0'/0'").address,
      ).toBe("0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf");
    });
  });
});
