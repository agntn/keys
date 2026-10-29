import { expect, describe, it } from "vite-plus/test";
import { bip39TestVectors, slip10WalletVectors, solanaTestVectors } from "../fixtures";
import Solana from "../../src/blockchains/solana";
import { useBlockchain } from "../../src/blockchain";
import type { Options } from "../../src/types";

describe("Solana Blockchain", () => {
  describe("Mainnet", () => {
    const blockchain = useBlockchain(new Solana());

    // Test private key generation
    it("generates a valid private key", () => {
      const keyPrivate = blockchain.generateKeyPrivate();

      expect(keyPrivate).toMatch(/^[0-9a-f]{64}$/i);
    });

    // Test public key generation
    it("generates a valid public key from a private key", () => {
      const keyPrivate = "0000000000000000000000000000000000000000000000000000000000000001";
      const keyPublic = blockchain.getKeyPublic(keyPrivate);

      expect(keyPublic).toMatch(/^[0-9a-f]+$/i);
    });

    // Test address generation
    it("generates a valid Solana address from a public key", () => {
      const keyPrivate = "0000000000000000000000000000000000000000000000000000000000000001";
      const keyPublic = blockchain.getKeyPublic(keyPrivate);
      const address = blockchain.getAddress(keyPublic);

      expect(blockchain.validateAddress?.(address)).toBe(true);
    });

    it.each([31, 33])("rejects a public key with %i bytes", (bytes) => {
      expect(() => blockchain.getAddress("00".repeat(bytes))).toThrow("32 bytes");
    });

    // Test address validation
    it("rejects strings that are not Solana addresses", () => {
      expect(blockchain.validateAddress?.("not-a-valid-address")).toBe(false);
      expect(blockchain.validateAddress?.("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")).toBe(false); // Bitcoin address
      expect(blockchain.validateAddress?.("")).toBe(false);
    });

    it("returns false for malformed signatures", () => {
      const keyPrivate = "0000000000000000000000000000000000000000000000000000000000000001";
      const keyPublic = blockchain.getKeyPublic(keyPrivate);

      expect(
        blockchain.verifyMessage("message", { signature: "not-a-signature", publicKey: keyPublic }),
      ).toBe(false);
    });
  });

  describe("Testnet", () => {
    const options: Options = { network: "testnet" };
    const testnetBlockchain = useBlockchain(new Solana(options));

    describe("blockchain interface", () => {
      it("has correct name", () => {
        expect(testnetBlockchain.name).toBe("solana");
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
        // Solana uses the same address format for both networks
        const mainnetBlockchain = useBlockchain(new Solana());
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

  describe("HD wallets from mnemonics", () => {
    const blockchain = useBlockchain(new Solana());
    const [vector] = slip10WalletVectors;

    it("derives the Phantom style m/44'/501'/0'/0' address over SLIP-10", () => {
      const path = blockchain.getDerivationPath();
      expect(path).toBe(vector.path);
      expect(blockchain.deriveHDWallet(bip39TestVectors.mnemonic, { path }).address).toBe(
        vector.address,
      );
    });

    it("reads the h hardened marker of BIP380 descriptors over SLIP-10", () => {
      expect(
        blockchain.deriveHDWallet(bip39TestVectors.mnemonic, {
          path: vector.path.replaceAll("'", "h"),
        }).address,
      ).toBe(vector.address);
    });

    it("hardens the account and the change branch and has no address index", () => {
      expect(blockchain.getDerivationPath({ account: 3, change: 1 })).toBe("m/44'/501'/3'/1'");
      expect(() => blockchain.getDerivationPath({ account: 0, change: 2 })).toThrow(RangeError);
      expect(() =>
        blockchain.getDerivationPath({ account: 0, change: 0, addressIndex: 1 }),
      ).toThrow(RangeError);
    });

    it("rejects non-hardened segments on ed25519", () => {
      expect(() =>
        blockchain.deriveHDWallet(bip39TestVectors.mnemonic, { path: "m/44'/501'/0'/0" }),
      ).toThrow("level 4 of the derivation path needs ' or h");
    });
  });

  describe("Message signing", () => {
    const blockchain = useBlockchain(new Solana());
    const vector = solanaTestVectors;

    it("derives the @solana/web3.js public key and address", () => {
      expect(blockchain.getKeyPublic(vector.privateKey)).toBe(vector.publicKey);
      expect(blockchain.getAddress(vector.publicKey)).toBe(vector.address);
    });

    it.each(vector.messages)("signs tweetnacl detached vector %# as is", (message, signature) => {
      expect(blockchain.signMessage(message, { privateKey: vector.privateKey })).toBe(signature);
      expect(
        blockchain.signMessage(new TextEncoder().encode(message), {
          privateKey: vector.privateKey,
        }),
      ).toBe(signature);
      expect(blockchain.verifyMessage(message, { signature, publicKey: vector.publicKey })).toBe(
        true,
      );
      expect(
        blockchain.verifyMessage(message + "!", { signature, publicKey: vector.publicKey }),
      ).toBe(false);
      expect(
        blockchain.verifyMessage(message, { signature: "invalid", publicKey: vector.publicKey }),
      ).toBe(false);
    });
  });
});
