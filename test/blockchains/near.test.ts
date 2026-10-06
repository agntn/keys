import { describe, expect, it } from "vite-plus/test";
import { bip39TestVectors, nearTestVectors } from "../fixtures";
import Near from "../../src/blockchains/near";
import { useBlockchain } from "../../src/blockchain";
import { blockchains } from "../../src/_blockchains";

describe("NEAR", () => {
  const blockchain = useBlockchain(new Near());
  const vector = nearTestVectors;
  const [[, privateKey, publicKey, nearKey]] = vector.wallets;

  describe("Keys and accounts", () => {
    it("derives the ed25519 public key", () => {
      expect(blockchain.getKeyPublic(privateKey)).toBe(publicKey);
    });

    it("writes the implicit account as the public key in hex", () => {
      expect(blockchain.getAddress(publicKey)).toBe(publicKey);
      expect(blockchain.getAddress(publicKey.toUpperCase())).toBe(publicKey);
    });

    it("reads the key as NEAR prints it", () => {
      expect(blockchain.getAddress(nearKey)).toBe(publicKey);
    });

    it("gives the same account on testnet", () => {
      const testnet = useBlockchain(new Near({ network: "testnet" }));
      expect(testnet.getAddress(nearKey)).toBe(publicKey);
    });

    it("rejects a public key that is not 32 bytes", () => {
      expect(() => blockchain.getAddress(publicKey.slice(2))).toThrow(RangeError);
      expect(() => blockchain.getAddress(`${publicKey}00`)).toThrow(RangeError);
      expect(() => blockchain.getAddress(nearKey.slice(0, -4))).toThrow(RangeError);
    });

    it("has one address format", () => {
      expect(() => blockchain.getAddress(publicKey, "segwit")).toThrow();
    });

    it("loads through the lazy registry", async () => {
      const near = await blockchains.near()();
      expect(near.name).toBe("near");
      expect(near.deriveWallet(privateKey).address).toBe(publicKey);
    });

    it("generates a wallet whose account validates", () => {
      const wallet = blockchain.generateWallet();
      expect(wallet.address).toBe(wallet.keys.public);
      expect(blockchain.validateAddress(wallet.address)).toBe(true);
    });
  });

  describe("Account validation", () => {
    it("accepts an implicit account", () => {
      expect(blockchain.validateAddress(publicKey)).toBe(true);
    });

    it.each([
      ["uppercase hex, which NEAR refuses as an account ID", publicKey.toUpperCase()],
      ["the key as NEAR prints it", nearKey],
      ["a named account", "alice.near"],
      ["an ETH-implicit account", "0x32400084c286cf3e17e7b677ea9583e60a000324"],
      ["63 characters", publicKey.slice(1)],
      ["an empty string", ""],
    ])("rejects %s", (_label, address) => {
      expect(blockchain.validateAddress(address)).toBe(false);
    });
  });

  describe("Message signing", () => {
    it("signs the raw bytes like tweetnacl", () => {
      expect(blockchain.signMessage(vector.message, privateKey)).toBe(vector.signature);
    });

    it("verifies against either key form", () => {
      expect(blockchain.verifyMessage(vector.message, vector.signature, publicKey)).toBe(true);
      expect(blockchain.verifyMessage(vector.message, vector.signature, nearKey)).toBe(true);
      expect(blockchain.verifyMessage(`${vector.message}!`, vector.signature, nearKey)).toBe(false);
      expect(blockchain.verifyMessage(vector.message, vector.signature, "ed25519:0OIl")).toBe(
        false,
      );
    });
  });

  describe("HD derivation", () => {
    it.each(vector.wallets)("derives %s like near-seed-phrase", (path, key, account) => {
      const wallet = blockchain.deriveHDWallet(bip39TestVectors.mnemonic, path);
      expect(wallet.keys.private).toBe(key);
      expect(wallet.address).toBe(account);
    });

    it("puts an account at the third level and nothing deeper", () => {
      expect(blockchain.getDerivationPath()).toBe("m/44'/397'/0'");
      expect(blockchain.getDerivationPath(1)).toBe("m/44'/397'/1'");
      expect(() => blockchain.getDerivationPath(0, 1)).toThrow(RangeError);
      expect(() => blockchain.getDerivationPath(0, 0, 1)).toThrow(RangeError);
    });
  });
});
