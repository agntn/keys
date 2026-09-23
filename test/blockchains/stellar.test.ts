import { describe, expect, it } from "vite-plus/test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { stellarTestVectors } from "../fixtures";
import Stellar from "../../src/blockchains/stellar";
import { useBlockchain } from "../../src/blockchain";

describe("Stellar", () => {
  const blockchain = useBlockchain(new Stellar());
  const vector = stellarTestVectors;

  describe("Keys and addresses", () => {
    it("derives the ed25519 public key", () => {
      expect(blockchain.getKeyPublic(vector.privateKey)).toBe(vector.publicKey);
    });

    it("encodes the public key as an account StrKey", () => {
      expect(blockchain.getAddress(vector.publicKey)).toBe(vector.address);
    });

    it("gives the same address on testnet", () => {
      const testnet = useBlockchain(new Stellar({ network: "testnet" }));
      expect(testnet.getAddress(vector.publicKey)).toBe(vector.address);
    });

    it("rejects a public key that is not 32 bytes", () => {
      expect(() => blockchain.getAddress(vector.publicKey.slice(2))).toThrow(RangeError);
      expect(() => blockchain.getAddress(vector.publicKey + "00")).toThrow(RangeError);
    });

    it("generates a wallet whose address validates", () => {
      const wallet = blockchain.generateWallet();
      expect(wallet.keys.private).toMatch(/^[0-9a-f]{64}$/);
      expect(wallet.address).toMatch(/^G[A-Z2-7]{55}$/);
      expect(blockchain.validateAddress(wallet.address)).toBe(true);
      expect(blockchain.getAddress(wallet.keys.public)).toBe(wallet.address);
    });
  });

  describe("Address validation", () => {
    it.each([
      ["account", vector.address],
      ["SEP-5 account", vector.hd.accounts[0][2]],
      ["muxed account", vector.muxedAddress],
      ["contract", vector.contractAddress],
    ])("accepts a %s StrKey", (_label, address) => {
      expect(blockchain.validateAddress(address)).toBe(true);
    });

    it.each([
      ["a secret seed", vector.secret],
      ["a wrong checksum", vector.address.slice(0, -1) + "B"],
      ["lowercase", vector.address.toLowerCase()],
      ["a truncated key", vector.address.slice(0, -1)],
      ["padding", vector.address + "="],
      ["a muxed account with a non-zero trailing bit", vector.muxedAddress.slice(0, -1) + "L"],
      ["a Bitcoin address", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"],
      ["an empty string", ""],
    ])("rejects %s", (_label, address) => {
      expect(blockchain.validateAddress(address)).toBe(false);
    });
  });

  describe("Message signing", () => {
    it.each(vector.messages)(
      "signs @stellar/stellar-sdk signMessage vector %#",
      (message, digest, signature) => {
        expect(
          ed25519.verify(hexToBytes(signature), hexToBytes(digest), hexToBytes(vector.publicKey)),
        ).toBe(true);

        expect(blockchain.signMessage(message, vector.privateKey)).toBe(signature);
        expect(blockchain.signMessage(new TextEncoder().encode(message), vector.privateKey)).toBe(
          signature,
        );
        expect(blockchain.verifyMessage(message, signature, vector.publicKey)).toBe(true);
        expect(blockchain.verifyMessage(message + "!", signature, vector.publicKey)).toBe(false);
        expect(blockchain.verifyMessage(message, "invalid", vector.publicKey)).toBe(false);
      },
    );

    it("rejects a raw ed25519 signature over the message bytes", () => {
      const [message, , signature] = vector.messages[1];
      const raw = bytesToHex(
        ed25519.sign(new TextEncoder().encode(message), hexToBytes(vector.privateKey)),
      );
      expect(raw).not.toBe(signature);
      expect(blockchain.verifyMessage(message, raw, vector.publicKey)).toBe(false);
    });
  });

  describe("HD derivation", () => {
    it.each(vector.hd.accounts)("derives SEP-0005 account %s", (path, privateKey, address) => {
      const wallet = blockchain.deriveHDWallet(vector.hd.mnemonic, path);
      expect(wallet.keys.private).toBe(privateKey);
      expect(wallet.address).toBe(address);
      expect(wallet.warnings).toBeUndefined();
    });

    it("refuses an unhardened segment", () => {
      expect(() => blockchain.deriveHDWallet(vector.hd.mnemonic, "m/44'/148'/0")).toThrow();
    });

    it("generates the SEP-0005 account path and nothing deeper", () => {
      for (const [index, [path, , address]] of vector.hd.accounts.entries()) {
        expect(blockchain.getDerivationPath(index)).toBe(path);
        expect(blockchain.deriveHDWallet(vector.hd.mnemonic, path).address).toBe(address);
      }
      expect(() => blockchain.getDerivationPath(0, 1)).toThrow(RangeError);
      expect(() => blockchain.getDerivationPath(0, 0, 1)).toThrow(RangeError);
    });
  });
});
