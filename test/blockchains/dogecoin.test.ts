import { base64 } from "@scure/base";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";
import { blockchains, getBlockchainPath } from "../../src/index.ts";
import Bitcoin from "../../src/blockchains/bitcoin.ts";
import Dogecoin, { Dogecoin as NamedDogecoin } from "../../src/blockchains/dogecoin.ts";
import {
  bip39TestVectors,
  dogecoinTestVectors as vector,
  secp256k1TestVectors,
  testMessages,
} from "../fixtures.ts";

/**
 * The r||s half of a compact signature, whose first byte is the recovery header.
 * @param signature - Compact signature in base64
 * @returns {string} r||s as hex
 */
const compactToRS = (signature: string): string => bytesToHex(base64.decode(signature).slice(1));

describe("Dogecoin", () => {
  it("loads through the public registry with SLIP-0044 coin type 3", async () => {
    const chain = await blockchains.dogecoin()();
    expect(chain).toBeInstanceOf(NamedDogecoin);
    expect(chain.name).toBe("dogecoin");
    expect(chain.curve).toBe("secp256k1");
    expect(getBlockchainPath(chain, 0, 1, 3)).toBe("m/44'/3'/0'/1/3");
    expect(() => new Dogecoin({ network: "regtest" })).toThrow("mainnet and testnet only");
  });

  it.each(vector.keys)("writes the node's address for $wif in both encodings", (key) => {
    const chain = new Dogecoin();
    const uncompressed = chain.getKeyPublic(key.privateKey, { compressed: false });
    const compressed = chain.getKeyPublic(key.privateKey);
    expect(chain.getAddress(uncompressed)).toBe(key.address);
    expect(chain.getAddress(compressed, "legacy")).toBe(key.addressCompressed);
  });

  it("refuses every address type but legacy, since the chain has no SegWit", () => {
    const chain = new Dogecoin();
    const { publicKeyCompressed } = secp256k1TestVectors;
    for (const type of ["p2sh", "segwit", "p2wsh", "taproot", "cashaddr", ""]) {
      expect(() => chain.getAddress(publicKeyCompressed, type)).toThrow("legacy P2PKH only");
    }
    expect(() => chain.getAddress("02" + "00".repeat(32))).toThrow();
  });

  it("validates the node's P2PKH and P2SH vectors on their network only", () => {
    const mainnet = new Dogecoin();
    const testnet = new Dogecoin({ network: "testnet" });
    for (const address of vector.mainnet) {
      expect(mainnet.validateAddress(address)).toBe(true);
      expect(testnet.validateAddress(address)).toBe(false);
    }
    for (const address of vector.testnet) {
      expect(testnet.validateAddress(address)).toBe(true);
      expect(mainnet.validateAddress(address)).toBe(false);
    }
  });

  it("refuses a broken checksum and Bitcoin's prefixes", () => {
    const chain = new Dogecoin();
    expect(chain.validateAddress(vector.badAddress)).toBe(false);
    expect(chain.validateAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")).toBe(false);
    expect(chain.validateAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")).toBe(false);
    expect(chain.validateAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")).toBe(false);
    expect(chain.validateAddress("")).toBe(false);
  });

  it("signs the bitcoinjs-message Dogecoin vector byte for byte", () => {
    const chain = new Dogecoin();
    const { privateKey, message, address, signatures } = vector.signed;
    const publicKey = chain.getKeyPublic(privateKey);
    expect(chain.getAddress(publicKey)).toBe(address);
    const signed = chain.signMessage(message, privateKey);
    for (const signature of signatures) {
      expect(signed).toBe(compactToRS(signature));
    }
    expect(chain.verifyMessage(message, signed, publicKey)).toBe(true);
    expect(chain.verifyMessage(`${message}!`, signed, publicKey)).toBe(false);
  });

  it("uses its own preamble, so a Bitcoin signature does not carry over", () => {
    const chain = new Dogecoin();
    const bitcoin = new Bitcoin();
    const { privateKey, publicKeyCompressed } = secp256k1TestVectors;
    for (const message of Object.values(testMessages)) {
      const signature = bitcoin.signMessage(message, privateKey);
      expect(chain.signMessage(message, privateKey)).not.toBe(signature);
      expect(chain.verifyMessage(message, signature, publicKeyCompressed)).toBe(false);
    }
    expect(() => chain.signMessage("hello", privateKey, { recovered: true })).toThrow();
  });

  it("derives the receive address Ledger Live gives for the public test mnemonic", () => {
    const chain = new Dogecoin();
    expect(chain.getDerivationPath(0)).toBe(vector.hd.path);
    expect(chain.deriveHDWallet(bip39TestVectors.mnemonic, vector.hd.path).address).toBe(
      vector.hd.address,
    );
  });

  it.each(["m/44'/3'/0'/0/0", "m/49'/3'/0'/0/0", "m/84'/3'/0'/0/0"])(
    "derives %s to a P2PKH address whatever the purpose",
    (path) => {
      const chain = new Dogecoin();
      const wallet = chain.deriveHDWallet(bip39TestVectors.mnemonic, path);
      expect(wallet.address).toBe(chain.getAddress(wallet.keys.public));
      expect(wallet.address).toMatch(/^D/u);
      expect(() => chain.deriveHDWallet(bip39TestVectors.mnemonic, path, {}, "p2sh")).toThrow(
        "legacy P2PKH only",
      );
    },
  );
});
