import { base64 } from "@scure/base";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";
import { blockchains, getBlockchainPath } from "../../src/index.ts";
import Bitcoin from "../../src/blockchains/bitcoin.ts";
import BitcoinGold, { BitcoinGold as NamedBitcoinGold } from "../../src/blockchains/bitcoingold.ts";
import { decodeWIF } from "../../src/utils/wif.ts";
import {
  bip39TestVectors,
  bitcoinGoldTestVectors as vector,
  secp256k1TestVectors,
  testMessages,
} from "../fixtures.ts";

/**
 * The r||s half of a compact signature, whose first byte is the recovery header.
 * @param signature - Compact signature in base64
 * @returns {string} r||s as hex
 */
const compactToRS = (signature: string): string => bytesToHex(base64.decode(signature).slice(1));
const signedKey = decodeWIF(vector.signed.wif, { chain: "bitcoin", network: "testnet" }).privateKey;

describe("Bitcoin Gold", () => {
  it("loads through the public registry with SLIP-0044 coin type 156", async () => {
    const chain = await blockchains.bitcoingold()();
    expect(chain).toBeInstanceOf(NamedBitcoinGold);
    expect(chain.name).toBe("bitcoingold");
    expect(chain.curve).toBe("secp256k1");
    expect(getBlockchainPath(chain, 0, 1, 3)).toBe("m/44'/156'/0'/1/3");
    expect(() => new BitcoinGold({ network: "regtest" })).toThrow("mainnet and testnet only");
  });

  it("writes the node's signing key in every format under Bitcoin Gold's prefixes", () => {
    const mainnet = new BitcoinGold();
    const testnet = new BitcoinGold({ network: "testnet" });
    const publicKey = mainnet.getKeyPublic(signedKey);
    expect(publicKey).toBe(vector.signed.publicKey);
    expect(signedKey).toBe(vector.signed.privateKey);
    expect(testnet.getAddress(publicKey)).toBe(vector.signed.address);
    expect(testnet.getAddress(publicKey, "segwit")).toBe(vector.signed.segwitTestnetAddress);
    expect(mainnet.getAddress(publicKey)).toBe(vector.signed.legacyAddress);
    expect(mainnet.getAddress(publicKey, "p2sh")).toBe(vector.signed.p2shAddress);
    expect(mainnet.getAddress(publicKey, "segwit")).toBe(vector.signed.segwitAddress);
    expect(mainnet.getAddress(publicKey, "p2wsh")).toMatch(/^btg1q.{58}$/u);
  });

  it("refuses taproot, which the chain never activated", () => {
    const chain = new BitcoinGold();
    expect(() => chain.getAddress(secp256k1TestVectors.publicKeyCompressed, "taproot")).toThrow(
      "never activated Taproot",
    );
    expect(() => chain.deriveHDWallet(bip39TestVectors.mnemonic, "m/86'/156'/0'/0/0")).toThrow(
      "never activated Taproot",
    );
  });

  it("validates the node's own address vectors on their network only", () => {
    const mainnet = new BitcoinGold();
    const testnet = new BitcoinGold({ network: "testnet" });
    for (const address of vector.mainnet) {
      expect(mainnet.validateAddress(address)).toBe(true);
      expect(testnet.validateAddress(address)).toBe(false);
    }
    for (const address of vector.testnet) {
      expect(testnet.validateAddress(address)).toBe(true);
      expect(mainnet.validateAddress(address)).toBe(false);
    }
  });

  it("refuses witness v1 and later, Bitcoin's prefixes, and broken checksums", () => {
    const chain = new BitcoinGold();
    for (const address of vector.unprotected) {
      expect(chain.validateAddress(address)).toBe(false);
    }
    expect(chain.validateAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")).toBe(false);
    expect(chain.validateAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")).toBe(false);
    expect(chain.validateAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")).toBe(false);
    expect(chain.validateAddress(vector.mainnet[0].replace(/G$/u, "H"))).toBe(false);
    expect(chain.validateAddress("")).toBe(false);
  });

  it("signs the node's signmessagewithprivkey vector byte for byte", () => {
    const chain = new BitcoinGold({ network: "testnet" });
    const { message, signature } = vector.signed;
    const signed = chain.signMessage(message, signedKey);
    expect(signed).toBe(compactToRS(signature));
    expect(chain.verifyMessage(message, signed, chain.getKeyPublic(signedKey))).toBe(true);
    expect(chain.verifyMessage(`${message}!`, signed, chain.getKeyPublic(signedKey))).toBe(false);
  });

  it("uses its own preamble, so a Bitcoin signature does not carry over", () => {
    const chain = new BitcoinGold();
    const bitcoin = new Bitcoin();
    const { privateKey, publicKeyCompressed } = secp256k1TestVectors;
    for (const message of Object.values(testMessages)) {
      const signature = bitcoin.signMessage(message, privateKey);
      expect(chain.signMessage(message, privateKey)).not.toBe(signature);
      expect(chain.verifyMessage(message, signature, publicKeyCompressed)).toBe(false);
    }
    expect(() => chain.signMessage("hello", privateKey, { recovered: true })).toThrow();
  });

  it.each([
    ["m/44'/156'/0'/0/0", /^G/u],
    ["m/49'/156'/0'/0/0", /^A/u],
    ["m/84'/156'/0'/0/0", /^btg1q/u],
  ])("reads the purpose of %s for the address type", (path, pattern) => {
    const wallet = new BitcoinGold().deriveHDWallet(bip39TestVectors.mnemonic, path);
    expect(wallet.address).toMatch(pattern);
  });
});
