import { base64 } from "@scure/base";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";
import { blockchains, getBlockchainPath } from "../../src/index.ts";
import Bitcoin from "../../src/blockchains/bitcoin.ts";
import BitcoinSV, { BitcoinSV as NamedBitcoinSV } from "../../src/blockchains/bitcoinsv.ts";
import { decodeWIF } from "../../src/utils/wif.ts";
import {
  bitcoinCashTestVectors,
  bitcoinSVTestVectors as vector,
  testMessages,
} from "../fixtures.ts";

/**
 * The r||s half of a compact signature, whose first byte is the recovery header.
 * @param signature - Compact signature in base64
 * @returns {string} r||s as hex
 */
const compactToRS = (signature: string): string => bytesToHex(base64.decode(signature).slice(1));
const privateKeyOf = (wif: string): string => decodeWIF(wif, { chain: "bitcoin" }).privateKey;

describe("Bitcoin SV", () => {
  it("loads through the public registry with SLIP-0044 coin type 236", async () => {
    const chain = await blockchains.bitcoinsv()();
    expect(chain).toBeInstanceOf(NamedBitcoinSV);
    expect(chain.name).toBe("bitcoinsv");
    expect(chain.curve).toBe("secp256k1");
    expect(getBlockchainPath(chain, 0, 1, 3)).toBe("m/44'/236'/0'/1/3");
    expect(() => new BitcoinSV({ network: "regtest" })).toThrow("mainnet and testnet only");
  });

  it("writes key 1 as Bitcoin's P2PKH address on mainnet and testnet", () => {
    const mainnet = new BitcoinSV();
    const testnet = new BitcoinSV({ network: "testnet" });
    expect(mainnet.getKeyPublic(vector.keyOne.privateKey)).toBe(vector.keyOne.publicKey);
    expect(mainnet.getAddress(vector.keyOne.publicKey)).toBe(vector.keyOne.address);
    expect(mainnet.getAddress(vector.keyOne.publicKey, "legacy")).toBe(vector.keyOne.address);
    expect(new Bitcoin().getAddress(vector.keyOne.publicKey)).toBe(vector.keyOne.address);
    expect(testnet.getAddress(vector.keyOne.publicKey)).toBe(vector.keyOne.testnetAddress);
  });

  it("refuses every address type but legacy and bytes that are not a point", () => {
    const chain = new BitcoinSV();
    for (const type of ["p2sh", "segwit", "p2wsh", "taproot", "cashaddr"]) {
      expect(() => chain.getAddress(vector.keyOne.publicKey, type)).toThrow("legacy P2PKH only");
    }
    expect(() => chain.getAddress("02" + "00".repeat(32))).toThrow();
  });

  it("keeps each network to its own version byte", () => {
    const mainnet = new BitcoinSV();
    const testnet = new BitcoinSV({ network: "testnet" });
    expect(mainnet.validateAddress(vector.keyOne.address)).toBe(true);
    expect(testnet.validateAddress(vector.keyOne.testnetAddress)).toBe(true);
    expect(mainnet.validateAddress(vector.keyOne.testnetAddress)).toBe(false);
    expect(testnet.validateAddress(vector.keyOne.address)).toBe(false);
  });

  it("refuses P2SH, which Genesis stopped paying to, and formats the chain never had", () => {
    const chain = new BitcoinSV();
    expect(chain.validateAddress(vector.p2shAddress)).toBe(false);
    expect(chain.validateAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")).toBe(false);
    expect(chain.validateAddress(bitcoinCashTestVectors.keyOne.address)).toBe(false);
    expect(chain.validateAddress(vector.keyOne.address.replace(/H$/u, "J"))).toBe(false);
    expect(chain.validateAddress("")).toBe(false);
  });

  it("signs the BSV SDK message vector byte for byte", () => {
    const chain = new BitcoinSV();
    const privateKey = privateKeyOf(vector.signed.wif);
    const signature = chain.signMessage(vector.signed.message, privateKey);
    expect(signature).toBe(compactToRS(vector.signed.signature));
    expect(
      chain.verifyMessage(vector.signed.message, signature, chain.getKeyPublic(privateKey)),
    ).toBe(true);
  });

  it("verifies the BSV SDK signature and rejects another message", () => {
    const chain = new BitcoinSV();
    const { publicKey, message, signature } = vector.verified;
    expect(chain.verifyMessage(message, compactToRS(signature), publicKey)).toBe(true);
    expect(chain.verifyMessage(`${message}!`, compactToRS(signature), publicKey)).toBe(false);
  });

  it("signs with Bitcoin's preamble, so both chains give one signature", () => {
    const chain = new BitcoinSV();
    const bitcoin = new Bitcoin();
    for (const message of Object.values(testMessages)) {
      const signature = chain.signMessage(message, vector.keyOne.privateKey);
      expect(signature).toBe(bitcoin.signMessage(message, vector.keyOne.privateKey));
    }
    expect(() =>
      chain.signMessage("hello", vector.keyOne.privateKey, { recovered: true }),
    ).toThrow();
  });

  it.each(vector.hd.wifs)("derives %s to the key the BSV SDK gives", (path, wif) => {
    const wallet = new BitcoinSV().deriveHDWallet(vector.hd.mnemonic, path);
    expect(wallet.keys.private).toBe(privateKeyOf(wif));
    expect(wallet.address).toBe(new Bitcoin().getAddress(wallet.keys.public));
  });
});
