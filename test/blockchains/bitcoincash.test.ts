import { describe, expect, it } from "vite-plus/test";
import { blockchains, getBlockchainPath } from "../../src/index.ts";
import Bitcoin from "../../src/blockchains/bitcoin.ts";
import BitcoinCash, { BitcoinCash as NamedBitcoinCash } from "../../src/blockchains/bitcoincash.ts";
import { bitcoinCashTestVectors as vector, testMessages } from "../fixtures.ts";

describe("Bitcoin Cash", () => {
  it("loads through the public registry with SLIP-0044 coin type 145", async () => {
    const chain = await blockchains.bitcoincash()();
    expect(chain).toBeInstanceOf(NamedBitcoinCash);
    expect(chain.name).toBe("bitcoincash");
    expect(chain.curve).toBe("secp256k1");
    expect(getBlockchainPath(chain, 0, 1, 3)).toBe("m/44'/145'/0'/1/3");
    expect(() => new BitcoinCash({ network: "regtest" })).toThrow("mainnet and testnet only");
  });

  it("turns the puzzle 130 mini-puzzle key into its prize address, Bitcoin's hash in CashAddr", () => {
    const chain = new BitcoinCash();
    const wallet = chain.deriveWallet(vector.prize.privateKey);
    expect(wallet.address).toBe(vector.prize.address);
    expect(new Bitcoin().getAddress(wallet.keys.public)).toBe(vector.prize.bitcoinAddress);
  });

  it("writes key 1 as the address libraries quote for it", () => {
    const chain = new BitcoinCash();
    expect(chain.getKeyPublic(vector.keyOne.privateKey)).toBe(vector.keyOne.publicKey);
    expect(chain.getAddress(vector.keyOne.publicKey)).toBe(vector.keyOne.address);
    expect(chain.getAddress(vector.keyOne.publicKey, "legacy")).toBe(vector.keyOne.address);
  });

  it("uses the bchtest prefix on testnet and keeps each network to its own", () => {
    const mainnet = new BitcoinCash();
    const testnet = new BitcoinCash({ network: "testnet" });
    const address = testnet.getAddress(vector.keyOne.publicKey);
    expect(address).toMatch(/^bchtest:q/u);
    expect(testnet.validateAddress(address)).toBe(true);
    expect(mainnet.validateAddress(address)).toBe(false);
    expect(testnet.validateAddress(vector.keyOne.address)).toBe(false);
  });

  it("refuses every address type but legacy and bytes that are not a point", () => {
    const chain = new BitcoinCash();
    for (const type of ["p2sh", "segwit", "p2wsh", "taproot", "cashaddr"]) {
      expect(() => chain.getAddress(vector.keyOne.publicKey, type)).toThrow("legacy P2PKH only");
    }
    expect(() => chain.getAddress("02" + "00".repeat(32))).toThrow();
  });

  it.each(vector.spec.filter(([type, address]) => type < 2 && !address.startsWith("pref")))(
    "validates spec type %i %s on its network only when Bitcoin Cash Node pays to it",
    (type, address, hash) => {
      const testnet = address.startsWith("bchtest:");
      const chain = new BitcoinCash({ network: testnet ? "testnet" : "mainnet" });
      const paid = hash.length === 40 || (type === 1 && hash.length === 64);
      expect(chain.validateAddress(address)).toBe(paid);
      expect(chain.validateAddress(address.slice(address.indexOf(":") + 1))).toBe(paid);
      expect(
        new BitcoinCash({ network: testnet ? "mainnet" : "testnet" }).validateAddress(address),
      ).toBe(false);
    },
  );

  it.each(vector.mainnet)("accepts the CashTokens vector %s", (address) => {
    expect(new BitcoinCash().validateAddress(address)).toBe(true);
  });

  it("refuses base58, which carries Bitcoin's bytes, and a corrupted prize address", () => {
    const chain = new BitcoinCash();
    expect(chain.validateAddress(vector.prize.bitcoinAddress)).toBe(false);
    expect(chain.validateAddress(vector.prize.address.replace(/z$/u, "q"))).toBe(false);
    expect(chain.validateAddress("")).toBe(false);
  });

  it("signs with Bitcoin's preamble, so both chains give one signature", () => {
    const chain = new BitcoinCash();
    const bitcoin = new Bitcoin();
    for (const message of Object.values(testMessages)) {
      const signature = chain.signMessage(message, vector.keyOne.privateKey);
      expect(signature).toBe(bitcoin.signMessage(message, vector.keyOne.privateKey));
      expect(chain.verifyMessage(message, signature, vector.keyOne.publicKey)).toBe(true);
      expect(chain.verifyMessage(`${message}!`, signature, vector.keyOne.publicKey)).toBe(false);
    }
    expect(() =>
      chain.signMessage("hello", vector.keyOne.privateKey, { recovered: true }),
    ).toThrow();
  });

  it.each(vector.hd.addresses)("derives %s to the address Trezor shows", (path, address) => {
    expect(new BitcoinCash().deriveHDWallet(vector.hd.mnemonic, path).address).toBe(address);
  });
});
