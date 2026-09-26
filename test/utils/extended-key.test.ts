import { describe, expect, it } from "vite-plus/test";
import { blockchains } from "../../src/index.ts";
import type { AbstractBlockchain } from "../../src/blockchain.ts";
import { getMasterKeyFromSeed } from "../../src/utils/bip32/index.ts";
import { mnemonicToSeed } from "../../src/utils/bip39/index.ts";
import { decodeBase58Check, encodeBase58Check } from "../../src/utils/encoding.ts";
import { bip39TestVectors, slip132PrivateKey, slip132Vectors } from "../fixtures.ts";

const mnemonic = bip39TestVectors.mnemonic;
const master = getMasterKeyFromSeed(mnemonicToSeed(mnemonic));

/**
 * Serializes the key at an account path under other version bytes, as wallets do per chain.
 * @param path - Hardened account path
 * @param version - Version bytes of the prefix to write
 * @returns {string} The extended public key
 */
function accountKey(path: string, version: number): string {
  const bytes = decodeBase58Check(master.derive(path).publicExtendedKey);
  new DataView(bytes.buffer, bytes.byteOffset).setUint32(0, version, false);
  return encodeBase58Check(bytes);
}

const XPUB = 0x0488b21e;

describe("extended public key derivation", () => {
  it.each(slip132Vectors)(
    "writes the $addressType address a $prefix stands for",
    async (vector) => {
      const bitcoin = await blockchains.bitcoin()();
      expect(bitcoin.deriveXpubWallet(vector.extendedKey, "m/0/0")).toEqual({
        keys: { public: bitcoin.deriveHDWallet(mnemonic, `${vector.path}/0/0`).keys.public },
        address: vector.address,
        prefix: vector.prefix,
        addressType: vector.addressType,
      });
    },
  );

  it("builds the SLIP-0132 accounts from the mnemonic", () => {
    const [xpub, ypub, zpub] = slip132Vectors;
    expect(accountKey(xpub.path, XPUB)).toBe(xpub.extendedKey);
    expect(accountKey(ypub.path, 0x049d7cb2)).toBe(ypub.extendedKey);
    expect(accountKey(zpub.path, 0x04b24746)).toBe(zpub.extendedKey);
  });

  it("lets addressType win over the prefix for a BIP84 account exported as xpub", async () => {
    const bitcoin = await blockchains.bitcoin()();
    const [, , zpub] = slip132Vectors;
    const xpub = accountKey(zpub.path, XPUB);

    expect(bitcoin.deriveXpubWallet(xpub, "m/0/0").address).not.toBe(zpub.address);
    expect(bitcoin.deriveXpubWallet(xpub, "m/0/0", "segwit")).toMatchObject({
      address: zpub.address,
      prefix: "xpub",
      addressType: "segwit",
    });
  });

  it.each([
    ["bitcoin", 0],
    ["bitcoincash", 145],
    ["bitcoingold", 156],
    ["bitcoinsv", 236],
    ["litecoin", 2],
    ["dash", 5],
    ["dogecoin", 3],
    ["zcash", 133],
    ["ecash", 899],
    ["ethereum", 60],
    ["base", 60],
    ["tron", 195],
  ] as const)("reaches the %s address the mnemonic path reaches", async (name, coin) => {
    const chain: AbstractBlockchain = await blockchains[name]()();
    const account = `m/44'/${coin}'/0'`;
    const xpub = accountKey(account, XPUB);
    for (const [below, full] of [
      ["m/0/0", `${account}/0/0`],
      ["m/1/7", `${account}/1/7`],
    ]) {
      const expected = chain.deriveHDWallet(mnemonic, full);
      const wallet = chain.deriveXpubWallet(xpub, below);
      expect(wallet.address, `${name} ${below}`).toBe(expected.address);
      expect(wallet.keys.public).toBe(expected.keys.public);
    }
  });

  it("reads Litecoin's own prefixes and the testnet ones", async () => {
    const litecoin = await blockchains.litecoin()();
    const legacy = litecoin.deriveHDWallet(mnemonic, "m/44'/2'/0'/0/0");
    const p2sh = litecoin.deriveHDWallet(mnemonic, "m/49'/2'/0'/0/0");
    expect(litecoin.deriveXpubWallet(accountKey("m/44'/2'/0'", 0x019da462), "m/0/0")).toMatchObject(
      { address: legacy.address, prefix: "Ltub", addressType: "legacy" },
    );
    expect(litecoin.deriveXpubWallet(accountKey("m/49'/2'/0'", 0x01b26ef6), "m/0/0")).toMatchObject(
      { address: p2sh.address, prefix: "Mtub", addressType: "p2sh" },
    );

    const testnet = await blockchains.bitcoin({ network: "testnet" })();
    const segwit = testnet.deriveHDWallet(mnemonic, "m/84'/1'/0'/0/0");
    expect(testnet.deriveXpubWallet(accountKey("m/84'/1'/0'", 0x045f1cf6), "m/0/0")).toMatchObject({
      address: segwit.address,
      prefix: "vpub",
      addressType: "segwit",
    });
  });

  it("refuses keys and paths a watch-only derivation cannot take, without echoing the key", async () => {
    const bitcoin = await blockchains.bitcoin()();
    const [xpub, , zpub] = slip132Vectors;
    const cases = [
      [slip132PrivateKey, "m/0/0", "Extended private keys are not accepted"],
      [xpub.extendedKey, "m/0'/0", "hardened levels need the private key"],
      [xpub.extendedKey, "m/2147483648", "hardened levels need the private key"],
      [xpub.extendedKey, "m", "hardened levels need the private key"],
      [`${xpub.extendedKey.slice(0, -1)}k`, "m/0", "Invalid extended key encoding or checksum"],
      [xpub.extendedKey.repeat(2), "m/0", "Invalid extended key encoding or checksum"],
      ["1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "m/0", "Invalid extended key encoding or checksum"],
    ] as const;
    for (const [key, path, message] of cases) {
      expect(() => bitcoin.deriveXpubWallet(key, path)).toThrow(message);
      try {
        bitcoin.deriveXpubWallet(key, path);
      } catch (error) {
        expect(String(error)).not.toContain(key.slice(4, 40));
      }
    }

    const testnet = await blockchains.bitcoin({ network: "testnet" })();
    expect(() => testnet.deriveXpubWallet(zpub.extendedKey, "m/0")).toThrow(
      'Extended key "zpub" is not accepted for bitcoin testnet. Accepted: tpub, upub, vpub',
    );
    const ethereum = await blockchains.ethereum()();
    expect(() => ethereum.deriveXpubWallet(zpub.extendedKey, "m/0")).toThrow(
      'Extended key "zpub" is not accepted for ethereum mainnet. Accepted: xpub',
    );
  });

  it.each(["solana", "stellar", "aptos", "cardano", "sui", "decred"] as const)(
    "refuses %s, which has no standard secp256k1 extended public key",
    async (name) => {
      const chain: AbstractBlockchain = await blockchains[name]()();
      expect(() => chain.deriveXpubWallet(slip132Vectors[0].extendedKey, "m/0/0")).toThrow();
    },
  );
});
