import { describe, expect, it } from "vite-plus/test";
import { bip39TestVectors, tonChainWallets, tonTestVectors } from "../fixtures";
import Ton from "../../src/blockchains/ton";
import { useBlockchain } from "../../src/blockchain";
import { blockchains } from "../../src/_blockchains";
import { decodeTonAddress } from "../../src/utils/ton-address";
import { isTonMnemonic } from "../../src/utils/ton-mnemonic";

const VERSIONS = ["v3r2", "v4r2", "v5r1"] as const;

describe("TON", () => {
  const blockchain = useBlockchain(new Ton());
  const testnet = useBlockchain(new Ton({ network: "testnet" }));
  const vector = tonTestVectors;

  describe("TON phrases", () => {
    it("restores the key of a phrase like @ton/crypto", () => {
      const wallet = blockchain.deriveSeedWallet(vector.phrase);
      expect(wallet.keys).toEqual({ private: vector.privateKey, public: vector.publicKey });
      expect(wallet.address).toBe(vector.mainnet.v4r2[2]);
      expect(wallet.addressType).toBe("v4r2");
    });

    it("reads the phrase in any case and spacing", () => {
      const loose = `  ${vector.phrase.toUpperCase().replaceAll(" ", "\n ")} `;
      expect(blockchain.deriveSeedWallet(loose).keys.private).toBe(vector.privateKey);
    });

    it("writes the address type the caller picks", () => {
      expect(blockchain.deriveSeedWallet(vector.phrase, { addressType: "v5r1" }).address).toBe(
        vector.mainnet.v5r1[2],
      );
    });

    it("tells TON phrases from BIP39 ones", () => {
      expect(isTonMnemonic(vector.phrase)).toBe(true);
      expect(isTonMnemonic(bip39TestVectors.mnemonic)).toBe(false);
      expect(isTonMnemonic(vector.lockedPhrase)).toBe(false);
    });

    it("says a locked phrase needs its password", () => {
      expect(() => blockchain.deriveSeedWallet(vector.lockedPhrase)).toThrow(/password/u);
    });

    it("refuses words that fail TON's version check", () => {
      const swapped = vector.phrase.split(" ").reverse().join(" ");
      expect(() => blockchain.deriveSeedWallet(swapped)).toThrow(/version check/u);
    });

    it("names the position of a word off the list, never the word", () => {
      const words = vector.phrase.split(" ");
      words[4] = "zzzz";
      expect(() => blockchain.deriveSeedWallet(words.join(" "))).toThrow(/word 5 is not/u);
    });

    it("refuses another word count", () => {
      expect(() => blockchain.deriveSeedWallet(bip39TestVectors.mnemonic)).toThrow(/24 words/u);
    });

    it("points a TON phrase passed as BIP39 to the seed wallet", () => {
      expect(() =>
        blockchain.deriveHDWallet(vector.phrase, { path: blockchain.getDerivationPath() }),
      ).toThrow(/deriveSeedWallet/u);
    });
  });

  describe("Addresses", () => {
    it.each(VERSIONS)("writes %s in both forms on mainnet", (version) => {
      const [, bounceable, plain] = vector.mainnet[version];
      expect(blockchain.getAddress(vector.publicKey, version)).toBe(plain);
      expect(blockchain.getAddress(vector.publicKey, `${version}-bounceable`)).toBe(bounceable);
    });

    it.each(VERSIONS)("writes %s with the testnet flag on testnet", (version) => {
      const [, bounceable, plain] = vector.testnet[version];
      expect(testnet.getAddress(vector.publicKey, version)).toBe(plain);
      expect(testnet.getAddress(vector.publicKey, `${version}-bounceable`)).toBe(bounceable);
    });

    it("gives the account ID the raw address names", () => {
      for (const version of VERSIONS) {
        const [raw, , plain] = vector.mainnet[version];
        expect(decodeTonAddress(plain)?.hash).toEqual(decodeTonAddress(raw)?.hash);
      }
    });

    it.each(tonChainWallets)("reaches the deployed %s wallet of key %s", (version, key, raw) => {
      const written = decodeTonAddress(blockchain.getAddress(key, version));
      expect(written?.hash).toEqual(decodeTonAddress(raw)?.hash);
    });

    it("refuses a type that names no contract", () => {
      expect(() => blockchain.getAddress(vector.publicKey, "v4r1")).toThrow(/Supported: v3r2/u);
      expect(() => blockchain.getAddress(vector.publicKey, "v4r2-raw")).toThrow(RangeError);
    });

    it("rejects a public key that is not 32 bytes", () => {
      expect(() => blockchain.getAddress(vector.publicKey.slice(2))).toThrow(RangeError);
    });

    it("loads through the lazy registry", async () => {
      const ton = await blockchains.ton()();
      expect(ton.deriveWallet(vector.privateKey).address).toBe(vector.mainnet.v4r2[2]);
    });

    it("generates a wallet whose address validates", () => {
      const wallet = blockchain.generateWallet();
      expect(wallet.addressType).toBe("v4r2");
      expect(blockchain.validateAddress(wallet.address)).toBe(true);
    });
  });

  describe("Address validation", () => {
    it("accepts every form of a mainnet address", () => {
      for (const version of VERSIONS) {
        for (const address of vector.mainnet[version]) {
          expect(blockchain.validateAddress(address)).toBe(true);
        }
      }
    });

    it("accepts the standard base64 alphabet too", () => {
      const standard = vector.mainnet.v4r2[1].replaceAll("-", "+").replaceAll("_", "/");
      expect(blockchain.validateAddress(standard)).toBe(true);
    });

    it("accepts a masterchain address", () => {
      expect(blockchain.validateAddress(`-1:${"ab".repeat(32)}`)).toBe(true);
    });

    it("keeps addresses with the testnet flag to testnet", () => {
      const [, bounceable] = vector.testnet.v4r2;
      expect(blockchain.validateAddress(bounceable)).toBe(false);
      expect(testnet.validateAddress(bounceable)).toBe(true);
      expect(testnet.validateAddress(vector.mainnet.v4r2[1])).toBe(false);
    });

    it.each([
      ["a broken checksum", `${vector.mainnet.v4r2[1].slice(0, -1)}D`],
      [
        "an unknown flag byte under a valid checksum",
        "MQDxrCm53vVUKOIgj1f3IiyjLDYLvaBR9-D5ZxVdH5nXVDow",
      ],
      ["workchain 1 under a valid checksum", "EQHxrCm53vVUKOIgj1f3IiyjLDYLvaBR9-D5ZxVdH5nXVBEe"],
      ["raw workchain 1", `1:${"ab".repeat(32)}`],
      ["a short raw ID", `0:${"ab".repeat(31)}`],
      ["mixed base64 alphabets", "EQDxrCm53vVUKOIgj1f3IiyjLDYLvaBR9+D5ZxVdH5nXVJz_"],
      ["the empty string", ""],
    ])("rejects %s", (_label, address) => {
      expect(blockchain.validateAddress(address)).toBe(false);
    });
  });

  describe("BIP39 wallets", () => {
    it("builds the Trust Wallet path for an account", () => {
      expect(blockchain.getDerivationPath()).toBe("m/44'/607'/0'");
      expect(blockchain.getDerivationPath({ account: 1 })).toBe("m/44'/607'/1'");
      expect(() => blockchain.getDerivationPath({ addressIndex: 1 })).toThrow(RangeError);
    });

    it.each(vector.bip39)("derives %s over SLIP-10", (path, privateKey, v4r2, v5r1) => {
      const wallet = blockchain.deriveHDWallet(bip39TestVectors.mnemonic, { path });
      expect(wallet.keys.private).toBe(privateKey);
      expect(wallet.address).toBe(v4r2);
      expect(blockchain.getAddress(wallet.keys.public, "v5r1")).toBe(v5r1);
    });
  });

  describe("Messages", () => {
    it("signs the raw bytes like @ton/crypto", () => {
      expect(blockchain.signMessage(vector.message, { privateKey: vector.privateKey })).toBe(
        vector.signature,
      );
    });

    it("verifies the signature and rejects another message", () => {
      const options = { signature: vector.signature, publicKey: vector.publicKey };
      expect(blockchain.verifyMessage(vector.message, options)).toBe(true);
      expect(blockchain.verifyMessage("ton you", options)).toBe(false);
    });
  });
});
