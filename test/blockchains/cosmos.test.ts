import { describe, expect, it } from "vite-plus/test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bech32 } from "@agntn/encodings/bech32";
import { bip39TestVectors, cosmosTestVectors, secp256k1TestVectors } from "../fixtures";
import Cosmos from "../../src/blockchains/cosmos";
import { useBlockchain } from "../../src/blockchain";
import { blockchains } from "../../src/_blockchains";
import { getAddress, validateAddress } from "../../src/tool-operations.ts";

describe("Cosmos", () => {
  const blockchain = useBlockchain(new Cosmos());
  const osmosis = useBlockchain(new Cosmos({ prefix: "osmo" }));
  const vector = cosmosTestVectors;
  const [[, privateKey, publicKey, address, osmoAddress]] = vector.wallets;

  describe("Keys and addresses", () => {
    it("derives the compressed public key", () => {
      expect(blockchain.getKeyPublic(privateKey)).toBe(publicKey);
    });

    it("writes bech32 over the key's hash160 under cosmos", () => {
      expect(blockchain.prefix).toBe("cosmos");
      expect(blockchain.getAddress(publicKey)).toBe(address);
      expect(blockchain.getAddress(secp256k1TestVectors.publicKeyCompressed)).toBe(
        vector.fixtureAddress,
      );
    });

    it("hashes the compressed key when it gets the uncompressed one", () => {
      const uncompressed = secp256k1.Point.fromHex(publicKey).toHex(false);
      expect(blockchain.getAddress(uncompressed)).toBe(address);
      expect(() => blockchain.deriveWallet(privateKey, { compressed: false })).toThrow(RangeError);
    });

    it("swaps only the prefix for another chain", () => {
      expect(osmosis.getAddress(publicKey)).toBe(osmoAddress);
      expect(new Cosmos({ prefix: "celestia" }).getAddress(publicKey)).toBe(vector.wallets[0][5]);
    });

    it("writes the same address on testnet", () => {
      expect(new Cosmos({ network: "testnet" }).getAddress(publicKey)).toBe(address);
    });

    it.each([["Osmo"], [""], ["1cosmos"], ["cosmos-hub"], ["a".repeat(31)]])(
      "refuses the prefix %j",
      (prefix) => {
        expect(() => new Cosmos({ prefix })).toThrow(RangeError);
      },
    );

    it("has one address format", () => {
      expect(() => blockchain.getAddress(publicKey, "segwit")).toThrow(RangeError);
    });

    it("loads through the lazy registry with its prefix", async () => {
      const chain = await blockchains.cosmos({ prefix: "osmo" })();
      expect(chain.name).toBe("cosmos");
      expect(chain.deriveWallet(privateKey).address).toBe(osmoAddress);
    });

    it("generates a wallet whose address validates", () => {
      const wallet = osmosis.generateWallet();
      expect(wallet.address.startsWith("osmo1")).toBe(true);
      expect(osmosis.validateAddress(wallet.address)).toBe(true);
    });
  });

  describe("Address validation", () => {
    it("accepts any payload the SDK's default verifier takes under its prefix", () => {
      expect(blockchain.validateAddress(address)).toBe(true);
      expect(blockchain.validateAddress(address.toUpperCase())).toBe(true);
      expect(blockchain.validateAddress(vector.contractAddress)).toBe(true);
      expect(blockchain.validateAddress(vector.shortAddress)).toBe(true);
      expect(blockchain.validateAddress(bech32.encode("cosmos", new Uint8Array(255), 1023))).toBe(
        true,
      );
      expect(osmosis.validateAddress(osmoAddress)).toBe(true);
    });

    it.each([
      ["another chain's prefix", osmoAddress],
      ["a broken checksum", `${address.slice(0, -1)}5`],
      ["no payload at all", vector.emptyAddress],
      ["256 bytes of payload", bech32.encode("cosmos", new Uint8Array(256), 1023)],
      ["mixed case", `${address.slice(0, 10)}${address.slice(10).toUpperCase()}`],
      ["an empty string", ""],
    ])("rejects %s", (_label, candidate) => {
      expect(blockchain.validateAddress(candidate)).toBe(false);
    });
  });

  describe("Message signing", () => {
    it("signs ADR-036 like Keplr's signArbitrary", () => {
      expect(blockchain.signMessage(vector.message, privateKey)).toBe(vector.signature);
    });

    it("verifies against the key, with the signer address under its own prefix", () => {
      expect(blockchain.verifyMessage(vector.message, vector.signature, publicKey)).toBe(true);
      expect(blockchain.verifyMessage(`${vector.message}!`, vector.signature, publicKey)).toBe(
        false,
      );
      expect(osmosis.verifyMessage(vector.message, vector.signature, publicKey)).toBe(false);
      expect(blockchain.verifyMessage(vector.message, `${vector.signature}1b`, publicKey)).toBe(
        false,
      );
      expect(blockchain.verifyMessage(vector.message, vector.signature, "02")).toBe(false);
    });

    it("signs bytes the same as their text", () => {
      const bytes = new TextEncoder().encode(vector.message);
      expect(blockchain.signMessage(bytes, privateKey)).toBe(vector.signature);
    });

    it("refuses a recovery byte", () => {
      expect(() => blockchain.signMessage(vector.message, privateKey, { recovered: true })).toThrow(
        /no recovery byte/,
      );
    });
  });

  describe("HD derivation", () => {
    it.each(vector.wallets)("derives %s like cosmjs", (path, key, _public, account, osmo) => {
      expect(blockchain.deriveHDWallet(bip39TestVectors.mnemonic, path).keys.private).toBe(key);
      expect(blockchain.deriveHDWallet(bip39TestVectors.mnemonic, path).address).toBe(account);
      expect(osmosis.deriveHDWallet(bip39TestVectors.mnemonic, path).address).toBe(osmo);
    });

    it("writes BIP44 under coin type 118", () => {
      expect(blockchain.getDerivationPath()).toBe("m/44'/118'/0'/0/0");
      expect(blockchain.getDerivationPath(1, 0, 3)).toBe("m/44'/118'/1'/0/3");
    });
  });

  describe("Tool executors", () => {
    it("read a blank prefix as left out", async () => {
      const result = await getAddress("cosmos", publicKey, undefined, undefined, " ");
      expect(result.details.address).toBe(address);
    });

    it("keep the prefix when they look for the address on the other network", async () => {
      const result = await validateAddress("cosmos", address, undefined, "osmo");
      expect(result.content[0]?.text).toBe(`${address} is not a valid cosmos address`);
    });

    it("say what a bad prefix looks like", async () => {
      await expect(getAddress("cosmos", publicKey, undefined, undefined, "Osmo")).rejects.toThrow(
        /lowercase letter/,
      );
      await expect(getAddress("ethereum", publicKey, undefined, undefined, "osmo")).rejects.toThrow(
        "Leave it out on ethereum",
      );
    });
  });
});
