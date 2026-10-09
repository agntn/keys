import { describe, expect, it } from "vite-plus/test";
import { keccak256 } from "@agntn/hashes";
import { hex } from "@agntn/encodings/hex";
import { bip39TestVectors, ed25519TestVectors, moneroTestVectors } from "../fixtures";
import Monero from "../../src/blockchains/monero";
import { useBlockchain } from "../../src/blockchain";
import { blockchains } from "../../src/_blockchains";
import { encodeMoneroBase58 } from "../../src/utils/monero-base58.ts";
import {
  deriveHdWallet,
  deriveWallet,
  generateBip44Path,
  getAddress,
  scanHdWallet,
  signMessage,
  validateAddress,
} from "../../src/tool-operations.ts";

describe("Monero", () => {
  const blockchain = useBlockchain(new Monero());
  const vector = moneroTestVectors;
  const [first, , reduced] = vector.wallets;

  describe("Seed words", () => {
    it.each(vector.wallets)("restores $address", (wallet) => {
      expect(blockchain.deriveSeedWallet(wallet.seed)).toEqual({
        keys: { private: wallet.spendKey, public: wallet.publicKey },
        address: wallet.address,
      });
      expect(blockchain.getViewKey(wallet.spendKey)).toBe(wallet.viewKey);
    });

    it("reads 24 words without the checksum word", () => {
      const words = first.seed.split(" ").slice(0, 24).join(" ");
      expect(blockchain.deriveSeedWallet(words).address).toBe(first.address);
    });

    it("matches words by their first three letters, in any case and spacing", () => {
      const prefixes = first.seed
        .split(" ")
        .map((word) => `${word.slice(0, 3).toUpperCase()}zz`)
        .join(" \n\t");
      expect(blockchain.deriveSeedWallet(`  ${prefixes}  `).address).toBe(first.address);
    });

    it("wants whole words when no checksum backs the guess", () => {
      const words = first.seed.split(" ").slice(0, 24);
      words[5] = "physzz";
      expect(() => blockchain.deriveSeedWallet(words.join(" "))).toThrow("Word 6");
    });

    it("refuses a checksum word that does not match", () => {
      const words = first.seed.split(" ");
      words[24] = "lymph";
      expect(() => blockchain.deriveSeedWallet(words.join(" "))).toThrow("checksum failed");
    });

    it.each([23, 26, 12])("refuses %i words", (count) => {
      const words = [...first.seed.split(" "), ...first.seed.split(" ")].slice(0, count);
      expect(() => blockchain.deriveSeedWallet(words.join(" "))).toThrow("25 words");
    });

    it("refuses words off the list", () => {
      expect(() => blockchain.deriveSeedWallet(first.seed.replace("giddy", "qwerty"))).toThrow(
        "Word 3 is not on Monero's English seed list",
      );
    });

    it("refuses a triplet that spells more than 32 bits", () => {
      const words = Array.from({ length: 8 }, () => "abbey zoom zones").join(" ");
      expect(() => blockchain.deriveSeedWallet(words)).toThrow("past 32 bits");
    });
  });

  describe("Keys and addresses", () => {
    it("reduces a private key mod l, as the wallet keeps it", () => {
      const wallet = blockchain.deriveWallet(vector.unreducedKey);
      expect(wallet.keys.private).toBe(reduced.spendKey);
      expect(wallet.address).toBe(reduced.address);
    });

    it("gives both public keys from the spend key", () => {
      expect(blockchain.getKeyPublic(first.spendKey)).toBe(first.publicKey);
      expect(blockchain.getAddress(first.publicKey)).toBe(first.address);
    });

    it.each([
      ["testnet", vector.testnet],
      ["stagenet", vector.stagenet],
    ])("writes the %s address", (network, address) => {
      const chain = new Monero({ network });
      expect(chain.getAddress(reduced.publicKey)).toBe(address);
      expect(chain.validateAddress(address)).toBe(true);
      expect(blockchain.validateAddress(address)).toBe(false);
    });

    it("refuses a network Monero does not run", () => {
      expect(() => new Monero({ network: "regtest" })).toThrow("mainnet, testnet and stagenet");
    });

    it("refuses a key of the wrong size, an address type and a zero key", () => {
      expect(() => blockchain.getAddress(ed25519TestVectors.publicKey)).toThrow("64 bytes");
      expect(() => blockchain.getAddress(first.publicKey, "segwit")).toThrow(RangeError);
      expect(() => blockchain.getKeyPublic("00".repeat(32))).toThrow("zero");
      expect(() => blockchain.getKeyPublic("00".repeat(31))).toThrow("32 bytes");
    });

    it.each([
      ["no curve point", `${"ff".repeat(31)}7f`],
      ["the identity", `01${"00".repeat(31)}`],
      ["a point of order 8", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"],
    ])("refuses a spend key that is %s, like check_address", (_, spend) => {
      const keyPublic = `${spend}${first.publicKey.slice(64)}`;
      expect(() => blockchain.getAddress(keyPublic)).toThrow("main subgroup");
      const body = Uint8Array.of(18, ...hex.decode(keyPublic));
      const address = encodeMoneroBase58(Uint8Array.of(...body, ...keccak256(body).subarray(0, 4)));
      expect(blockchain.validateAddress(address)).toBe(false);
    });

    it("validates only standard addresses with a matching checksum", () => {
      const [, second] = vector.wallets;
      expect(blockchain.validateAddress(second.address)).toBe(true);
      expect(blockchain.validateAddress(`${first.address.slice(0, -1)}n`)).toBe(false);
      expect(blockchain.validateAddress(first.address.slice(0, -1))).toBe(false);
      expect(blockchain.validateAddress(`${first.address}1`)).toBe(false);
      expect(blockchain.validateAddress(first.address.replace("4", "0"))).toBe(false);
      expect(blockchain.validateAddress("")).toBe(false);
    });

    it("generates a wallet whose address validates", async () => {
      const chain = await blockchains.monero()();
      const wallet = chain.generateWallet();
      expect(chain.deriveWallet(wallet.keys.private)).toEqual(wallet);
      expect(chain.validateAddress(wallet.address)).toBe(true);
      expect(wallet.address).toHaveLength(95);
    });
  });

  describe("What Monero does not do here", () => {
    it("has no BIP39 wallets or BIP44 paths", () => {
      expect(() => blockchain.deriveHDWallet()).toThrow("25-word seed");
      expect(() => blockchain.getDerivationPath()).toThrow("25-word seed");
    });

    it("signs no messages yet", () => {
      expect(() => blockchain.signMessage()).toThrow("SigV2");
      expect(() => blockchain.verifyMessage()).toThrow("SigV2");
    });
  });

  describe("Tools", () => {
    it("derives a wallet from seed words or the spend key", async () => {
      const fromSeed = await deriveWallet("monero", first.seed);
      expect(fromSeed.details).toEqual({
        chain: "monero",
        network: "mainnet",
        publicKey: first.publicKey,
        address: first.address,
      });
      const fromKey = await deriveWallet("monero", vector.unreducedKey, undefined, "testnet");
      expect(fromKey.details.address).toBe(vector.testnet);
      await expect(deriveWallet("xrpl", first.seed)).rejects.toThrow("keys_hd_wallet_derive");
      await expect(deriveWallet("monero", `${first.seed} ${"a".repeat(1024)}`)).rejects.toThrow(
        "1024 characters",
      );
    });

    it("writes and checks addresses from the 64-byte key", async () => {
      expect((await getAddress("monero", first.publicKey)).details.address).toBe(first.address);
      await expect(getAddress("monero", ed25519TestVectors.publicKey)).rejects.toThrow(
        "64 bytes of hex",
      );
      await expect(getAddress("solana", first.publicKey)).rejects.toThrow("Monero's spend");
      const checked = await validateAddress("monero", vector.testnet);
      expect(checked.content[0]?.text).toContain("valid on testnet");
      const staged = await validateAddress("monero", vector.stagenet);
      expect(staged.content[0]?.text).toContain("valid on stagenet");
    });

    it("takes stagenet on monero and nowhere else", async () => {
      const wallet = await deriveWallet("monero", reduced.seed, undefined, "stagenet");
      expect(wallet.details.address).toBe(vector.stagenet);
      await expect(
        getAddress("solana", ed25519TestVectors.publicKey, undefined, "stagenet"),
      ).rejects.toThrow("Unsupported network");
    });

    it("points BIP39 words, paths and signatures elsewhere", async () => {
      await expect(
        deriveHdWallet("monero", bip39TestVectors.mnemonic, "m/44'/128'/0'/0/0"),
      ).rejects.toThrow("25-word seed");
      await expect(
        scanHdWallet("monero", bip39TestVectors.mnemonic, first.address),
      ).rejects.toThrow("pass them to keys_wallet_derive");
      await expect(generateBip44Path("monero")).rejects.toThrow("25-word seed");
      await expect(signMessage("monero", "hi", first.spendKey)).rejects.toThrow("SigV2");
    });
  });
});
