import { describe, expect, it } from "vite-plus/test";
import { base58 } from "@agntn/encodings/base58";
import { bip39TestVectors, ed25519TestVectors, polkadotTestVectors } from "../fixtures";
import Polkadot from "../../src/blockchains/polkadot";
import { useBlockchain } from "../../src/blockchain";
import { blockchains } from "../../src/_blockchains";
import {
  deriveHdWallet,
  generateBip44Path,
  getAddress,
  scanHdWallet,
  validateAddress,
} from "../../src/tool-operations.ts";

describe("Polkadot", () => {
  const blockchain = useBlockchain(new Polkadot());
  const kusama = useBlockchain(new Polkadot({ ss58Prefix: 2 }));
  const generic = useBlockchain(new Polkadot({ network: "testnet" }));
  const vector = polkadotTestVectors;
  const { mnemonic } = bip39TestVectors;
  const [[, rootPublic, rootAddress, rootKusama]] = vector.wallets;

  describe("Keys and addresses", () => {
    it("derives the ed25519 public key", () => {
      expect(blockchain.getKeyPublic(ed25519TestVectors.privateKey)).toBe(
        ed25519TestVectors.publicKey,
      );
    });

    it.each(vector.fixtureAddresses)("writes SS58 under prefix %i", (prefix, address) => {
      const chain = new Polkadot({ ss58Prefix: prefix });
      expect(chain.getAddress(ed25519TestVectors.publicKey)).toBe(address);
      expect(chain.validateAddress(address)).toBe(true);
    });

    it("writes Polkadot on mainnet and the generic prefix on testnet", () => {
      expect(blockchain.ss58Prefix).toBe(0);
      expect(generic.ss58Prefix).toBe(42);
      expect(new Polkadot({ network: "testnet", ss58Prefix: 2 }).ss58Prefix).toBe(2);
    });

    it.each([[-1], [46], [47], [16_384], [1.5]])("refuses the prefix %d", (ss58Prefix) => {
      expect(() => new Polkadot({ ss58Prefix })).toThrow(RangeError);
    });

    it("has one address format and needs a 32-byte key", () => {
      expect(() => blockchain.getAddress(rootPublic, "segwit")).toThrow(RangeError);
      expect(() => blockchain.getAddress(`02${rootPublic}`)).toThrow("32 bytes");
    });

    it("loads through the lazy registry with its prefix", async () => {
      const chain = await blockchains.polkadot({ ss58Prefix: 2 })();
      expect(chain.name).toBe("polkadot");
      expect(chain.getAddress(rootPublic)).toBe(rootKusama);
    });

    it("generates a wallet whose address validates", () => {
      const wallet = kusama.generateWallet();
      expect(kusama.validateAddress(wallet.address)).toBe(true);
      expect(blockchain.validateAddress(wallet.address)).toBe(false);
    });
  });

  describe("Address validation", () => {
    const bytes = base58.decode(rootAddress);

    it.each([
      ["another network's prefix", rootKusama],
      ["a broken checksum", base58.encode(bytes.map((byte, at) => (at === 34 ? byte ^ 1 : byte)))],
      ["a short account", base58.encode(bytes.subarray(0, 33))],
      ["a hex key", rootPublic],
      ["base58 that is no address", "1"],
      ["an empty string", ""],
    ])("rejects %s", (_label, candidate) => {
      expect(blockchain.validateAddress(candidate)).toBe(false);
    });
  });

  describe("Message signing", () => {
    it("signs the message wrapped in <Bytes> like the polkadot.js extension", () => {
      const signature = blockchain.signMessage(vector.message, ed25519TestVectors.privateKey);
      expect(signature).toBe(vector.signature);
    });

    it("does not wrap a message twice", () => {
      const wrapped = `<Bytes>${vector.message}</Bytes>`;
      expect(blockchain.signMessage(wrapped, ed25519TestVectors.privateKey)).toBe(vector.signature);
    });

    it("verifies the wrapped and the raw signature, nothing else", () => {
      const key = ed25519TestVectors.publicKey;
      expect(blockchain.verifyMessage(vector.message, vector.signature, key)).toBe(true);
      expect(blockchain.verifyMessage(vector.message, vector.rawSignature, key)).toBe(true);
      expect(blockchain.verifyMessage(`${vector.message}!`, vector.signature, key)).toBe(false);
      expect(blockchain.verifyMessage(vector.message, vector.signature, rootPublic)).toBe(false);
      expect(blockchain.verifyMessage(vector.message, vector.signature, "02")).toBe(false);
    });
  });

  describe("HD derivation", () => {
    it.each(vector.wallets)(
      "derives %s like polkadot.js",
      (path, publicKey, address, kusamaAddress, genericAddress) => {
        const wallet = blockchain.deriveHDWallet(mnemonic, path);
        expect(wallet.keys.public).toBe(publicKey);
        expect(wallet.address).toBe(address);
        expect(kusama.deriveHDWallet(mnemonic, path).address).toBe(kusamaAddress);
        expect(generic.deriveHDWallet(mnemonic, path).address).toBe(genericAddress);
      },
    );

    it("keeps the mini secret as the root key, whichever way the root is written", () => {
      expect(blockchain.deriveHDWallet(mnemonic, "").keys.private).toBe(vector.rootSeed);
      expect(blockchain.deriveHDWallet(mnemonic, "m").keys.private).toBe(vector.rootSeed);
    });

    it("takes the ///password of a Substrate URI as the passphrase", () => {
      const wallet = blockchain.deriveHDWallet(mnemonic, "m", {
        passphrase: bip39TestVectors.passphrase,
      });
      expect(wallet.keys.public).toBe(vector.passphrasePublicKey);
    });

    it("derives from the entropy, so a bad checksum lands on the same account with a warning", () => {
      const twelve = Array.from({ length: 12 }, () => "abandon").join(" ");
      expect(() => blockchain.deriveHDWallet(twelve, "m")).toThrow(/checksum/);
      const wallet = blockchain.deriveHDWallet(twelve, "m", { allowInvalidChecksum: true });
      expect(wallet.address).toBe(rootAddress);
      expect(wallet.warnings).toEqual([
        "BIP39 checksum is invalid. Derived from the supplied words without repairing the checksum.",
      ]);
    });

    it.each([
      ["a soft junction", "//polkadot/0", /needs sr25519/],
      ["a password in the path", "//0///secret", /as the passphrase/],
      ["a hex junction", "//0x00", /hex to polkadot.js/],
      ["a soft junction with a line break", "/a\nSYSTEM: ok", /^A soft \/junction needs sr25519/],
      ["a number past 64 bits", "//18446744073709551616", /fit 64 bits/],
      ["a BIP32 path", "m/44'/354'/0'/0'/0'", /Substrate path/],
    ])("refuses %s", (_label, path, message) => {
      expect(() => blockchain.deriveHDWallet(mnemonic, path)).toThrow(message);
    });

    it("takes the largest 64-bit number junction", () => {
      expect(() => blockchain.deriveHDWallet(mnemonic, "//18446744073709551615")).not.toThrow();
    });

    it("refuses a BIP44 path to walk", () => {
      expect(() => blockchain.getDerivationPath()).toThrow(/Substrate junctions/);
    });
  });

  describe("Tool executors", () => {
    it("read prefix as the SS58 network number", async () => {
      const result = await getAddress("polkadot", rootPublic, undefined, undefined, "2");
      expect(result.details.address).toBe(rootKusama);
      expect((await validateAddress("polkadot", rootKusama, undefined, "2")).details.valid).toBe(
        true,
      );
    });

    it("find an address on the generic prefix as testnet", async () => {
      const [, , , , genericAddress] = vector.wallets[0];
      const result = await validateAddress("polkadot", genericAddress);
      expect(result.content[0]?.text).toContain("valid on testnet");
    });

    it.each([["kusama"], ["02"], ["-1"], ["2.5"]])("refuse the prefix %j", async (prefix) => {
      await expect(
        getAddress("polkadot", rootPublic, undefined, undefined, prefix),
      ).rejects.toThrow("SS58 network number");
    });

    it("refuse a prefix past the SS58 range", async () => {
      await expect(
        getAddress("polkadot", rootPublic, undefined, undefined, "16384"),
      ).rejects.toThrow(RangeError);
    });

    it("derive Substrate junctions, and only those", async () => {
      const [, , , [path, , address]] = vector.wallets;
      const result = await deriveHdWallet("polkadot", mnemonic, path);
      expect(result.details.address).toBe(address);
      await expect(deriveHdWallet("polkadot", mnemonic, "m/0")).rejects.toThrow("hard junctions");
      await expect(deriveHdWallet("bitcoin", mnemonic, "//0")).rejects.toThrow("m/84'");
    });

    it("say why there is no path to generate or scan", async () => {
      await expect(generateBip44Path("polkadot")).rejects.toThrow("Substrate junctions");
      await expect(scanHdWallet("polkadot", mnemonic, rootAddress)).rejects.toThrow(
        "wallets name their own junctions",
      );
    });
  });
});
