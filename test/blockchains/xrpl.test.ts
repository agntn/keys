import { describe, expect, it } from "vite-plus/test";
import { bip39TestVectors, xrplTestVectors } from "../fixtures";
import XRPL from "../../src/blockchains/xrpl";
import Solana from "../../src/blockchains/solana";
import { blockchains } from "../../src/_blockchains";
import { useBlockchain } from "../../src/blockchain";

describe("XRPL", () => {
  const blockchain = useBlockchain(new XRPL());
  const vector = xrplTestVectors;

  describe("Keys and addresses", () => {
    it("derives a compressed secp256k1 key and its classic address by default", () => {
      const wallet = blockchain.deriveWallet(vector.secp256k1.privateKey);
      expect(wallet.keys.public).toBe(vector.secp256k1.publicKey);
      expect(wallet.address).toBe(vector.secp256k1.address);
      expect(wallet.addressType).toBe("secp256k1");
    });

    it("writes an ed25519 key in XRPL's ED form", () => {
      const wallet = blockchain.deriveWallet(vector.ed25519.privateKey, {}, "ed25519");
      expect(wallet.keys.public).toBe(vector.ed25519.publicKey);
      expect(wallet.address).toBe(vector.ed25519.address);
      expect(wallet.addressType).toBe("ed25519");
    });

    it("reads the curve from the key when no type is given", () => {
      expect(blockchain.getAddress(vector.ed25519.publicKey)).toBe(vector.ed25519.address);
      expect(blockchain.getAddress(vector.ed25519.publicKey.slice(2))).toBe(vector.ed25519.address);
      expect(blockchain.getAddress(vector.secp256k1.publicKey)).toBe(vector.secp256k1.address);
    });

    it("tells a caller holding an ed25519 key to ask for ed25519", () => {
      expect(() => blockchain.getAddress(vector.ed25519.publicKey, "secp256k1")).toThrow(
        "pass ed25519 as the address type",
      );
    });

    it("refuses a type that is no scheme", () => {
      expect(() => blockchain.getAddress(vector.secp256k1.publicKey, "legacy")).toThrow(
        "Supported: secp256k1, ed25519",
      );
    });

    it("refuses compressed: false, since the address hashes the compressed key", () => {
      expect(() =>
        blockchain.deriveWallet(vector.secp256k1.privateKey, { compressed: false }),
      ).toThrow(RangeError);
    });

    it("gives the same address on testnet", () => {
      const testnet = useBlockchain(new XRPL({ network: "testnet" }));
      expect(testnet.deriveWallet(vector.secp256k1.privateKey).address).toBe(
        vector.secp256k1.address,
      );
    });

    it.each(["secp256k1", "ed25519"])("generates a %s wallet whose address validates", (type) => {
      const wallet = blockchain.generateWallet({}, type);
      expect(wallet.addressType).toBe(type);
      expect(blockchain.validateAddress(wallet.address)).toBe(true);
      expect(blockchain.getAddress(wallet.keys.public, type)).toBe(wallet.address);
    });

    it("loads through the lazy registry", async () => {
      const loaded = await blockchains.xrpl()();
      expect(loaded.name).toBe("xrpl");
      expect(loaded.deriveWallet(vector.secp256k1.privateKey).address).toBe(
        vector.secp256k1.address,
      );
    });
  });

  describe("Family seeds", () => {
    it.each(Object.entries(vector.seeds))("derives the %s seed like xrpl.js", (_name, seed) => {
      const wallet = blockchain.deriveSeedWallet(seed.seed);
      expect(wallet.keys.private).toBe(seed.privateKey);
      expect(wallet.keys.public).toBe(seed.publicKey);
      expect(wallet.address).toBe(seed.address);
    });

    it("lets the address type override the scheme the seed names", () => {
      const { secp256k1AsEd25519, ed25519AsSecp256k1 } = vector.crossed;
      const ed = blockchain.deriveSeedWallet(secp256k1AsEd25519.seed, {}, "ed25519");
      expect(ed.address).toBe(secp256k1AsEd25519.address);
      expect(ed.addressType).toBe("ed25519");
      const secp = blockchain.deriveSeedWallet(ed25519AsSecp256k1.seed, { scheme: "secp256k1" });
      expect(secp.address).toBe(ed25519AsSecp256k1.address);
    });

    it("names a mistyped character instead of deriving another wallet", () => {
      const seed = vector.seeds.master.seed;
      expect(() => blockchain.deriveSeedWallet(`${seed.slice(0, -1)}c`)).toThrow(
        "mistyped character",
      );
    });

    it("refuses a classic address passed as a seed", () => {
      expect(() => blockchain.deriveSeedWallet(vector.secp256k1.address)).toThrow(
        "neither secp256k1 (s...) nor ed25519 (sEd...)",
      );
    });

    it("leaves seed strings to the XRP Ledger", () => {
      expect(() => new Solana().deriveSeedWallet(vector.seeds.master.seed)).toThrow(
        "solana has no seed string of its own",
      );
    });
  });

  describe("HD wallets from mnemonics", () => {
    it.each(vector.hd)("derives %s like Wallet.fromMnemonic", (path, publicKey, address) => {
      const wallet = blockchain.deriveHDWallet(bip39TestVectors.mnemonic, path);
      expect(wallet.keys.public).toBe(publicKey);
      expect(wallet.address).toBe(address);
    });

    it("writes the BIP44 path", () => {
      expect(blockchain.getDerivationPath()).toBe("m/44'/144'/0'/0/0");
      expect(blockchain.getDerivationPath(1, 0, 4)).toBe("m/44'/144'/1'/0/4");
    });

    it("refuses ed25519, which no XRPL wallet derives from BIP39 words", () => {
      const [[path]] = vector.hd;
      expect(() =>
        blockchain.deriveHDWallet(bip39TestVectors.mnemonic, path, {}, "ed25519"),
      ).toThrow("secp256k1 only");
      expect(() => blockchain.getDerivationPath(0, 0, 0, { scheme: "ed25519" })).toThrow(
        "secp256k1 only",
      );
    });
  });

  describe("Address validation", () => {
    it.each([vector.secp256k1.address, vector.ed25519.address, vector.seeds.master.address])(
      "accepts %s",
      (address) => {
        expect(blockchain.validateAddress(address)).toBe(true);
      },
    );

    it.each([
      ["a wrong checksum", `${vector.secp256k1.address.slice(0, -1)}x`],
      ["an X-address", vector.xAddress],
      ["a family seed", vector.seeds.master.seed],
      ["a Bitcoin address", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"],
      ["a character outside the alphabet", `${vector.secp256k1.address.slice(0, -1)}0`],
      ["an empty string", ""],
    ])("rejects %s", (_label, address) => {
      expect(blockchain.validateAddress(address)).toBe(false);
    });
  });

  describe("Message signing", () => {
    const { message, signatures } = vector;

    it("signs secp256k1 as DER over SHA-512Half, byte for byte like ripple-keypairs", () => {
      expect(blockchain.signMessage(message, vector.secp256k1.privateKey)).toBe(
        signatures.secp256k1,
      );
    });

    it("signs ed25519 over the raw message, like ripple-keypairs", () => {
      expect(
        blockchain.signMessage(message, vector.ed25519.privateKey, { scheme: "ed25519" }),
      ).toBe(signatures.ed25519);
    });

    it("verifies both, reading the curve from the key", () => {
      expect(
        blockchain.verifyMessage(message, signatures.secp256k1, vector.secp256k1.publicKey),
      ).toBe(true);
      expect(blockchain.verifyMessage(message, signatures.ed25519, vector.ed25519.publicKey)).toBe(
        true,
      );
      expect(
        blockchain.verifyMessage(message, signatures.ed25519, vector.ed25519.publicKey.slice(2)),
      ).toBe(true);
    });

    it("rejects another message, the other key and a signature that is not hex", () => {
      expect(
        blockchain.verifyMessage(`${message}!`, signatures.secp256k1, vector.secp256k1.publicKey),
      ).toBe(false);
      expect(
        blockchain.verifyMessage(message, signatures.ed25519, vector.secp256k1.publicKey),
      ).toBe(false);
      expect(blockchain.verifyMessage(message, "zz", vector.secp256k1.publicKey)).toBe(false);
    });

    it("refuses the recovery byte, which an XRPL signature never carries", () => {
      expect(() =>
        blockchain.signMessage(message, vector.secp256k1.privateKey, { recovered: true }),
      ).toThrow("no recovery byte");
    });
  });
});
