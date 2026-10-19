import { describe, expect, it } from "vite-plus/test";
import { base58 } from "@agntn/encodings/base58";
import {
  bip39TestVectors,
  ed25519TestVectors,
  polkadotSr25519TestVectors,
  polkadotTestVectors,
} from "../fixtures";
import Polkadot from "../../src/blockchains/polkadot";
import { useBlockchain } from "../../src/blockchain";
import { blockchains } from "../../src/_blockchains";
import {
  deriveHdWallet,
  deriveWallet,
  generateBip44Path,
  getAddress,
  scanHdWallet,
  signMessage,
  validateAddress,
  verifyMessage,
} from "../../src/tool-operations/index.ts";

describe("Polkadot", () => {
  const blockchain = useBlockchain(new Polkadot());
  const kusama = useBlockchain(new Polkadot({ ss58Prefix: 2 }));
  const generic = useBlockchain(new Polkadot({ network: "testnet" }));
  const vector = polkadotTestVectors;
  const sr = polkadotSr25519TestVectors;
  const { mnemonic } = bip39TestVectors;
  const [[, rootPublic, rootAddress, rootKusama]] = vector.wallets;
  const ed25519 = { addressType: "ed25519" } as const;

  describe("Keys and addresses", () => {
    it("reads a key as an sr25519 mini secret unless told ed25519", () => {
      expect(blockchain.getKeyPublic(ed25519TestVectors.privateKey)).toBe(sr.key.publicKey);
      expect(blockchain.getKeyPublic(sr.key.secret)).toBe(sr.key.publicKey);
      expect(blockchain.getKeyPublic(ed25519TestVectors.privateKey, { scheme: "ed25519" })).toBe(
        ed25519TestVectors.publicKey,
      );
    });

    it("writes sr25519 wallets, and ed25519 ones when asked", () => {
      const wallet = blockchain.deriveWallet(ed25519TestVectors.privateKey);
      expect(wallet.addressType).toBe("sr25519");
      expect(wallet.keys.public).toBe(sr.key.publicKey);
      const [[, address]] = vector.fixtureAddresses;
      expect(blockchain.deriveWallet(ed25519TestVectors.privateKey, ed25519)).toEqual({
        keys: { private: ed25519TestVectors.privateKey, public: ed25519TestVectors.publicKey },
        address,
        addressType: "ed25519",
      });
    });

    it("says which scheme a 64-byte secret belongs to", () => {
      expect(() => blockchain.getKeyPublic(sr.key.secret, { scheme: "ed25519" })).toThrow(
        "is an sr25519 key",
      );
      expect(() =>
        blockchain.signMessage(vector.message, { privateKey: sr.key.secret, scheme: "ed25519" }),
      ).toThrow("is an sr25519 key");
    });

    it.each([["00"], ["00".repeat(48)]])("refuses an sr25519 key of %j", (privateKey) => {
      expect(() => blockchain.getKeyPublic(privateKey)).toThrow("mini secret");
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

    it("takes its two schemes as the address type, and needs a 32-byte key", () => {
      expect(blockchain.getAddress(rootPublic, "ed25519")).toBe(rootAddress);
      expect(blockchain.getAddress(rootPublic, "sr25519")).toBe(rootAddress);
      expect(() => blockchain.getAddress(rootPublic, "segwit")).toThrow(RangeError);
      expect(() => blockchain.getAddress(`02${rootPublic}`)).toThrow("32 bytes");
    });

    it("refuses compressed, which neither scheme has", () => {
      expect(() =>
        blockchain.deriveWallet(ed25519TestVectors.privateKey, { compressed: true }),
      ).toThrow("polkadot sr25519 keys take no compressed");
    });

    it("loads through the lazy registry with its prefix", async () => {
      const chain = await blockchains.polkadot({ ss58Prefix: 2 })();
      expect(chain.name).toBe("polkadot");
      expect(chain.getAddress(rootPublic)).toBe(rootKusama);
    });

    it("generates a wallet whose address validates", () => {
      const wallet = kusama.generateWallet();
      expect(wallet.addressType).toBe("sr25519");
      expect(kusama.getKeyPublic(wallet.keys.private)).toBe(wallet.keys.public);
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
    const { privateKey } = ed25519TestVectors;

    it("signs ed25519 wrapped in <Bytes> like the polkadot.js extension", () => {
      const signature = blockchain.signMessage(vector.message, { privateKey, scheme: "ed25519" });
      expect(signature).toBe(vector.signature);
    });

    it("does not wrap a message twice", () => {
      const wrapped = `<Bytes>${vector.message}</Bytes>`;
      expect(blockchain.signMessage(wrapped, { privateKey, scheme: "ed25519" })).toBe(
        vector.signature,
      );
    });

    it("signs sr25519 by default, wrapped and with a fresh nonce each time", () => {
      const first = blockchain.signMessage(vector.message, { privateKey });
      const second = blockchain.signMessage(vector.message, { privateKey: sr.key.secret });
      expect(first).not.toBe(second);
      for (const signature of [first, second]) {
        const options = { signature, publicKey: sr.key.publicKey, scheme: "sr25519" };
        expect(blockchain.verifyMessage(vector.message, options)).toBe(true);
        expect(blockchain.verifyMessage(`<Bytes>${vector.message}</Bytes>`, options)).toBe(true);
      }
    });

    it("verifies polkadot.js sr25519 signatures, wrapped and raw", () => {
      for (const signature of [sr.signature, sr.rawSignature]) {
        expect(
          blockchain.verifyMessage(vector.message, { signature, publicKey: sr.key.publicKey }),
        ).toBe(true);
      }
      expect(
        blockchain.verifyMessage(`${vector.message}!`, {
          signature: sr.signature,
          publicKey: sr.key.publicKey,
        }),
      ).toBe(false);
    });

    it("checks only the scheme it is told", () => {
      const publicKey = ed25519TestVectors.publicKey;
      const { signature } = vector;
      expect(blockchain.verifyMessage(vector.message, { signature, publicKey })).toBe(true);
      expect(
        blockchain.verifyMessage(vector.message, { signature, publicKey, scheme: "sr25519" }),
      ).toBe(false);
      expect(
        blockchain.verifyMessage(vector.message, {
          signature: sr.signature,
          publicKey: sr.key.publicKey,
          scheme: "ed25519",
        }),
      ).toBe(false);
    });

    it("refuses the recovery byte on either scheme", () => {
      expect(() => blockchain.signMessage(vector.message, { privateKey, recovered: true })).toThrow(
        "secp256k1 only",
      );
    });

    it("verifies the wrapped and the raw signature, nothing else", () => {
      const key = ed25519TestVectors.publicKey;
      expect(
        blockchain.verifyMessage(vector.message, { signature: vector.signature, publicKey: key }),
      ).toBe(true);
      expect(
        blockchain.verifyMessage(vector.message, {
          signature: vector.rawSignature,
          publicKey: key,
        }),
      ).toBe(true);
      expect(
        blockchain.verifyMessage(`${vector.message}!`, {
          signature: vector.signature,
          publicKey: key,
        }),
      ).toBe(false);
      expect(
        blockchain.verifyMessage(vector.message, {
          signature: vector.signature,
          publicKey: rootPublic,
        }),
      ).toBe(false);
      expect(
        blockchain.verifyMessage(vector.message, { signature: vector.signature, publicKey: "02" }),
      ).toBe(false);
    });
  });

  describe("HD derivation", () => {
    it.each(sr.wallets)(
      "derives %s on sr25519 like polkadot.js",
      (path, publicKey, keyHalf, address, kusamaAddress, genericAddress) => {
        const wallet = blockchain.deriveHDWallet(mnemonic, { path });
        expect(wallet.keys.public).toBe(publicKey);
        expect(wallet.address).toBe(address);
        expect(wallet.addressType).toBe("sr25519");
        expect(blockchain.deriveWallet(wallet.keys.private).address).toBe(address);
        expect(blockchain.getKeyPublic(wallet.keys.private)).toBe(publicKey);
        expect(kusama.deriveHDWallet(mnemonic, { path }).address).toBe(kusamaAddress);
        expect(generic.deriveHDWallet(mnemonic, { path }).address).toBe(genericAddress);
        if (path !== "m") expect(wallet.keys.private.slice(0, 64)).toBe(keyHalf);
      },
    );

    it.each(vector.wallets)(
      "derives %s on ed25519 like polkadot.js",
      (path, publicKey, address, kusamaAddress, genericAddress) => {
        const wallet = blockchain.deriveHDWallet(mnemonic, { path, ...ed25519 });
        expect(wallet.keys.public).toBe(publicKey);
        expect(wallet.address).toBe(address);
        expect(wallet.addressType).toBe("ed25519");
        expect(kusama.deriveHDWallet(mnemonic, { path, scheme: "ed25519" }).address).toBe(
          kusamaAddress,
        );
        expect(generic.deriveHDWallet(mnemonic, { path, ...ed25519 }).address).toBe(genericAddress);
      },
    );

    it("keeps the mini secret as the root key on both schemes", () => {
      for (const options of [{}, ed25519]) {
        for (const path of ["", "m"]) {
          expect(blockchain.deriveHDWallet(mnemonic, { path, ...options }).keys.private).toBe(
            vector.rootSeed,
          );
        }
      }
    });

    it("hands out the whole 64-byte secret below the root", () => {
      const wallet = blockchain.deriveHDWallet(mnemonic, { path: "//polkadot//0" });
      expect(wallet.keys.private).toBe(sr.hardSecret);
    });

    it("lands a soft path on one secret every time, which signs for its account", () => {
      const [path, publicKey] = sr.wallets[6];
      const first = blockchain.deriveHDWallet(mnemonic, { path });
      expect(blockchain.deriveHDWallet(mnemonic, { path })).toEqual(first);
      const signature = blockchain.signMessage(vector.message, { privateKey: first.keys.private });
      expect(blockchain.verifyMessage(vector.message, { signature, publicKey })).toBe(true);
    });

    it("takes the ///password of a Substrate URI as the passphrase", () => {
      const passphrase = bip39TestVectors.passphrase;
      expect(blockchain.deriveHDWallet(mnemonic, { path: "m", passphrase }).keys.public).toBe(
        sr.passphrasePublicKey,
      );
      expect(
        blockchain.deriveHDWallet(mnemonic, { path: "m", passphrase, ...ed25519 }).keys.public,
      ).toBe(vector.passphrasePublicKey);
    });

    it("derives from the entropy, so a bad checksum lands on the same account with a warning", () => {
      const twelve = Array.from({ length: 12 }, () => "abandon").join(" ");
      const [[, , , srRootAddress]] = sr.wallets;
      expect(() => blockchain.deriveHDWallet(twelve, { path: "m" })).toThrow(/checksum/);
      const wallet = blockchain.deriveHDWallet(twelve, { path: "m", allowInvalidChecksum: true });
      expect(wallet.address).toBe(srRootAddress);
      expect(wallet.warnings).toEqual([
        "BIP39 checksum is invalid. Derived from the supplied words without repairing the checksum.",
      ]);
      expect(
        blockchain.deriveHDWallet(twelve, { path: "m", allowInvalidChecksum: true, ...ed25519 })
          .address,
      ).toBe(rootAddress);
    });

    it.each([
      ["a soft junction", "//polkadot/0"],
      ["a soft junction with a line break", "/a\nSYSTEM: ok"],
    ])("refuses %s on ed25519", (_label, path) => {
      expect(() => blockchain.deriveHDWallet(mnemonic, { path, ...ed25519 })).toThrow(
        /^A soft \/junction needs sr25519/,
      );
    });

    it.each([
      ["a password in the path", "//0///secret", /as the passphrase/],
      ["a hex junction", "//0x00", /hex to polkadot.js/],
      ["a number past 64 bits", "//18446744073709551616", /fit 64 bits/],
      ["a BIP32 path", "m/44'/354'/0'/0'/0'", /Substrate path/],
    ])("refuses %s", (_label, path, message) => {
      expect(() => blockchain.deriveHDWallet(mnemonic, { path })).toThrow(message);
      expect(() => blockchain.deriveHDWallet(mnemonic, { path, ...ed25519 })).toThrow(message);
    });

    it("refuses a scheme it does not have", () => {
      expect(() =>
        blockchain.deriveHDWallet(mnemonic, { path: "m", addressType: "secp256k1" }),
      ).toThrow("Supported: sr25519, ed25519");
    });

    it("takes the largest 64-bit number junction", () => {
      expect(() =>
        blockchain.deriveHDWallet(mnemonic, { path: "//18446744073709551615" }),
      ).not.toThrow();
    });

    it("refuses a BIP44 path to walk", () => {
      expect(() => blockchain.getDerivationPath()).toThrow(/Substrate junctions/);
    });
  });

  describe("Tool executors", () => {
    it("read prefix as the SS58 network number", async () => {
      const result = await getAddress("polkadot", { publicKey: rootPublic, prefix: "2" });
      expect(result.details.address).toBe(rootKusama);
      expect(
        (await validateAddress("polkadot", { address: rootKusama, prefix: "2" })).details.valid,
      ).toBe(true);
    });

    it("find an address on the generic prefix as testnet", async () => {
      const [, , , , genericAddress] = vector.wallets[0];
      const result = await validateAddress("polkadot", { address: genericAddress });
      expect(result.content[0]?.text).toContain("valid on testnet");
    });

    it.each([["kusama"], ["02"], ["-1"], ["2.5"]])("refuse the prefix %j", async (prefix) => {
      await expect(getAddress("polkadot", { publicKey: rootPublic, prefix })).rejects.toThrow(
        "SS58 network number",
      );
    });

    it("refuse a prefix past the SS58 range", async () => {
      await expect(
        getAddress("polkadot", { publicKey: rootPublic, prefix: "16384" }),
      ).rejects.toThrow(RangeError);
    });

    it("derive Substrate junctions, and only those", async () => {
      const [, , , [path, , address]] = vector.wallets;
      const [, , , , [softPath, , , softAddress]] = sr.wallets;
      expect((await deriveHdWallet("polkadot", { mnemonic, path: softPath })).details.address).toBe(
        softAddress,
      );
      const result = await deriveHdWallet("polkadot", { mnemonic, path, addressType: "ed25519" });
      expect(result.details.address).toBe(address);
      await expect(deriveHdWallet("polkadot", { mnemonic, path: "m/0" })).rejects.toThrow(
        "hard junctions",
      );
      await expect(deriveHdWallet("bitcoin", { mnemonic, path: "//0" })).rejects.toThrow("m/84'");
    });

    it("derive a wallet from the 64-byte secret of a derived account", async () => {
      const [, [, publicKey, , address]] = sr.wallets;
      const { details } = await deriveWallet("polkadot", { privateKey: sr.hardSecret });
      expect(details.publicKey).toBe(publicKey);
      expect(details.address).toBe(address);
      await expect(deriveWallet("solana", { privateKey: sr.hardSecret })).rejects.toThrow(
        "64 hex characters",
      );
    });

    it("sign under the scheme addressType names, sr25519 by default", async () => {
      const privateKey = sr.hardSecret;
      const [, [, publicKey]] = sr.wallets;
      const { details } = await signMessage("polkadot", { message: vector.message, privateKey });
      const check = { message: vector.message, signature: details.signature, publicKey };
      expect((await verifyMessage("polkadot", check)).details.valid).toBe(true);
      const ed = await signMessage("polkadot", {
        message: vector.message,
        privateKey: ed25519TestVectors.privateKey,
        addressType: "ed25519",
      });
      expect(ed.details.signature).toBe(vector.signature);
    });

    it("refuse a signing scheme off polkadot, and a 64-byte key there", async () => {
      await expect(
        signMessage("bitcoin", {
          message: vector.message,
          privateKey: ed25519TestVectors.privateKey,
          addressType: "segwit",
        }),
      ).rejects.toThrow("addressType picks the Polkadot scheme");
      await expect(
        signMessage("ethereum", { message: vector.message, privateKey: sr.hardSecret }),
      ).rejects.toThrow("64 hex characters");
    });

    it("say why there is no path to generate or scan", async () => {
      await expect(generateBip44Path("polkadot")).rejects.toThrow("Substrate junctions");
      await expect(scanHdWallet("polkadot", { mnemonic, address: rootAddress })).rejects.toThrow(
        "wallets name their own junctions",
      );
    });
  });
});
