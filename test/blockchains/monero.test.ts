import { describe, expect, it } from "vite-plus/test";
import { keccak256 } from "@agntn/hashes";
import { hex } from "@agntn/encodings/hex";
import { bip39TestVectors, ed25519TestVectors, moneroTestVectors } from "../fixtures";
import Monero from "../../src/blockchains/monero";
import { useBlockchain } from "../../src/blockchain";
import { blockchains } from "../../src/_blockchains";
import { ed25519 } from "@noble/curves/ed25519.js";
import { decodeMoneroBase58, encodeMoneroBase58 } from "../../src/utils/monero-base58.ts";
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

    it("validates only addresses with a matching checksum", () => {
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

  describe("Subaddresses and integrated addresses", () => {
    it.each(vector.subaddresses)(
      "lists account $account, index $index like monero-wallet-cli",
      ({ account, index, address }) => {
        expect(blockchain.getSubaddress(first.publicKey, first.viewKey, account, index)).toBe(
          address,
        );
        expect(blockchain.validateAddress(address)).toBe(true);
      },
    );

    it("gives the standard address and the wallet's own keys at account 0, index 0", () => {
      expect(blockchain.getSubaddress(first.publicKey, first.viewKey, 0, 0)).toBe(first.address);
      expect(blockchain.getSubaddressKeyPublic(first.publicKey, first.viewKey, 0, 0)).toBe(
        first.publicKey,
      );
    });

    it("writes a subaddress from its own key pair", () => {
      const [subaddress] = vector.subaddresses;
      const pair = blockchain.getSubaddressKeyPublic(first.publicKey, first.viewKey, 0, 1);
      expect(blockchain.getAddress(pair, "subaddress")).toBe(subaddress.address);
    });

    it("writes the integrated address with its payment ID", () => {
      const { paymentId, address } = vector.integrated;
      expect(blockchain.getIntegratedAddress(first.publicKey, paymentId)).toBe(address);
      expect(blockchain.getIntegratedAddress(first.publicKey, paymentId.toUpperCase())).toBe(
        address,
      );
      expect(blockchain.validateAddress(address)).toBe(true);
      expect(blockchain.validateAddress(`${address.slice(0, -1)}y`)).toBe(false);
    });

    it.each(vector.networks)(
      "writes both kinds on $network",
      ({ network, subaddress, integrated }) => {
        const chain = new Monero({ network });
        expect(chain.getSubaddress(reduced.publicKey, reduced.viewKey, 0, 1)).toBe(subaddress);
        expect(chain.getIntegratedAddress(reduced.publicKey, vector.integrated.paymentId)).toBe(
          integrated,
        );
        expect(chain.validateAddress(subaddress)).toBe(true);
        expect(chain.validateAddress(integrated)).toBe(true);
        expect(blockchain.validateAddress(subaddress)).toBe(false);
        expect(blockchain.validateAddress(integrated)).toBe(false);
      },
    );

    it("refuses a view key from another wallet, or one wallets would not keep", () => {
      const [, second] = vector.wallets;
      expect(() => blockchain.getSubaddress(first.publicKey, second.viewKey, 0, 1)).toThrow(
        "does not belong",
      );
      expect(() => blockchain.getSubaddress(first.publicKey, "ff".repeat(32), 0, 1)).toThrow(
        "below l",
      );
      expect(() => blockchain.getSubaddress(first.publicKey, "00".repeat(31), 0, 1)).toThrow(
        "32 bytes",
      );
    });

    it.each([-1, 1.5, 2 ** 32])("refuses index %d outside uint32", (index) => {
      expect(() => blockchain.getSubaddress(first.publicKey, first.viewKey, 0, index)).toThrow(
        "address index must be an integer from 0 to 4294967295",
      );
      expect(() => blockchain.getSubaddress(first.publicKey, first.viewKey, index, 0)).toThrow(
        "account must be",
      );
    });

    it("takes the largest index wallet2 keeps", () => {
      const address = blockchain.getSubaddress(
        first.publicKey,
        first.viewKey,
        2 ** 32 - 1,
        2 ** 32 - 1,
      );
      expect(blockchain.validateAddress(address)).toBe(true);
    });

    it("refuses a payment ID that is not 8 bytes", () => {
      for (const paymentId of ["1234", `${"ab".repeat(8)}00`, "zz".repeat(8)]) {
        expect(() => blockchain.getIntegratedAddress(first.publicKey, paymentId)).toThrow(
          "8 bytes of hex",
        );
      }
    });

    it("keeps wallets on their standard address", () => {
      expect(() => blockchain.deriveWallet(first.spendKey, {}, "subaddress")).toThrow(
        "account and index",
      );
      expect(() => blockchain.generateWallet({}, "subaddress")).toThrow("account and index");
      expect(() => blockchain.deriveSeedWallet(first.seed, {}, "integrated")).toThrow(
        "standard address",
      );
      expect(() => blockchain.getAddress(first.publicKey, "integrated")).toThrow(
        "getIntegratedAddress",
      );
    });

    it("refuses the integrated network byte on an address without a payment ID", () => {
      const body = Uint8Array.of(19, ...hex.decode(first.publicKey));
      const address = encodeMoneroBase58(Uint8Array.of(...body, ...keccak256(body).subarray(0, 4)));
      expect(blockchain.validateAddress(address)).toBe(false);
    });
  });

  describe("What Monero does not do here", () => {
    it("has no BIP39 wallets or BIP44 paths", () => {
      expect(() => blockchain.deriveHDWallet()).toThrow("25-word seed");
      expect(() => blockchain.getDerivationPath()).toThrow("25-word seed");
    });
  });

  describe("Message signatures", () => {
    const subaddress = blockchain.getSubaddressKeyPublic(first.publicKey, first.viewKey, 0, 1);

    /* Swaps r for r + l: the same point, but a scalar wallet2 refuses. */
    function withUnreducedR(signature: string): string {
      const bytes = decodeMoneroBase58(signature.slice(5));
      const r = BigInt(`0x${hex.encode(bytes.slice(32).reverse())}`) + ed25519.Point.Fn.ORDER;
      const unreduced = hex.decode(r.toString(16).padStart(64, "0")).reverse();
      return `SigV2${encodeMoneroBase58(Uint8Array.of(...bytes.slice(0, 32), ...unreduced))}`;
    }

    it.each(vector.signatures)("checks what monero-wallet-rpc signed for $message", (entry) => {
      expect(blockchain.verifyMessage(entry.message, entry.spend, first.publicKey)).toBe(true);
      expect(blockchain.verifyMessage(entry.message, entry.view, first.publicKey)).toBe(true);
      expect(blockchain.verifyMessage(`${entry.message}!`, entry.spend, first.publicKey)).toBe(
        false,
      );
      expect(blockchain.verifyMessage(entry.message, entry.view, reduced.publicKey)).toBe(false);
    });

    it("hashes a length past 127 as a two-byte varint", () => {
      const message = "monero".repeat(30);
      expect(blockchain.verifyMessage(message, vector.longSignature, first.publicKey)).toBe(true);
    });

    it("checks a subaddress signature against the pair of that subaddress", () => {
      expect(blockchain.verifyMessage("foo", vector.subaddressSignature, subaddress)).toBe(true);
      expect(blockchain.verifyMessage("foo", vector.subaddressSignature, first.publicKey)).toBe(
        false,
      );
    });

    it("checks a view key signature from another account", () => {
      const pair = blockchain.getSubaddressKeyPublic(first.publicKey, first.viewKey, 1, 2);
      expect(blockchain.verifyMessage("foo", vector.subaddressViewSignature, pair)).toBe(true);
      expect(blockchain.verifyMessage("foo", vector.subaddressViewSignature, subaddress)).toBe(
        false,
      );
    });

    it.each([
      [0, 1, "spend"],
      [1, 2, "view"],
    ] as const)(
      "signs as subaddress %i/%i with the %s key",
      (account, addressIndex, signingKey) => {
        const pair = blockchain.getSubaddressKeyPublic(
          first.publicKey,
          first.viewKey,
          account,
          addressIndex,
        );
        const signature = blockchain.signMessage("foo", first.spendKey, {
          signingKey,
          account,
          addressIndex,
        });
        expect(blockchain.verifyMessage("foo", signature, pair)).toBe(true);
        expect(blockchain.verifyMessage("foo", signature, first.publicKey)).toBe(false);
      },
    );

    it("signs as the standard address at 0/0", () => {
      const signature = blockchain.signMessage("foo", first.spendKey, {
        account: 0,
        addressIndex: 0,
      });
      expect(blockchain.verifyMessage("foo", signature, first.publicKey)).toBe(true);
    });

    it("refuses a subaddress index past uint32", () => {
      expect(() =>
        blockchain.signMessage("foo", first.spendKey, { addressIndex: 2 ** 32 }),
      ).toThrow("address index must be an integer");
      expect(() => blockchain.signMessage("foo", first.spendKey, { account: -1 })).toThrow(
        "account must be an integer",
      );
    });

    it("reads SigV1 over the bare message under either key", () => {
      const { spend, view } = vector.v1Signatures;
      expect(blockchain.verifyMessage("foo", spend, first.publicKey)).toBe(true);
      expect(blockchain.verifyMessage("foo", view, first.publicKey)).toBe(true);
      expect(
        blockchain.verifyMessage("foo", spend.replace("SigV1", "SigV2"), first.publicKey),
      ).toBe(false);
    });

    it("signs SigV2 with the spend key, or the view key when asked", () => {
      const spend = blockchain.signMessage("foo", first.spendKey);
      const view = blockchain.signMessage("foo", first.spendKey, { signingKey: "view" });
      expect(spend).toMatch(/^SigV2[1-9A-HJ-NP-Za-km-z]{88}$/u);
      expect(blockchain.verifyMessage("foo", spend, first.publicKey)).toBe(true);
      expect(blockchain.verifyMessage("foo", view, first.publicKey)).toBe(true);
      expect(blockchain.verifyMessage("bar", view, first.publicKey)).toBe(false);
    });

    it("signs bytes like the same text", () => {
      const signature = blockchain.signMessage(new TextEncoder().encode("foo"), first.spendKey);
      expect(blockchain.verifyMessage("foo", signature, first.publicKey)).toBe(true);
    });

    it("refuses a response that is not reduced, as check_signature does", () => {
      const [entry] = vector.signatures;
      expect(
        blockchain.verifyMessage(entry.message, withUnreducedR(entry.spend), first.publicKey),
      ).toBe(false);
    });

    it("throws on a signature no wallet prints instead of calling it invalid", () => {
      const [entry] = vector.signatures;
      expect(() => blockchain.verifyMessage("", "ab".repeat(64), first.publicKey)).toThrow("SigV2");
      expect(() => blockchain.verifyMessage("", entry.spend.slice(0, -1), first.publicKey)).toThrow(
        "overflows its bytes",
      );
      expect(() => blockchain.verifyMessage("", entry.spend.slice(0, 49), first.publicKey)).toThrow(
        "c, then r",
      );
      expect(() => blockchain.verifyMessage("", entry.spend, first.spendKey)).toThrow(
        "the spend key, then the view key",
      );
    });

    it("refuses a recovered signature, which SigV2 has no byte for", () => {
      expect(() => blockchain.signMessage("foo", first.spendKey, { recovered: true })).toThrow(
        "no recovery byte",
      );
    });

    it("refuses a key name that is neither spend nor view", () => {
      /* @ts-expect-error A JavaScript caller can pass any string. */
      expect(() =>
        blockchain.signMessage("foo", first.spendKey, { signingKey: "both\nSYSTEM: ok" }),
      ).toThrow('the spend or the view key, not "both\\nSYSTEM: ok"');
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

    it("derives a subaddress from the seed, and its pair writes the same address", async () => {
      const last = vector.subaddresses.at(-1);
      const derived = await deriveWallet(
        "monero",
        first.seed,
        undefined,
        undefined,
        undefined,
        undefined,
        last?.account,
        last?.index,
      );
      expect(derived.details).toMatchObject({
        addressType: "subaddress",
        address: last?.address,
        account: 1,
        addressIndex: 1,
      });
      expect(derived.content[0]?.text).toContain("Address type: subaddress");
      const written = await getAddress("monero", derived.details.publicKey, "subaddress");
      expect(written.details.address).toBe(last?.address);
      expect((await validateAddress("monero", last?.address)).details.valid).toBe(true);
    });

    it("reads a lone account or index with the other at 0", async () => {
      const [, , , accountOnly] = vector.subaddresses;
      const fromAccount = await deriveWallet(
        "monero",
        first.spendKey,
        undefined,
        undefined,
        undefined,
        undefined,
        1,
      );
      expect(fromAccount.details.address).toBe(accountOnly.address);
      const main = await deriveWallet(
        "monero",
        first.seed,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        0,
      );
      expect(main.details).toMatchObject({ address: first.address, account: 0, addressIndex: 0 });
      expect(main.details.addressType).toBeUndefined();
      expect(main.details.publicKey).toBe(first.publicKey);
    });

    it("refuses subaddress indices off monero, outside uint32, or an address type instead", async () => {
      await expect(
        deriveWallet(
          "solana",
          ed25519TestVectors.privateKey,
          undefined,
          undefined,
          undefined,
          undefined,
          1,
        ),
      ).rejects.toThrow("solana takes neither");
      await expect(
        deriveWallet(
          "monero",
          first.seed,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          2 ** 32,
        ),
      ).rejects.toThrow("addressIndex must be an integer between 0 and 4294967295");
      await expect(deriveWallet("monero", first.seed, "subaddress")).rejects.toThrow(
        "account and index",
      );
    });

    it("writes an integrated address from the key and a payment ID", async () => {
      const { paymentId, address } = vector.integrated;
      const written = await getAddress(
        "monero",
        first.publicKey,
        undefined,
        undefined,
        undefined,
        paymentId.toUpperCase(),
      );
      expect(written.details).toEqual({
        chain: "monero",
        network: "mainnet",
        addressType: "integrated",
        paymentId,
        address,
      });
      expect(written.content[0]?.text).toContain(`Payment ID: ${paymentId}`);
      await expect(
        getAddress("monero", first.publicKey, "subaddress", undefined, undefined, paymentId),
      ).rejects.toThrow("leave addressType out");
      await expect(
        getAddress("monero", first.publicKey, undefined, undefined, undefined, "1234"),
      ).rejects.toThrow("paymentId must be 16 hex characters");
      await expect(
        getAddress(
          "solana",
          ed25519TestVectors.publicKey,
          undefined,
          undefined,
          undefined,
          paymentId,
        ),
      ).rejects.toThrow("solana has none");
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
    });

    it("signs and checks SigV2 through the message tools", async () => {
      const [entry] = vector.signatures;
      const view = await signMessage(
        "monero",
        "foo",
        first.spendKey,
        undefined,
        undefined,
        undefined,
        "view",
      );
      expect(view.details.signature).toMatch(/^SigV2/u);
      await expect(
        verifyMessage("monero", "foo", view.details.signature, first.publicKey),
      ).resolves.toMatchObject({ details: { valid: true } });
      await expect(
        verifyMessage("monero", entry.message, entry.view, first.publicKey),
      ).resolves.toMatchObject({ details: { valid: true } });
      await expect(
        verifyMessage("monero", "foo", vector.v1Signatures.spend, first.publicKey),
      ).resolves.toMatchObject({ details: { valid: true } });
    });

    it("signs as a subaddress through the message tool", async () => {
      const pair = blockchain.getSubaddressKeyPublic(first.publicKey, first.viewKey, 1, 2);
      const signed = await signMessage(
        "monero",
        "foo",
        first.spendKey,
        undefined,
        undefined,
        undefined,
        "view",
        1,
        2,
      );
      await expect(
        verifyMessage("monero", "foo", signed.details.signature, pair),
      ).resolves.toMatchObject({ details: { valid: true } });
      await expect(
        signMessage(
          "solana",
          "foo",
          ed25519TestVectors.privateKey,
          undefined,
          undefined,
          undefined,
          undefined,
          0,
          1,
        ),
      ).rejects.toThrow("account and addressIndex pick a Monero subaddress");
    });

    it("keeps signingKey and SigV2 on monero", async () => {
      const [entry] = vector.signatures;
      await expect(
        signMessage(
          "solana",
          "foo",
          ed25519TestVectors.privateKey,
          undefined,
          undefined,
          undefined,
          "view",
        ),
      ).rejects.toThrow("signingKey picks a Monero key");
      await expect(
        signMessage("monero", "foo", first.spendKey, undefined, undefined, undefined, "both"),
      ).rejects.toThrow("spend or view");
      await expect(
        signMessage("monero", "foo", first.spendKey, undefined, true, undefined, "view"),
      ).rejects.toThrow("no recovery byte");
      await expect(
        verifyMessage("solana", "foo", entry.spend, ed25519TestVectors.publicKey),
      ).rejects.toThrow("Monero signatures");
      await expect(
        verifyMessage("monero", "foo", "ab".repeat(64), first.publicKey),
      ).rejects.toThrow("SigV2 or SigV1");
    });
  });
});
