import { describe, expect, it } from "vite-plus/test";
import { hex } from "@agntn/encodings/hex";
import { HDKey } from "@scure/bip32";
import {
  deriveEntropy,
  deriveHex,
  deriveMnemonic,
  deriveWif,
  deriveXprv,
} from "../../src/utils/bip85/index.ts";
import { decode as decodeWIF } from "../../src/utils/wif/index.ts";
import { bip32ParentVector, bip85Vectors } from "../fixtures.ts";

const { root } = bip85Vectors;

/** The BIP85 root as a testnet master, same key and chain code under tprv. */
const testnetRoot = new HDKey({
  versions: { private: 0x04358394, public: 0x043587cf },
  chainCode: HDKey.fromExtendedKey(root).chainCode ?? undefined,
  privateKey: HDKey.fromExtendedKey(root).privateKey ?? undefined,
}).privateExtendedKey;

describe("BIP85 entropy", () => {
  it.each(bip85Vectors.cases)("derives the entropy at $path", ({ path, entropy }) => {
    expect(hex.encode(deriveEntropy(root, path))).toBe(entropy);
  });

  it("reads h as the hardened marker and takes an HDKey node", () => {
    const [first] = bip85Vectors.cases;
    expect(hex.encode(deriveEntropy(HDKey.fromExtendedKey(root), "m/83696968h/0h/0h"))).toBe(
      first.entropy,
    );
  });

  it.each([
    ["a normal level", "m/83696968'/0'/0", "BIP85 walks hardened levels only, and level 3"],
    ["another purpose", "m/44'/0'/0'", "A BIP85 path starts with m/83696968'"],
    ["the purpose alone", "m", "A BIP85 path starts with m/83696968'"],
  ])("refuses %s", (_, path, message) => {
    expect(() => deriveEntropy(root, path)).toThrow(message);
  });

  it("refuses an xpub, a key below the master and a yprv-shaped prefix", () => {
    expect(() => deriveEntropy(bip32ParentVector.xpub, "m/83696968'/0'/0'")).toThrow(
      "must be a private key, not an xpub",
    );
    expect(() => deriveEntropy(bip32ParentVector.child.xprv, "m/83696968'/0'/0'")).toThrow(
      "BIP85 starts from the master key at depth 0, not depth 1",
    );
    const yprv = new HDKey({
      versions: { private: 0x049d7878, public: 0x049d7cb2 },
      chainCode: new Uint8Array(32).fill(1),
      privateKey: new Uint8Array(32).fill(2),
    }).privateExtendedKey;
    expect(() => deriveEntropy(yprv, "m/83696968'/0'/0'")).toThrow("an xprv or a tprv");
  });

  it("never echoes the root key in an error", () => {
    const broken = `${root.slice(0, -1)}c`;
    expect(() => deriveEntropy(broken, "m/83696968'/0'/0'")).toThrow(/^(?!.*xprv9s).*$/u);
    expect(() => deriveEntropy(broken, "m/83696968'/0'/0'")).toThrow("Invalid BIP85 root key");
  });
});

describe("BIP85 applications", () => {
  it.each(bip85Vectors.mnemonics)(
    "writes the $words-word mnemonic",
    async ({ words, path, entropy, mnemonic }) => {
      const child = await deriveMnemonic(root, { words });
      expect(child.path).toBe(path);
      expect(hex.encode(child.entropy)).toBe(entropy);
      expect(child.mnemonic).toBe(mnemonic);
    },
  );

  it("puts the language and the index into the path", async () => {
    const child = await deriveMnemonic(root, { language: "czech", words: 15, index: 7 });
    expect(child.path).toBe("m/83696968'/39'/8'/15'/7'");
    expect(child.entropy).toHaveLength(20);
    expect(child.mnemonic.split(" ")).toHaveLength(15);
  });

  it("writes the HD seed WIF, and a testnet one from a tprv", () => {
    const { path, entropy, wif } = bip85Vectors.wif;
    const child = deriveWif(root);
    expect(child).toMatchObject({ path, wif });
    expect(hex.encode(child.entropy)).toBe(entropy);
    const testnet = deriveWif(testnetRoot);
    expect(testnet.wif).toMatch(/^c/u);
    expect(decodeWIF(testnet.wif, { chain: "bitcoin", network: "testnet" })).toMatchObject({
      privateKey: entropy,
      compressed: true,
    });
  });

  it("writes the child xprv with BIP85's reversed halves, and a tprv from a tprv", () => {
    const { path, privateKey, extendedPrivateKey } = bip85Vectors.xprv;
    const child = deriveXprv(root);
    expect(child.path).toBe(path);
    expect(child.extendedPrivateKey).toBe(extendedPrivateKey);
    expect(hex.encode(child.entropy.slice(32))).toBe(privateKey);
    const node = HDKey.fromExtendedKey(child.extendedPrivateKey);
    expect(node.chainCode).toEqual(child.entropy.slice(0, 32));
    expect(node).toMatchObject({ depth: 0, index: 0, parentFingerprint: 0 });
    expect(deriveXprv(testnetRoot).extendedPrivateKey).toMatch(/^tprv/u);
  });

  it("keeps the leading bytes for hex", () => {
    const { path, entropy } = bip85Vectors.hex;
    const child = deriveHex(root);
    expect(child.path).toBe(path);
    expect(hex.encode(child.entropy)).toBe(entropy);
    const short = deriveHex(root, { bytes: 16, index: 1 });
    expect(short.path).toBe("m/83696968'/128169'/16'/1'");
    expect(hex.encode(short.entropy)).toBe(
      hex.encode(deriveEntropy(root, short.path).slice(0, 16)),
    );
  });

  it.each([
    ["a word count", () => deriveMnemonic(root, { words: 13 }), "12, 15, 18, 21 or 24 words"],
    [
      "a language",
      /* @ts-expect-error a language outside the BIP39 lists on purpose */
      () => deriveMnemonic(root, { language: "klingon" }),
      "Unknown BIP39 language",
    ],
    ["an index", () => deriveWif(root, { index: 2 ** 31 }), "between 0 and 2147483647"],
    ["a fractional index", () => deriveXprv(root, { index: 1.5 }), "between 0 and 2147483647"],
    ["too few bytes", () => deriveHex(root, { bytes: 15 }), "16 to 64 bytes"],
    ["too many bytes", () => deriveHex(root, { bytes: 65 }), "16 to 64 bytes"],
    [
      "positional options",
      /* @ts-expect-error the index where the options object goes */
      () => deriveWif(root, 3),
      "Pass the options as an object",
    ],
  ])("refuses %s outside the BIP85 tables", async (_, call, message) => {
    await expect((async () => await call())()).rejects.toThrow(message);
  });
});
