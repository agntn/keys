import { hex } from "@agntn/encodings/hex";
import { describe, expect, it } from "vite-plus/test";
import {
  deriveOldMasterPublicKey,
  deriveOldPublicKey,
  deriveSeed,
  inspect,
  normalize,
} from "../../src/utils/electrum/index.ts";
import { decodeLegacyWords } from "../../src/utils/electrum/legacy.ts";
import { normalizeElectrumText } from "../../src/utils/electrum/normalize.ts";
import { deriveElectrumWallet } from "../../src/tool-operations/index.ts";
import { deriveMnemonicKey } from "../../src/utils/hd.ts";
import { electrumOldVectors, electrumVectors } from "../fixtures.ts";

describe("Electrum seed derivation", () => {
  it.each(electrumVectors)("matches upstream seed bytes and addresses: $name", async (vector) => {
    expect(inspect(vector.mnemonic)).toBe(vector.seedType);
    const result = deriveSeed(vector.mnemonic, vector.passphrase);
    expect(hex.encode(result.seed)).toBe(vector.seed);
    expect(result.scheme).toBe("electrum");
    const wallet = await deriveElectrumWallet(vector.mnemonic, {
      path: vector.path,
      passphrase: vector.passphrase,
    });
    expect(wallet.details).toMatchObject({
      address: vector.address,
      publicKey: vector.publicKey,
      seedType: vector.seedType,
      scheme: "electrum",
    });
    expect(wallet.details).not.toHaveProperty("privateKey");
    expect(wallet.details).not.toHaveProperty("seed");
  });

  it("normalizes case, accents and whitespace in phrases and passphrases", () => {
    const vector = electrumVectors[0];
    expect(
      deriveSeed(`  ${vector.mnemonic.toUpperCase().replaceAll(" ", "\n\t")} `, "  CAFÉ\nTEST "),
    ).toEqual(deriveSeed(vector.mnemonic, "cafe test"));
    expect(normalizeElectrumText("a\u034F\uFE0F é \u0903")).toBe("a\u034F\uFE0F e \u0903");
    expect(normalizeElectrumText("眼 \u{20000} 悲")).toBe("眼\u{20000}悲");
    expect(normalizeElectrumText("a\u0085b\u001Cc")).toBe("a b c");
    expect(normalizeElectrumText("\uFEFFa\uFEFF")).toBe("\uFEFFa\uFEFF");
  });

  it.each([
    ["  CAF\u00C9\tTest  ", "cafe test"],
    ["cafe test", "cafe test"],
    ["\u6F22 \u5B57", "\u6F22\u5B57"],
    ["a\u2003b\u3000c\u001Fd", "a b c d"],
    ["\u30AB \u30BF a \uD55C \uAE00", "\u30AB\u30BF a \u1112\u1161\u11AB\u1100\u1173\u11AF"],
    ["a\u034F\uFE0F e\u0301 \u0903", "a\u034F\uFE0F e \u0903"],
  ])("normalizes %j the same on a second pass", (text, expected) => {
    expect(normalize(text)).toBe(expected);
    expect(normalize(expected)).toBe(expected);
    expect(normalize).toBe(normalizeElectrumText);
  });

  it("refuses text the normalizer can't read", () => {
    const refusal = "Electrum text must be well-formed Unicode of at most 4096 characters";
    expect(normalize("\u{1F511}".repeat(4096))).toHaveLength(8192);
    expect(() => normalize("a".repeat(4097))).toThrow(new TypeError(refusal));
    expect(() => normalize("seed \uD83D")).toThrow(new TypeError(refusal));
    /* @ts-expect-error a number is wrong on purpose */
    expect(() => normalize(1)).toThrow(new TypeError(refusal));
  });

  it.each([
    ["cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze", "old"],
    ["8edad31a95e7d59f8837667510d75a4d", "old"],
    ["science dawn member doll dutch real can brick knife deny drive list", "2fa"],
    ["science dawn member doll dutch real can brick knife deny drive list \u0301", "unknown"],
    ["agree install", "2fa_segwit"],
    ["not a seed", "unknown"],
  ])("rejects unsupported versions without exposing the phrase", (phrase, seedType) => {
    expect(inspect(phrase)).toBe(seedType);
    expect(() => deriveSeed(phrase)).toThrow("Unsupported or unrecognized Electrum seed version");
  });

  it.each([12, 13, 19, 20, 21, 24, 25])(
    "preserves Electrum's 2FA classification at %i words",
    (count) => {
      const phrase = "science dawn member doll dutch real can brick knife deny drive list";
      const candidate = phrase + " \u0301".repeat(count - 12);
      expect(normalizeElectrumText(candidate)).toBe(phrase);
      expect(inspect(candidate)).toBe(count === 12 || count >= 20 ? "2fa" : "unknown");
    },
  );

  it("does not confuse BIP39 checksum bypass with Electrum derivation", async () => {
    const vector = electrumVectors[0];
    expect(() =>
      deriveMnemonicKey(vector.mnemonic, { path: vector.path, curve: "secp256k1" }),
    ).toThrow("Invalid BIP39 mnemonic");
    const bip39 = deriveMnemonicKey(vector.mnemonic, {
      path: vector.path,
      curve: "secp256k1",
      passphrase: "",
      allowInvalidChecksum: true,
    });
    const { blockchains } = await import("../../src/index.ts");
    const bitcoin = await blockchains.bitcoin()();
    expect(
      bitcoin.deriveWallet(bip39.privateKey, { compressed: true, addressType: "segwit" }).address,
    ).not.toBe(vector.address);
  });

  it("rejects malformed direct executor inputs", async () => {
    const vector = electrumVectors[0];
    for (const args of [
      [vector.mnemonic, "m/not-a-path"],
      [vector.mnemonic, "m" + "/0".repeat(128)],
      [vector.mnemonic, vector.path, "\uD800"],
      [vector.mnemonic, vector.path, false],
      [vector.mnemonic, vector.path, "", "wrong-network"],
      ["x".repeat(4097), vector.path],
      [vector.mnemonic, vector.path, "x".repeat(4097)],
    ]) {
      await expect(
        deriveElectrumWallet(args[0], { path: args[1], passphrase: args[2], network: args[3] }),
      ).rejects.toThrow();
    }
  });
});

describe("Old Electrum seeds", () => {
  it.each(electrumOldVectors)(
    "matches Electrum's keys and addresses: $name",
    { timeout: 30_000 },
    async (vector) => {
      expect(inspect(vector.mnemonic)).toBe("old");
      const masterPublicKey = deriveOldMasterPublicKey(vector.mnemonic);
      expect(hex.encode(masterPublicKey)).toBe(vector.masterPublicKey);
      for (const child of vector.children) {
        expect(
          hex.encode(
            deriveOldPublicKey(masterPublicKey, { change: child.change, index: child.index }),
          ),
        ).toBe(child.publicKey);
        const wallet = await deriveElectrumWallet(vector.mnemonic, {
          change: child.change,
          index: child.index,
        });
        expect(wallet.details).toEqual({
          chain: "bitcoin",
          network: "mainnet",
          scheme: "electrum",
          seedType: "old",
          masterPublicKey: vector.masterPublicKey,
          change: child.change,
          index: child.index,
          publicKey: child.publicKey,
          address: child.address,
        });
      }
    },
  );

  it("decodes words to the hex seed Electrum stores", () => {
    const [vector] = electrumOldVectors;
    expect(decodeLegacyWords(vector.mnemonic.split(" "))).toBe(vector.hexSeed);
  });

  it.each([
    { form: "the hex seed", seed: electrumOldVectors[0].hexSeed },
    { form: "shouted words", seed: ` ${electrumOldVectors[0].mnemonic.toUpperCase()}\n` },
    { form: "uppercase hex", seed: electrumOldVectors[0].hexSeed.toUpperCase() },
  ])("opens $form", ({ seed }) => {
    expect(hex.encode(deriveOldMasterPublicKey(seed))).toBe(electrumOldVectors[0].masterPublicKey);
  });

  it.each([
    { name: "no path", path: undefined },
    { name: "an empty path", path: "" },
    { name: "a blank path", path: "  " },
  ])("defaults to the first receiving address with $name", async ({ path }) => {
    const [vector] = electrumOldVectors;
    const wallet = await deriveElectrumWallet(vector.mnemonic, { path });
    expect(wallet.details.address).toBe(vector.children[0].address);
  });

  it("writes the first receiving key as a testnet address", async () => {
    const [vector] = electrumOldVectors;
    const [first] = vector.children;
    const testnet = await deriveElectrumWallet(vector.mnemonic, {
      passphrase: "",
      network: "testnet",
    });
    expect(testnet.details).toMatchObject({ network: "testnet", publicKey: first.publicKey });
    expect(testnet.details.address).toMatch(/^[mn]/u);
  });

  it("refuses what Electrum cannot open", () => {
    const masterPublicKey = hex.decode(electrumOldVectors[0].masterPublicKey);
    expect(() => deriveOldMasterPublicKey(electrumVectors[0].mnemonic)).toThrow(
      "Not an old Electrum seed",
    );
    expect(() =>
      deriveOldMasterPublicKey("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"),
    ).toThrow("Electrum cannot open spaced hex seeds");
    expect(() => deriveOldPublicKey(masterPublicKey.subarray(1), { change: 0, index: 0 })).toThrow(
      "64 bytes",
    );
    expect(() => deriveOldPublicKey(masterPublicKey, { change: 2, index: 0 })).toThrow(
      "Change must be 0 or 1",
    );
    expect(() => deriveOldPublicKey(masterPublicKey, { change: 0, index: -1 })).toThrow(
      "non-negative integer",
    );
    expect(() => deriveOldPublicKey(masterPublicKey, { change: 0, index: 1.5 })).toThrow(
      "non-negative integer",
    );
  });

  it("keeps paths, passphrases, change and index to the seeds that use them", async () => {
    const old = electrumOldVectors[0].mnemonic;
    const segwit = electrumVectors[0];
    for (const [mnemonic, options, message] of [
      [old, { path: "m/0/0" }, "Old Electrum seeds have no BIP32 path"],
      [old, { passphrase: "extension" }, "Old Electrum seeds take no passphrase"],
      [
        old,
        { passphrase: "", network: "", change: 2 },
        "Change must be an integer between 0 and 1",
      ],
      [
        old,
        { passphrase: "", network: "", change: 0, index: 2 ** 31 },
        "Index must be an integer between 0 and 2147483647",
      ],
      [
        segwit.mnemonic,
        { path: segwit.path, passphrase: "", network: "", change: 0 },
        "Change and index apply to old Electrum seeds only",
      ],
      [
        segwit.mnemonic,
        { path: segwit.path, passphrase: "", network: "", index: 0 },
        "Change and index apply",
      ],
      [segwit.mnemonic, {}, "Standard and SegWit Electrum seeds need a BIP32 path"],
      [segwit.mnemonic, { path: " " }, "need a BIP32 path"],
    ] as const) {
      await expect(deriveElectrumWallet(mnemonic, options)).rejects.toThrow(message);
    }
  });
});
