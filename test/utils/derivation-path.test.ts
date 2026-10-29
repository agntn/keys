import { HDKey as BIP32Key } from "@scure/bip32";
import { HDKey as SLIP10Key } from "micro-key-producer/slip10.js";
import { describe, expect, it } from "vite-plus/test";
import { blockchains } from "../../src/_blockchains.ts";
import { deriveHDKey as deriveBIP32Key } from "../../src/utils/bip32/index.ts";
import { normalizeDerivationPath, normalizeHardenedMarkers } from "../../src/utils/hd-index.ts";
import { deriveHDKey as deriveSLIP10Key } from "../../src/utils/slip10/index.ts";
import { bip39TestVectors } from "../fixtures.ts";

const seed = new Uint8Array(32).fill(7);

/* Paths on both sides of the BIP32 grammar, the shapes agents type included. */
const candidates = [
  "m",
  "M",
  "m'",
  "m/0",
  "m/0'",
  "m/0h",
  "m'/0'",
  "M/44'/0'",
  "m/01/2",
  "m/2147483647'",
  "m/2147483648",
  "m/2147483648'",
  "m/99999999999999999999",
  "",
  "0/0",
  "/0",
  "m/",
  "m//0",
  "m/0/",
  "m0",
  "m'0",
  "m/0H",
  "m/-1",
  "m/ 0",
  "m/0x1",
  "m/1.5",
  "m/0''",
  "mixed abandon ability",
];

/* Whether a call returns instead of throwing. */
function passes(run: () => unknown): boolean {
  try {
    run();
    return true;
  } catch {
    return false;
  }
}

describe("normalizeDerivationPath", () => {
  it.each(candidates)("accepts %j exactly when @scure/bip32 derives it", (path) => {
    const bip32 = BIP32Key.fromMasterSeed(seed);
    expect(passes(() => normalizeDerivationPath(path))).toBe(
      passes(() => bip32.derive(normalizeHardenedMarkers(path))),
    );
  });

  it.each(candidates)("accepts %j on ed25519 exactly when SLIP-10 derives it", (path) => {
    const slip10 = SLIP10Key.fromMasterSeed(seed);
    expect(passes(() => normalizeDerivationPath(path, { hardenedOnly: true }))).toBe(
      passes(() => slip10.derive(normalizeHardenedMarkers(path))),
    );
  });

  it.each([
    ["84'/0'/0'/0/0", {}, "Derivation path must be m or start with m/, such as m/84'/0'/0'/0/0"],
    ["m84'/0'/0'", {}, "Derivation path must be m or start with m/"],
    [
      "m/84'/0'/x",
      {},
      "Level 3 of the derivation path must be digits, with ' or h for a hardened level",
    ],
    ["m/84'/0'/0'/0/", {}, "Level 5 of the derivation path must be digits"],
    [
      "m/44'/0'/2147483648'",
      {},
      "Level 3 of the derivation path is above 2147483647; mark a hardened level with ' or h instead of adding 2^31",
    ],
    [
      "m/44'/501'/0'/0",
      { hardenedOnly: true },
      "SLIP-10 walks ed25519 down hardened levels only, so level 4 of the derivation path needs ' or h",
    ],
  ] as const)("refuses %j with the level and the rule", (path, rules, message) => {
    expect(() => normalizeDerivationPath(path, rules)).toThrow(RangeError);
    expect(() => normalizeDerivationPath(path, rules)).toThrow(message);
  });

  it("keeps a mnemonic typed into the path out of the error", () => {
    const { mnemonic } = bip39TestVectors;
    expect(() => normalizeDerivationPath(`m/${mnemonic}`)).toThrow(
      "Level 1 of the derivation path",
    );
    expect(() => normalizeDerivationPath(`m/${mnemonic}`)).not.toThrow("abandon");
  });

  it("refuses a path that is not a string", () => {
    expect(() => {
      Reflect.apply(normalizeDerivationPath, undefined, [44]);
    }).toThrow(TypeError);
  });

  it("names the level for both public walkers", () => {
    expect(() => deriveBIP32Key(BIP32Key.fromMasterSeed(seed), "m/0/2147483648")).toThrow(
      "Level 2 of the derivation path is above 2147483647",
    );
    const slip10 = SLIP10Key.fromMasterSeed(seed);
    expect(() => deriveSLIP10Key(slip10, { path: "m/0'/1", forceHardened: false })).toThrow(
      "level 2 of the derivation path needs ' or h",
    );
    expect(deriveSLIP10Key(slip10, { path: "m/0'/1" }).privateKey).toEqual(
      slip10.derive("m/0'/1'").privateKey,
    );
  });
});

describe("HD wallet paths on every chain", () => {
  const { mnemonic } = bip39TestVectors;
  /* Chains that refuse BIP32 paths before reading them, each with its own reason. */
  const ownPaths = new Set(["cardano", "decred", "monero", "polkadot"]);
  const names = Object.keys(blockchains).filter((name) => !ownPaths.has(name));

  it.each(names)("%s names the level a path breaks", async (name) => {
    const chain = await blockchains[name as keyof typeof blockchains]()();
    const [curve] = typeof chain.curve === "string" ? [chain.curve] : chain.curve;
    expect(() => chain.deriveHDWallet(mnemonic, { path: "m/44'/0'/2147483648'" })).toThrow(
      "Level 3 of the derivation path is above 2147483647",
    );
    if (curve === "ed25519") {
      expect(() => chain.deriveHDWallet(mnemonic, { path: "m/44'/0'/0'/0" })).toThrow(
        "SLIP-10 walks ed25519 down hardened levels only, so level 4 of the derivation path needs ' or h",
      );
    }
  });
});
