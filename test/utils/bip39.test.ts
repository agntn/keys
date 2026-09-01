import { describe, it, expect } from "vitest";
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  mnemonicToEntropy,
  entropyToMnemonic,
  getMnemonicWordCandidates,
  BIP39_LANGUAGES,
  isBIP39Language,
  lookupBIP39Indices,
  lookupBIP39Words,
} from "../../src/utils/bip39";
import { hexToBytes } from "@noble/hashes/utils.js";
import { bip39TestVectors } from "../fixtures";

describe("BIP39 Utils", () => {
  // Test vectors from BIP39 specification
  const wordlistVectors = [
    ["czech", "abdikace"],
    ["english", "abandon"],
    ["french", "abaisser"],
    ["italian", "abaco"],
    ["japanese", "あいこくしん"],
    ["korean", "가격"],
    ["portuguese", "abacate"],
    ["simplified-chinese", "的"],
    ["spanish", "ábaco"],
    ["traditional-chinese", "的"],
  ] as const;

  const testVectors = [
    {
      entropy: "00000000000000000000000000000000",
      mnemonic: bip39TestVectors.mnemonic,
      seed: bip39TestVectors.seed,
    },
    {
      entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
      mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
      seed: "878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096",
    },
  ];

  it("generates valid mnemonics of different strengths", () => {
    const mnemonic12 = generateMnemonic(128); // 12 words
    const mnemonic24 = generateMnemonic(256); // 24 words

    expect(validateMnemonic(mnemonic12)).toBe(true);
    expect(validateMnemonic(mnemonic24)).toBe(true);

    expect(mnemonic12.split(" ").length).toBe(12);
    expect(mnemonic24.split(" ").length).toBe(24);
  });

  it.each(wordlistVectors)("looks up words in the %s BIP39 list", async (language, word) => {
    const lookups = await lookupBIP39Words([word], language);

    expect(lookups).toEqual([{ word: word.toLowerCase().normalize("NFKD"), zeroBasedIndex: 0 }]);
  });

  it("publishes every official BIP39 language key", () => {
    expect(BIP39_LANGUAGES).toEqual(wordlistVectors.map(([language]) => language));
    expect(isBIP39Language("italian")).toBe(true);
    expect(isBIP39Language("unknown")).toBe(false);
  });

  it("normalizes localized BIP39 words before lookup", async () => {
    const lookups = await lookupBIP39Words(["ÁBACO", "acción"], "spanish");
    const compatibilityLookup = await lookupBIP39Words(["𝐀𝐁𝐀𝐍𝐃𝐎𝐍"]);

    expect(lookups).toEqual([
      { word: "ábaco", zeroBasedIndex: 0 },
      { word: "acción", zeroBasedIndex: 14 },
    ]);
    expect(compatibilityLookup).toEqual([{ word: "abandon", zeroBasedIndex: 0 }]);
  });

  it("maps indices from either base to localized BIP39 words", async () => {
    await expect(lookupBIP39Indices([0, 1619, 2047])).resolves.toEqual([
      { index: 0, word: "abandon" },
      { index: 1619, word: "skill" },
      { index: 2047, word: "zoo" },
    ]);
    await expect(lookupBIP39Indices([1, 1179, 2048], "italian", 1)).resolves.toEqual([
      { index: 1, word: "abaco" },
      { index: 1179, word: "orologio" },
      { index: 2048, word: "zuppa" },
    ]);
    await expect(lookupBIP39Indices([-1, 2048])).resolves.toEqual([
      { index: -1, word: null },
      { index: 2048, word: null },
    ]);
    await expect(Reflect.apply(lookupBIP39Indices, undefined, [[1], "english", 2])).rejects.toThrow(
      "BIP39 index base must be 0 or 1",
    );
  });

  it("validates mnemonics correctly", () => {
    expect(
      validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      ),
    ).toBe(true);
    expect(
      validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon wrong",
      ),
    ).toBe(false);
    expect(validateMnemonic("not a valid mnemonic")).toBe(false);
  });

  it.each([
    [
      "? abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "abandon",
    ],
    [
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
      "about",
    ],
  ])("finds words compatible with the checksum for a missing position", (template, expected) => {
    const candidates = getMnemonicWordCandidates(template);

    expect(candidates).toContain(expected);
    for (const candidate of candidates) {
      expect(validateMnemonic(template.replace("?", candidate))).toBe(true);
    }
  });

  it("rejects malformed mnemonic templates", () => {
    expect(() =>
      getMnemonicWordCandidates(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      ),
    ).toThrow("exactly one ? placeholder");
    expect(() =>
      getMnemonicWordCandidates(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ? ?",
      ),
    ).toThrow("exactly one ? placeholder");
    expect(() => getMnemonicWordCandidates("abandon abandon ?")).toThrow(
      "12, 15, 18, 21, or 24 words",
    );
  });

  it("converts mnemonic to seed correctly", () => {
    for (const vector of testVectors) {
      const seed = mnemonicToSeed(vector.mnemonic);
      expect(Buffer.from(seed).toString("hex")).toBe(vector.seed);
    }
  });

  it("converts mnemonic to seed with passphrase", () => {
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const seedNoPass = mnemonicToSeed(mnemonic);
    const seedWithPass = mnemonicToSeed(mnemonic, "TREZOR");

    // Should be different with passphrase
    expect(Buffer.from(seedNoPass).toString("hex")).not.toBe(
      Buffer.from(seedWithPass).toString("hex"),
    );

    // Known test vector with passphrase 'TREZOR'
    expect(Buffer.from(seedWithPass).toString("hex")).toBe(
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    );
  });

  it("converts entropy to mnemonic and back", () => {
    for (const vector of testVectors) {
      const entropy = hexToBytes(vector.entropy);
      const mnemonic = entropyToMnemonic(entropy);
      expect(mnemonic).toBe(vector.mnemonic);

      const backToEntropy = mnemonicToEntropy(mnemonic);
      expect(Buffer.from(backToEntropy).toString("hex")).toBe(vector.entropy);
    }
  });

  it("integrates with the wallet generation process", () => {
    // This test ensures the BIP39 -> seed -> BIP32/SLIP-10 workflow works correctly
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const seed = mnemonicToSeed(mnemonic);

    // Check seed generation is consistent
    expect(Buffer.from(seed).toString("hex")).toBe(
      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    );
  });
});
