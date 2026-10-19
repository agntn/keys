import { describe, it, expect } from "vite-plus/test";
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  mnemonicToEntropy,
  entropyToMnemonic,
  getMnemonicWordCandidates,
  inspect,
  BIP39_LANGUAGES,
  isBIP39Language,
  lookupIndices,
  lookupWords,
  lookupPrefixes,
  loadWordlist,
} from "../../src/utils/bip39";
import { hex } from "@agntn/encodings/hex";
import { getMasterKeyFromSeed } from "../../src/utils/bip32";
import {
  bip39TestVectors,
  colemanBadChecksum,
  colemanMnemonicVectors,
  frenchMuralMnemonic,
  invalidChecksumPuzzle,
  localizedMnemonicVectors,
  pbkdf2RoundsVectors,
} from "../fixtures";

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
    const lookups = await lookupWords([word], language);

    expect(lookups).toEqual([{ word: word.toLowerCase().normalize("NFKD"), zeroBasedIndex: 0 }]);
  });

  it("loads English by default and rejects unknown word lists", async () => {
    const words = await loadWordlist();
    expect(words[0]).toBe("abandon");
    words[0] = "changed";
    expect((await loadWordlist())[0]).toBe("abandon");
    for (const language of ["unknown", "constructor", "__proto__"]) {
      await expect(Reflect.apply(loadWordlist, undefined, [language])).rejects.toThrow(
        "Unknown BIP39 language",
      );
    }
  });

  it("publishes every official BIP39 language key", () => {
    expect(BIP39_LANGUAGES).toEqual(wordlistVectors.map(([language]) => language));
    expect(isBIP39Language("italian")).toBe(true);
    expect(isBIP39Language("unknown")).toBe(false);
  });

  it("normalizes localized BIP39 words before lookup", async () => {
    const lookups = await lookupWords(["ÁBACO", "acción"], "spanish");
    const compatibilityLookup = await lookupWords(["𝐀𝐁𝐀𝐍𝐃𝐎𝐍"]);

    expect(lookups).toEqual([
      { word: "ábaco", zeroBasedIndex: 0 },
      { word: "acción", zeroBasedIndex: 14 },
    ]);
    expect(compatibilityLookup).toEqual([{ word: "abandon", zeroBasedIndex: 0 }]);
  });

  it("expands abbreviations to every word they start and keeps whole words whole", async () => {
    const english = await loadWordlist();
    const found = await lookupPrefixes(["ABOU", "acc", "act", "zo", "xyz"]);

    expect(found).toEqual([
      { prefix: "abou", matches: [{ word: "about", zeroBasedIndex: 3 }] },
      {
        prefix: "acc",
        matches: ["access", "accident", "account", "accuse"].map((word) => ({
          word,
          zeroBasedIndex: english.indexOf(word),
        })),
      },
      { prefix: "act", matches: [{ word: "act", zeroBasedIndex: 19 }] },
      { prefix: "zo", matches: [] },
      { prefix: "xyz", matches: [] },
    ]);
    const fourLetters = await lookupPrefixes(english.map((word) => word.slice(0, 4)));
    expect(fourLetters.map(({ matches }) => matches.map((match) => match.word))).toEqual(
      english.map((word) => [word]),
    );
  });

  it("expands abbreviations in the selected list after NFKD normalization", async () => {
    expect(await lookupPrefixes(["orol"], "italian")).toEqual([
      { prefix: "orol", matches: [{ word: "orologio", zeroBasedIndex: 1178 }] },
    ]);
    const [accented] = await lookupPrefixes(["\u00E9l\u00E8"], "french");
    expect(accented?.matches.map((match) => match.word.normalize("NFC"))).toEqual([
      "\u00E9l\u00E8ve",
    ]);
  });

  it("maps indices from either base to localized BIP39 words", async () => {
    await expect(lookupIndices([0, 1619, 2047])).resolves.toEqual([
      { index: 0, word: "abandon" },
      { index: 1619, word: "skill" },
      { index: 2047, word: "zoo" },
    ]);
    await expect(
      lookupIndices([1, 1179, 2048], { language: "italian", indexBase: 1 }),
    ).resolves.toEqual([
      { index: 1, word: "abaco" },
      { index: 1179, word: "orologio" },
      { index: 2048, word: "zuppa" },
    ]);
    await expect(lookupIndices([-1, 2048])).resolves.toEqual([
      { index: -1, word: null },
      { index: 2048, word: null },
    ]);
    await expect(
      Reflect.apply(lookupIndices, undefined, [[1], { language: "english", indexBase: 2 }]),
    ).rejects.toThrow("BIP39 index base must be 0 or 1");
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

  it.each(localizedMnemonicVectors)(
    "finds the missing $language word in the selected list",
    async ({ language, mnemonic }) => {
      const wordlist = await loadWordlist(language);
      const words = mnemonic.normalize("NFKD").split(/\s+/u);
      const missing = words.at(-1);
      const template = [...words.slice(0, -1), "?"].join(" ");

      const candidates = getMnemonicWordCandidates(template, { wordlist });

      expect(candidates).toHaveLength(128);
      expect(candidates).toContain(missing);
      for (const candidate of candidates) {
        expect(inspect(template.replace("?", candidate), { wordlist }).valid).toBe(true);
      }
    },
  );

  it("refuses template words outside the selected list by position", async () => {
    const italian = await loadWordlist("italian");
    const template =
      "abandon abandn abandon abandon abandon abandon abandon abandon zoo abandon abandon ?";

    expect(() => getMnemonicWordCandidates(template)).toThrow(
      "Mnemonic template word 2 is not in the English list",
    );
    expect(() => getMnemonicWordCandidates(template.replace("zoo", "zo"))).toThrow(
      "Mnemonic template words 2, 9 are not in the English list",
    );
    expect(() =>
      getMnemonicWordCandidates(template, { wordlist: italian, listName: "italian" }),
    ).toThrow("None of the mnemonic template words is in the italian list");
    expect(() => getMnemonicWordCandidates(template, { wordlist: italian.slice(1) })).toThrow(
      "BIP39 word list of 2048 words",
    );
  });

  it("reports a checksum failure independently from word count and dictionary membership", () => {
    const { mnemonic } = invalidChecksumPuzzle;
    expect(inspect(mnemonic)).toEqual({
      valid: false,
      words: 24,
      wordCountValid: true,
      wordlistValid: true,
      checksumValid: false,
    });
    expect(inspect(bip39TestVectors.mnemonic)).toEqual({
      valid: true,
      words: 12,
      wordCountValid: true,
      wordlistValid: true,
      checksumValid: true,
    });
    expect(inspect(mnemonic.replace("path", "notaword"))).toMatchObject({
      valid: false,
      wordCountValid: true,
      wordlistValid: false,
      checksumValid: null,
    });
    expect(inspect("abandon")).toMatchObject({
      valid: false,
      wordCountValid: false,
      wordlistValid: true,
      checksumValid: null,
    });
    expect(inspect("")).toMatchObject({
      valid: false,
      words: 0,
      wordCountValid: false,
      wordlistValid: false,
      checksumValid: null,
    });
    expect(inspect(bip39TestVectors.mnemonic.replaceAll("a", "\uFF41"))).toMatchObject({
      valid: true,
    });
    expect(getMnemonicWordCandidates(mnemonic.replace(/shine$/u, "?"))).not.toContain("shine");
    expect(validateMnemonic(mnemonic)).toBe(false);
    expect(() => mnemonicToEntropy(mnemonic)).toThrow("Invalid checksum");
  });

  it.each(localizedMnemonicVectors)(
    "inspects $language with the explicitly selected word list",
    async ({ language, mnemonic }) => {
      const wordlist = await loadWordlist(language);
      expect(inspect(mnemonic.normalize("NFC"), { wordlist })).toEqual({
        valid: true,
        words: 12,
        wordCountValid: true,
        wordlistValid: true,
        checksumValid: true,
      });
    },
  );

  it("distinguishes a localized checksum failure from the wrong dictionary", async () => {
    const wordlist = await loadWordlist("spanish");
    const mnemonic = Array.from({ length: 12 }, () => "ábaco").join(" ");
    expect(inspect(mnemonic, { wordlist })).toMatchObject({
      valid: false,
      wordCountValid: true,
      wordlistValid: true,
      checksumValid: false,
    });
    expect(inspect(mnemonic)).toMatchObject({
      valid: false,
      wordCountValid: true,
      wordlistValid: false,
      checksumValid: null,
    });
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
    const seedWithPass = mnemonicToSeed(mnemonic, { passphrase: "TREZOR" });

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
      const entropy = hex.decode(vector.entropy);
      const mnemonic = entropyToMnemonic(entropy);
      expect(mnemonic).toBe(vector.mnemonic);

      const backToEntropy = mnemonicToEntropy(mnemonic);
      expect(Buffer.from(backToEntropy).toString("hex")).toBe(vector.entropy);
    }
  });

  it.each(localizedMnemonicVectors)(
    "round trips $language through the four short helpers",
    async ({ language, entropy, mnemonic }) => {
      const wordlist = await loadWordlist(language);

      expect(entropyToMnemonic(hex.decode(entropy), { wordlist })).toBe(mnemonic);
      expect(hex.encode(mnemonicToEntropy(mnemonic, { wordlist }))).toBe(entropy);
      expect(validateMnemonic(mnemonic, { wordlist })).toBe(true);
      expect(validateMnemonic(generateMnemonic(256, wordlist), { wordlist })).toBe(true);
    },
  );

  it("turns the mural's entropy into its French phrase, not the English one", async () => {
    const french = await loadWordlist("french");
    const entropy = hex.decode(frenchMuralMnemonic.entropy);

    expect(entropyToMnemonic(entropy, { wordlist: french })).toBe(frenchMuralMnemonic.french);
    expect(entropyToMnemonic(entropy)).toBe(frenchMuralMnemonic.english);
    expect(validateMnemonic(frenchMuralMnemonic.french)).toBe(false);
    expect(() => mnemonicToEntropy(frenchMuralMnemonic.french)).toThrow();
  });

  describe("Coleman lengths", () => {
    const coleman = { coleman: true };

    it.each(colemanMnemonicVectors)(
      "reads $entropy the way Coleman's codec does",
      ({ entropy, mnemonic, passphrase, seed }) => {
        expect(entropyToMnemonic(hex.decode(entropy), { ...coleman })).toBe(mnemonic);
        expect(hex.encode(mnemonicToEntropy(mnemonic, { ...coleman }))).toBe(entropy);
        expect(hex.encode(mnemonicToSeed(mnemonic, { passphrase, ...coleman }))).toBe(seed);
        expect(validateMnemonic(mnemonic, { ...coleman })).toBe(true);
        expect(inspect(mnemonic, { ...coleman })).toEqual({
          valid: true,
          words: mnemonic.split(" ").length,
          wordCountValid: true,
          wordlistValid: true,
          checksumValid: true,
          standardLength: false,
        });
      },
    );

    it("keeps strict BIP39 the default", () => {
      const { mnemonic, entropy } = colemanMnemonicVectors[0];
      expect(inspect(mnemonic)).toEqual({
        valid: false,
        words: 3,
        wordCountValid: false,
        wordlistValid: true,
        checksumValid: null,
      });
      expect(validateMnemonic(mnemonic)).toBe(false);
      expect(() => mnemonicToSeed(mnemonic)).toThrow("Invalid mnemonic");
      expect(() => mnemonicToEntropy(mnemonic)).toThrow();
      expect(() => entropyToMnemonic(hex.decode(entropy))).toThrow();
    });

    it("checks the checksum instead of the length alone", () => {
      expect(inspect(colemanBadChecksum, { ...coleman })).toMatchObject({
        valid: false,
        wordCountValid: true,
        checksumValid: false,
      });
      expect(() => mnemonicToEntropy(colemanBadChecksum, { ...coleman })).toThrow(
        "Invalid mnemonic",
      );
    });

    it("gives the standard lengths the same answer as BIP39", async () => {
      const { mnemonic, passphrase, seedWithPassphrase } = bip39TestVectors;
      expect(inspect(mnemonic, { ...coleman })).toMatchObject({
        valid: true,
        standardLength: true,
      });
      expect(hex.encode(mnemonicToSeed(mnemonic, { passphrase, ...coleman }))).toBe(
        seedWithPassphrase,
      );
      const japanese = await loadWordlist("japanese");
      const entropy = new Uint8Array(16).fill(7);
      expect(entropyToMnemonic(entropy, { wordlist: japanese, ...coleman })).toBe(
        entropyToMnemonic(entropy, { wordlist: japanese }),
      );
    });

    it("refuses a word list short of 2048 words, as strict BIP39 does", async () => {
      const short = (await loadWordlist()).slice(0, 10);
      const { mnemonic } = colemanMnemonicVectors[0];
      expect(() => entropyToMnemonic(new Uint8Array(4), { wordlist: short, ...coleman })).toThrow(
        "2048 words",
      );
      expect(inspect(mnemonic, { wordlist: short, ...coleman })).toMatchObject({
        valid: false,
        checksumValid: false,
      });
      expect(() => mnemonicToEntropy(mnemonic, { wordlist: short, ...coleman })).toThrow(
        "Invalid mnemonic",
      );
    });

    it("refuses lengths Coleman's codec has no checksum for", () => {
      expect(inspect("abandon abandon", { ...coleman }).wordCountValid).toBe(false);
      expect(
        inspect(Array.from({ length: 771 }, () => "abandon").join(" "), { ...coleman })
          .wordCountValid,
      ).toBe(false);
      expect(() => mnemonicToSeed("abandon abandon", { passphrase: "", ...coleman })).toThrow(
        "multiple of 3",
      );
      for (const bytes of [0, 6, 1028]) {
        expect(() => entropyToMnemonic(new Uint8Array(bytes), { ...coleman })).toThrow(RangeError);
      }
      expect(entropyToMnemonic(new Uint8Array(1024), { ...coleman }).split(" ")).toHaveLength(768);
    });
  });

  describe("PBKDF2 rounds", () => {
    const { mnemonic, passphrase, fingerprints } = pbkdf2RoundsVectors;
    const fingerprint = (seed: Uint8Array) =>
      getMasterKeyFromSeed(seed).fingerprint.toString(16).padStart(8, "0");

    it.each(fingerprints)("finds the Genesis master key at $rounds rounds", (vector) => {
      const seed = mnemonicToSeed(mnemonic, { passphrase, rounds: vector.rounds });
      expect(fingerprint(seed)).toBe(vector.fingerprint);
    });

    it("misses both keys at BIP39's own 2048", () => {
      const seed = mnemonicToSeed(mnemonic, { passphrase });
      expect(fingerprints.map((vector) => vector.fingerprint)).not.toContain(fingerprint(seed));
      expect(mnemonicToSeed(mnemonic, { passphrase, rounds: 2048 })).toEqual(seed);
    });

    it("runs 2048 rounds the way BIP39 does, Coleman lengths included", () => {
      const { mnemonic: tiny, seed } = colemanMnemonicVectors[0];
      const { mnemonic: standard, passphrase: trezor, seedWithPassphrase } = bip39TestVectors;
      expect(
        hex.encode(mnemonicToSeed(tiny, { passphrase: "", coleman: true, rounds: 2048 })),
      ).toBe(seed);
      expect(
        hex.encode(mnemonicToSeed(standard, { passphrase: trezor, coleman: true, rounds: 2048 })),
      ).toBe(seedWithPassphrase);
    });

    it("keeps the length check when it leaves BIP39's PBKDF2 behind", () => {
      const { mnemonic: tiny } = colemanMnemonicVectors[0];
      expect(() => mnemonicToSeed(tiny, { passphrase: "", rounds: 1 })).toThrow("Invalid mnemonic");
      expect(() =>
        mnemonicToSeed("abandon abandon", { passphrase: "", coleman: true, rounds: 1 }),
      ).toThrow("multiple of 3");
      expect(mnemonicToSeed(tiny, { passphrase: "", coleman: true, rounds: 1 })).toHaveLength(64);
    });

    it.each([0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1])(
      "refuses %s rounds",
      (rounds) => {
        expect(() => mnemonicToSeed(mnemonic, { passphrase, rounds })).toThrow(RangeError);
      },
    );
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
