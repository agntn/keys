import { describe, it, expect } from "vite-plus/test";
import { repairWords, suggestWords, validateMnemonic, loadWordlist } from "../../src/utils/bip39";
import { bip39WordRepairVectors } from "../fixtures";

const twelve = (last: string): string => `${"abandon ".repeat(11)}${last}`;

describe("BIP39 word repair", () => {
  it("turns the typo from the issue back into about", () => {
    const { written, mnemonic } = bip39WordRepairVectors.typo;
    const [first] = repairWords(written);

    expect(first).toEqual({ words: mnemonic.split(" "), distance: 1 });
    expect(validateMnemonic(mnemonic)).toBe(true);
  });

  it("keeps exactly the combinations the checksum accepts, fewest edits first", () => {
    const { written, mnemonic, positions, combinations, valid } = bip39WordRepairVectors.twoWords;
    const suggestions = suggestWords(written);
    const [second, last] = suggestions;
    if (second === undefined || last === undefined) throw new Error("two words should be off");

    expect(suggestions.map(({ position }) => position)).toEqual(positions);
    expect(second.suggestions.length * last.suggestions.length).toBe(combinations);
    const words = written.split(" ");
    const brute = second.suggestions.flatMap((a) =>
      last.suggestions
        .map((b) => [...words.slice(0, 1), a.word, ...words.slice(2, 11), b.word].join(" "))
        .filter((phrase) => validateMnemonic(phrase)),
    );
    const repairs = repairWords(written);

    expect(repairs).toHaveLength(valid);
    expect(new Set(repairs.map(({ words: found }) => found.join(" ")))).toEqual(new Set(brute));
    expect(repairs[0]).toEqual({ words: mnemonic.split(" "), distance: 2 });
    for (const [index, repair] of repairs.entries()) {
      expect(repair.distance).toBeGreaterThanOrEqual(repairs[index - 1]?.distance ?? 0);
    }
  });

  it.each([
    ["abuot", "about", "two letters swapped"],
    ["abot", "about", "a letter missing"],
    ["abourt", "about", "a letter too many"],
    ["abcut", "about", "a letter wrong"],
    ["rnarble", "marble", "rn read for m"],
    ["vvalk", "walk", "vv read for w"],
    ["clance", "dance", "cl read for d"],
    ["lmage", "image", "l read for i"],
    ["ABUOT", "about", "capitals"],
  ])("finds %s one edit from %s: %s", (written, word) => {
    const [entry] = suggestWords(twelve(written), { maxDistance: 1 });
    expect(entry?.position).toBe(12);
    expect(entry?.suggestions.find((suggestion) => suggestion.word === word)?.distance).toBe(1);
  });

  it("reads a missing accent as one edit in the Spanish list", async () => {
    const wordlist = await loadWordlist("spanish");
    const [entry] = suggestWords(`abaco ${wordlist.slice(1, 12).join(" ")}`, { wordlist });

    expect(entry?.suggestions[0]).toEqual({ word: wordlist[0], zeroBasedIndex: 0, distance: 1 });
  });

  it("answers a phrase without words outside the list with the phrase or nothing", () => {
    const { mnemonic } = bip39WordRepairVectors.typo;

    expect(suggestWords(mnemonic)).toEqual([]);
    expect(repairWords(mnemonic)).toEqual([{ words: mnemonic.split(" "), distance: 0 }]);
    expect(repairWords(twelve("abandon"))).toEqual([]);
  });

  it("gives nothing for a word without any list word in reach", () => {
    expect(suggestWords(twelve("zzzzzzzzz"))).toEqual([{ position: 12, suggestions: [] }]);
    expect(repairWords(twelve("zzzzzzzzz"))).toEqual([]);
  });

  it("refuses a bad length, a bad list and a bad edit limit", () => {
    expect(() => repairWords("abandon abuot")).toThrow(
      "A mnemonic must have 12, 15, 18, 21, or 24 words",
    );
    expect(() => repairWords(twelve("abuot"), { wordlist: ["about"] })).toThrow(
      "wordlist must be a BIP39 word list of 2048 words",
    );
    for (const maxDistance of [0, 1.5]) {
      expect(() => suggestWords(twelve("abuot"), { maxDistance })).toThrow(
        "maxDistance must be a positive integer",
      );
    }
  });
});
