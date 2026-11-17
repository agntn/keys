import { describe, it, expect } from "vite-plus/test";
import { loadWordlist, scanText } from "../../src/utils/bip39";
import { bip39TextScanVectors } from "../fixtures";

/* Start, end and zero-based index of every match, the part a caller cuts the text with. */
const spans = (text: string, wordlist?: readonly string[]): Array<readonly number[]> =>
  scanText(text, { wordlist }).map(({ start, end, zeroBasedIndex }) => [
    start,
    end,
    zeroBasedIndex,
  ]);

describe("BIP39 text scan", () => {
  it("finds the words of the issue's sentence where they sit", () => {
    const { text, matches } = bip39TextScanVectors.issue;

    expect(scanText(text)).toEqual(matches);
  });

  it("keeps repeats, in reading order", () => {
    expect(spans("zoo abandon zoo")).toEqual([
      [0, 3, 2047],
      [4, 11, 0],
      [12, 15, 2047],
    ]);
  });

  it.each([
    ["abandonment", "a longer word"],
    ["xzoo", "a word with a letter in front"],
    ["zo o", "a word broken by a space"],
    ["zoo\u0301", "a word with a mark the list does not have"],
    ["zo", "half a word"],
    ["", "an empty text"],
  ])("finds nothing in %j: %s", (text) => {
    expect(scanText(text)).toEqual([]);
  });

  it.each([
    ["zoo's", "an apostrophe"],
    ["(zoo)", "brackets"],
    ["zoo2", "a digit"],
    ["zoo_zoo", "an underscore"],
    ["zoo\u200Bzoo", "a zero-width space"],
    ["zoo-zoo", "a hyphen"],
  ])("ends a word at %j: %s", (text) => {
    expect(scanText(text).map(({ match }) => match)).toContain("zoo");
  });

  it("counts offsets in UTF-16 units past an astral character", () => {
    expect(spans("😀 zoo")).toEqual([[3, 6, 2047]]);
    expect(spans("𝐀𝐁𝐀𝐍𝐃𝐎𝐍 zoo")).toEqual([
      [0, 14, 0],
      [15, 18, 2047],
    ]);
  });

  it("spans the word as written, not as normalized", async () => {
    const spanish = await loadWordlist("spanish");

    expect(scanText("ÁBACO, a\u0301baco", { wordlist: spanish })).toEqual([
      { match: "ÁBACO", word: "a\u0301baco", zeroBasedIndex: 0, start: 0, end: 5 },
      { match: "a\u0301baco", word: "a\u0301baco", zeroBasedIndex: 0, start: 7, end: 13 },
    ]);
    expect(scanText("abaco", { wordlist: spanish })).toEqual([]);
  });

  it("reads the Chinese lists character by character", async () => {
    const { text, spans: expected } = bip39TextScanVectors.chinese;

    expect(spans(text, await loadWordlist("simplified-chinese"))).toEqual(expected);
  });

  it("matches Japanese and Korean words the text sets apart", async () => {
    const japanese = await loadWordlist("japanese");
    const korean = await loadWordlist("korean");

    expect(spans("あいこくしん\u3000あいだ、あいさつあいだ", japanese)).toEqual([
      [0, 6, 0],
      [7, 10, 2],
    ]);
    expect(spans("가격, 가끔", korean)).toEqual([
      [0, 2, 0],
      [4, 6, 1],
    ]);
  });

  it("cuts every match back out of the source", async () => {
    const texts = [
      bip39TextScanVectors.issue.text,
      "😀Zoo\u0301 ZOO\nzoo\u2028𝐳𝐨𝐨 ﬁx e\u0301toile étoile",
      "的一x\u0301是 我",
    ];
    for (const language of ["english", "french", "simplified-chinese"] as const) {
      const wordlist = await loadWordlist(language);
      for (const text of texts) {
        for (const { match, word, zeroBasedIndex, start, end } of scanText(text, { wordlist })) {
          expect(text.slice(start, end)).toBe(match);
          expect(wordlist[zeroBasedIndex]).toBe(word);
        }
      }
    }
  });

  it("refuses a text that is no string, options that are no object and a list that is no array", () => {
    for (const text of [undefined, null, 12, ["zoo"]]) {
      expect(() => {
        Reflect.apply(scanText, undefined, [text]);
      }).toThrow("scanText takes the text as a string");
    }
    expect(() => {
      Reflect.apply(scanText, undefined, ["zoo", "english"]);
    }).toThrow("Pass the options as an object: scanText(text, { wordlist })");
    expect(() => {
      Reflect.apply(scanText, undefined, ["zoo", { wordlist: "english" }]);
    }).toThrow("scanText takes the word list as an array, from loadWordlist");
  });

  it("stays linear on a hundred thousand letters that never make a word", () => {
    const started = performance.now();
    for (const text of ["a".repeat(100_000), "\u0301".repeat(100_000), "zo ".repeat(33_000)]) {
      expect(scanText(text)).toEqual([]);
    }
    expect(performance.now() - started).toBeLessThan(2000);
  });
});
