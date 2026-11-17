import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { assertOptions } from "../options.ts";

/** Which list `scanText` looks for. */
export interface TextScanOptions {
  /** BIP39 word list to find, from `loadWordlist`. Default: English. */
  readonly wordlist?: readonly string[];
}

/** One list word found in a text, and where it sits. */
export interface TextMatch {
  /** The word as the text writes it. */
  readonly match: string;
  /** The list word it folds to. */
  readonly word: string;
  readonly zeroBasedIndex: number;
  /** UTF-16 offset of the match, as `slice` counts. */
  readonly start: number;
  /** UTF-16 offset just past the match. */
  readonly end: number;
}

/** A run of letters and marks. Anything else ends the word. */
const WORD = /\p{L}[\p{L}\p{M}]*/gu;

/** One letter with its marks, for the Chinese lists. */
const CHARACTER = /\p{L}\p{M}*/gu;

/**
 * Folds a word to the form the lists are written in.
 * @param word - Word as written
 * @returns {string} The word in NFKD and lowercase
 */
export function normalizeWord(word: string): string {
  return word.normalize("NFKD").toLowerCase().normalize("NFKD");
}

/**
 * Maps each folded list word to its first index.
 * @param wordlist - BIP39 word list
 * @returns {ReadonlyMap<string, number>} Zero-based index by word
 */
function indexWords(wordlist: readonly string[]): ReadonlyMap<string, number> {
  const indices = new Map<string, number>();
  for (const [index, listed] of wordlist.entries()) {
    const word = normalizeWord(listed);
    if (!indices.has(word)) indices.set(word, index);
  }
  return indices;
}

/**
 * Finds the whole words of one BIP39 list in a text, in reading order, repeats included.
 * @param text - Text to scan
 * @param options - Word list, English by default
 * @returns {ReadonlyArray<TextMatch>} Matches, each with `text.slice(start, end)` as written
 * @throws {TypeError} On a text, options or word list of the wrong type
 */
export function scanText(text: string, options: TextScanOptions = {}): readonly TextMatch[] {
  if (typeof text !== "string") throw new TypeError("scanText takes the text as a string");
  assertOptions(options, "scanText(text, { wordlist })");
  const { wordlist = english } = options;
  if (!Array.isArray(wordlist)) {
    throw new TypeError("scanText takes the word list as an array, from loadWordlist");
  }
  const indices = indexWords(wordlist);
  const token = [...indices.keys()].every((word) => Array.from(word).length === 1)
    ? CHARACTER
    : WORD;
  return Array.from(text.matchAll(token)).flatMap(({ 0: match, index: start }) => {
    const word = normalizeWord(match);
    const zeroBasedIndex = indices.get(word);
    if (zeroBasedIndex === undefined) return [];
    return [{ match, word, zeroBasedIndex, start, end: start + match.length }];
  });
}
