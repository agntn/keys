import * as bip39 from "@scure/bip39";
import * as english from "@scure/bip39/wordlists/english.js";
import { isBIP39Language, type BIP39Language } from "./languages.ts";

export { BIP39_LANGUAGES, isBIP39Language } from "./languages.ts";
export type { BIP39Language } from "./languages.ts";
export { countWordOrders, orderWords } from "./order.ts";
export type { WordOrderOptions } from "./order.ts";
export { repairWords, suggestWords } from "./repair.ts";
export type { WordRepair, WordRepairOptions, WordSuggestion, WordSuggestions } from "./repair.ts";

// Get English wordlist
const wordlist = english.wordlist;

/** A normalized word and its index in one BIP39 word list. */
export interface BIP39WordLookup {
  readonly word: string;
  readonly zeroBasedIndex: number | null;
}

/** A word of the list and its zero-based index. */
export interface BIP39WordMatch {
  readonly word: string;
  readonly zeroBasedIndex: number;
}

/** A normalized prefix and every word of one BIP39 list it can stand for. */
export interface BIP39PrefixLookup {
  readonly prefix: string;
  readonly matches: readonly BIP39WordMatch[];
}

/** One requested BIP39 index and the word found at that position. */
export interface BIP39IndexLookup {
  readonly index: number;
  readonly word: string | null;
}

interface BIP39WordlistModule {
  readonly wordlist: readonly string[];
}

const BIP39_WORDLIST_LOADERS = {
  czech: () => import("@scure/bip39/wordlists/czech.js"),
  english: () => import("@scure/bip39/wordlists/english.js"),
  french: () => import("@scure/bip39/wordlists/french.js"),
  italian: () => import("@scure/bip39/wordlists/italian.js"),
  japanese: () => import("@scure/bip39/wordlists/japanese.js"),
  korean: () => import("@scure/bip39/wordlists/korean.js"),
  portuguese: () => import("@scure/bip39/wordlists/portuguese.js"),
  "simplified-chinese": () => import("@scure/bip39/wordlists/simplified-chinese.js"),
  spanish: () => import("@scure/bip39/wordlists/spanish.js"),
  "traditional-chinese": () => import("@scure/bip39/wordlists/traditional-chinese.js"),
} satisfies Record<BIP39Language, () => Promise<BIP39WordlistModule>>;

/**
 * Loads a copy of one official word list for the exported bip39 codec.
 * @param language - Official language key, defaulting to English
 * @returns {Promise<string[]>} The selected BIP39 word list
 */
export async function loadWordlist(language: BIP39Language = "english"): Promise<string[]> {
  if (!isBIP39Language(language)) throw new RangeError("Unknown BIP39 language");
  const { wordlist: selectedWordlist } = await BIP39_WORDLIST_LOADERS[language]();
  return [...selectedWordlist];
}

/**
 * Finds words in one official BIP39 list after Unicode NFKD normalization.
 * @param words - Words to look up
 * @param language - Official BIP39 language key
 * @returns {Promise<ReadonlyArray<BIP39WordLookup>>} Normalized words and zero-based indices
 */
export async function lookupWords(
  words: readonly string[],
  language: BIP39Language = "english",
): Promise<readonly BIP39WordLookup[]> {
  const selectedWordlist = await loadWordlist(language);
  return words.map((word) => {
    const normalizedWord = word.normalize("NFKD").toLowerCase().normalize("NFKD");
    const zeroBasedIndex = selectedWordlist.indexOf(normalizedWord);
    return {
      word: normalizedWord,
      zeroBasedIndex: zeroBasedIndex === -1 ? null : zeroBasedIndex,
    };
  });
}

/** Shortest abbreviation `lookupPrefixes` expands, in letters. */
const MIN_PREFIX_LENGTH = 3;

/**
 * Expands abbreviations to the words of one BIP39 list; a whole word matches only itself.
 * @param prefixes - Abbreviated or whole words
 * @param language - Official BIP39 language key
 * @returns {Promise<ReadonlyArray<BIP39PrefixLookup>>} Every match per prefix, in list order
 */
export async function lookupPrefixes(
  prefixes: readonly string[],
  language: BIP39Language = "english",
): Promise<readonly BIP39PrefixLookup[]> {
  const selectedWordlist = await loadWordlist(language);
  return prefixes.map((input) => {
    const prefix = input.normalize("NFKD").toLowerCase().normalize("NFKD");
    const exact = selectedWordlist.indexOf(prefix);
    if (exact !== -1) return { prefix, matches: [{ word: prefix, zeroBasedIndex: exact }] };
    if ((prefix.match(/\p{L}/gu) ?? []).length < MIN_PREFIX_LENGTH) return { prefix, matches: [] };
    const matches = selectedWordlist.flatMap((word, zeroBasedIndex) =>
      word.startsWith(prefix) ? [{ word, zeroBasedIndex }] : [],
    );
    return { prefix, matches };
  });
}

/**
 * Finds words at positions in one official BIP39 list.
 * @param indices - Positions using base 0 or 1
 * @param language - Official BIP39 language key
 * @param indexBase - Whether the supplied positions start at 0 or 1
 * @returns {Promise<ReadonlyArray<BIP39IndexLookup>>} Requested positions and matching words
 */
export async function lookupIndices(
  indices: readonly number[],
  language: BIP39Language = "english",
  indexBase: 0 | 1 = 0,
): Promise<readonly BIP39IndexLookup[]> {
  if (indexBase !== 0 && indexBase !== 1) {
    throw new RangeError("BIP39 index base must be 0 or 1");
  }

  const selectedWordlist = await loadWordlist(language);
  return indices.map((index) => ({
    index,
    word: selectedWordlist[index - indexBase] ?? null,
  }));
}

/**
 * Draws a fresh mnemonic from `crypto.getRandomValues`, so a throwaway one, nothing more.
 * @param strength - Entropy bits, 128 to 256 in steps of 32
 * @param selectedWordlist - BIP39 word list, from `loadWordlist`, defaulting to English
 * @returns {string} The phrase, ideographic spaces included for Japanese
 */
export function generateMnemonic(
  strength = 128,
  selectedWordlist: readonly string[] = wordlist,
): string {
  return bip39.generateMnemonic([...selectedWordlist], strength);
}

/**
 * Checks words, length and checksum against one list; `inspect` says which of them failed.
 * @param mnemonic - Candidate phrase
 * @param selectedWordlist - BIP39 word list, from `loadWordlist`, defaulting to English
 * @returns {boolean} Whether the phrase is valid in that list
 */
export function validateMnemonic(
  mnemonic: string,
  selectedWordlist: readonly string[] = wordlist,
): boolean {
  return bip39.validateMnemonic(mnemonic, [...selectedWordlist]);
}

export const mnemonicToSeed = bip39.mnemonicToSeedSync;

/**
 * Reads the entropy back out of a phrase, throwing on a word off the list or a bad checksum.
 * @param mnemonic - Valid phrase
 * @param selectedWordlist - BIP39 word list, from `loadWordlist`, defaulting to English
 * @returns {Uint8Array} 16 to 32 bytes of entropy
 */
export function mnemonicToEntropy(
  mnemonic: string,
  selectedWordlist: readonly string[] = wordlist,
): Uint8Array {
  return bip39.mnemonicToEntropy(mnemonic, [...selectedWordlist]);
}

/**
 * Turns entropy into the phrase it stands for, in any of the ten lists.
 * @param entropy - 16 to 32 bytes, a multiple of 4
 * @param selectedWordlist - BIP39 word list, from `loadWordlist`, defaulting to English
 * @returns {string} The phrase, ideographic spaces included for Japanese
 */
export function entropyToMnemonic(
  entropy: Uint8Array,
  selectedWordlist: readonly string[] = wordlist,
): string {
  return bip39.entropyToMnemonic(entropy, [...selectedWordlist]);
}

const MNEMONIC_WORD_COUNTS: readonly number[] = [12, 15, 18, 21, 24];

/** BIP39 diagnostics without the input words or entropy. */
export interface BIP39MnemonicInspection {
  readonly valid: boolean;
  readonly words: number;
  readonly wordCountValid: boolean;
  readonly wordlistValid: boolean;
  /** Null when word count or dictionary membership prevents checking the checksum. */
  readonly checksumValid: boolean | null;
}

/**
 * Separates word count, dictionary membership and checksum after NFKD normalization.
 * @param mnemonic - Candidate phrase with words separated by single spaces
 * @param selectedWordlist - BIP39 word list, defaulting to English
 * @returns {BIP39MnemonicInspection} Diagnostics without echoing the phrase
 */
export function inspect(
  mnemonic: string,
  selectedWordlist: readonly string[] = wordlist,
): BIP39MnemonicInspection {
  const normalized = mnemonic.normalize("NFKD");
  const words = normalized === "" ? [] : normalized.split(" ");
  const wordCountValid = MNEMONIC_WORD_COUNTS.includes(words.length);
  const wordlistValid = words.length > 0 && words.every((word) => selectedWordlist.includes(word));
  const checksumValid =
    wordCountValid && wordlistValid
      ? bip39.validateMnemonic(normalized, [...selectedWordlist])
      : null;
  return {
    valid: checksumValid === true,
    words: words.length,
    wordCountValid,
    wordlistValid,
    checksumValid,
  };
}

/**
 * Refuses template words outside the list by position, never echoing the words.
 * @param words - Template words after NFKD normalization, the placeholder included
 * @param selectedWordlist - BIP39 word list the words should come from
 * @param listName - Word list name for the error
 */
function assertTemplateWords(
  words: readonly string[],
  selectedWordlist: readonly string[],
  listName: string,
): void {
  const unknown = words.flatMap((word, index) =>
    word === "?" || selectedWordlist.includes(word) ? [] : [index + 1],
  );
  if (unknown.length === 0) return;
  if (unknown.length === words.length - 1) {
    throw new RangeError(`None of the mnemonic template words is in the ${listName} list`);
  }
  throw new RangeError(
    unknown.length === 1
      ? `Mnemonic template word ${unknown[0]} is not in the ${listName} list`
      : `Mnemonic template words ${unknown.join(", ")} are not in the ${listName} list`,
  );
}

/**
 * Lists the words of one BIP39 list that pass the checksum in the one `?` slot of a template.
 * @param mnemonic - Mnemonic template containing exactly one `?`
 * @param selectedWordlist - BIP39 word list the other words come from, defaulting to English
 * @param listName - Word list name for the error on a word outside the list
 * @returns {ReadonlyArray<string>} Candidate words in the list's order
 */
export function getMnemonicWordCandidates(
  mnemonic: string,
  selectedWordlist: readonly string[] = wordlist,
  listName = selectedWordlist === wordlist ? "English" : "selected",
): readonly string[] {
  if (selectedWordlist.length !== 2048) {
    throw new TypeError("wordlist must be a BIP39 word list of 2048 words");
  }
  const words = mnemonic.normalize("NFKD").trim().split(/\s+/u);
  if (!MNEMONIC_WORD_COUNTS.includes(words.length)) {
    throw new RangeError("Mnemonic template must contain 12, 15, 18, 21, or 24 words");
  }

  const placeholderCount = words.filter((word) => word === "?").length;
  if (placeholderCount !== 1) {
    throw new RangeError("Mnemonic template must contain exactly one ? placeholder");
  }

  assertTemplateWords(words, selectedWordlist, listName);

  const placeholderIndex = words.indexOf("?");
  const list = [...selectedWordlist];
  const candidates: string[] = [];
  for (const candidate of list) {
    words[placeholderIndex] = candidate;
    if (bip39.validateMnemonic(words.join(" "), list)) {
      candidates.push(candidate);
    }
  }

  return candidates;
}

// Re-export original components
export { bip39 };
export { wordlist };
