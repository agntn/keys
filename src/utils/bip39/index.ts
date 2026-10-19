import { Sha512Hasher, pbkdf2 } from "@agntn/hashes";
import * as bip39 from "@scure/bip39";
import * as english from "@scure/bip39/wordlists/english.js";
import { BIP39_WORD_COUNTS, decodeColeman, encodeColeman, isWordCount } from "./coleman.ts";
import { isBIP39Language, type BIP39Language } from "./languages.ts";
import { assertOptions } from "../options.ts";

export { BIP39_LANGUAGES, isBIP39Language } from "./languages.ts";
export type { BIP39Language } from "./languages.ts";
export { countWordOrders, orderWords } from "./order.ts";
export type { WordOrderOptions } from "./order.ts";
export { repairWords, suggestWords } from "./repair.ts";
export type { WordRepair, WordRepairOptions, WordSuggestion, WordSuggestions } from "./repair.ts";

// Get English wordlist
const wordlist = english.wordlist;

/** Which list a phrase comes from and how strictly it is read. */
export interface MnemonicOptions {
  /** BIP39 word list, from `loadWordlist`. Default: English. */
  readonly wordlist?: readonly string[];
  /** Any 3 words per 32 bits, 3 to 768, as Ian Coleman's tool writes. Not BIP39. Default: false. */
  readonly coleman?: boolean;
}

/** The passphrase, how a phrase is read and how hard PBKDF2 works it into a seed. */
export interface SeedOptions extends Pick<MnemonicOptions, "coleman"> {
  /** BIP39 passphrase, NFKD normalized and never trimmed. Default: empty. */
  readonly passphrase?: string;
  /** PBKDF2 rounds. Anything but 2048 makes a seed no wallet app will find. Default: 2048. */
  readonly rounds?: number;
}

/** Which list `lookupIndices` reads and where its positions start. */
export interface IndexLookupOptions {
  /** Official BIP39 language key. Default: `english`. */
  readonly language?: BIP39Language;
  /** Whether the positions start at 0 or 1. Default: 0. */
  readonly indexBase?: 0 | 1;
}

/** Which list fills the `?` of a template, and its name in errors. */
export interface WordCandidateOptions {
  /** BIP39 word list the other words come from, from `loadWordlist`. Default: English. */
  readonly wordlist?: readonly string[];
  /** Word list name for the error on a word outside the list. Default: `English` or `selected`. */
  readonly listName?: string;
}

/** Rounds BIP39 fixes for its PBKDF2. */
const BIP39_ROUNDS = 2048;

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
 * @param options - Language and whether the positions start at 0 or 1
 * @returns {Promise<ReadonlyArray<BIP39IndexLookup>>} Requested positions and matching words
 */
export async function lookupIndices(
  indices: readonly number[],
  options: IndexLookupOptions = {},
): Promise<readonly BIP39IndexLookup[]> {
  assertOptions(options, "lookupIndices(indices, { language, indexBase })");
  const { language = "english", indexBase = 0 } = options;
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
 * @param options - Word list, English by default, and `coleman` for Ian Coleman's lengths too
 * @returns {boolean} Whether the phrase is valid in that list
 */
export function validateMnemonic(mnemonic: string, options: MnemonicOptions = {}): boolean {
  assertOptions(options, "validateMnemonic(mnemonic, { wordlist, coleman })");
  if (options.coleman === true) return inspect(mnemonic, options).valid;
  return bip39.validateMnemonic(mnemonic, [...(options.wordlist ?? wordlist)]);
}

/**
 * Stretches a phrase into the 64-byte BIP39 seed, checking its length but never its checksum.
 * @param mnemonic - Words separated by single spaces
 * @param options - Passphrase, empty by default, `coleman` for Ian Coleman's lengths too and
 * `rounds` in place of BIP39's 2048
 * @returns {Uint8Array} The seed, which is not a BIP32 master key yet
 */
export function mnemonicToSeed(mnemonic: string, options: SeedOptions = {}): Uint8Array {
  assertOptions(options, "mnemonicToSeed(mnemonic, { passphrase, coleman, rounds })");
  const { passphrase = "" } = options;
  const rounds = seedRounds(options.rounds);
  const coleman = options.coleman === true;
  if (!coleman && rounds === BIP39_ROUNDS) return bip39.mnemonicToSeedSync(mnemonic, passphrase);
  if (!isWordCount(mnemonic.normalize("NFKD").split(" ").length, coleman)) {
    throw new Error(
      coleman
        ? "Invalid mnemonic: Coleman phrases have a multiple of 3 words, 3 to 768"
        : "Invalid mnemonic",
    );
  }
  return stretchSeed(mnemonic, { passphrase, rounds });
}

/**
 * Reads the round count, refusing anything PBKDF2 cannot run.
 * @param rounds - Requested count, BIP39's 2048 when omitted
 * @returns {number} The count
 */
function seedRounds(rounds = BIP39_ROUNDS): number {
  if (!Number.isSafeInteger(rounds) || rounds < 1) {
    throw new RangeError("rounds must be a positive integer");
  }
  return rounds;
}

/**
 * Runs PBKDF2-HMAC-SHA512 over any phrase, BIP39's salt and NFKD included.
 * @param mnemonic - Phrase, NFKD normalized here
 * @param stretch - BIP39 passphrase, NFKD normalized and never trimmed, and PBKDF2 rounds
 * @returns {Uint8Array} The 64-byte seed
 */
function stretchSeed(
  mnemonic: string,
  stretch: { readonly passphrase: string; readonly rounds: number },
): Uint8Array {
  const { passphrase, rounds } = stretch;
  const encoder = new TextEncoder();
  return pbkdf2(
    () => new Sha512Hasher(),
    encoder.encode(mnemonic.normalize("NFKD")),
    encoder.encode(`mnemonic${passphrase}`.normalize("NFKD")),
    rounds,
    64,
  );
}

/**
 * Reads the entropy back out of a phrase, throwing on a word off the list or a bad checksum.
 * @param mnemonic - Valid phrase
 * @param options - Word list, English by default, and `coleman` for Ian Coleman's lengths too
 * @returns {Uint8Array} 16 to 32 bytes of entropy, or 4 to 1024 under `coleman`
 */
export function mnemonicToEntropy(mnemonic: string, options: MnemonicOptions = {}): Uint8Array {
  assertOptions(options, "mnemonicToEntropy(mnemonic, { wordlist, coleman })");
  const { wordlist: selectedWordlist = wordlist } = options;
  if (options.coleman !== true) return bip39.mnemonicToEntropy(mnemonic, [...selectedWordlist]);
  if (!inspect(mnemonic, options).valid) {
    throw new Error("Invalid mnemonic: inspect says which check it fails");
  }
  return decodeColeman(mnemonic.normalize("NFKD").split(" "), selectedWordlist).entropy;
}

/**
 * Turns entropy into the phrase it stands for, in any of the ten lists.
 * @param entropy - 16 to 32 bytes, a multiple of 4; under `coleman` 4 to 1024 bytes
 * @param options - Word list, English by default, and `coleman` for Ian Coleman's lengths too
 * @returns {string} The phrase, ideographic spaces included for Japanese
 */
export function entropyToMnemonic(entropy: Uint8Array, options: MnemonicOptions = {}): string {
  assertOptions(options, "entropyToMnemonic(entropy, { wordlist, coleman })");
  const { wordlist: selectedWordlist = wordlist } = options;
  if (options.coleman === true) return encodeColeman(entropy, selectedWordlist);
  return bip39.entropyToMnemonic(entropy, [...selectedWordlist]);
}

/** BIP39 diagnostics without the input words or entropy. */
export interface BIP39MnemonicInspection {
  readonly valid: boolean;
  readonly words: number;
  /** Under `coleman`, any multiple of 3 from 3 to 768 counts. */
  readonly wordCountValid: boolean;
  readonly wordlistValid: boolean;
  /** Null when word count or dictionary membership prevents checking the checksum. */
  readonly checksumValid: boolean | null;
  /** Only under `coleman`: whether the length is one of BIP39's own 12, 15, 18, 21 or 24. */
  readonly standardLength?: boolean;
}

/**
 * Separates word count, dictionary membership and checksum after NFKD normalization.
 * @param mnemonic - Candidate phrase with words separated by single spaces
 * @param options - Word list, English by default, and `coleman` for Ian Coleman's lengths too,
 * which adds `standardLength`
 * @returns {BIP39MnemonicInspection} Diagnostics without echoing the phrase
 */
export function inspect(mnemonic: string, options: MnemonicOptions = {}): BIP39MnemonicInspection {
  assertOptions(options, "inspect(mnemonic, { wordlist, coleman })");
  const { wordlist: selectedWordlist = wordlist } = options;
  const coleman = options.coleman === true;
  const normalized = mnemonic.normalize("NFKD");
  const words = normalized === "" ? [] : normalized.split(" ");
  const wordCountValid = isWordCount(words.length, coleman);
  const wordlistValid = words.length > 0 && words.every((word) => selectedWordlist.includes(word));
  const checksumValid =
    wordCountValid && wordlistValid
      ? checksumMatches(words, { wordlist: selectedWordlist, coleman })
      : null;
  return {
    valid: checksumValid === true,
    words: words.length,
    wordCountValid,
    wordlistValid,
    checksumValid,
    ...(coleman ? { standardLength: BIP39_WORD_COUNTS.includes(words.length) } : {}),
  };
}

/**
 * Checks the checksum of a phrase whose length and words already passed.
 * @param words - Words of the NFKD normalized phrase
 * @param read - BIP39 word list the words come from, and `coleman` to read it with Coleman's
 * codec, which takes any 3 words per 32 bits
 * @returns {boolean} Whether the checksum matches; never with a list short of 2048 words
 */
function checksumMatches(
  words: readonly string[],
  read: { readonly wordlist: readonly string[]; readonly coleman: boolean },
): boolean {
  const { wordlist: selectedWordlist, coleman } = read;
  if (coleman) {
    return selectedWordlist.length === 2048 && decodeColeman(words, selectedWordlist).checksumValid;
  }
  return bip39.validateMnemonic(words.join(" "), [...selectedWordlist]);
}

/**
 * Refuses template words outside the list by position, never echoing the words.
 * @param words - Template words after NFKD normalization, the placeholder included
 * @param list - BIP39 word list the words should come from, and its name for the error
 */
function assertTemplateWords(
  words: readonly string[],
  list: { readonly wordlist: readonly string[]; readonly listName: string },
): void {
  const { wordlist: selectedWordlist, listName } = list;
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
 * Splits a template into words, refusing a length BIP39 lacks and anything but one `?`.
 * @param mnemonic - Mnemonic template
 * @returns {string[]} Its words after NFKD normalization
 */
function templateWords(mnemonic: string): string[] {
  const words = mnemonic.normalize("NFKD").trim().split(/\s+/u);
  if (!BIP39_WORD_COUNTS.includes(words.length)) {
    throw new RangeError("Mnemonic template must contain 12, 15, 18, 21, or 24 words");
  }
  if (words.filter((word) => word === "?").length !== 1) {
    throw new RangeError("Mnemonic template must contain exactly one ? placeholder");
  }
  return words;
}

/**
 * Lists the words of one BIP39 list that pass the checksum in the one `?` slot of a template.
 * @param mnemonic - Mnemonic template containing exactly one `?`
 * @param options - Word list the other words come from, English by default, and its name for the
 * error on a word outside the list
 * @returns {ReadonlyArray<string>} Candidate words in the list's order
 */
export function getMnemonicWordCandidates(
  mnemonic: string,
  options: WordCandidateOptions = {},
): readonly string[] {
  assertOptions(options, "getMnemonicWordCandidates(mnemonic, { wordlist, listName })");
  const {
    wordlist: selectedWordlist = wordlist,
    listName = selectedWordlist === wordlist ? "English" : "selected",
  } = options;
  if (selectedWordlist.length !== 2048) {
    throw new TypeError("wordlist must be a BIP39 word list of 2048 words");
  }
  const words = templateWords(mnemonic);
  assertTemplateWords(words, { wordlist: selectedWordlist, listName });

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
