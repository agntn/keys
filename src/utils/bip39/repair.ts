import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { checksumTest } from "./order.ts";

const MNEMONIC_WORD_COUNTS: readonly number[] = [12, 15, 18, 21, 24];
const DEFAULT_MAX_DISTANCE = 2;

/** Letter groups a scan or a photo mixes up, each swap one edit like a typo. */
const OCR_CONFUSIONS: ReadonlyArray<readonly [string, string]> = [
  ["rn", "m"],
  ["m", "rn"],
  ["vv", "w"],
  ["w", "vv"],
  ["cl", "d"],
  ["d", "cl"],
];

/** Which list the phrase comes from and how far a suggestion may be from a word. */
export interface WordRepairOptions {
  /** BIP39 word list the phrase comes from, English by default. */
  readonly wordlist?: readonly string[];
  /** Most edits between a word and a suggestion, 2 by default. */
  readonly maxDistance?: number;
}

/** A word of the list and the edits that turn the written word into it. */
export interface WordSuggestion {
  readonly word: string;
  readonly zeroBasedIndex: number;
  readonly distance: number;
}

/** One word that is not in the list, by its one-based position, and the words close to it. */
export interface WordSuggestions {
  readonly position: number;
  readonly suggestions: readonly WordSuggestion[];
}

/** A phrase that passes the checksum and the edits it took to get there. */
export interface WordRepair {
  readonly words: readonly string[];
  readonly distance: number;
}

interface RepairSearch {
  readonly wordlist: readonly string[];
  readonly words: readonly string[];
  readonly positions: readonly WordSuggestions[];
}

/** Edits so far for every pair of prefixes, one row per typed prefix. */
interface EditTable {
  readonly cells: readonly number[];
  readonly width: number;
}

/**
 * Reads one cell of the edit table.
 * @param table - Edits for every pair of prefixes
 * @param i - Typed prefix length
 * @param j - Word prefix length
 * @returns {number} Edits between the two prefixes
 */
function cell(table: EditTable, i: number, j: number): number {
  return table.cells[i * table.width + j] ?? 0;
}

/**
 * Tells whether the two letters before i in the written word are the two before j, swapped.
 * @param typed - Letters of the written word
 * @param word - Letters of the list word
 * @param i - Typed prefix length
 * @param j - Word prefix length
 * @returns {boolean} True for a swap of neighbours
 */
function isSwap(typed: readonly string[], word: readonly string[], i: number, j: number): boolean {
  if (i < 2 || j < 2) return false;
  return typed[i - 1] === word[j - 2] && typed[i - 2] === word[j - 1];
}

/**
 * Finds the cheapest OCR group that ends both prefixes.
 * @param typed - Letters of the written word
 * @param word - Letters of the list word
 * @param table - Edits for the shorter prefixes
 * @param at - Typed and word prefix lengths
 * @returns {number} Edits through the group, or Infinity when none ends there
 */
function confusionCost(
  typed: readonly string[],
  word: readonly string[],
  table: EditTable,
  at: readonly [number, number],
): number {
  const [i, j] = at;
  let best = Number.POSITIVE_INFINITY;
  for (const [from, to] of OCR_CONFUSIONS) {
    if (i < from.length || j < to.length) continue;
    if (typed.slice(i - from.length, i).join("") !== from) continue;
    if (word.slice(j - to.length, j).join("") !== to) continue;
    best = Math.min(best, cell(table, i - from.length, j - to.length) + 1);
  }
  return best;
}

/**
 * Counts the fewest edits between two words; a swap of neighbours and an OCR group cost one each.
 * @param typed - Letters of the written word
 * @param word - Letters of the list word
 * @returns {number} The fewest edits
 */
function editDistance(typed: readonly string[], word: readonly string[]): number {
  const width = word.length + 1;
  const cells = Array.from({ length: (typed.length + 1) * width }, (_, index) =>
    index < width ? index : Math.floor(index / width),
  );
  const table = { cells, width };
  for (let i = 1; i <= typed.length; i++) {
    for (let j = 1; j <= word.length; j++) {
      const kept = cell(table, i - 1, j - 1) + (typed[i - 1] === word[j - 1] ? 0 : 1);
      const swapped = isSwap(typed, word, i, j) ? cell(table, i - 2, j - 2) + 1 : kept;
      cells[i * width + j] = Math.min(
        cell(table, i - 1, j) + 1,
        cell(table, i, j - 1) + 1,
        kept,
        swapped,
        confusionCost(typed, word, table, [i, j]),
      );
    }
  }
  return cell(table, typed.length, word.length);
}

/**
 * Lists the words of the list within reach of one written word, closest first, then in list order.
 * @param written - The word as written, normalized
 * @param wordlist - BIP39 word list
 * @param maxDistance - Most edits allowed
 * @returns {ReadonlyArray<WordSuggestion>} The words in reach
 */
function nearestWords(
  written: string,
  wordlist: readonly string[],
  maxDistance: number,
): readonly WordSuggestion[] {
  const typed = Array.from(written);
  return wordlist
    .flatMap((word, zeroBasedIndex) => {
      const letters = Array.from(word);
      if (Math.abs(letters.length - typed.length) > maxDistance) return [];
      const distance = editDistance(typed, letters);
      return distance <= maxDistance ? [{ word, zeroBasedIndex, distance }] : [];
    })
    .sort((left, right) => left.distance - right.distance);
}

/**
 * Splits the phrase, checks its length and finds the words close to each word outside the list.
 * @param mnemonic - Phrase with one or more mistyped words
 * @param options - Word list and edit limit
 * @returns {RepairSearch} Normalized words and the suggestions per position
 */
function prepareRepair(mnemonic: string, options: WordRepairOptions): RepairSearch {
  const wordlist = options.wordlist ?? english;
  if (wordlist.length !== 2048) {
    throw new TypeError("wordlist must be a BIP39 word list of 2048 words");
  }
  const maxDistance = options.maxDistance ?? DEFAULT_MAX_DISTANCE;
  if (!Number.isInteger(maxDistance) || maxDistance < 1) {
    throw new RangeError("maxDistance must be a positive integer");
  }
  const words = mnemonic.normalize("NFKD").toLowerCase().normalize("NFKD").trim().split(/\s+/u);
  if (!MNEMONIC_WORD_COUNTS.includes(words.length)) {
    throw new RangeError("A mnemonic must have 12, 15, 18, 21, or 24 words");
  }
  const positions = words.flatMap((word, index) =>
    wordlist.includes(word)
      ? []
      : [{ position: index + 1, suggestions: nearestWords(word, wordlist, maxDistance) }],
  );
  return { wordlist, words, positions };
}

/**
 * Finds the list words close to each word of the phrase that is not in the list.
 * @param mnemonic - Phrase with one or more mistyped words
 * @param options - Word list and edit limit
 * @returns {ReadonlyArray<WordSuggestions>} One entry per word outside the list, in phrase order
 */
export function suggestWords(
  mnemonic: string,
  options: WordRepairOptions = {},
): readonly WordSuggestions[] {
  return prepareRepair(mnemonic, options).positions;
}

/**
 * Picks the suggestion for each position in one combination, the last position turning fastest.
 * @param positions - Suggestions per position
 * @param combination - Number of the combination, from zero
 * @returns {ReadonlyArray<readonly [number, WordSuggestion]>} Zero-based phrase index and the word put there
 */
function combinationAt(
  positions: readonly WordSuggestions[],
  combination: number,
): ReadonlyArray<readonly [number, WordSuggestion]> {
  let rest = combination;
  return positions
    .toReversed()
    .flatMap(({ position, suggestions }) => {
      const suggestion = suggestions[rest % suggestions.length];
      rest = Math.floor(rest / suggestions.length);
      return suggestion === undefined ? [] : [[position - 1, suggestion] as const];
    })
    .toReversed();
}

/**
 * Tries every combination of the suggestions and keeps the checksum passes, fewest edits first.
 * @param mnemonic - Phrase with one or more mistyped words
 * @param options - Word list and edit limit
 * @returns {ReadonlyArray<WordRepair>} Phrases that pass, the phrase itself when nothing is outside the list and it passes
 */
export function repairWords(
  mnemonic: string,
  options: WordRepairOptions = {},
): readonly WordRepair[] {
  const { wordlist, words, positions } = prepareRepair(mnemonic, options);
  const passes = checksumTest(words.length);
  const placed = Uint16Array.from(words, (word) => Math.max(wordlist.indexOf(word), 0));
  const total = positions.reduce((product, { suggestions }) => product * suggestions.length, 1);
  const repairs: WordRepair[] = [];
  for (let combination = 0; combination < total; combination++) {
    let distance = 0;
    for (const [index, suggestion] of combinationAt(positions, combination)) {
      placed[index] = suggestion.zeroBasedIndex;
      distance += suggestion.distance;
    }
    if (passes(placed)) {
      repairs.push({ words: Array.from(placed, (index) => wordlist[index] ?? ""), distance });
    }
  }
  return repairs.sort((left, right) => left.distance - right.distance);
}
