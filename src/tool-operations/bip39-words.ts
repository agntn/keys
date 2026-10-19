import {
  MAX_BIP39_LOOKUP_ITEMS,
  DEFAULT_BIP39_PHRASES_SHOWN,
  MAX_BIP39_PHRASES_SHOWN,
  MAX_BIP39_PHRASE_LENGTH,
  MAX_BIP39_CHECKSUM_SEARCH,
  DEFAULT_BIP39_REPAIR_DISTANCE,
  MAX_BIP39_REPAIR_DISTANCE,
  MAX_BIP39_REPAIR_WORDS,
} from "../tool-parameters.ts";
import {
  lookupIndices as lookupBIP39Indices,
  lookupWords as lookupBIP39Words,
  lookupPrefixes as lookupBIP39Prefixes,
  loadWordlist as loadBIP39Wordlist,
  countWordOrders,
  orderWords,
  type WordSuggestions,
  suggestWords,
  repairWords,
  getMnemonicWordCandidates,
} from "../utils/bip39/index.ts";
import { integerArray, stringArray, optionalName } from "./arguments.ts";
import { parseBIP39Language, normalizedMnemonic } from "./bip39.ts";
import { type ToolResult, content } from "./results.ts";

/** Result of a BIP39 index lookup. */
export interface BIP39IndexLookupDetails {
  language: string;
  indexBase: 0 | 1;
  lookups: Array<{ index: number; word: string | null }>;
}

/** A list word with both index conventions. */
export interface BIP39IndexedWord {
  word: string;
  zeroBasedIndex: number;
  oneBasedIndex: number;
}

/** Result of a BIP39 word lookup. */
export interface BIP39WordLookupDetails {
  language: string;
  lookups: Array<{
    word: string;
    zeroBasedIndex: number | null;
    oneBasedIndex: number | null;
    /** Words a missing entry of three or more letters starts, in list order. */
    prefixOf?: BIP39IndexedWord[];
  }>;
}

/** Orders of scattered words that pass the BIP39 checksum. */
export interface BIP39WordOrderDetails {
  language: string;
  checked: number;
  valid: number;
  orders: string[];
}

/** Words close to the ones outside the list and the repaired phrases that pass the checksum. */
export interface BIP39WordRepairDetails {
  language: string;
  maxDistance: number;
  positions: Array<{ position: number; suggestions: Array<{ word: string; distance: number }> }>;
  checked: number;
  valid: number;
  repairs: Array<{ mnemonic: string; distance: number }>;
}

/** Candidate words for one missing mnemonic position. */
export interface MnemonicRecoveryDetails {
  language: string;
  position: number;
  candidates: readonly string[];
}

function parseIndexBase(value: unknown): 0 | 1 {
  if (value === undefined || value === 0) return 0;
  if (value === 1) return 1;
  throw new RangeError("BIP39 index base must be 0 or 1");
}

function assertLookupSize(length: number, label: string): void {
  if (length === 0 || length > MAX_BIP39_LOOKUP_ITEMS) {
    throw new RangeError(`Provide between 1 and ${MAX_BIP39_LOOKUP_ITEMS} ${label}`);
  }
}

function assertIndexRange(indices: readonly number[], indexBase: 0 | 1): void {
  const maximumIndex = 2047 + indexBase;
  if (indices.some((index) => index < indexBase || index > maximumIndex)) {
    throw new RangeError(`BIP39 indices must be between ${indexBase} and ${maximumIndex}`);
  }
}

const BIP39_WORD_PATTERN = /^[\p{L}\p{M}]+$/u;

/** Index lookup arguments besides the indices, raw until the executor checks them. */
export interface Bip39IndexLookupArguments {
  readonly language?: unknown;
  /** Zero-based or one-based convention. */
  readonly indexBase?: unknown;
}

/**
 * Read words at numeric positions in an official BIP39 list.
 * @param indicesValue - Numeric positions to read.
 * @param options - Official language key and index base, both optional.
 * @returns {Promise<ToolResult<BIP39IndexLookupDetails>>} Ordered word lookups.
 */
export async function lookupBip39Indices(
  indicesValue: unknown,
  options: Bip39IndexLookupArguments = {},
): Promise<ToolResult<BIP39IndexLookupDetails>> {
  const indices = integerArray(indicesValue, "BIP39 indices");
  assertLookupSize(indices.length, "indices");
  const indexBase = parseIndexBase(options.indexBase);
  assertIndexRange(indices, indexBase);
  const language = parseBIP39Language(options.language);
  const lookups = await lookupBIP39Indices(indices, language, indexBase);
  return {
    content: content(
      [
        `Language: ${language}`,
        `Index base: ${indexBase}`,
        ...lookups.map((lookup) => `${lookup.index}: ${lookup.word ?? "not in range"}`),
      ].join("\n"),
    ),
    details: { language, indexBase, lookups: lookups.map((lookup) => ({ ...lookup })) },
  };
}

/**
 * Look up word membership and both index conventions in an official BIP39 list.
 * @param wordsValue - Words to find.
 * @param languageValue - Optional official language key.
 * @returns {Promise<ToolResult<BIP39WordLookupDetails>>} Membership and indices.
 */
export async function lookupBip39Words(
  wordsValue: unknown,
  languageValue?: unknown,
): Promise<ToolResult<BIP39WordLookupDetails>> {
  const words = stringArray(wordsValue, "BIP39 lookup words");
  assertLookupSize(words.length, "words");
  if (words.some((word) => !BIP39_WORD_PATTERN.test(word))) {
    throw new TypeError("BIP39 lookup words must contain letters and combining marks only");
  }
  const language = parseBIP39Language(languageValue);
  const found = await lookupBIP39Words(words, language);
  const missing = found.flatMap((lookup) => (lookup.zeroBasedIndex === null ? [lookup.word] : []));
  const expanded = new Map(
    (await lookupBIP39Prefixes(missing, language)).map(({ prefix, matches }) => [
      prefix,
      matches.map(({ word, zeroBasedIndex }) => ({
        word,
        zeroBasedIndex,
        oneBasedIndex: zeroBasedIndex + 1,
      })),
    ]),
  );
  const lookups = found.map((lookup) => {
    const prefixOf = expanded.get(lookup.word) ?? [];
    return {
      word: lookup.word,
      zeroBasedIndex: lookup.zeroBasedIndex,
      oneBasedIndex: lookup.zeroBasedIndex === null ? null : lookup.zeroBasedIndex + 1,
      ...(prefixOf.length === 0 ? {} : { prefixOf }),
    };
  });
  return {
    content: content(
      [
        `Language: ${language}`,
        "Indices: zero-based, one-based",
        ...lookups.map((lookup) => {
          if (lookup.zeroBasedIndex !== null) {
            return `${lookup.word}: ${lookup.zeroBasedIndex}, ${lookup.oneBasedIndex}`;
          }
          if (lookup.prefixOf === undefined) return `${lookup.word}: not in BIP39`;
          const matches = lookup.prefixOf.map(
            (match) => `${match.word} (${match.zeroBasedIndex}, ${match.oneBasedIndex})`,
          );
          return `${lookup.word}: not in BIP39, prefix of ${matches.join(", ")}`;
        }),
      ].join("\n"),
    ),
    details: { language, lookups },
  };
}

/**
 * Applies the word count and letter rules of the order schema for hosts that skip it.
 * @param value - Raw words argument.
 * @returns {ReadonlyArray<string>} The words unchanged.
 */
function orderWordsArgument(value: unknown): readonly string[] {
  const words = stringArray(value, "BIP39 words");
  if (words.length === 0 || words.length > 24) {
    throw new RangeError("Provide between 1 and 24 words");
  }
  if (words.some((word) => !BIP39_WORD_PATTERN.test(word))) {
    throw new TypeError("BIP39 words must contain letters and combining marks only");
  }
  return words;
}

/**
 * Reads how many valid orders to list, the default when it is left out.
 * @param value - Raw limit argument.
 * @returns {number} An integer from 1 to the listing cap.
 */
function phraseLimit(value: unknown): number {
  const limit = value ?? DEFAULT_BIP39_PHRASES_SHOWN;
  if (
    typeof limit !== "number" ||
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > MAX_BIP39_PHRASES_SHOWN
  ) {
    throw new RangeError(`Limit must be an integer between 1 and ${MAX_BIP39_PHRASES_SHOWN}`);
  }
  return limit;
}

/** Word order arguments besides the words, raw until the executor checks them. */
export interface Bip39WordOrderArguments {
  /** Phrase with known words and one ? per loose word. */
  readonly template?: unknown;
  readonly language?: unknown;
  /** How many valid orders to list. */
  readonly limit?: unknown;
}

/**
 * Put scattered words in every order the open positions allow and keep the checksum passes.
 * @param wordsValue - Words without a known position.
 * @param options - Template, official BIP39 language key and limit, each optional.
 * @returns {Promise<ToolResult<BIP39WordOrderDetails>>} Orders checked, passed and listed.
 */
export async function orderBip39Words(
  wordsValue: unknown,
  options: Bip39WordOrderArguments = {},
): Promise<ToolResult<BIP39WordOrderDetails>> {
  const words = orderWordsArgument(wordsValue);
  const template = optionalName(options.template, "Template");
  if (template !== undefined && template.length > MAX_BIP39_PHRASE_LENGTH) {
    throw new RangeError(`Template must be at most ${MAX_BIP39_PHRASE_LENGTH} characters`);
  }
  const language = parseBIP39Language(options.language);
  const limit = phraseLimit(options.limit);
  const search = { template, wordlist: await loadBIP39Wordlist(language), listName: language };
  const total = countWordOrders(words, search);
  if (total > BigInt(MAX_BIP39_CHECKSUM_SEARCH)) {
    throw new RangeError(
      `These words have ${total} orders, over the ${MAX_BIP39_CHECKSUM_SEARCH} one call checks. Fix more positions in template, or search with orderWords from @agntn/keys/bip39`,
    );
  }
  const orders: string[] = [];
  let valid = 0;
  for (const order of orderWords(words, search)) {
    valid++;
    if (orders.length < limit) orders.push(order.join(" "));
  }
  const checked = Number(total);
  return {
    content: content(
      [
        `Language: ${language}`,
        `Orders checked: ${checked}`,
        `Valid checksum: ${valid}`,
        ...(valid === 0
          ? []
          : [`First ${orders.length}, sorted by the list index of the loose words:`, ...orders]),
      ].join("\n"),
    ),
    details: { language, checked, valid, orders },
  };
}

/** Suggestions per word the repair text lists, the rest only counted. */
const SUGGESTIONS_SHOWN = 10;

/**
 * Reads how many edits a suggestion may be away, the default when it is left out.
 * @param value - Raw maxDistance argument.
 * @returns {number} An integer from 1 to the repair cap.
 */
function repairDistance(value: unknown): number {
  if (value === undefined) return DEFAULT_BIP39_REPAIR_DISTANCE;
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 1 ||
    value > MAX_BIP39_REPAIR_DISTANCE
  ) {
    throw new RangeError(
      `maxDistance must be an integer between 1 and ${MAX_BIP39_REPAIR_DISTANCE}`,
    );
  }
  return value;
}

/**
 * Refuses a phrase with too many words outside the list or too many combinations to check.
 * @param positions - Suggestions per word outside the list.
 * @param language - List name for the error.
 * @returns {number} Combinations the repair checks.
 */
function repairCombinations(positions: readonly WordSuggestions[], language: string): number {
  if (positions.length > MAX_BIP39_REPAIR_WORDS) {
    throw new RangeError(
      `Words ${positions.map(({ position }) => position).join(", ")} are not in the ${language} list, and one call repairs ${MAX_BIP39_REPAIR_WORDS} at most. Correct the others first`,
    );
  }
  const total = positions.reduce((product, { suggestions }) => product * suggestions.length, 1);
  if (total > MAX_BIP39_CHECKSUM_SEARCH) {
    throw new RangeError(
      `These suggestions make ${total} combinations, over the ${MAX_BIP39_CHECKSUM_SEARCH} one call checks. Lower maxDistance`,
    );
  }
  return total;
}

/**
 * Writes an edit count as words.
 * @param count - Number of edits.
 * @returns {string} "1 edit" or "N edits".
 */
function edits(count: number): string {
  return count === 1 ? "1 edit" : `${count} edits`;
}

/**
 * Lists the nearest words for one position, the rest only counted.
 * @param entry - Position and its suggestions.
 * @param maxDistance - Edits the search allowed.
 * @returns {string} One line of the repair text.
 */
function suggestionLine(entry: WordSuggestions, maxDistance: number): string {
  const { position, suggestions } = entry;
  if (suggestions.length === 0) return `Word ${position}: nothing within ${edits(maxDistance)}`;
  const shown = suggestions
    .slice(0, SUGGESTIONS_SHOWN)
    .map(({ word, distance }) => `${word} (${distance})`);
  const more = suggestions.length - shown.length;
  return `Word ${position}, ${suggestions.length} within ${edits(maxDistance)}: ${shown.join(", ")}${more > 0 ? `, ${more} more` : ""}`;
}

/** Word repair arguments besides the phrase, raw until the executor checks them. */
export interface Bip39WordRepairArguments {
  readonly language?: unknown;
  /** Most edits per word. */
  readonly maxDistance?: unknown;
  /** How many repaired phrases to list. */
  readonly limit?: unknown;
}

/**
 * Suggest list words for the words of a phrase outside the list and keep the checksum passes.
 * @param mnemonicValue - Phrase with mistyped words.
 * @param options - Official BIP39 language key, edit distance and limit, each optional.
 * @returns {Promise<ToolResult<BIP39WordRepairDetails>>} Suggestions, combinations and repairs.
 */
export async function repairBip39Words(
  mnemonicValue: unknown,
  options: Bip39WordRepairArguments = {},
): Promise<ToolResult<BIP39WordRepairDetails>> {
  const mnemonic = normalizedMnemonic(mnemonicValue);
  if (mnemonic.length > MAX_BIP39_PHRASE_LENGTH) {
    throw new RangeError(`BIP39 mnemonic must be at most ${MAX_BIP39_PHRASE_LENGTH} characters`);
  }
  const language = parseBIP39Language(options.language);
  const maxDistance = repairDistance(options.maxDistance);
  const limit = phraseLimit(options.limit);
  const search = { wordlist: await loadBIP39Wordlist(language), maxDistance };
  const positions = suggestWords(mnemonic, search);
  const checked = repairCombinations(positions, language);
  const repairs = repairWords(mnemonic, search).map(({ words, distance }) => ({
    mnemonic: words.join(" "),
    distance,
  }));
  const listed = repairs.slice(0, limit);
  const outside = positions.map(({ position }) => position);
  return {
    content: content(
      [
        `Language: ${language}`,
        `Not in the list: ${outside.length === 0 ? "none" : `${outside.length === 1 ? "word" : "words"} ${outside.join(", ")}`}`,
        ...positions.map((entry) => suggestionLine(entry, maxDistance)),
        `Combinations checked: ${checked}`,
        `Valid checksum: ${repairs.length}`,
        ...(listed.length === 0 ? [] : [`First ${listed.length}, fewest edits first:`]),
        ...listed.map(({ mnemonic: phrase, distance }) => `${edits(distance)}: ${phrase}`),
        "A wrong word that is in the list stays as written. If no phrase here opens the wallet, put ? in its place and use keys_bip39_word_recover.",
      ].join("\n"),
    ),
    details: {
      language,
      maxDistance,
      positions: positions.map(({ position, suggestions }) => ({
        position,
        suggestions: suggestions.map(({ word, distance }) => ({ word, distance })),
      })),
      checked,
      valid: repairs.length,
      repairs: listed,
    },
  };
}

/**
 * List the words of one BIP39 list that satisfy one missing checksum position.
 * @param mnemonicValue - Mnemonic template containing one question mark.
 * @param languageValue - Optional official BIP39 language key.
 * @returns {Promise<ToolResult<MnemonicRecoveryDetails>>} Language, position and candidate words.
 */
export async function recoverMnemonicWord(
  mnemonicValue: unknown,
  languageValue?: unknown,
): Promise<ToolResult<MnemonicRecoveryDetails>> {
  const mnemonic = normalizedMnemonic(mnemonicValue);
  const language = parseBIP39Language(languageValue);
  const wordlist = await loadBIP39Wordlist(language);
  const position = mnemonic.normalize("NFKD").split(" ").indexOf("?") + 1;
  const candidates = getMnemonicWordCandidates(mnemonic, wordlist, language);
  return {
    content: content(
      `Language: ${language}\nPosition: ${position}\nCandidates (${candidates.length}): ${candidates.length === 0 ? "none" : candidates.join(", ")}`,
    ),
    details: { language, position, candidates },
  };
}
