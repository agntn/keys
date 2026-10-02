import { sha256 } from "@agntn/hashes";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";

const MNEMONIC_WORD_COUNTS: readonly number[] = [12, 15, 18, 21, 24];
const PROGRESS_INTERVAL = 65_536;

/** Where the scattered words may go and which list they come from. */
export interface WordOrderOptions {
  /** Phrase with known words in place and `?` in each open slot; all slots open without it. */
  readonly template?: string;
  /** BIP39 word list the words come from, English by default. */
  readonly wordlist?: readonly string[];
  /** Name of the list in errors. */
  readonly listName?: string;
  /** Gets the number of orders checked so far, every 65,536 orders and once at the end. */
  readonly onProgress?: (checked: number) => void;
}

interface WordOrderSearch {
  readonly wordlist: readonly string[];
  readonly placed: Uint16Array;
  readonly open: readonly number[];
  readonly free: Uint16Array;
}

/**
 * Refuses words outside the list by position, never echoing the words.
 * @param words - Words after NFKD normalization, placeholders included
 * @param wordlist - BIP39 word list the words should come from
 * @param label - What the words are, for the error
 * @param listName - Word list name for the error
 */
function assertListWords(
  words: readonly string[],
  wordlist: readonly string[],
  label: string,
  listName: string,
): void {
  const unknown = words.flatMap((word, index) =>
    word === "?" || wordlist.includes(word) ? [] : [index + 1],
  );
  if (unknown.length === 0) return;
  throw new RangeError(
    unknown.length === 1
      ? `${label} ${unknown[0]} is not in the ${listName} list`
      : `${label}s ${unknown.join(", ")} are not in the ${listName} list`,
  );
}

/**
 * Splits the template into slots and checks that the loose words fill its open ones.
 * @param template - Phrase with `?` in each open slot, or undefined for all slots open
 * @param count - Number of loose words
 * @returns {ReadonlyArray<string>} Slots after NFKD normalization
 */
function templateSlots(template: string | undefined, count: number): readonly string[] {
  const slots =
    template === undefined
      ? Array.from({ length: count }, () => "?")
      : template.normalize("NFKD").trim().split(/\s+/u);
  if (!MNEMONIC_WORD_COUNTS.includes(slots.length)) {
    throw new RangeError("A mnemonic must have 12, 15, 18, 21, or 24 words");
  }
  const open = slots.filter((slot) => slot === "?").length;
  if (open !== count) {
    throw new RangeError(`The template has ${open} open positions for ${count} words`);
  }
  return slots;
}

/**
 * Checks the words and the template and sorts the loose words by their list index.
 * @param words - Words without a known position
 * @param options - Template and word list
 * @returns {WordOrderSearch} Known indices, open positions and the loose indices in ascending order
 */
function prepareSearch(words: readonly string[], options: WordOrderOptions): WordOrderSearch {
  const wordlist = options.wordlist ?? english;
  const listName = options.listName ?? (wordlist === english ? "English" : "selected");
  if (wordlist.length !== 2048) {
    throw new TypeError("wordlist must be a BIP39 word list of 2048 words");
  }
  const loose = words.map((word) => word.normalize("NFKD").trim());
  const slots = templateSlots(options.template, loose.length);
  assertListWords(loose, wordlist, "Word", listName);
  assertListWords(slots, wordlist, "Template word", listName);
  return {
    wordlist,
    placed: Uint16Array.from(slots, (slot) => (slot === "?" ? 0 : wordlist.indexOf(slot))),
    open: slots.flatMap((slot, index) => (slot === "?" ? [index] : [])),
    free: Uint16Array.from(loose, (word) => wordlist.indexOf(word)).sort(),
  };
}

/**
 * Moves sorted indices to their next order, skipping repeats of a word that appears twice.
 * @param indices - Word indices, rearranged in place
 * @returns {boolean} False after the last order
 */
function nextOrder(indices: Uint16Array): boolean {
  const at = (position: number): number => indices[position] ?? 0;
  let pivot = indices.length - 2;
  while (pivot >= 0 && at(pivot) >= at(pivot + 1)) pivot--;
  if (pivot < 0) return false;
  let next = indices.length - 1;
  while (at(next) <= at(pivot)) next--;
  const value = at(pivot);
  indices[pivot] = at(next);
  indices[next] = value;
  indices.subarray(pivot + 1).reverse();
  return true;
}

/**
 * Writes the loose indices into the open positions of the phrase.
 * @param placed - Indices of the whole phrase, written in place
 * @param open - Open positions in order
 * @param free - Loose indices in their current order
 */
function fillOpen(placed: Uint16Array, open: readonly number[], free: Uint16Array): void {
  for (const [slot, position] of open.entries()) placed[position] = free[slot] ?? 0;
}

/**
 * Builds the BIP39 checksum test for phrases of one length.
 * @param length - Words in the phrase
 * @returns {(placed: Uint16Array) => boolean} True when the indices pass the checksum
 */
export function checksumTest(length: number): (placed: Uint16Array) => boolean {
  const checksumBits = length / 3;
  const checksumMask = (1 << checksumBits) - 1;
  const entropyBytes = (length * 11 - checksumBits) / 8;
  const packed = new Uint8Array(Math.ceil((length * 11) / 8));
  return (placed) => {
    let buffer = 0;
    let bits = 0;
    let byte = 0;
    for (const index of placed) {
      buffer = (buffer << 11) | index;
      for (bits += 11; bits >= 8; bits -= 8) packed[byte++] = buffer >> (bits - 8);
      buffer &= (1 << bits) - 1;
    }
    const checksum = (sha256(packed.subarray(0, entropyBytes))[0] ?? 0) >> (8 - checksumBits);
    return checksum === ((placed.at(-1) ?? 0) & checksumMask);
  };
}

/**
 * Counts the distinct orders `orderWords` checks, so a caller can see the cost before the search.
 * @param words - Words without a known position, a repeated word counted once per copy
 * @param options - Template and word list
 * @returns {bigint} Orders to check, past `Number.MAX_SAFE_INTEGER` for 24 open positions
 */
export function countWordOrders(words: readonly string[], options: WordOrderOptions = {}): bigint {
  const { free } = prepareSearch(words, options);
  let total = 1n;
  let run = 0;
  for (const [position, index] of free.entries()) {
    run = position > 0 && free[position - 1] === index ? run + 1 : 1;
    total = (total * BigInt(position + 1)) / BigInt(run);
  }
  return total;
}

/**
 * Yields the orders of the loose words that pass the BIP39 checksum, sorted by list index.
 * @param words - Words without a known position
 * @param options - Template with the known positions, word list and progress callback
 * @yields {ReadonlyArray<string>} One full phrase as words in the list's spelling
 */
export function* orderWords(
  words: readonly string[],
  options: WordOrderOptions = {},
): Generator<readonly string[], void, undefined> {
  const { wordlist, placed, open, free } = prepareSearch(words, options);
  const passes = checksumTest(placed.length);
  let checked = 0;
  do {
    fillOpen(placed, open, free);
    if (passes(placed)) yield Array.from(placed, (index) => wordlist[index] ?? "");
    checked++;
    if (checked % PROGRESS_INTERVAL === 0) options.onProgress?.(checked);
  } while (nextOrder(free));
  if (checked % PROGRESS_INTERVAL !== 0) options.onProgress?.(checked);
}
