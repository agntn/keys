import * as bip39 from "@scure/bip39";
import * as english from "@scure/bip39/wordlists/english.js";
import type { BIP39Language } from "./languages.js";

export { BIP39_LANGUAGES, isBIP39Language } from "./languages.js";
export type { BIP39Language } from "./languages.js";

// Get English wordlist
const wordlist = english.wordlist;

/** A normalized word and its index in one BIP39 word list. */
export interface BIP39WordLookup {
  readonly word: string;
  readonly zeroBasedIndex: number | null;
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
 * Finds words in one official BIP39 list after Unicode NFKD normalization.
 * @param words - Words to look up
 * @param language - Official BIP39 language key
 * @returns {Promise<ReadonlyArray<BIP39WordLookup>>} Normalized words and zero-based indices
 */
export async function lookupBIP39Words(
  words: readonly string[],
  language: BIP39Language = "english",
): Promise<readonly BIP39WordLookup[]> {
  const { wordlist: selectedWordlist } = await BIP39_WORDLIST_LOADERS[language]();
  return words.map((word) => {
    const normalizedWord = word.normalize("NFKD").toLowerCase().normalize("NFKD");
    const zeroBasedIndex = selectedWordlist.indexOf(normalizedWord);
    return {
      word: normalizedWord,
      zeroBasedIndex: zeroBasedIndex === -1 ? null : zeroBasedIndex,
    };
  });
}

// Re-export main functionality with default wordlist
export const generateMnemonic = (strength = 128) => bip39.generateMnemonic(wordlist, strength);
export const validateMnemonic = (mnemonic: string) => bip39.validateMnemonic(mnemonic, wordlist);
export const mnemonicToSeed = bip39.mnemonicToSeedSync;
export const mnemonicToEntropy = (mnemonic: string) => bip39.mnemonicToEntropy(mnemonic, wordlist);
export const entropyToMnemonic = (entropy: Uint8Array) =>
  bip39.entropyToMnemonic(entropy, wordlist);

const MNEMONIC_WORD_COUNTS: readonly number[] = [12, 15, 18, 21, 24];

/**
 * Lists English BIP39 words that make the checksum valid for a mnemonic with one placeholder.
 * @param mnemonic - Mnemonic template containing exactly one `?`
 * @returns {ReadonlyArray<string>} Candidate words in BIP39 list order
 */
export function getMnemonicWordCandidates(mnemonic: string): readonly string[] {
  const words = mnemonic.trim().split(/\s+/u);
  if (!MNEMONIC_WORD_COUNTS.includes(words.length)) {
    throw new RangeError("Mnemonic template must contain 12, 15, 18, 21, or 24 words");
  }

  const placeholderCount = words.filter((word) => word === "?").length;
  if (placeholderCount !== 1) {
    throw new RangeError("Mnemonic template must contain exactly one ? placeholder");
  }

  const placeholderIndex = words.indexOf("?");
  const candidates: string[] = [];
  for (const candidate of wordlist) {
    words[placeholderIndex] = candidate;
    if (validateMnemonic(words.join(" "))) {
      candidates.push(candidate);
    }
  }

  return candidates;
}

// Re-export original components
export { bip39 };
export { wordlist };
