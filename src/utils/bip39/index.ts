import * as bip39 from "@scure/bip39";
import * as english from "@scure/bip39/wordlists/english.js";

// Get English wordlist
const wordlist = english.wordlist;

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
