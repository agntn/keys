/** Every official BIP39 word list shipped by `@scure/bip39`. */
export const BIP39_LANGUAGES = [
  "czech",
  "english",
  "french",
  "italian",
  "japanese",
  "korean",
  "portuguese",
  "simplified-chinese",
  "spanish",
  "traditional-chinese",
] as const;

/** The key of an official BIP39 word list. */
export type BIP39Language = (typeof BIP39_LANGUAGES)[number];

/**
 * Reports whether a string names an official BIP39 word list.
 * @param language - Language key to check
 * @returns {boolean} Whether the key names an official list
 */
export function isBIP39Language(language: string): language is BIP39Language {
  return BIP39_LANGUAGES.some((candidate) => candidate === language);
}
