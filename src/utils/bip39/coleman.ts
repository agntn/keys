import { Sha512Hasher, pbkdf2, sha256 } from "@agntn/hashes";

/** Word counts BIP39 itself allows. */
export const BIP39_WORD_COUNTS: readonly number[] = [12, 15, 18, 21, 24];

/** Past 768 words the checksum wants more bits than SHA-256 has, and Coleman's codec says no. */
const MAX_COLEMAN_WORDS = 768;

/** First word of the Japanese list, which joins its words with an ideographic space. */
const JAPANESE_FIRST_WORD = "あいこくしん";

/** Bits one word index carries. */
const WORD_BITS = 11n;

/**
 * Whether a length passes: BIP39's five, or any 3 words per 32 bits as Coleman's tool writes.
 * @param words - Number of words
 * @param coleman - Accept Ian Coleman's lengths
 * @returns {boolean} Whether the length is accepted
 */
export function isWordCount(words: number, coleman: boolean): boolean {
  if (!coleman) return BIP39_WORD_COUNTS.includes(words);
  return Number.isInteger(words) && words > 0 && words % 3 === 0 && words <= MAX_COLEMAN_WORDS;
}

/**
 * The first bits of SHA-256 over the entropy, one per 32 bits of it.
 * @param entropy - Entropy bytes, a multiple of 4
 * @returns {bigint} The checksum bits
 */
function checksumBits(entropy: ArrayLike<number>): bigint {
  const digest = BigInt(`0x${sha256(Uint8Array.from(entropy)).toHex()}`);
  return digest >> BigInt(256 - (entropy.length * 8) / 32);
}

/**
 * Spells entropy of any 4-byte multiple up to 1024 bytes, the way Coleman's `toMnemonic` does.
 * @param entropy - Entropy bytes
 * @param wordlist - BIP39 word list of 2048 words
 * @returns {string} The phrase, ideographic spaces included for Japanese
 */
export function encodeColeman(entropy: ArrayLike<number>, wordlist: readonly string[]): string {
  if (wordlist.length !== 2048) {
    throw new TypeError("wordlist must be a BIP39 word list of 2048 words");
  }
  const words = (entropy.length * 3) / 4;
  if (!isWordCount(words, true) || entropy.length % 4 !== 0) {
    throw new RangeError(
      `Coleman entropy must be 4 to ${(MAX_COLEMAN_WORDS * 4) / 3} bytes, a multiple of 4`,
    );
  }
  const checksumLength = BigInt(entropy.length / 4);
  let bits = BigInt(`0x${Uint8Array.from(entropy).toHex()}`);
  bits = (bits << checksumLength) | checksumBits(entropy);
  const phrase = Array.from({ length: words }, (_, index) => {
    const shift = BigInt(words - 1 - index) * WORD_BITS;
    return wordlist[Number((bits >> shift) & 2047n)] ?? "";
  });
  return phrase.join(wordlist[0] === JAPANESE_FIRST_WORD ? "　" : " ");
}

/**
 * Reads the entropy back out of listed words and checks the checksum, as Coleman's `check` does.
 * @param words - NFKD normalized words, every one in the list, a count `isWordCount` accepts
 * @param wordlist - BIP39 word list the words come from
 * @returns {{ entropy: Uint8Array; checksumValid: boolean }} Entropy bytes and the checksum verdict
 */
export function decodeColeman(
  words: readonly string[],
  wordlist: readonly string[],
): { readonly entropy: Uint8Array; readonly checksumValid: boolean } {
  let bits = 0n;
  for (const word of words) bits = (bits << WORD_BITS) | BigInt(wordlist.indexOf(word));
  const checksumLength = BigInt(words.length / 3);
  const entropy = Uint8Array.fromHex(
    (bits >> checksumLength).toString(16).padStart((words.length * 8) / 3, "0"),
  );
  const checksum = bits & ((1n << checksumLength) - 1n);
  return { entropy, checksumValid: checksum === checksumBits(entropy) };
}

/**
 * Stretches any phrase into the 64-byte BIP39 seed, PBKDF2-SHA512 at 2048 rounds.
 * @param mnemonic - Phrase, NFKD normalized here
 * @param passphrase - BIP39 passphrase, NFKD normalized and never trimmed
 * @returns {Uint8Array} The seed
 */
export function colemanSeed(mnemonic: string, passphrase: string): Uint8Array {
  const encoder = new TextEncoder();
  return pbkdf2(
    () => new Sha512Hasher(),
    encoder.encode(mnemonic.normalize("NFKD")),
    encoder.encode(`mnemonic${passphrase}`.normalize("NFKD")),
    2048,
    64,
  );
}
