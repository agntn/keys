import { Sha512Hasher, hmac, pbkdf2 } from "@agntn/hashes";
import { wordlist as englishWordlist } from "./bip39/index.ts";

/** Words in a TON wallet's phrase, the count Tonkeeper and the official wallets write. */
const TON_WORDS = 24;

/** Rounds of the seed check, `PBKDF_ITERATIONS / 256` in `@ton/crypto`. */
const CHECK_ROUNDS = 390;

/** Rounds of the seed itself. */
const SEED_ROUNDS = 100_000;

/**
 * Creates the SHA-512 every step of the scheme runs on.
 * @returns {Sha512Hasher} A fresh hasher
 */
function createSha512(): Sha512Hasher {
  return new Sha512Hasher();
}

/**
 * Stretches the entropy under a salt, the way each step of the TON scheme does.
 * @param entropy - HMAC-SHA512 of the phrase
 * @param salt - The step's salt
 * @param rounds - PBKDF2 rounds
 * @returns {Uint8Array} 64 bytes
 */
function stretch(entropy: Uint8Array, salt: string, rounds: number): Uint8Array {
  return pbkdf2(createSha512, entropy, new TextEncoder().encode(salt), rounds, 64);
}

/**
 * Reads the words of a TON phrase, lower case and single spaced, as `@ton/crypto` does.
 * @param mnemonic - The phrase
 * @returns {string[]} The words
 * @throws {RangeError} When it is not 24 words from the BIP39 English list, naming positions only
 */
function readWords(mnemonic: string): string[] {
  const words = mnemonic.trim().toLowerCase().split(/\s+/u);
  if (words.length !== TON_WORDS) {
    throw new RangeError(`A TON phrase has ${TON_WORDS} words, not ${words.length}`);
  }
  const unknown = words.flatMap((word, index) =>
    englishWordlist.includes(word) ? [] : [index + 1],
  );
  if (unknown.length > 0) {
    throw new RangeError(
      `TON phrases take words from the BIP39 English list; word ${unknown.join(", ")} is not on it`,
    );
  }
  return words;
}

/**
 * Checks the first byte the TON scheme reserves as its version mark.
 * @param entropy - HMAC-SHA512 of the phrase
 * @returns {boolean} Whether a wallet would take the phrase without a password
 */
function isBasicSeed(entropy: Uint8Array): boolean {
  return stretch(entropy, "TON seed version", CHECK_ROUNDS)[0] === 0;
}

/**
 * Hashes the phrase into the entropy every later step stretches.
 * @param words - The checked words
 * @returns {Uint8Array} HMAC-SHA512 keyed by the phrase, over an empty password
 */
function phraseEntropy(words: readonly string[]): Uint8Array {
  return hmac(createSha512, new TextEncoder().encode(words.join(" ")), new Uint8Array(0));
}

/**
 * Tells a TON phrase from anything else, BIP39 included: about one BIP39 phrase in 256 passes.
 * @param mnemonic - The phrase
 * @returns {boolean} Whether TON wallets would restore it without a password
 */
export function isTonMnemonic(mnemonic: string): boolean {
  try {
    return isBasicSeed(phraseEntropy(readWords(mnemonic)));
  } catch {
    return false;
  }
}

/**
 * Restores the ed25519 private key of a TON phrase, as `mnemonicToPrivateKey` in `@ton/crypto`.
 * @param mnemonic - 24 words, which TON checks with its own version byte instead of a checksum
 * @returns {Uint8Array} The 32-byte private key
 * @throws {RangeError} When the words fail the check, or the phrase needs a password
 */
export function decodeTonMnemonic(mnemonic: string): Uint8Array {
  const entropy = phraseEntropy(readWords(mnemonic));
  if (!isBasicSeed(entropy)) {
    const locked = stretch(entropy, "TON fast seed version", 1)[0] === 1;
    throw new RangeError(
      locked
        ? "This TON phrase is locked with a password, which keys does not take"
        : "Not a TON phrase: the words fail TON's version check. A BIP39 phrase goes to deriveHDWallet",
    );
  }
  return stretch(entropy, "TON default seed", SEED_ROUNDS).slice(0, 32);
}
