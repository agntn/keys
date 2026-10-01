import { getMasterKeyFromSeed as getBIP32MasterKey } from "./bip32/index.ts";
import {
  inspect as inspectBIP39Mnemonic,
  mnemonicToSeed,
  wordlist as englishWordlist,
  type BIP39MnemonicInspection,
} from "./bip39/index.ts";
import { normalizeHardenedMarkers } from "./hd-index.ts";
import { getMasterKeyFromSeed as getSLIP10MasterKey } from "./slip10/index.ts";
import type { Curve } from "../types.ts";

/**
 * Collapses whitespace so a phrase pasted with line breaks still validates.
 * @param mnemonic - Raw mnemonic text
 * @returns {string} Words joined by single spaces
 */
export function normalizeMnemonic(mnemonic: string): string {
  return mnemonic.trim().split(/\s+/u).join(" ");
}

/**
 * Names the BIP39 check a phrase fails, by word position and never by the word itself.
 * @param mnemonic - Phrase with words separated by single spaces
 * @param inspection - Verdict of `inspectBIP39Mnemonic` for the same phrase and word list
 * @param wordlist - Word list the phrase was checked against
 * @param listName - Word list name for the message
 * @returns {string} Error message for a phrase the inspection rejected
 */
export function describeInvalidMnemonic(
  mnemonic: string,
  inspection: BIP39MnemonicInspection,
  wordlist: readonly string[] = englishWordlist,
  listName = "English",
): string {
  const reasons: string[] = [];
  if (!inspection.wordCountValid) {
    reasons.push(`${inspection.words} words, expected 12, 15, 18, 21 or 24`);
  }
  if (!inspection.wordlistValid && inspection.words > 0) {
    const unknown = mnemonic
      .normalize("NFKD")
      .split(" ")
      .flatMap((word, index) => (wordlist.includes(word) ? [] : [index + 1]));
    if (unknown.length === inspection.words) {
      reasons.push(`none of the words is in the ${listName} list`);
    } else if (unknown.length === 1) {
      reasons.push(`word ${unknown[0]} is not in the ${listName} list`);
    } else {
      reasons.push(`words ${unknown.join(", ")} are not in the ${listName} list`);
    }
  }
  if (inspection.checksumValid === false) {
    reasons.push("the checksum does not match");
  }
  return `Invalid BIP39 mnemonic: ${reasons.join("; ")}`;
}

/**
 * Adds the override hint to a phrase that only fails the checksum.
 * @param mnemonic - Normalized phrase
 * @param inspection - Its BIP39 verdict
 * @param wordlist - Word list the phrase was checked against
 * @returns {string} Error message for `deriveMnemonicKey`
 */
function describeRejectedMnemonic(
  mnemonic: string,
  inspection: BIP39MnemonicInspection,
  wordlist: readonly string[],
): string {
  const message = describeInvalidMnemonic(
    mnemonic,
    inspection,
    wordlist,
    wordlist === englishWordlist ? "English" : "selected",
  );
  return inspection.checksumValid === false
    ? `${message}. allowInvalidChecksum derives from it anyway`
    : message;
}

/**
 * Refuses a non-boolean override and a list that the checksum check would read as a bad checksum.
 * @param allowInvalidChecksum - Override as the caller passed it
 * @param wordlist - Candidate BIP39 word list
 */
function assertDerivationInput(allowInvalidChecksum: unknown, wordlist: unknown): void {
  if (typeof allowInvalidChecksum !== "boolean") {
    throw new TypeError("allowInvalidChecksum must be a boolean");
  }
  if (!Array.isArray(wordlist) || wordlist.length !== 2048) {
    throw new TypeError("wordlist must be a BIP39 word list of 2048 words");
  }
}

/**
 * Walks a BIP39 mnemonic down a path: BIP32 for secp256k1, SLIP-10 for ed25519.
 * @param mnemonic - BIP39 words from `wordlist`, never repaired to satisfy a checksum
 * @param path - Derivation path such as `m/84'/0'/0'/0/0`, or `m/84h/0h/0h/0/0` as descriptors write it
 * @param curve - Curve of the key the chain expects
 * @param passphrase - BIP39 passphrase, empty by default
 * @param allowInvalidChecksum - Accept only checksum failures when explicitly true
 * @param wordlist - BIP39 word list the words come from, English by default
 * @returns {{ privateKey: string; checksumValid: boolean }} Derived key and actual checksum verdict
 */
export function deriveMnemonicKey(
  mnemonic: string,
  path: string,
  curve: Curve,
  passphrase = "",
  allowInvalidChecksum = false,
  wordlist: readonly string[] = englishWordlist,
): { readonly privateKey: string; readonly checksumValid: boolean } {
  assertDerivationInput(allowInvalidChecksum, wordlist);
  const normalizedMnemonic = normalizeMnemonic(mnemonic);
  const inspection = inspectBIP39Mnemonic(normalizedMnemonic, wordlist);
  if (inspection.checksumValid === null || (!inspection.valid && !allowInvalidChecksum)) {
    throw new Error(describeRejectedMnemonic(normalizedMnemonic, inspection, wordlist));
  }

  const seed = mnemonicToSeed(normalizedMnemonic, passphrase);
  const hdPath = normalizeHardenedMarkers(path);
  const privateKey =
    curve === "ed25519"
      ? getSLIP10MasterKey(seed).derive(hdPath).privateKey
      : getBIP32MasterKey(seed).derive(hdPath).privateKey;
  if (!privateKey) {
    throw new Error(`No private key at ${path}`);
  }
  return { privateKey: privateKey.toHex(), checksumValid: inspection.valid };
}
