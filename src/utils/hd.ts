import { getMasterKeyFromSeed as getBIP32MasterKey } from "./bip32/index.ts";
import {
  inspect as inspectBIP39Mnemonic,
  mnemonicToSeed,
  wordlist as englishWordlist,
  type BIP39MnemonicInspection,
} from "./bip39/index.ts";
import { normalizeHardenedMarkers } from "./hd-index.ts";
import { getMasterKeyFromSeed as getSLIP10MasterKey } from "./slip10/index.ts";
import type { Curve, ElectrumSeed } from "../types.ts";

/**
 * Collapses whitespace so a phrase pasted with line breaks still validates.
 * @param mnemonic - Raw mnemonic text
 * @returns {string} Words joined by single spaces
 */
export function normalizeMnemonic(mnemonic: string): string {
  return mnemonic.trim().split(/\s+/u).join(" ");
}

/**
 * Names the word count a phrase should have had, under the mode the inspection ran in.
 * @param inspection - Verdict whose word count failed
 * @returns {string} The reason
 */
function describeWordCount(inspection: BIP39MnemonicInspection): string {
  const expected =
    inspection.standardLength === undefined
      ? "12, 15, 18, 21 or 24"
      : "a multiple of 3 from 3 to 768";
  return `${inspection.words} words, expected ${expected}`;
}

/** A BIP39 verdict on a phrase and the list it was checked against. */
export interface MnemonicVerdict {
  /** Verdict of `inspectBIP39Mnemonic` for the phrase and word list. */
  readonly inspection: BIP39MnemonicInspection;
  /** Word list the phrase was checked against. Default: English. */
  readonly wordlist?: readonly string[];
  /** Word list name for the message. Default: `English`. */
  readonly listName?: string;
}

/**
 * Names the BIP39 check a phrase fails, by word position and never by the word itself.
 * @param mnemonic - Phrase with words separated by single spaces
 * @param verdict - Its inspection, the list it was checked against and that list's name
 * @returns {string} Error message for a phrase the inspection rejected
 */
export function describeInvalidMnemonic(mnemonic: string, verdict: MnemonicVerdict): string {
  const { inspection, wordlist = englishWordlist, listName = "English" } = verdict;
  const reasons: string[] = [];
  if (!inspection.wordCountValid) reasons.push(describeWordCount(inspection));
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
 * @param verdict - Its BIP39 verdict and the word list it was checked against
 * @returns {string} Error message for `deriveMnemonicKey`
 */
function describeRejectedMnemonic(mnemonic: string, verdict: MnemonicVerdict): string {
  const { inspection, wordlist = englishWordlist } = verdict;
  const message = describeInvalidMnemonic(mnemonic, {
    inspection,
    wordlist,
    listName: wordlist === englishWordlist ? "English" : "selected",
  });
  return inspection.checksumValid === false
    ? `${message}. allowInvalidChecksum derives from it anyway`
    : message;
}

/** Derivation options as an untyped caller may pass them. */
interface DerivationInput {
  readonly allowInvalidChecksum: unknown;
  readonly wordlist: unknown;
  readonly coleman?: unknown;
}

/**
 * Refuses a non-boolean override and a list that the checksum check would read as a bad checksum.
 * @param input - Override, candidate BIP39 word list and length mode as the caller passed them
 */
function assertDerivationInput(input: DerivationInput): void {
  const { allowInvalidChecksum, wordlist, coleman = false } = input;
  if (typeof allowInvalidChecksum !== "boolean") {
    throw new TypeError("allowInvalidChecksum must be a boolean");
  }
  if (typeof coleman !== "boolean") {
    throw new TypeError("coleman must be a boolean");
  }
  if (!Array.isArray(wordlist) || wordlist.length !== 2048) {
    throw new TypeError("wordlist must be a BIP39 word list of 2048 words");
  }
}

/**
 * Reads the entropy back out of word indices, dropping the checksum bits without checking them.
 * @param words - NFKD normalized words, every one in the list
 * @param wordlist - BIP39 word list the words come from
 * @returns {Uint8Array} The 16 to 32 entropy bytes
 */
function wordsToEntropy(words: readonly string[], wordlist: readonly string[]): Uint8Array {
  let bits = 0n;
  for (const word of words) bits = (bits << 11n) | BigInt(wordlist.indexOf(word));
  const checksumBits = words.length / 3;
  const bytes = (words.length * 11 - checksumBits) / 8;
  return Uint8Array.fromHex((bits >> BigInt(checksumBits)).toString(16).padStart(bytes * 2, "0"));
}

/**
 * Reads the entropy behind a BIP39 mnemonic, which Substrate derives from instead of the seed.
 * @param mnemonic - BIP39 words from `wordlist`, never repaired to satisfy a checksum
 * @param options - `allowInvalidChecksum` accepts only checksum failures when explicitly true,
 * `wordlist` is the list the words come from, English by default
 * @returns {{ entropy: Uint8Array; checksumValid: boolean }} Entropy bytes and actual checksum verdict
 */
export function deriveMnemonicEntropy(
  mnemonic: string,
  options: MnemonicEntropyOptions = {},
): { readonly entropy: Uint8Array; readonly checksumValid: boolean } {
  const { allowInvalidChecksum = false, wordlist = englishWordlist } = options;
  assertDerivationInput({ allowInvalidChecksum, wordlist });
  const normalizedMnemonic = normalizeMnemonic(mnemonic);
  const inspection = inspectBIP39Mnemonic(normalizedMnemonic, { wordlist });
  if (inspection.checksumValid === null || (!inspection.valid && !allowInvalidChecksum)) {
    throw new Error(describeRejectedMnemonic(normalizedMnemonic, { inspection, wordlist }));
  }
  const words = normalizedMnemonic.normalize("NFKD").split(" ");
  return { entropy: wordsToEntropy(words, wordlist), checksumValid: inspection.valid };
}

/** How `deriveMnemonicEntropy` reads a phrase. */
export interface MnemonicEntropyOptions {
  /** Accept only checksum failures. Default: false. */
  readonly allowInvalidChecksum?: boolean;
  /** BIP39 word list the words come from. Default: English. */
  readonly wordlist?: readonly string[];
}

/** Where `deriveMnemonicKey` walks a phrase and how it reads it. */
export interface MnemonicKeyOptions extends MnemonicEntropyOptions, SeedPath {
  /** BIP39 passphrase. Default: empty. */
  readonly passphrase?: string;
  /** Take Ian Coleman's lengths too, any 3 words per 32 bits. Default: false. */
  readonly coleman?: boolean;
}

/** A derivation path and the curve that picks BIP32 or SLIP-10 for it. */
interface SeedPath {
  /** Derivation path such as `m/84'/0'/0'/0/0`, or `m/84h/0h/0h/0/0` as descriptors write it. */
  readonly path: string;
  /** Curve of the key the chain expects. */
  readonly curve: Curve;
}

/**
 * Walks a BIP39 mnemonic down a path: BIP32 for secp256k1, SLIP-10 for ed25519.
 * @param mnemonic - BIP39 words from `wordlist`, never repaired to satisfy a checksum
 * @param options - Path and curve, then the passphrase, the checksum override, the word list and
 * Coleman's lengths
 * @returns {{ privateKey: string; checksumValid: boolean; standardLength: boolean }} Key, verdicts
 */
export function deriveMnemonicKey(
  mnemonic: string,
  options: MnemonicKeyOptions,
): {
  readonly privateKey: string;
  readonly checksumValid: boolean;
  readonly standardLength: boolean;
} {
  const {
    path,
    curve,
    passphrase = "",
    allowInvalidChecksum = false,
    wordlist = englishWordlist,
    coleman = false,
  } = options;
  assertDerivationInput({ allowInvalidChecksum, wordlist, coleman });
  const normalizedMnemonic = normalizeMnemonic(mnemonic);
  const inspection = inspectBIP39Mnemonic(normalizedMnemonic, { wordlist, coleman });
  if (inspection.checksumValid === null || (!inspection.valid && !allowInvalidChecksum)) {
    throw new Error(describeRejectedMnemonic(normalizedMnemonic, { inspection, wordlist }));
  }

  const seed = mnemonicToSeed(normalizedMnemonic, { passphrase, coleman });
  return {
    privateKey: deriveSeedKey(seed, { path, curve }),
    checksumValid: inspection.valid,
    standardLength: inspection.standardLength ?? true,
  };
}

/**
 * Walks a seed down a path: BIP32 for secp256k1, SLIP-10 for ed25519.
 * @param seed - BIP39 or Electrum seed bytes
 * @param target - Derivation path, `h` taken for `'`, and the curve of the key the chain expects
 * @returns {string} The private key at the path, as hex
 * @throws {RangeError} For sr25519, whose keys walk Substrate junctions instead
 */
function deriveSeedKey(seed: Uint8Array, target: SeedPath): string {
  const { path, curve } = target;
  if (curve === "sr25519") {
    throw new RangeError("sr25519 keys walk Substrate junctions, not BIP32 or SLIP-10 paths");
  }
  const hdPath = normalizeHardenedMarkers(path);
  const privateKey =
    curve === "ed25519"
      ? getSLIP10MasterKey(seed).derive(hdPath).privateKey
      : getBIP32MasterKey(seed).derive(hdPath).privateKey;
  if (!privateKey) {
    throw new Error(`No private key at ${path}`);
  }
  return privateKey.toHex();
}

/**
 * Walks an Electrum seed down a BIP32 path, refusing anything `deriveSeed` didn't return.
 * @param seed - Seed from `deriveSeed` in `@agntn/keys/electrum`
 * @param path - Derivation path such as `m/0'/0/0`
 * @returns {string} The secp256k1 private key at the path, as hex
 */
export function deriveElectrumKey(seed: ElectrumSeed, path: string): string {
  if (!isElectrumSeed(seed)) {
    throw new TypeError(
      "Pass the seed that deriveSeed from @agntn/keys/electrum returns, not the phrase",
    );
  }
  return deriveSeedKey(seed.seed, { path, curve: "secp256k1" });
}

/** Seed versions `deriveSeed` hands out; old and 2FA seeds never get that far. */
const ELECTRUM_SEED_TYPES: readonly unknown[] = ["standard", "segwit"];

/**
 * Checks for the scheme, version and 64 bytes `deriveSeed` returns, for untyped callers.
 * @param seed - Seed as the caller passed it
 * @returns {boolean} Whether it came from `deriveSeed`
 */
function isElectrumSeed(seed: unknown): boolean {
  if (typeof seed !== "object" || seed === null) return false;
  if (!("scheme" in seed && "seedType" in seed && "seed" in seed)) return false;
  return (
    seed.scheme === "electrum" &&
    ELECTRUM_SEED_TYPES.includes(seed.seedType) &&
    seed.seed instanceof Uint8Array &&
    seed.seed.length === 64
  );
}
