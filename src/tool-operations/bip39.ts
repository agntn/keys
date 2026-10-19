import {
  MAX_COLEMAN_ENTROPY_BYTES,
  BIP39_ENTROPY_BYTE_LENGTHS,
  MAX_MNEMONIC_LENGTH,
  MAX_BIP39_SEED_INPUT_LENGTH,
  TOOL_MNEMONIC_WORD_COUNTS,
  MAX_ENTROPY_PREIMAGES,
  MAX_ENTROPY_PREIMAGE_LENGTH,
} from "../tool-parameters.ts";
import {
  loadWordlist as loadBIP39Wordlist,
  inspect as inspectBIP39Mnemonic,
  mnemonicToSeed,
  bip39,
  type BIP39MnemonicInspection,
  mnemonicToEntropy,
  entropyToMnemonic,
} from "../utils/bip39/index.ts";
import { type BIP39Language, isBIP39Language, BIP39_LANGUAGES } from "../utils/bip39/languages.ts";
import {
  type EntropyProfile,
  type EntropyPattern,
  type EntropyPreimage,
  profileEntropy,
  ENTROPY_DIGEST_BYTES,
  BUILT_IN_PREIMAGES,
  entropyHashAlgorithms,
} from "../utils/entropy-profile.ts";
import { describeInvalidMnemonic } from "../utils/hd.ts";
import {
  costArgument,
  isUnsetCost,
  requiredString,
  optionalString,
  stringArray,
} from "./arguments.ts";
import { type ToolResult, content } from "./results.ts";

/** What a result says when a phrase has one of Coleman's lengths but not one of BIP39's own. */
export const NONSTANDARD_LENGTH_WARNING =
  "Not a BIP39 length. Read the way Ian Coleman's tool reads it; wallet apps will refuse these words.";

/** What a seed result says when PBKDF2 ran some count other than BIP39's 2048. */
export const NONSTANDARD_ROUNDS_WARNING =
  "Not BIP39's 2048 PBKDF2 rounds. Wallet apps derive a different seed from these words.";

/** A disposable BIP39 seed, never a BIP32 master private key. */
export interface DerivedBIP39SeedDetails {
  language: BIP39Language;
  seed: string;
  warnings?: readonly string[];
}

/** BIP39 inspection result without the supplied mnemonic. */
export interface MnemonicInspectionDetails {
  language: BIP39Language;
  valid: boolean;
  words: number;
  wordCountValid: boolean;
  wordlistValid: boolean;
  checksumValid: boolean | null;
  /** Only with `coleman`: whether the length is one of BIP39's own. */
  standardLength?: boolean;
  entropy?: string;
  entropyProfile?: EntropyProfile;
}

/** Fresh disposable mnemonic and its word count. */
export interface GeneratedMnemonicDetails {
  language: BIP39Language;
  words: number;
  mnemonic: string;
}

/** Mnemonic generated from supplied entropy. */
export interface EncodedEntropyDetails {
  language: BIP39Language;
  words: number;
  mnemonic: string;
  warnings?: readonly string[];
}

const BIP39_ENTROPY_PATTERN = /^[0-9a-f]+$/i;

/**
 * Decodes BIP39 entropy from hex, refusing lengths the mode has no word count for.
 * @param value - Entropy as the caller passed it
 * @param coleman - Take Coleman's lengths, any 4-byte multiple up to 1024 bytes
 * @returns {Uint8Array} Entropy bytes
 */
export function parseBip39Entropy(value: unknown, coleman = false): Uint8Array {
  const entropyText = requiredString(value, "BIP39 entropy");
  if (!BIP39_ENTROPY_PATTERN.test(entropyText)) {
    throw new TypeError("BIP39 entropy must be a hexadecimal string");
  }
  const bytes = entropyText.length / 2;
  if (coleman) {
    if (bytes % 4 !== 0 || bytes > MAX_COLEMAN_ENTROPY_BYTES) {
      throw new RangeError(
        `Coleman entropy must be 4 to ${MAX_COLEMAN_ENTROPY_BYTES} bytes, a multiple of 4`,
      );
    }
  } else if (!BIP39_ENTROPY_BYTE_LENGTHS.includes(bytes)) {
    throw new RangeError(
      "BIP39 entropy must be 16, 20, 24, 28, or 32 bytes; coleman takes any multiple of 4",
    );
  }
  return Uint8Array.fromHex(entropyText);
}

/**
 * Reads the optional `coleman` flag, refusing anything but a boolean.
 * @param value - Flag as the caller passed it
 * @returns {boolean} Whether Coleman's lengths are taken
 */
export function colemanFlag(value: unknown): boolean {
  if (value === undefined) return false;
  if (typeof value !== "boolean") throw new TypeError("coleman must be a boolean");
  return value;
}

export function parseBIP39Language(value: unknown): BIP39Language {
  const language = optionalString(value, "BIP39 language") ?? "english";
  if (!isBIP39Language(language)) {
    throw new RangeError(`Unknown BIP39 language. Supported: ${BIP39_LANGUAGES.join(", ")}`);
  }
  return language;
}

export function normalizedMnemonic(value: unknown): string {
  const mnemonic = requiredString(value, "BIP39 mnemonic").trim().replaceAll(/\s+/gu, " ");
  if (mnemonic === "") throw new TypeError("BIP39 mnemonic must not be empty");
  return mnemonic;
}

/** The word list a BIP39 tool reads, raw until the executor checks it. */
export interface Bip39ListArguments {
  readonly language?: unknown;
  readonly coleman?: unknown;
}

/** Seed tool arguments besides the mnemonic, raw until the executor checks them. */
export interface Bip39SeedArguments extends Bip39ListArguments {
  readonly passphrase?: unknown;
  readonly rounds?: unknown;
}

/**
 * Derive a disposable seed after validating the mnemonic against the selected list.
 * @param mnemonicValue - Public or disposable BIP39 mnemonic.
 * @param options - Passphrase, language, `coleman` and PBKDF2 `rounds`, each optional.
 * @returns {Promise<ToolResult<DerivedBIP39SeedDetails>>} Seed hex and transcript warning.
 */
export async function deriveBip39Seed(
  mnemonicValue: unknown,
  options: Bip39SeedArguments,
): Promise<ToolResult<DerivedBIP39SeedDetails>> {
  const coleman = colemanFlag(options.coleman);
  const rounds = isUnsetCost(options.rounds)
    ? 2048
    : costArgument(options.rounds, { name: "rounds" });
  const input = requiredString(mnemonicValue, "BIP39 mnemonic");
  const passphrase = optionalString(options.passphrase, "BIP39 passphrase") ?? "";
  if (Array.from(input).length > MAX_MNEMONIC_LENGTH) {
    throw new RangeError(`BIP39 mnemonic must not exceed ${MAX_MNEMONIC_LENGTH} characters`);
  }
  if (Array.from(passphrase).length > MAX_BIP39_SEED_INPUT_LENGTH) {
    throw new RangeError(
      `BIP39 passphrase must not exceed ${MAX_BIP39_SEED_INPUT_LENGTH} characters`,
    );
  }
  const mnemonic = normalizedMnemonic(input);
  const language = parseBIP39Language(options.language);
  const wordlist = await loadBIP39Wordlist(language);
  const inspection = inspectBIP39Mnemonic(mnemonic, { wordlist, coleman });
  if (!inspection.valid) {
    throw new TypeError(
      describeInvalidMnemonic(mnemonic, { inspection, wordlist, listName: language }),
    );
  }
  const seed = mnemonicToSeed(mnemonic, { passphrase, coleman, rounds }).toHex();
  const warnings = [
    ...(inspection.standardLength === false ? [NONSTANDARD_LENGTH_WARNING] : []),
    ...(rounds === 2048 ? [] : [NONSTANDARD_ROUNDS_WARNING]),
  ];
  return {
    content: content(
      [
        `Language: ${language}`,
        `Seed: ${seed}`,
        ...warnings.map((warning) => `Warning: ${warning}`),
        "This seed is saved in the transcript. Never use it for real funds.",
      ].join("\n"),
    ),
    details: { language, seed, ...(warnings.length === 0 ? {} : { warnings }) },
  };
}

/**
 * Generate a disposable mnemonic using the library's cryptographic randomness.
 * @param wordsValue - Word count, defaulting to 12.
 * @param languageValue - Optional official BIP39 language key.
 * @returns {Promise<ToolResult<GeneratedMnemonicDetails>>} Mnemonic and transcript warning.
 */
export async function generateBip39Mnemonic(
  wordsValue: unknown = 12,
  languageValue?: unknown,
): Promise<ToolResult<GeneratedMnemonicDetails>> {
  if (typeof wordsValue !== "number" || !TOOL_MNEMONIC_WORD_COUNTS.includes(wordsValue)) {
    throw new RangeError("BIP39 word count must be 12, 15, 18, 21, or 24");
  }
  const language = parseBIP39Language(languageValue);
  const wordlist = await loadBIP39Wordlist(language);
  const mnemonic = bip39.generateMnemonic(wordlist, (wordsValue / 3) * 32);
  return {
    content: content(
      `Language: ${language}\nMnemonic: ${mnemonic}\nWords: ${wordsValue}\nThis mnemonic is saved in the transcript. Never use it for real funds.`,
    ),
    details: { language, words: wordsValue, mnemonic },
  };
}

/**
 * Quotes text for one result line, escaping every code point that could break or hide it.
 * @param text - Text read from entropy or passed by the caller.
 * @returns {string} The text in double quotes.
 */
function quoteEntropyText(text: string): string {
  const escaped = text.replaceAll(/[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}"\\]/gu, (character) =>
    character === '"' || character === "\\"
      ? `\\${character}`
      : `\\u{${character.codePointAt(0)?.toString(16) ?? ""}}`,
  );
  return `"${escaped}"`;
}

function describeEntropyPattern(pattern: EntropyPattern, length: number): string {
  switch (pattern.kind) {
    case "all-zeros":
      return "all zeros";
    case "all-ones":
      return "all ones (ff)";
    case "repeated-byte":
      return `byte ${pattern.byte} repeated`;
    case "repeated-block":
      return `${pattern.block.length / 2}-byte block ${pattern.block} repeated`;
    case "low-diversity":
      return `only ${pattern.distinct} distinct bytes out of ${length}`;
    case "date":
      return `date ${pattern.date} as ${pattern.encoding.replace("-", " ")}`;
  }
}

function describeEntropyPreimage(preimage: EntropyPreimage, length: number): string {
  const { algorithm, text, source } = preimage;
  const prefix = ENTROPY_DIGEST_BYTES[algorithm] > length ? `, first ${length} bytes` : "";
  return `${algorithm} of ${quoteEntropyText(text)} (${source}${prefix})`;
}

interface InspectedEntropy {
  details: { entropy?: string; entropyProfile?: EntropyProfile };
  lines: string[];
}

/**
 * Entropy of a valid mnemonic for the result, with what its bytes look like.
 * @param entropy - Entropy bytes, or undefined for an invalid mnemonic.
 * @param preimages - Caller texts hashed against the entropy.
 * @returns {InspectedEntropy} Detail fields and result lines.
 */
function inspectedEntropy(
  entropy: Uint8Array | undefined,
  preimages: readonly string[],
): InspectedEntropy {
  if (entropy === undefined) return { details: {}, lines: [] };
  const { length } = entropy;
  const profile = profileEntropy(entropy, preimages);
  const matches = profile.preimages.map((preimage) => describeEntropyPreimage(preimage, length));
  const checked = `${BUILT_IN_PREIMAGES.length} built-in, ${preimages.length} given; ${entropyHashAlgorithms(length).join(", ")}`;
  const patterns = profile.patterns.map((pattern) => describeEntropyPattern(pattern, length));
  return {
    details: { entropy: entropy.toHex(), entropyProfile: profile },
    lines: [
      `Entropy: ${entropy.toHex()}`,
      `Entropy text: ${profile.text === null ? "none" : quoteEntropyText(profile.text)}`,
      `Entropy pattern: ${patterns.join("; ") || "none"}`,
      `Entropy preimage: ${matches.join("; ") || `none (${checked})`}`,
    ],
  };
}

function entropyPreimageTexts(value: unknown): readonly string[] {
  if (value === undefined) return [];
  const texts = stringArray(value, "Entropy preimages");
  if (texts.length > MAX_ENTROPY_PREIMAGES) {
    throw new RangeError(`Provide at most ${MAX_ENTROPY_PREIMAGES} entropy preimages`);
  }
  if (texts.some((text) => text.length > MAX_ENTROPY_PREIMAGE_LENGTH)) {
    throw new RangeError(
      `Each entropy preimage must be at most ${MAX_ENTROPY_PREIMAGE_LENGTH} characters`,
    );
  }
  return texts;
}

/**
 * Writes the verdict lines of an inspection, with the BIP39 length line only under `coleman`.
 * @param inspection - Verdict of the inspection
 * @param coleman - Whether Coleman's lengths were taken
 * @returns {string[]} Lines without the language and the entropy
 */
function inspectionLines(inspection: BIP39MnemonicInspection, coleman: boolean): string[] {
  const { valid, words, wordCountValid, wordlistValid, checksumValid, standardLength } = inspection;
  const yesNo = (flag: boolean): string => (flag ? "yes" : "no");
  return [
    `Valid ${coleman ? "Coleman" : "BIP39"}: ${yesNo(valid)}`,
    `Words: ${words}`,
    `Word count valid: ${yesNo(wordCountValid)}`,
    ...(standardLength === undefined
      ? []
      : [`BIP39 length: ${standardLength ? "yes" : "no, only Coleman's tool reads it"}`]),
    `Wordlist valid: ${yesNo(wordlistValid)}`,
    `Checksum valid: ${checksumValid === null ? "not checked" : yesNo(checksumValid)}`,
  ];
}

/** Inspection tool arguments besides the mnemonic, raw until the executor checks them. */
export interface MnemonicInspectionArguments extends Bip39ListArguments {
  /** Caller texts hashed against the entropy after the built-in list. */
  readonly preimages?: unknown;
}

/**
 * Validate a BIP39 mnemonic against the selected list and recover its entropy when valid.
 * @param mnemonicValue - BIP39 mnemonic candidate.
 * @param options - Language, preimages and `coleman` for Ian Coleman's lengths, each optional.
 * @returns {Promise<ToolResult<MnemonicInspectionDetails>>} Validity, entropy and its profile.
 */
export async function inspectMnemonic(
  mnemonicValue: unknown,
  options: MnemonicInspectionArguments = {},
): Promise<ToolResult<MnemonicInspectionDetails>> {
  const coleman = colemanFlag(options.coleman);
  const mnemonic = normalizedMnemonic(mnemonicValue);
  const language = parseBIP39Language(options.language);
  const preimages = entropyPreimageTexts(options.preimages);
  const wordlist = await loadBIP39Wordlist(language);
  const inspection = inspectBIP39Mnemonic(mnemonic, { wordlist, coleman });
  const entropy = inspectedEntropy(
    inspection.valid ? mnemonicToEntropy(mnemonic, { wordlist, coleman }) : undefined,
    preimages,
  );
  return {
    content: content(
      [`Language: ${language}`, ...inspectionLines(inspection, coleman), ...entropy.lines].join(
        "\n",
      ),
    ),
    details: { language, ...inspection, ...entropy.details },
  };
}

/**
 * Encode a supported BIP39 entropy length using the selected word list.
 * @param entropyValue - BIP39 entropy as hexadecimal text.
 * @param options - Official BIP39 language key and `coleman` for Ian Coleman's lengths.
 * @returns {Promise<ToolResult<EncodedEntropyDetails>>} Canonical mnemonic and language.
 */
export async function encodeBip39Entropy(
  entropyValue: unknown,
  options: Bip39ListArguments = {},
): Promise<ToolResult<EncodedEntropyDetails>> {
  const coleman = colemanFlag(options.coleman);
  const entropy = parseBip39Entropy(entropyValue, coleman);
  const language = parseBIP39Language(options.language);
  const wordlist = await loadBIP39Wordlist(language);
  const mnemonic = entropyToMnemonic(entropy, { wordlist, coleman });
  const words = mnemonic.split(/\s+/u).length;
  const warnings = BIP39_ENTROPY_BYTE_LENGTHS.includes(entropy.length)
    ? []
    : [NONSTANDARD_LENGTH_WARNING];
  return {
    content: content(
      [
        `Language: ${language}`,
        `Words: ${words}`,
        `Mnemonic: ${mnemonic}`,
        ...warnings.map((warning) => `Warning: ${warning}`),
      ].join("\n"),
    ),
    details: { language, words, mnemonic, ...(warnings.length === 0 ? {} : { warnings }) },
  };
}
