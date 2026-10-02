import { create } from "@agntn/hashes";

/** A shape in the entropy bytes that a random draw almost never has. */
export type EntropyPattern =
  | { readonly kind: "all-zeros" }
  | { readonly kind: "all-ones" }
  | { readonly kind: "repeated-byte"; readonly byte: string }
  | { readonly kind: "repeated-block"; readonly block: string }
  | { readonly kind: "low-diversity"; readonly distinct: number };

/** A text whose digest, cut to the entropy length, equals the entropy. */
export interface EntropyPreimage {
  readonly algorithm: EntropyHashAlgorithm;
  readonly text: string;
  readonly source: "built-in" | "given";
}

/** What the entropy bytes look like besides their hex. */
export interface EntropyProfile {
  readonly text: string | null;
  readonly patterns: readonly EntropyPattern[];
  readonly preimages: readonly EntropyPreimage[];
}

/** Digests compared against the entropy, each cut to the entropy length. */
export const ENTROPY_HASH_ALGORITHMS = ["md5", "sha1", "sha256"] as const;

export type EntropyHashAlgorithm = (typeof ENTROPY_HASH_ALGORITHMS)[number];

/** Digest length of each algorithm in bytes. */
export const ENTROPY_DIGEST_BYTES: Record<EntropyHashAlgorithm, number> = {
  md5: 16,
  sha1: 20,
  sha256: 32,
};

/** Texts a puzzle author hashes when the entropy should look random but mean something. */
export const BUILT_IN_PREIMAGES: readonly string[] = [
  "",
  "password",
  "bitcoin",
  "satoshi",
  "satoshi nakamoto",
  "hello",
  "hello world",
  "test",
  "secret",
  "seed",
  "puzzle",
  "answer",
  "abandon",
  "123456",
];

const NOT_PRINTABLE = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u;

/** Share of code points that must be printable before the bytes count as text. */
const TEXT_SHARE = 0.75;

/** Random entropy almost never has this few distinct bytes: under 1e-20 at 16 bytes. */
const LOW_DIVERSITY_SHARE = 0.25;

function entropyText(entropy: Uint8Array): string | null {
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(entropy);
  } catch {
    return null;
  }
  let characters = 0;
  let printable = 0;
  for (const character of decoded) {
    characters++;
    if (!NOT_PRINTABLE.test(character) || /[\t\n\r]/u.test(character)) printable++;
  }
  return printable >= characters * TEXT_SHARE ? decoded : null;
}

function repeatPeriod(entropy: Uint8Array): number | null {
  for (let period = 1; period <= entropy.length / 2; period++) {
    if (entropy.every((byte, index) => index < period || byte === entropy[index - period])) {
      return period;
    }
  }
  return null;
}

function entropyPatterns(entropy: Uint8Array): EntropyPattern[] {
  const period = repeatPeriod(entropy);
  if (period === 1) {
    const [byte] = entropy;
    if (byte === 0x00) return [{ kind: "all-zeros" }];
    if (byte === 0xff) return [{ kind: "all-ones" }];
    return [{ kind: "repeated-byte", byte: entropy.subarray(0, 1).toHex() }];
  }
  if (period !== null)
    return [{ kind: "repeated-block", block: entropy.subarray(0, period).toHex() }];
  const distinct = new Set(entropy).size;
  return distinct <= entropy.length * LOW_DIVERSITY_SHARE
    ? [{ kind: "low-diversity", distinct }]
    : [];
}

/**
 * Algorithms whose digest is long enough to cover entropy of this length.
 * @param length - Entropy length in bytes.
 * @returns {EntropyHashAlgorithm[]} The algorithms compared for that length.
 */
export function entropyHashAlgorithms(length: number): EntropyHashAlgorithm[] {
  return ENTROPY_HASH_ALGORITHMS.filter((algorithm) => ENTROPY_DIGEST_BYTES[algorithm] >= length);
}

function entropyPreimages(entropy: Uint8Array, given: readonly string[]): EntropyPreimage[] {
  const target = entropy.toHex();
  const algorithms = entropyHashAlgorithms(entropy.length);
  const encoder = new TextEncoder();
  const candidates = [
    ...BUILT_IN_PREIMAGES.map((text) => ({ text, source: "built-in" as const })),
    ...given.map((text) => ({ text, source: "given" as const })),
  ];
  return candidates.flatMap(({ text, source }) => {
    const bytes = encoder.encode(text);
    return algorithms
      .filter((algorithm) => {
        const { digest } = create(algorithm).hash(bytes);
        return typeof digest === "string" && digest.startsWith(target);
      })
      .map((algorithm) => ({ algorithm, text, source }));
  });
}

/**
 * Reads entropy as text, as a byte pattern and as the hash of a known text.
 * @param entropy - BIP39 entropy bytes.
 * @param preimages - Caller texts checked after the built-in list.
 * @returns {EntropyProfile} The text reading, the patterns and every matching preimage.
 */
export function profileEntropy(
  entropy: Uint8Array,
  preimages: readonly string[] = [],
): EntropyProfile {
  return {
    text: entropyText(entropy),
    patterns: entropyPatterns(entropy),
    preimages: entropyPreimages(entropy, preimages),
  };
}
