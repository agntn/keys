/**
 * Electrum - lightweight Bitcoin client
 * Copyright (C) 2014 Thomas Voegtlin
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

import { hmac } from "@noble/hashes/hmac.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { ELECTRUM_LEGACY_WORDS } from "./electrum-legacy.ts";

/** Electrum seed versions, including those this library refuses to derive. */
export type ElectrumSeedType = "standard" | "segwit" | "old" | "2fa" | "2fa_segwit" | "unknown";

/** Python str.split() includes four separators that Unicode White_Space omits. */
/* oxlint-disable-next-line no-control-regex */
const ELECTRUM_WHITESPACE = /[\p{White_Space}\u001C-\u001F]+/gu;

/** Electrum's CJK intervals, not the Unicode Script=Han property. */
const CJK_INTERVALS: ReadonlyArray<readonly [number, number]> = [
  [0x4e00, 0x9fff],
  [0x3400, 0x4dbf],
  [0x20000, 0x2a6df],
  [0x2a700, 0x2b73f],
  [0x2b740, 0x2b81f],
  [0xf900, 0xfaff],
  [0x2f800, 0x2fa1d],
  [0x3190, 0x319f],
  [0x2e80, 0x2eff],
  [0x2f00, 0x2fdf],
  [0x31c0, 0x31ef],
  [0x2ff0, 0x2fff],
  [0xe0100, 0xe01ef],
  [0x3100, 0x312f],
  [0x31a0, 0x31bf],
  [0xff00, 0xffef],
  [0x3040, 0x309f],
  [0x30a0, 0x30ff],
  [0x31f0, 0x31ff],
  [0x1b000, 0x1b0ff],
  [0xac00, 0xd7af],
  [0x1100, 0x11ff],
  [0xa960, 0xa97f],
  [0xd7b0, 0xd7ff],
  [0x3130, 0x318f],
  [0xa4d0, 0xa4ff],
  [0x16f00, 0x16f9f],
  [0xa000, 0xa48f],
  [0xa490, 0xa4cf],
];

/**
 * Tests Electrum's historical CJK ranges.
 * @param character - One code point
 * @returns {boolean} Whether Electrum treats it as CJK
 */
function isCJK(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return (
    codePoint !== undefined &&
    CJK_INTERVALS.some(([low, high]) => codePoint >= low && codePoint <= high)
  );
}

/**
 * Applies Electrum normalization to both the phrase and its passphrase.
 * Canonical ordering between classes 240 and 1 detects nonzero combining classes;
 * unlike stripping all marks, it preserves class-zero marks and variation selectors.
 * @param text - Phrase or passphrase
 * @returns {string} Electrum-normalized text
 */
export function normalizeElectrumText(text: string): string {
  if (typeof text !== "string" || !text.isWellFormed() || Array.from(text).length > 4096) {
    throw new TypeError("Electrum text must be well-formed Unicode of at most 4096 characters");
  }
  const unaccented = Array.from(text.normalize("NFKD").toLowerCase())
    .filter((character) => `\u0345${character}\u0334`.normalize("NFD").startsWith("\u0345"))
    .join("");
  const characters = Array.from(
    unaccented.replaceAll(ELECTRUM_WHITESPACE, " ").replaceAll(/^ | $/gu, ""),
  );
  return characters
    .filter(
      (character, index) =>
        character !== " " ||
        !isCJK(characters[index - 1] ?? "") ||
        !isCJK(characters[index + 1] ?? ""),
    )
    .join("");
}

/**
 * Preserves Electrum's legacy detection precedence over version prefixes.
 * @param normalized - Normalized phrase
 * @returns {boolean} Whether the phrase uses an unsupported legacy format
 */
function isLegacySeed(normalized: string): boolean {
  const words = normalized.split(" ");
  return (
    (/^(?:[a-f0-9]{2} *)+$/u.test(normalized) &&
      [32, 64].includes(normalized.replaceAll(" ", "").length)) ||
    ([12, 24].includes(words.length) && words.every((word) => ELECTRUM_LEGACY_WORDS.has(word)))
  );
}

/**
 * Inspects Electrum versions without falling back to BIP39 or deriving a secret.
 * Electrum 2.7 reused prefix 101 for different derivation rules, distinguished only by word count.
 * @param mnemonic - Complete supplied phrase
 * @returns {ElectrumSeedType} Detected version, or unknown
 */
export function inspectElectrumMnemonic(mnemonic: string): ElectrumSeedType {
  const normalized = normalizeElectrumText(mnemonic);
  const wordCount = mnemonic.split(ELECTRUM_WHITESPACE).filter(Boolean).length;
  if (isLegacySeed(normalized)) {
    return "old";
  }
  const version = bytesToHex(hmac(sha512, utf8ToBytes("Seed version"), utf8ToBytes(normalized)));
  if (version.startsWith("01")) return "standard";
  if (version.startsWith("100")) return "segwit";
  if (version.startsWith("101") && (wordCount === 12 || wordCount >= 20)) return "2fa";
  if (version.startsWith("102")) return "2fa_segwit";
  return "unknown";
}

/**
 * Derives an Electrum seed, never a BIP39 seed or a BIP32 master key.
 * @param mnemonic - Complete standard or SegWit phrase
 * @param passphrase - Electrum seed extension, normalized like the phrase
 * @returns {{ scheme: "electrum"; seedType: "standard" | "segwit"; seed: Uint8Array }} Seed and version
 */
export function deriveElectrumSeed(
  mnemonic: string,
  passphrase = "",
): {
  readonly scheme: "electrum";
  readonly seedType: "standard" | "segwit";
  readonly seed: Uint8Array;
} {
  const seedType = inspectElectrumMnemonic(mnemonic);
  if (seedType !== "standard" && seedType !== "segwit") {
    throw new Error("Unsupported or unrecognized Electrum seed version");
  }
  const normalizedPassphrase = normalizeElectrumText(passphrase);
  return {
    scheme: "electrum",
    seedType,
    seed: pbkdf2(
      sha512,
      utf8ToBytes(normalizeElectrumText(mnemonic)),
      utf8ToBytes(`electrum${normalizedPassphrase}`),
      { c: 2048, dkLen: 64 },
    ),
  };
}
