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

/** Python str.split() includes four separators that Unicode White_Space omits. */
/* oxlint-disable-next-line no-control-regex */
export const ELECTRUM_WHITESPACE = /[\p{White_Space}\u001C-\u001F]+/gu;

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
