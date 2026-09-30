import { TOOL_NAMES } from "../../../src/tool-parameters.ts";

/** How many tools `keys mcp` lists, counted from the library instead of written into the copy. */
export const TOOL_COUNT = TOOL_NAMES.length;

const ONES = [
  "zero",
  "one",
  "two",
  "three",
  "four",
  "five",
  "six",
  "seven",
  "eight",
  "nine",
  "ten",
  "eleven",
  "twelve",
  "thirteen",
  "fourteen",
  "fifteen",
  "sixteen",
  "seventeen",
  "eighteen",
  "nineteen",
];
const TENS = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"];

/**
 * Spells a count below one hundred the way a heading writes it: `Twenty-one`.
 * @param value - Integer from 0 to 99
 * @returns {string} The number in English words, first letter capitalized
 */
export function spellOut(value: number): string {
  if (!Number.isInteger(value) || value < 0 || value > 99) {
    throw new RangeError("spellOut takes an integer from 0 to 99");
  }
  const tens = TENS[Math.floor(value / 10)] ?? "";
  const ones = ONES[value % 10] ?? "";
  const words = value < 20 ? (ONES[value] ?? "") : value % 10 === 0 ? tens : `${tens}-${ones}`;
  return words.charAt(0).toUpperCase() + words.slice(1);
}
