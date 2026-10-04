/** BIP380 input characters, in the three groups of 32 the checksum reads them in. */
const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/** Checksum characters, the bech32 alphabet. */
export const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const GENERATOR = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

/** Length of a descriptor checksum. */
export const CHECKSUM_LENGTH = 8;

/**
 * Runs the BIP380 BCH code over the symbols.
 * @param symbols - Expanded descriptor symbols
 * @returns {bigint} The 40-bit residue
 */
function polymod(symbols: readonly number[]): bigint {
  let residue = 1n;
  for (const value of symbols) {
    const top = residue >> 35n;
    residue = ((residue & 0x7_ffff_ffffn) << 5n) ^ BigInt(value);
    for (const [bit, generator] of GENERATOR.entries()) {
      if (((top >> BigInt(bit)) & 1n) === 1n) residue ^= generator;
    }
  }
  return residue;
}

/**
 * Turns each character into its place in its group, then adds a symbol for every three groups.
 * @param descriptor - Descriptor without its checksum
 * @returns {number[]} The symbols
 */
function expand(descriptor: string): number[] {
  const symbols: number[] = [];
  const groups: number[] = [];
  for (const [position, character] of Array.from(descriptor).entries()) {
    const value = INPUT_CHARSET.indexOf(character);
    if (value === -1) {
      throw new TypeError(
        `Descriptor has a character outside the BIP380 set at position ${position + 1}`,
      );
    }
    symbols.push(value & 31);
    groups.push(value >> 5);
    if (groups.length === 3)
      symbols.push(groups.splice(0).reduce((sum, group) => sum * 3 + group, 0));
  }
  if (groups.length > 0) symbols.push(groups.reduce((sum, group) => sum * 3 + group, 0));
  return symbols;
}

/**
 * Splits a descriptor from the checksum after its `#`, refusing a second `#`.
 * @param descriptor - Descriptor with or without a checksum
 * @returns {[string, string | undefined]} The descriptor and the checksum it carries
 */
export function splitChecksum(descriptor: string): [string, string | undefined] {
  const parts = descriptor.split("#");
  if (parts.length > 2) throw new TypeError("Descriptor has more than one #");
  return [parts[0] ?? "", parts[1]];
}

/**
 * Computes the BIP380 checksum of a descriptor, leaving out one it carries after `#`.
 * @param descriptor - Descriptor text
 * @returns {string} The eight checksum characters
 */
export function checksum(descriptor: string): string {
  const [body] = splitChecksum(descriptor);
  const residue = polymod([...expand(body), 0, 0, 0, 0, 0, 0, 0, 0]) ^ 1n;
  return Array.from({ length: CHECKSUM_LENGTH }, (_, index) =>
    CHECKSUM_CHARSET.charAt(Number((residue >> BigInt(5 * (7 - index))) & 31n)),
  ).join("");
}
