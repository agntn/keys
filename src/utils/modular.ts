/**
 * Reduces a number into `0..modulus - 1`, negatives included.
 * @param value - Any integer
 * @param modulus - The modulus
 * @returns {bigint} The residue
 */
function mod(value: bigint, modulus: bigint): bigint {
  const residue = value % modulus;
  return residue < 0n ? residue + modulus : residue;
}

/**
 * Modular power. Variable time, so public input only.
 * @param base - The base
 * @param exponent - The power, zero or more
 * @param modulus - The modulus, above 1
 * @returns {bigint} `base ** exponent mod modulus`
 * @throws {RangeError} When the modulus is 1 or less, or the exponent is negative
 */
export function pow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 1n) throw new RangeError("Modulus must be above 1");
  if (exponent < 0n) throw new RangeError("Exponent must not be negative");
  let result = 1n;
  let square = mod(base, modulus);
  for (let rest = exponent; rest > 0n; rest >>= 1n) {
    if ((rest & 1n) === 1n) result = (result * square) % modulus;
    square = (square * square) % modulus;
  }
  return result;
}

/**
 * Modular inverse. Variable time, so public input only.
 * @param value - The number to invert
 * @param modulus - The modulus, above 1
 * @returns {bigint} The inverse in `1..modulus - 1`
 * @throws {RangeError} When the modulus is 1 or less, or no inverse exists
 */
export function invert(value: bigint, modulus: bigint): bigint {
  if (modulus <= 1n) throw new RangeError("Modulus must be above 1");
  let [a, b] = [mod(value, modulus), modulus];
  let [x, u] = [0n, 1n];
  while (a !== 0n) {
    const quotient = b / a;
    [a, b] = [b - a * quotient, a];
    [x, u] = [u, x - u * quotient];
  }
  if (b !== 1n) throw new RangeError("Number has no inverse under this modulus");
  return mod(x, modulus);
}
