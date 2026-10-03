/** Bases that make Miller-Rabin exact below 3.3 * 10^24, and a strong test above. */
const WITNESSES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n];

/**
 * Reduce a value into 0 to p minus 1, negative values included.
 * @param value - Any integer
 * @param p - The modulus
 * @returns {bigint} The value mod p
 */
export function mod(value: bigint, p: bigint): bigint {
  const rest = value % p;
  return rest < 0n ? rest + p : rest;
}

/**
 * Raise a base to a power mod p.
 * @param base - Any integer
 * @param exponent - Zero or more
 * @param p - The modulus
 * @returns {bigint} base to the exponent, mod p
 */
export function power(base: bigint, exponent: bigint, p: bigint): bigint {
  let result = 1n;
  let factor = mod(base, p);
  for (let rest = exponent; rest > 0n; rest >>= 1n) {
    if ((rest & 1n) === 1n) result = (result * factor) % p;
    factor = (factor * factor) % p;
  }
  return result;
}

/**
 * Invert a value mod a prime with the extended Euclidean algorithm.
 * @param value - Not a multiple of p
 * @param p - A prime modulus
 * @returns {bigint} The inverse
 */
export function invert(value: bigint, p: bigint): bigint {
  let [low, high] = [mod(value, p), p];
  let [lowFactor, highFactor] = [1n, 0n];
  while (low > 1n) {
    const quotient = high / low;
    [low, high] = [high - quotient * low, low];
    [lowFactor, highFactor] = [highFactor - quotient * lowFactor, lowFactor];
  }
  return mod(lowFactor, p);
}

/**
 * The integer square root, rounded down.
 * @param value - Zero or more
 * @returns {bigint} The largest root whose square does not pass the value
 */
export function squareRoot(value: bigint): bigint {
  if (value < 2n) return value;
  let root = BigInt(Math.floor(Math.sqrt(Number(value))));
  while (root * root > value) root = (root + value / root) >> 1n;
  while ((root + 1n) * (root + 1n) <= value) root += 1n;
  return root;
}

/**
 * Run one Miller-Rabin round.
 * @param n - An odd number above the witness
 * @param witness - The base
 * @returns {boolean} False when the witness proves n composite
 */
function passesRound(n: bigint, witness: bigint): boolean {
  let odd = n - 1n;
  let shifts = 0;
  while ((odd & 1n) === 0n) {
    odd >>= 1n;
    shifts += 1;
  }
  let x = power(witness, odd, n);
  if (x === 1n || x === n - 1n) return true;
  for (let round = 1; round < shifts; round += 1) {
    x = (x * x) % n;
    if (x === n - 1n) return true;
  }
  return false;
}

/**
 * Test a number for primality, exactly below 3.3 * 10^24.
 * @param n - Any integer
 * @returns {boolean} True for a prime
 */
export function isPrime(n: bigint): boolean {
  if (n < 2n) return false;
  for (const witness of WITNESSES) {
    if (n === witness) return true;
    if (n % witness === 0n) return false;
  }
  return WITNESSES.every((witness) => passesRound(n, witness));
}

/**
 * Split a number into its distinct prime factors by trial division, in Number arithmetic.
 * @param value - From 1 to 2^53 minus 1
 * @returns {bigint[]} The distinct primes, smallest first
 */
export function primeFactors(value: bigint): bigint[] {
  const factors: bigint[] = [];
  let rest = Number(value);
  for (let divisor = 2; divisor * divisor <= rest; divisor += divisor === 2 ? 1 : 2) {
    if (rest % divisor !== 0) continue;
    factors.push(BigInt(divisor));
    while (rest % divisor === 0) rest /= divisor;
  }
  if (rest > 1) factors.push(BigInt(rest));
  return factors;
}
