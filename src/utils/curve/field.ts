/** Small primes for trial division and Miller-Rabin, exact on their own only below 3.3 * 10^24. */
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
 * Invert a value mod p with the extended Euclidean algorithm.
 * @param value - Not a multiple of p
 * @param p - The modulus
 * @returns {bigint} The inverse
 * @throws {RangeError} When the value shares a factor with p, so p is no prime
 */
export function invert(value: bigint, p: bigint): bigint {
  let [low, high] = [mod(value, p), p];
  let [lowFactor, highFactor] = [1n, 0n];
  while (low > 1n) {
    const quotient = high / low;
    [low, high] = [high - quotient * low, low];
    [lowFactor, highFactor] = [highFactor - quotient * lowFactor, lowFactor];
  }
  if (low === 0n) throw new RangeError("No inverse exists mod p, so p is not prime");
  return mod(lowFactor, p);
}

/**
 * The integer square root, rounded down.
 * @param value - Zero or more
 * @returns {bigint} The largest root whose square does not pass the value
 */
export function squareRoot(value: bigint): bigint {
  if (value < 2n) return value;
  let root = 1n << BigInt(Math.ceil(value.toString(2).length / 2));
  for (let next = (root + value / root) >> 1n; next < root; next = (root + value / root) >> 1n) {
    root = next;
  }
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
 * The Jacobi symbol of top over an odd bottom.
 * @param top - Any integer
 * @param bottom - An odd positive integer
 * @returns {number} 1, -1, or 0 when they share a factor
 */
function jacobi(top: bigint, bottom: bigint): number {
  let [a, n] = [mod(top, bottom), bottom];
  let result = 1;
  while (a !== 0n) {
    for (; (a & 1n) === 0n; a >>= 1n) {
      if (n % 8n === 3n || n % 8n === 5n) result = -result;
    }
    [a, n] = [n, a];
    if (a % 4n === 3n && n % 4n === 3n) result = -result;
    a %= n;
  }
  return n === 1n ? result : 0;
}

/**
 * Find D for the Lucas test, the first of 5, -7, 9, -11 and on with Jacobi symbol -1.
 * @param n - An odd number above 41 that is no perfect square
 * @returns {bigint | undefined} D, or undefined when one of the candidates shares a factor with n
 */
function lucasParameter(n: bigint): bigint | undefined {
  for (let d = 5n; ; d = d > 0n ? -d - 2n : 2n - d) {
    const symbol = jacobi(d, n);
    if (symbol === -1) return d;
    if (symbol === 0) return undefined;
  }
}

/**
 * Halve a value mod an odd n.
 * @param value - Any integer
 * @param n - An odd modulus
 * @returns {bigint} value / 2 mod n
 */
function halve(value: bigint, n: bigint): bigint {
  const rest = mod(value, n);
  return ((rest & 1n) === 1n ? rest + n : rest) >> 1n;
}

/**
 * Walk the Lucas sequences with P = 1 up to index k.
 * @param n - The odd modulus
 * @param d - The discriminant
 * @param k - The index, 1 or more
 * @returns {[bigint, bigint, bigint]} U_k, V_k and Q^k, mod n
 */
function lucasSequence(n: bigint, d: bigint, k: bigint): [bigint, bigint, bigint] {
  const q = mod((1n - d) / 4n, n);
  let [u, v, qk] = [1n, 1n, q];
  for (const bit of k.toString(2).slice(1)) {
    [u, v, qk] = [(u * v) % n, mod(v * v - 2n * qk, n), (qk * qk) % n];
    if (bit === "1") {
      [u, v, qk] = [halve(u + v, n), halve(d * u + v, n), (qk * q) % n];
    }
  }
  return [u, v, qk];
}

/**
 * Run the strong Lucas probable prime test with Selfridge parameters.
 * @param n - An odd number above 41
 * @returns {boolean} False when n is shown composite
 */
function passesLucas(n: bigint): boolean {
  const root = squareRoot(n);
  const d = root * root === n ? undefined : lucasParameter(n);
  if (d === undefined) return false;
  let odd = n + 1n;
  let shifts = 0;
  for (; (odd & 1n) === 0n; odd >>= 1n) shifts += 1;
  let [u, v, qk] = lucasSequence(n, d, odd);
  if (u === 0n || v === 0n) return true;
  for (let round = 1; round < shifts; round += 1) {
    [v, qk] = [mod(v * v - 2n * qk, n), (qk * qk) % n];
    if (v === 0n) return true;
  }
  return false;
}

/**
 * Test a number for primality: Miller-Rabin on small prime bases plus a strong Lucas test, as in
 * Baillie-PSW, which no known composite passes.
 * @param n - Any integer
 * @returns {boolean} True for a prime
 */
export function isPrime(n: bigint): boolean {
  if (n < 2n) return false;
  for (const witness of WITNESSES) {
    if (n === witness) return true;
    if (n % witness === 0n) return false;
  }
  return WITNESSES.every((witness) => passesRound(n, witness)) && passesLucas(n);
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
