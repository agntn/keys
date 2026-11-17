/**
 * Joins byte arrays into one new array, in order.
 * @param parts - The arrays to join
 * @returns {Uint8Array} A new array holding every byte of every part
 */
export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Compares bytes without an early exit, once the lengths match.
 * @param a - One array
 * @param b - The other
 * @returns {boolean} Whether both hold the same bytes
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (const [index, byte] of a.entries()) diff |= byte ^ (b[index] ?? 0);
  return diff === 0;
}

/**
 * Reads big endian bytes as a number.
 * @param bytes - The bytes, empty for 0
 * @returns {bigint} The number
 */
export function bytesToNumberBE(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt(`0x${bytes.toHex()}`);
}

/**
 * Reads little endian bytes as a number.
 * @param bytes - The bytes, empty for 0
 * @returns {bigint} The number
 */
export function bytesToNumberLE(bytes: Uint8Array): bigint {
  return bytesToNumberBE(bytes.toReversed());
}

/**
 * Writes a number as big endian bytes of a fixed length.
 * @param value - The number, zero or more
 * @param length - How many bytes to fill
 * @returns {Uint8Array} Zero padded bytes
 * @throws {RangeError} When the number is negative or needs more bytes
 */
export function numberToBytesBE(value: bigint, length: number): Uint8Array<ArrayBuffer> {
  const digits = value.toString(16);
  if (value < 0n || digits.length > length * 2) {
    throw new RangeError(`Number does not fit ${length} bytes`);
  }
  return Uint8Array.fromHex(digits.padStart(length * 2, "0"));
}

/**
 * Draws random bytes from `globalThis.crypto`.
 * @param length - How many bytes
 * @returns {Uint8Array} Fresh random bytes
 */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}
