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
