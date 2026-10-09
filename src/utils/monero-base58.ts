import { base58 } from "@agntn/encodings/base58";
import { concatBytes } from "./bytes.ts";

/** Bytes in a full block. */
const BLOCK_BYTES = 8;

/** Characters a block of 0 to 8 bytes always takes, padded with `1` in front. */
const ENCODED_SIZES: readonly number[] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

/** Characters of a full block. */
const ENCODED_BLOCK = 11;

/**
 * Writes bytes the way Monero writes addresses: base58 in blocks of eight bytes, each padded to a
 * fixed width, so the length of the text depends only on the length of the bytes.
 * @param bytes - The bytes to encode
 * @returns {string} The block base58 text
 */
export function encodeMoneroBase58(bytes: Uint8Array): string {
  let text = "";
  for (let start = 0; start < bytes.length; start += BLOCK_BYTES) {
    const block = bytes.subarray(start, start + BLOCK_BYTES);
    text += base58.encode(block).padStart(ENCODED_SIZES[block.length] ?? ENCODED_BLOCK, "1");
  }
  return text;
}

/**
 * Reads one block back: its value has to fit the bytes its width stands for.
 * @param chunk - Up to 11 characters
 * @returns {Uint8Array} The bytes of the block
 * @throws {RangeError} When no block takes that width or the value overflows it
 */
function decodeBlock(chunk: string): Uint8Array {
  const size = ENCODED_SIZES.indexOf(chunk.length);
  if (size < 1) throw new RangeError("Monero base58 has no block of this length");
  const raw = base58.decode(chunk);
  const start = raw.findIndex((byte) => byte !== 0);
  const value = start === -1 ? new Uint8Array(0) : raw.subarray(start);
  if (value.length > size) throw new RangeError("Monero base58 block overflows its bytes");
  const block = new Uint8Array(size);
  block.set(value, size - value.length);
  return block;
}

/**
 * Reads Monero's block base58 back into bytes.
 * @param text - The block base58 text
 * @returns {Uint8Array} The bytes it encodes
 * @throws {RangeError} On a character off the alphabet, a bad last block or an overflowing one
 */
export function decodeMoneroBase58(text: string): Uint8Array {
  const blocks: Uint8Array[] = [];
  for (let start = 0; start < text.length; start += ENCODED_BLOCK) {
    blocks.push(decodeBlock(text.slice(start, start + ENCODED_BLOCK)));
  }
  return concatBytes(...blocks);
}
