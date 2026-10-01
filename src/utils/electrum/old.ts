/**
 * Electrum - lightweight Bitcoin client
 * Copyright (C) 2016 The Electrum developers
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

import { sha256 } from "@agntn/hashes";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { concatBytes } from "../bytes.ts";
import { decodeLegacyWords } from "./legacy.ts";

const STRETCH_ROUNDS = 100_000;
const HEX_SEED = /^(?:[0-9a-f]{32}|[0-9a-f]{64})$/u;

/**
 * Reads an old seed like `Old_KeyStore.format_seed`, refusing the spaced hex Electrum can't open.
 * @param normalized - Phrase after Electrum normalization, already inspected as `old`
 * @returns {string} The hex seed Electrum stretches
 */
export function oldHexSeed(normalized: string): string {
  if (HEX_SEED.test(normalized)) return normalized;
  if (/^[0-9a-f ]+$/u.test(normalized)) throw new Error("Electrum cannot open spaced hex seeds");
  return decodeLegacyWords(normalized.split(" "));
}

/**
 * Stretches the hex seed into the master public key, as `Old_KeyStore.mpk_from_seed` does.
 * @param hexSeed - Hex seed, hashed as ASCII text, not as bytes
 * @returns {Uint8Array} 64 bytes, x then y, without the 04 prefix
 */
export function oldMasterPublicKey(hexSeed: string): Uint8Array {
  const seed = new TextEncoder().encode(hexSeed);
  let stretched: Uint8Array = seed;
  for (let round = 0; round < STRETCH_ROUNDS; round++) {
    stretched = sha256(concatBytes(stretched, seed));
  }
  return secp256k1.getPublicKey(stretched, false).subarray(1);
}

/**
 * Adds `SHA256d("index:change:" || MPK)·G` to the master key, as `get_pubkey_from_mpk` does.
 * @param masterPublicKey - 64 byte master public key
 * @param change - 0 for receiving, 1 for change
 * @param index - Address index on that chain
 * @returns {Uint8Array} Uncompressed SEC1 public key, 65 bytes
 */
export function oldChildPublicKey(
  masterPublicKey: Uint8Array,
  change: 0 | 1,
  index: number,
): Uint8Array {
  const label = new TextEncoder().encode(`${index}:${change}:`);
  const sequence = BigInt(`0x${sha256(sha256(concatBytes(label, masterPublicKey))).toHex()}`);
  const { Point } = secp256k1;
  const master = Point.fromBytes(concatBytes(Uint8Array.of(4), masterPublicKey));
  return master.add(Point.BASE.multiply(Point.Fn.create(sequence))).toBytes(false);
}
