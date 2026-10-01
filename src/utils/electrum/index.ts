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

import { Sha512Hasher, hmac, pbkdf2 } from "@agntn/hashes";
import { ELECTRUM_LEGACY_WORDS } from "./legacy.ts";
import { ELECTRUM_WHITESPACE, normalizeElectrumText } from "./normalize.ts";
import { oldChildPublicKey, oldHexSeed, oldMasterPublicKey } from "./old.ts";

/**
 * Starts the SHA-512 state that Electrum's HMAC and PBKDF2 run on.
 * @returns {Sha512Hasher} A fresh hasher
 */
const createSha512 = (): Sha512Hasher => new Sha512Hasher();

/** Electrum seed versions, including those this library refuses to derive. */
export type ElectrumSeedType = "standard" | "segwit" | "old" | "2fa" | "2fa_segwit" | "unknown";

/**
 * Preserves Electrum's legacy detection precedence over version prefixes.
 * @param normalized - Normalized phrase
 * @returns {boolean} Whether the phrase uses an unsupported legacy format
 */
function isLegacySeed(normalized: string): boolean {
  const words = normalized.split(" ");
  return (
    (/^(?:[a-f0-9]{2} *)+$/u.test(normalized) &&
      [32, 64].includes(normalized.replaceAll(" ", "").length)) ||
    ([12, 24].includes(words.length) && words.every((word) => ELECTRUM_LEGACY_WORDS.has(word)))
  );
}

/**
 * Inspects Electrum versions without falling back to BIP39 or deriving a secret.
 * Electrum 2.7 reused prefix 101 for different derivation rules, distinguished only by word count.
 * @param mnemonic - Complete supplied phrase
 * @returns {ElectrumSeedType} Detected version, or unknown
 */
export function inspect(mnemonic: string): ElectrumSeedType {
  const normalized = normalizeElectrumText(mnemonic);
  const wordCount = mnemonic.split(ELECTRUM_WHITESPACE).filter(Boolean).length;
  if (isLegacySeed(normalized)) {
    return "old";
  }
  const version = hmac(
    createSha512,
    new TextEncoder().encode("Seed version"),
    new TextEncoder().encode(normalized),
  ).toHex();
  if (version.startsWith("01")) return "standard";
  if (version.startsWith("100")) return "segwit";
  if (version.startsWith("101") && (wordCount === 12 || wordCount >= 20)) return "2fa";
  if (version.startsWith("102")) return "2fa_segwit";
  return "unknown";
}

/**
 * Derives an Electrum seed, never a BIP39 seed or a BIP32 master key.
 * @param mnemonic - Complete standard or SegWit phrase
 * @param passphrase - Electrum seed extension, normalized like the phrase
 * @returns {{ scheme: "electrum"; seedType: "standard" | "segwit"; seed: Uint8Array }} Seed and version
 */
export function deriveSeed(
  mnemonic: string,
  passphrase = "",
): {
  readonly scheme: "electrum";
  readonly seedType: "standard" | "segwit";
  readonly seed: Uint8Array;
} {
  const seedType = inspect(mnemonic);
  if (seedType !== "standard" && seedType !== "segwit") {
    throw new Error("Unsupported or unrecognized Electrum seed version");
  }
  const normalizedPassphrase = normalizeElectrumText(passphrase);
  return {
    scheme: "electrum",
    seedType,
    seed: pbkdf2(
      createSha512,
      new TextEncoder().encode(normalizeElectrumText(mnemonic)),
      new TextEncoder().encode(`electrum${normalizedPassphrase}`),
      2048,
      64,
    ),
  };
}

/**
 * Derives the master public key of an old (pre-2.0) seed: 100000 SHA-256 rounds, no BIP32.
 * @param mnemonic - Old seed words or the 32 or 64 digit hex seed Electrum also takes
 * @returns {Uint8Array} 64 bytes, x then y, as Electrum shows the MPK
 */
export function deriveOldMasterPublicKey(mnemonic: string): Uint8Array {
  if (inspect(mnemonic) !== "old") throw new Error("Not an old Electrum seed");
  return oldMasterPublicKey(oldHexSeed(normalizeElectrumText(mnemonic)));
}

/**
 * Derives the uncompressed public key of one old seed address from its master public key.
 * @param masterPublicKey - 64 byte MPK from `deriveOldMasterPublicKey` or a watching wallet
 * @param change - 0 for receiving addresses, 1 for change
 * @param index - Address index on that chain
 * @returns {Uint8Array} Uncompressed SEC1 public key, the one its P2PKH address hashes
 */
export function deriveOldPublicKey(
  masterPublicKey: Uint8Array,
  change: number,
  index: number,
): Uint8Array {
  if (masterPublicKey.length !== 64) throw new RangeError("Master public key must be 64 bytes");
  if (change !== 0 && change !== 1) throw new RangeError("Change must be 0 or 1");
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new RangeError("Index must be a non-negative integer");
  }
  return oldChildPublicKey(masterPublicKey, change, index);
}
