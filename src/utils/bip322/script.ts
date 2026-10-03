import { secp256k1 } from "@noble/curves/secp256k1.js";
import { concatBytes } from "../bytes.ts";

const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;
const OP_1NEGATE = 0x4f;
const OP_1 = 0x51;
const OP_16 = 0x60;

/** Pushes a scriptSig holds, or why it cannot be read as pushes alone. */
export type Pushes =
  | { readonly pushes: readonly Uint8Array[] }
  | { readonly state: "invalid" | "inconclusive"; readonly reason: string };

/**
 * Writes the shortest push of the data, the form `MINIMALDATA` demands.
 * @param data - Bytes to push, 1 to 75 of them in every script BIP322 signs here
 * @returns {Uint8Array} The push opcode, then the data
 */
export function push(data: Uint8Array): Uint8Array {
  if (data.length < 1 || data.length > 75) throw new RangeError("Push takes 1 to 75 bytes");
  return concatBytes(Uint8Array.of(data.length), data);
}

/**
 * What `OP_0`, `OP_1NEGATE` and `OP_1` to `OP_16` push, the opcodes that push without data bytes.
 * @param opcode - Script opcode
 * @returns {Uint8Array | undefined} The pushed bytes, undefined for any other opcode
 */
function smallNumber(opcode: number): Uint8Array | undefined {
  if (opcode === 0) return new Uint8Array(0);
  if (opcode === OP_1NEGATE) return Uint8Array.of(0x81);
  return opcode >= OP_1 && opcode <= OP_16 ? Uint8Array.of(opcode - OP_1 + 1) : undefined;
}

/**
 * Smallest data length each push opcode may carry under `MINIMALDATA`.
 * @param opcode - Push opcode
 * @returns {number} The floor, 0 for a direct push
 */
function minimalFloor(opcode: number): number {
  if (opcode === OP_PUSHDATA1) return 76;
  return opcode === OP_PUSHDATA2 ? 256 : 65_536;
}

/**
 * Reads the length a push opcode announces.
 * @param script - Whole script
 * @param offset - Position after the opcode
 * @param opcode - Push opcode
 * @returns {[number, number]} Data length and the offset of the data
 */
function pushLength(script: Uint8Array, offset: number, opcode: number): [number, number] {
  if (opcode < OP_PUSHDATA1) return [opcode, offset];
  const width = opcode === OP_PUSHDATA1 ? 1 : opcode === OP_PUSHDATA2 ? 2 : 4;
  if (offset + width > script.length) return [-1, offset];
  let length = 0;
  for (let index = width - 1; index >= 0; index--) {
    length = length * 256 + (script[offset + index] ?? 0);
  }
  return [length, offset + width];
}

/**
 * Splits a scriptSig into its pushes, refusing a push longer than it needs.
 * @param script - scriptSig bytes
 * @returns {Pushes} The pushed data, or why the script is not plain pushes
 */
export function readPushes(script: Uint8Array): Pushes {
  const pushes: Uint8Array[] = [];
  let offset = 0;
  while (offset < script.length) {
    const opcode = script[offset] ?? 0;
    const number = smallNumber(opcode);
    if (number !== undefined) {
      pushes.push(number);
      offset += 1;
      continue;
    }
    if (opcode > OP_PUSHDATA4) {
      return { state: "inconclusive", reason: "scriptSig runs opcodes besides data pushes" };
    }
    const [length, start] = pushLength(script, offset + 1, opcode);
    if (length < 0 || start + length > script.length) {
      return { state: "invalid", reason: "scriptSig ends inside a push" };
    }
    if (opcode >= OP_PUSHDATA1 && length < minimalFloor(opcode)) {
      return {
        state: "invalid",
        reason: "scriptSig pushes data with a longer opcode than it needs",
      };
    }
    pushes.push(script.slice(start, start + length));
    offset = start + length;
  }
  return { pushes };
}

/**
 * Splits an ECDSA signature from a script into DER and its hash type byte.
 * @param signature - DER signature, then one hash type byte
 * @returns {{ der: Uint8Array; hashType: number | undefined }} The two parts
 */
export function splitEcdsa(signature: Uint8Array): {
  der: Uint8Array;
  hashType: number | undefined;
} {
  return { der: signature.subarray(0, -1), hashType: signature.at(-1) };
}

/**
 * Checks a strict DER, low S ECDSA signature, as `STRICTENC`, `LOW_S` and `NULLFAIL` require.
 * @param der - DER signature without the hash type byte
 * @param digest - Sighash the signature commits to
 * @param publicKey - SEC1 public key
 * @returns {boolean} Whether the signature holds; false for any unreadable input
 */
export function verifyEcdsa(der: Uint8Array, digest: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return secp256k1.verify(der, digest, publicKey, { prehash: false, format: "der", lowS: true });
  } catch {
    return false;
  }
}

/**
 * Tells a public key that `STRICTENC` takes: 33 bytes starting 02 or 03, or 65 starting 04.
 * @param key - Pushed key bytes
 * @param compressedOnly - Demand 33 bytes, the rule for keys in a SegWit v0 witness
 * @returns {boolean} Whether the encoding passes
 */
export function isStrictPublicKey(key: Uint8Array, compressedOnly: boolean): boolean {
  if (key.length === 33) return key[0] === 2 || key[0] === 3;
  return !compressedOnly && key.length === 65 && key[0] === 4;
}
