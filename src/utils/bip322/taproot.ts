import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import { taggedHash } from "../address.ts";
import { concatBytes } from "../bytes.ts";
import { varBytes } from "../transaction/transaction.ts";

/** First byte BIP341 reserves for an annex, the last of two or more witness items. */
const ANNEX_TAG = 0x50;

/** Control block sizes: parity and leaf version byte, internal key, then up to 128 path nodes. */
const CONTROL = { base: 33, node: 32, nodes: 128 } as const;

/**
 * Drops the annex from a Taproot witness, which no signature check reads here.
 * @param witness - Witness items of the input
 * @returns {readonly Uint8Array[]} The items without the annex
 */
export function withoutAnnex(witness: readonly Uint8Array[]): readonly Uint8Array[] {
  const last = witness.at(-1);
  return witness.length >= 2 && last?.[0] === ANNEX_TAG ? witness.slice(0, -1) : witness;
}

/**
 * Orders two nodes the way BIP341 hashes a branch: the smaller one first.
 * @param left - One node
 * @param right - The other node
 * @returns {boolean} Whether `left` sorts before or equal to `right`
 */
function sortsFirst(left: Uint8Array, right: Uint8Array): boolean {
  for (let index = 0; index < left.length; index++) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference < 0;
  }
  return true;
}

/**
 * Walks from the leaf hash up the control block path to the Merkle root.
 * @param control - Control block
 * @param leaf - `TapLeaf` hash of the script
 * @returns {Uint8Array} The root
 */
function merkleRoot(control: Uint8Array, leaf: Uint8Array): Uint8Array {
  let node = leaf;
  for (let offset = CONTROL.base; offset < control.length; offset += CONTROL.node) {
    const sibling = control.subarray(offset, offset + CONTROL.node);
    const pair = sortsFirst(node, sibling) ? [node, sibling] : [sibling, node];
    node = taggedHash("TapBranch", concatBytes(...pair));
  }
  return node;
}

/**
 * Tells a control block of the length BIP341 allows.
 * @param control - Last witness item
 * @returns {boolean} True for 33 bytes plus whole path nodes, at most 128 of them
 */
function hasControlLength(control: Uint8Array): boolean {
  const path = control.length - CONTROL.base;
  return path >= 0 && path % CONTROL.node === 0 && path / CONTROL.node <= CONTROL.nodes;
}

/**
 * Tweaks the internal key by the root into the output key, or undefined when the tweak breaks.
 * @param internal - x-only internal key
 * @param root - Merkle root of the script tree
 * @returns {Uint8Array | undefined} The compressed output key
 */
function tweakedKey(internal: Uint8Array, root: Uint8Array): Uint8Array | undefined {
  try {
    const point = secp256k1.Point.fromBytes(concatBytes(Uint8Array.of(2), internal));
    const tweak = secp256k1.Point.Fn.fromBytes(taggedHash("TapTweak", concatBytes(internal, root)));
    return point.add(secp256k1.Point.BASE.multiply(tweak)).toBytes(true);
  } catch {
    return undefined;
  }
}

/**
 * Checks that a script path spend commits to the output key, the part BIP341 settles without
 * running the script.
 * @param stack - Witness items without the annex: inputs, then the script and the control block
 * @param outputKey - x-only output key the address holds
 * @returns {string | undefined} Why the spend cannot be valid, undefined when the commitment holds
 */
export function scriptPathMismatch(
  stack: readonly Uint8Array[],
  outputKey: Uint8Array,
): string | undefined {
  const control = stack.at(-1);
  const script = stack.at(-2);
  if (control === undefined || script === undefined) {
    return "Taproot script path needs a script and a control block";
  }
  if (!hasControlLength(control)) return "Control block has a length BIP341 does not allow";
  const head = control[0] ?? 0;
  const leaf = taggedHash("TapLeaf", concatBytes(Uint8Array.of(head & 0xfe), varBytes(script)));
  const output = tweakedKey(control.subarray(1, CONTROL.base), merkleRoot(control, leaf));
  if (output === undefined) return "Control block holds no valid internal key";
  const parity = (output[0] ?? 0) & 1;
  if (!equalBytes(output.subarray(1), outputKey) || parity !== (head & 1)) {
    return "Control block does not commit to the address";
  }
  return undefined;
}
