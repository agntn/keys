import { sha256 } from "@agntn/hashes";
import { hash160, taggedHash } from "../address.ts";
import { tapBranch, tweakedKey } from "../bip322/taproot.ts";
import { concatBytes } from "../bytes.ts";
import { encodeBase58Check } from "../encoding.ts";
import { HARDENED_OFFSET } from "../hd-index.ts";
import { MAX_MULTISIG_KEYS, MAX_P2SH_SCRIPT_SIZE } from "../script/limits.ts";
import {
  multisigScript,
  numberPush,
  p2shAddress,
  p2shProgram,
  p2wshProgram,
  readNetwork,
  SCRIPT_NETWORKS,
  segwitAddress,
  sortKeys,
  type ScriptNetwork,
} from "../script/script.ts";
import { pushOf } from "../transaction/script.ts";
import { varBytes } from "../transaction/transaction.ts";
import {
  CHECKSUM_CHARSET,
  CHECKSUM_LENGTH,
  checksum as computeChecksum,
  splitChecksum,
} from "./checksum.ts";
import { parseKey, type DescriptorKey, type KeyContext } from "./keys.ts";

/** Network of the addresses. */
export interface DescriptorOptions {
  readonly network?: ScriptNetwork;
}

/** What a descriptor pays to at one index. */
export interface DescriptorOutput {
  /** The output script, the scriptPubKey. */
  readonly script: Uint8Array;
  readonly address: string;
}

/** A descriptor read and checked, ready to derive. */
export interface Descriptor {
  /** The BIP380 checksum of the descriptor as given. */
  readonly checksum: string;
  /** Whether a key ends in `/*`, so each index gives another output. */
  readonly ranged: boolean;
  /** The output at an index, which a ranged descriptor needs and any other refuses. */
  readonly derive: (index?: number) => DescriptorOutput;
}

/** A part of a descriptor that turns an index into bytes. */
interface Part {
  readonly ranged: boolean;
  readonly at: (index: number) => Uint8Array;
}

/** Most keys `multi_a` takes, Core's limit. */
const MAX_MULTI_A_KEYS = 999;

/** Deepest script tree BIP341 lets a control block prove. */
const MAX_TREE_DEPTH = 128;

const OP = {
  DUP: 0x76,
  EQUALVERIFY: 0x88,
  HASH160: 0xa9,
  NUMEQUAL: 0x9c,
  CHECKSIG: 0xac,
  CHECKSIGADD: 0xba,
} as const;

/** Eight characters of the checksum alphabet. */
const CHECKSUM_PATTERN = new RegExp(`^[${CHECKSUM_CHARSET}]{${CHECKSUM_LENGTH}}$`, "u");

/** Leaf version of a tapscript. */
const TAPSCRIPT_LEAF = 0xc0;

/**
 * Names an expression in an error without echoing what might be a key.
 * @param name - Text before the parenthesis
 * @returns {string} `name()` for a plain name, otherwise a neutral word
 */
function shown(name: string): string {
  return /^[a-z_]{1,20}$/u.test(name) ? `${name}()` : "This expression";
}

/**
 * Splits `name(args)` into the name and the text inside.
 * @param text - Script expression
 * @returns {[string, string]} The name and the arguments, or an empty name for anything else
 */
function call(text: string): [string, string] {
  const open = text.indexOf("(");
  if (open <= 0 || !text.endsWith(")")) return ["", text];
  return [text.slice(0, open), text.slice(open + 1, -1)];
}

/**
 * Splits arguments at the commas outside any brackets.
 * @param text - Arguments of one expression
 * @returns {string[]} Each argument
 */
function split(text: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (const [index, character] of Array.from(text).entries()) {
    if ("([{".includes(character)) depth++;
    else if (")]}".includes(character)) depth--;
    if (depth < 0) throw new TypeError("Descriptor has a closing bracket without its opening one");
    if (character === "," && depth === 0) {
      parts.push(text.slice(start, index));
      start = index + 1;
    }
  }
  if (depth !== 0) throw new TypeError("Descriptor has an opening bracket without its closing one");
  parts.push(text.slice(start));
  return parts;
}

/**
 * Reads the one key argument of `pk`, `pkh` or `wpkh`.
 * @param name - Expression name
 * @param args - Its arguments
 * @param context - Where the key lands
 * @param network - Network of the key
 * @returns {DescriptorKey} The key
 */
function singleKey(
  name: string,
  args: string,
  context: KeyContext,
  network: ScriptNetwork,
): DescriptorKey {
  const parts = split(args);
  if (parts.length !== 1 || parts[0] === "" || /[()]/u.test(args)) {
    throw new TypeError(`${name}() takes one key`);
  }
  return parseKey(args, context, network);
}

/**
 * Builds on one part, keeping whether it is ranged.
 * @param part - Part to build on
 * @param build - Turns its bytes at one index into the result
 * @returns {Part} The new part
 */
function mapped(part: Part, build: (value: Uint8Array) => Uint8Array): Part {
  return { ranged: part.ranged, at: (index) => build(part.at(index)) };
}

/**
 * Joins parts into one, ranged when any of them is.
 * @param parts - Parts to join
 * @param build - Turns their bytes at one index into the result
 * @returns {Part} The joined part
 */
function joined(
  parts: readonly Part[],
  build: (values: readonly Uint8Array[]) => Uint8Array,
): Part {
  return {
    ranged: parts.some((part) => part.ranged),
    at: (index) => build(parts.map((part) => part.at(index))),
  };
}

/**
 * The script `pkh` writes for a key.
 * @param key - The key as the script holds it
 * @returns {Uint8Array} `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`
 */
function pkhScript(key: Uint8Array): Uint8Array {
  return concatBytes(
    Uint8Array.of(OP.DUP, OP.HASH160),
    pushOf(hash160(key)),
    Uint8Array.of(OP.EQUALVERIFY, OP.CHECKSIG),
  );
}

/**
 * Reads the threshold and keys of a multisig expression.
 * @param name - Expression name
 * @param args - Its arguments
 * @param context - Where the keys land
 * @param network - Network of the keys
 * @returns {[number, DescriptorKey[]]} The threshold and the keys
 */
function multisigArguments(
  name: string,
  args: string,
  context: KeyContext,
  network: ScriptNetwork,
): [number, DescriptorKey[]] {
  const [threshold = "", ...keys] = split(args);
  const limit = context === "taproot" ? MAX_MULTI_A_KEYS : MAX_MULTISIG_KEYS;
  if (!/^[0-9]{1,4}$/u.test(threshold) || keys.length === 0 || keys.length > limit) {
    throw new TypeError(`${name}() takes a threshold, then 1 to ${limit} keys`);
  }
  const required = Number(threshold);
  if (required < 1 || required > keys.length) {
    throw new RangeError(
      `${name}() threshold must be from 1 to the number of keys, ${keys.length}`,
    );
  }
  return [required, keys.map((key) => parseKey(key, context, network))];
}

/**
 * Builds a script inside `sh()` or `wsh()`: `pk`, `pkh`, `multi` or `sortedmulti`.
 * @param text - Script expression
 * @param context - legacy under `sh()`, segwit under `wsh()`
 * @param network - Network of the keys
 * @returns {Part} The script
 */
function innerScript(text: string, context: KeyContext, network: ScriptNetwork): Part {
  const [name, args] = call(text);
  if (name === "pk") {
    return mapped(singleKey(name, args, context, network), (key) =>
      concatBytes(pushOf(key), Uint8Array.of(OP.CHECKSIG)),
    );
  }
  if (name === "pkh") {
    return mapped(singleKey(name, args, context, network), pkhScript);
  }
  if (name === "multi" || name === "sortedmulti") {
    const [threshold, keys] = multisigArguments(name, args, context, network);
    return joined(keys, (values) =>
      multisigScript(threshold, name === "multi" ? values : sortKeys(values)),
    );
  }
  throw new TypeError(
    `${shown(name)} is not allowed here; sh() and wsh() take pk, pkh, multi or sortedmulti`,
  );
}

/**
 * The tapscript of `multi_a` or `sortedmulti_a`.
 * @param threshold - Signatures it needs
 * @param keys - x-only keys
 * @returns {Uint8Array} `<k1> OP_CHECKSIG <k2> OP_CHECKSIGADD ... <m> OP_NUMEQUAL`
 */
function multiAScript(threshold: number, keys: readonly Uint8Array[]): Uint8Array {
  return concatBytes(
    ...keys.map((key, index) =>
      concatBytes(pushOf(key), Uint8Array.of(index === 0 ? OP.CHECKSIG : OP.CHECKSIGADD)),
    ),
    numberPush(threshold),
    Uint8Array.of(OP.NUMEQUAL),
  );
}

/**
 * Builds the tapscript of one leaf: `pk`, `pkh`, `multi_a` or `sortedmulti_a`.
 * @param text - Leaf expression
 * @param network - Network of the keys
 * @returns {Part} The leaf script
 */
function leafScript(text: string, network: ScriptNetwork): Part {
  const [name, args] = call(text);
  if (name === "pk" || name === "pkh") {
    return innerScript(text, "taproot", network);
  }
  if (name === "multi_a" || name === "sortedmulti_a") {
    const [threshold, keys] = multisigArguments(name, args, "taproot", network);
    return joined(keys, (values) =>
      multiAScript(threshold, name === "multi_a" ? values : sortKeys(values)),
    );
  }
  throw new TypeError(
    `${shown(name)} is not allowed in a tr() tree; it takes pk, pkh, multi_a or sortedmulti_a`,
  );
}

/**
 * Hashes a script tree, `{A,B}` for a branch, into its Merkle root.
 * @param text - Tree expression
 * @param network - Network of the keys
 * @param depth - Branches above this node
 * @returns {Part} The root
 */
function tree(text: string, network: ScriptNetwork, depth: number): Part {
  if (depth > MAX_TREE_DEPTH)
    throw new RangeError(`tr() tree is deeper than ${MAX_TREE_DEPTH} levels`);
  if (text.startsWith("{") && text.endsWith("}")) {
    const branches = split(text.slice(1, -1));
    if (branches.length !== 2) throw new TypeError("A tr() branch {A,B} holds exactly two parts");
    const [left, right] = branches.map((branch) => tree(branch, network, depth + 1));
    if (left === undefined || right === undefined) throw new TypeError("A tr() branch is empty");
    return {
      ranged: left.ranged || right.ranged,
      at: (index) => tapBranch(left.at(index), right.at(index)),
    };
  }
  return mapped(leafScript(text, network), (script) =>
    taggedHash("TapLeaf", concatBytes(Uint8Array.of(TAPSCRIPT_LEAF), varBytes(script))),
  );
}

/**
 * The Taproot output key of an internal key and an optional tree.
 * @param args - Arguments of `tr()`
 * @param network - Network of the keys
 * @returns {Part} The x-only output key
 */
function taproot(args: string, network: ScriptNetwork): Part {
  const [key = "", ...trees] = split(args);
  if (trees.length > 1) throw new TypeError("tr() takes a key and at most one tree");
  const internal = parseKey(key, "taproot", network);
  const root = trees[0] === undefined ? undefined : tree(trees[0], network, 0);
  return {
    ranged: internal.ranged || root?.ranged === true,
    at: (index) => {
      const output = tweakedKey(internal.at(index), root?.at(index) ?? new Uint8Array());
      if (output === undefined) throw new RangeError("tr() tweak gives no valid output key");
      return output.subarray(1);
    },
  };
}

/**
 * Refuses a P2SH redeem script larger than a spend can push.
 * @param script - Redeem script
 * @returns {Uint8Array} The script
 */
function shSized(script: Uint8Array): Uint8Array {
  if (script.length > MAX_P2SH_SCRIPT_SIZE) {
    throw new RangeError(
      `sh() script is ${script.length} bytes, over the ${MAX_P2SH_SCRIPT_SIZE} a P2SH spend can push`,
    );
  }
  return script;
}

/**
 * Builds the redeem script of `sh()`: `wpkh`, `wsh`, or a script.
 * @param text - Expression inside `sh()`
 * @param network - Network of the keys
 * @returns {Part} The redeem script
 */
function shInner(text: string, network: ScriptNetwork): Part {
  const [name, args] = call(text);
  if (name === "wpkh") {
    return mapped(singleKey(name, args, "segwit", network), (key) =>
      concatBytes(Uint8Array.of(0), pushOf(hash160(key))),
    );
  }
  if (name === "wsh") {
    return mapped(innerScript(args, "segwit", network), p2wshProgram);
  }
  return innerScript(text, "legacy", network);
}

/**
 * Builds the output of a top level expression.
 * @param text - Descriptor without its checksum
 * @param network - Network of the address
 * @returns {{ ranged: boolean; at: (index: number) => DescriptorOutput }} The output per index
 */
function top(
  text: string,
  network: ScriptNetwork,
): { readonly ranged: boolean; readonly at: (index: number) => DescriptorOutput } {
  const [name, args] = call(text);
  if (name === "pkh") {
    const key = singleKey(name, args, "legacy", network);
    return {
      ranged: key.ranged,
      at: (index) => {
        const hash = hash160(key.at(index));
        return {
          script: pkhScript(key.at(index)),
          address: encodeBase58Check(
            concatBytes(Uint8Array.of(SCRIPT_NETWORKS[network].p2pkh), hash),
          ),
        };
      },
    };
  }
  if (name === "wpkh") {
    const key = singleKey(name, args, "segwit", network);
    return {
      ranged: key.ranged,
      at: (index) => {
        const program = hash160(key.at(index));
        return {
          script: concatBytes(Uint8Array.of(0), pushOf(program)),
          address: segwitAddress(0, program, network),
        };
      },
    };
  }
  if (name === "sh") {
    const redeem = shInner(args, network);
    return {
      ranged: redeem.ranged,
      at: (index) => {
        const script = shSized(redeem.at(index));
        return { script: p2shProgram(script), address: p2shAddress(script, network) };
      },
    };
  }
  if (name === "wsh") {
    const witness = innerScript(args, "segwit", network);
    return {
      ranged: witness.ranged,
      at: (index) => {
        const script = witness.at(index);
        return { script: p2wshProgram(script), address: segwitAddress(0, sha256(script), network) };
      },
    };
  }
  if (name === "tr") {
    const output = taproot(args, network);
    return {
      ranged: output.ranged,
      at: (index) => {
        const key = output.at(index);
        return {
          script: concatBytes(Uint8Array.of(0x51), pushOf(key)),
          address: segwitAddress(1, key, network),
        };
      },
    };
  }
  throw new TypeError(
    `${shown(name)} has no address here; a descriptor starts with pkh, wpkh, sh, wsh or tr`,
  );
}

/**
 * Checks the checksum a descriptor carries against the one it computes to.
 * @param given - Checksum after `#`
 * @param computed - Checksum of the descriptor
 * @returns {void} Nothing; it throws on a missing or wrong checksum
 */
function assertChecksum(given: string, computed: string): void {
  if (!CHECKSUM_PATTERN.test(given)) {
    throw new TypeError(`Checksum after # must be ${CHECKSUM_LENGTH} characters of the bech32 set`);
  }
  if (given !== computed) {
    throw new TypeError(
      `Checksum ${given} does not match the descriptor, which sums to ${computed}`,
    );
  }
}

/**
 * Reads an output descriptor, checks its checksum when it carries one, and derives its outputs.
 * @param descriptor - `pkh`, `wpkh`, `sh`, `wsh` or `tr` descriptor, with or without `#checksum`
 * @param options - Network of the keys and addresses
 * @returns {Descriptor} The descriptor, already derived once to surface any error
 */
export function parse(descriptor: string, options: DescriptorOptions = {}): Descriptor {
  const network = readNetwork(options.network);
  const [body, given] = splitChecksum(descriptor);
  const checksum = computeChecksum(body);
  if (given !== undefined) assertChecksum(given, checksum);
  split(body);
  const output = top(body, network);
  const derive = (index?: number): DescriptorOutput => {
    if (!output.ranged) {
      if (index !== undefined)
        throw new TypeError("Descriptor has no /* step, so it takes no index");
      return output.at(0);
    }
    if (index === undefined || !Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
      throw new RangeError("Ranged descriptor needs an index from 0 to 2^31 - 1");
    }
    return output.at(index);
  };
  derive(output.ranged ? 0 : undefined);
  return { checksum, ranged: output.ranged, derive };
}
