import { sha256 } from "@agntn/hashes";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { concatBytes } from "../bytes.ts";
import { scriptOperations, scriptPushes } from "./script.ts";
import { legacySighash, segwitSighash, taprootSighash } from "./sighash.ts";
import {
  decodeTransaction,
  type Transaction,
  type TransactionInput,
  type TransactionOutput,
} from "./transaction.ts";

/** The output an input spends: its script as hex and its value in satoshis. */
export interface SpentOutput {
  readonly script: string;
  readonly value: bigint | number;
}

/** One signature an input carries, with the digest it signs. */
export interface InputSignature {
  /** ECDSA for legacy and SegWit v0 inputs, Schnorr for a Taproot key path. */
  readonly type: "ecdsa" | "schnorr";
  /** r as 64 hex digits; for Schnorr the x coordinate of the nonce point R. */
  readonly r: string;
  readonly s: string;
  /** The sighash the signature signs, 64 hex digits. */
  readonly z: string;
  /** The hash type byte; 0 for a 64-byte Taproot signature, which implies `SIGHASH_ALL`. */
  readonly hashType: number;
  /**
   * The key the signature verifies under, SEC1 hex for ECDSA and x-only for Schnorr. Absent
   * when no key in the input or the spent script verifies it.
   */
  readonly publicKey?: string;
}

/** The input being read, with the outputs that the sighash needs. */
interface Spend {
  readonly transaction: Transaction;
  readonly index: number;
  readonly input: TransactionInput;
  readonly spent: readonly TransactionOutput[];
  readonly output: TransactionOutput;
}

/** The script code an input's signatures commit to, and whether BIP143 hashes them. */
interface SighashRules {
  readonly spend: Spend;
  readonly scriptCode: Uint8Array;
  readonly segwit: boolean;
}

const { Fn } = secp256k1.Point;
const OP_CODESEPARATOR = 0xab;
const ANNEX_TAG = 0x50;
const MAX_SATOSHIS = 0xffff_ffff_ffff_ffffn;

/**
 * Reads hex the caller passed.
 * @param value - Hex without 0x
 * @param name - What the error calls it
 * @returns {Uint8Array} The bytes
 * @throws {TypeError} When the value is no even-length hex
 */
function decodeHex(value: unknown, name: string): Uint8Array {
  if (typeof value !== "string" || !/^(?:[0-9a-f]{2})*$/iu.test(value)) {
    throw new TypeError(`${name} must be hex without 0x`);
  }
  return Uint8Array.fromHex(value);
}

/**
 * Reads a spent output the caller passed.
 * @param output - Script hex and value in satoshis
 * @param position - Its place in the list, for the error
 * @returns {TransactionOutput} The output
 * @throws {TypeError} When the script is no hex or the value no whole number of satoshis
 */
function readSpentOutput(output: Readonly<SpentOutput>, position: number): TransactionOutput {
  const script = decodeHex(output.script, `Spent output ${position} script`);
  const { value } = output;
  const amount = typeof value === "number" && Number.isSafeInteger(value) ? BigInt(value) : value;
  if (typeof amount !== "bigint" || amount < 0n || amount > MAX_SATOSHIS) {
    throw new TypeError(`Spent output ${position} value must be a whole number of satoshis`);
  }
  return { script, value: amount };
}

/**
 * Decodes the raw transaction, naming the encoding rule it breaks.
 * @param transaction - Raw transaction hex
 * @returns {Transaction} The transaction
 * @throws {RangeError} When the bytes are no transaction
 */
function readTransaction(transaction: string): Transaction {
  const bytes = decodeHex(transaction, "Transaction");
  try {
    return decodeTransaction(bytes);
  } catch (error) {
    throw new RangeError(`Transaction ${error instanceof Error ? error.message : "is unreadable"}`);
  }
}

/**
 * Reads the transaction and picks the input and the output it spends.
 * @param transaction - Raw transaction hex
 * @param index - Input to read
 * @param spent - The output this input spends, or one per input in order
 * @returns {Spend} The input with its spent outputs
 * @throws {RangeError} When the index or the number of spent outputs does not fit the transaction
 */
function readSpend(
  transaction: string,
  index: number,
  spent: readonly Readonly<SpentOutput>[],
): Spend {
  const decoded = readTransaction(transaction);
  const input = Number.isSafeInteger(index) ? decoded.inputs[index] : undefined;
  if (input === undefined) {
    throw new RangeError(
      `Index must be an input of the transaction, 0 to ${decoded.inputs.length - 1}`,
    );
  }
  const outputs = spent.map((output, position) => readSpentOutput(output, position));
  const output = outputs.length === decoded.inputs.length ? outputs[index] : outputs[0];
  if (output === undefined || (outputs.length !== 1 && outputs.length !== decoded.inputs.length)) {
    throw new RangeError(
      `Pass the output input ${index} spends, or one spent output for each of the ${decoded.inputs.length} inputs in order`,
    );
  }
  return { transaction: decoded, index, input, spent: outputs, output };
}

/**
 * Reads r and s as loosely as Core's lax DER parser, which still takes pre-BIP66 signatures.
 * @param der - DER signature without the hash type byte
 * @returns {[bigint, bigint] | undefined} r and s, undefined when the bytes are no signature
 */
function readDer(der: Uint8Array): [bigint, bigint] | undefined {
  if (der[0] !== 0x30 || der.length < 8) return undefined;
  const r = readDerInteger(der, 2);
  const s = r === undefined ? undefined : readDerInteger(der, r[1]);
  if (r === undefined || s === undefined) return undefined;
  return Fn.isValidNot0(r[0]) && Fn.isValidNot0(s[0]) ? [r[0], s[0]] : undefined;
}

/**
 * Reads one DER integer as unsigned.
 * @param der - DER signature
 * @param offset - Position of its 0x02 tag
 * @returns {[bigint, number] | undefined} The value and the offset after it, or undefined
 */
function readDerInteger(der: Uint8Array, offset: number): [bigint, number] | undefined {
  const length = der[offset + 1] ?? 0;
  const end = offset + 2 + length;
  if (der[offset] !== 0x02 || length === 0 || end > der.length) return undefined;
  return [BigInt(`0x${der.subarray(offset + 2, end).toHex()}`), end];
}

/**
 * Tells a pushed item that holds an ECDSA signature and its hash type byte.
 * @param item - Pushed bytes
 * @returns {{ r: bigint; s: bigint; hashType: number } | undefined} Its parts, or undefined
 */
function readEcdsa(item: Uint8Array): { r: bigint; s: bigint; hashType: number } | undefined {
  if (item.length < 9 || item.length > 73) return undefined;
  const parts = readDer(item.subarray(0, -1));
  return parts === undefined ? undefined : { r: parts[0], s: parts[1], hashType: item.at(-1) ?? 0 };
}

/**
 * Keeps the pushed items that read as SEC1 public keys, each once.
 * @param items - Pushed bytes
 * @returns {Uint8Array[]} The keys
 */
function publicKeys(items: readonly Uint8Array[]): Uint8Array[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const hex = item.toHex();
    if (seen.has(hex) || (item.length !== 33 && item.length !== 65)) return false;
    seen.add(hex);
    try {
      secp256k1.Point.fromBytes(item);
      return true;
    } catch {
      return false;
    }
  });
}

/**
 * Finds the key an ECDSA signature verifies under, high s included.
 * @param r - r
 * @param s - s
 * @param digest - The sighash
 * @param keys - Candidate keys
 * @returns {string | undefined} The key as hex, or undefined
 */
function ecdsaSigner(
  r: bigint,
  s: bigint,
  digest: Uint8Array,
  keys: readonly Uint8Array[],
): string | undefined {
  const compact = concatBytes(Fn.toBytes(r), Fn.toBytes(s));
  const options = { prehash: false, lowS: false, format: "compact" } as const;
  return keys.find((key) => secp256k1.verify(compact, digest, key, options))?.toHex();
}

/**
 * Drops pushes of the signatures from a legacy script code, as `FindAndDelete` does.
 * @param scriptCode - Script code
 * @param signatures - Signatures with their hash type bytes
 * @returns {Uint8Array} The script code without them
 */
function findAndDelete(scriptCode: Uint8Array, signatures: readonly Uint8Array[]): Uint8Array {
  const pushes = new Set(
    signatures.map((signature) => concatBytes(Uint8Array.of(signature.length), signature).toHex()),
  );
  const operations = scriptOperations(scriptCode);
  const read = operations.reduce((total, operation) => total + operation.bytes.length, 0);
  const kept = operations.filter((operation) => !pushes.has(operation.bytes.toHex()));
  return concatBytes(...kept.map((operation) => operation.bytes), scriptCode.subarray(read));
}

/**
 * Refuses `OP_CODESEPARATOR`, whose signed part depends on which separator runs last.
 * @param scriptCode - Script code
 * @throws {RangeError} When one is there
 */
function assertNoCodeSeparator(scriptCode: Uint8Array): void {
  if (scriptOperations(scriptCode).some((operation) => operation.opcode === OP_CODESEPARATOR)) {
    throw new RangeError(
      "The script holds OP_CODESEPARATOR, so the signed part depends on execution, which is not run here",
    );
  }
}

/**
 * The sighash one signature signs under its input's rules.
 * @param rules - The input, its script code and whether BIP143 applies
 * @param hashType - Hash type byte of the signature
 * @returns {Uint8Array} The digest
 */
function digestOf(rules: Readonly<SighashRules>, hashType: number): Uint8Array {
  const { spend, scriptCode } = rules;
  return rules.segwit
    ? segwitSighash(spend.transaction, spend.index, scriptCode, spend.output.value, hashType)
    : legacySighash(spend.transaction, spend.index, scriptCode, hashType);
}

/**
 * Reads every ECDSA signature among the items and computes its sighash.
 * @param items - Pushed items of the scriptSig or witness
 * @param keys - Candidate keys
 * @param rules - How to hash for them
 * @returns {InputSignature[]} The signatures in item order
 */
function ecdsaSignatures(
  items: readonly Uint8Array[],
  keys: readonly Uint8Array[],
  rules: Readonly<SighashRules>,
): InputSignature[] {
  return items.flatMap((item) => {
    const parts = readEcdsa(item);
    if (parts === undefined) return [];
    const z = digestOf(rules, parts.hashType);
    const publicKey = ecdsaSigner(parts.r, parts.s, z, keys);
    return [
      {
        type: "ecdsa",
        r: Fn.toBytes(parts.r).toHex(),
        s: Fn.toBytes(parts.s).toHex(),
        z: z.toHex(),
        hashType: parts.hashType,
        ...(publicKey === undefined ? {} : { publicKey }),
      },
    ];
  });
}

/**
 * Reads a legacy spend: P2PKH, P2PK, bare multisig or a P2SH redeem script.
 * @param spend - The input
 * @param scriptCode - Script the signatures commit to
 * @param items - Pushed items that may hold signatures
 * @returns {InputSignature[]} The signatures
 */
function legacySignatures(
  spend: Readonly<Spend>,
  scriptCode: Uint8Array,
  items: readonly Uint8Array[],
): InputSignature[] {
  assertNoCodeSeparator(scriptCode);
  const keys = publicKeys([...scriptPushes(spend.input.scriptSig), ...scriptPushes(scriptCode)]);
  const signatures = items.filter((item) => readEcdsa(item) !== undefined);
  const signed = findAndDelete(scriptCode, signatures);
  return ecdsaSignatures(items, keys, { spend, scriptCode: signed, segwit: false });
}

/**
 * Reads a SegWit v0 program, native or nested in P2SH.
 * @param spend - The input
 * @param program - Version 0 witness program, 20 or 32 bytes
 * @returns {InputSignature[]} The signatures
 * @throws {RangeError} When a P2WSH witness script does not hash to the program
 */
function witnessSignatures(spend: Readonly<Spend>, program: Uint8Array): InputSignature[] {
  const { witness } = spend.input;
  if (program.length === 20) {
    const scriptCode = concatBytes(
      Uint8Array.of(0x76, 0xa9, 0x14),
      program,
      Uint8Array.of(0x88, 0xac),
    );
    return ecdsaSignatures(witness, publicKeys(witness), { spend, scriptCode, segwit: true });
  }
  const witnessScript = witness.at(-1);
  if (witnessScript === undefined) return [];
  if (sha256(witnessScript).toHex() !== program.toHex()) {
    throw new RangeError("The last witness item does not hash to the P2WSH program");
  }
  assertNoCodeSeparator(witnessScript);
  const items = witness.slice(0, -1);
  const keys = publicKeys([...items, ...scriptPushes(witnessScript)]);
  return ecdsaSignatures(items, keys, { spend, scriptCode: witnessScript, segwit: true });
}

/**
 * Reads a version 0 witness program from a script: `OP_0`, then a push of 20 or 32 bytes.
 * @param script - Output or redeem script
 * @returns {Uint8Array | undefined} The program, or undefined for any other script
 */
function witnessProgram(script: Uint8Array): Uint8Array | undefined {
  const fits = script[0] === 0 && script[1] === script.length - 2;
  return fits && (script.length === 22 || script.length === 34) ? script.subarray(2) : undefined;
}

/**
 * Reads a P2SH spend: the last push is the redeem script.
 * @param spend - The input
 * @returns {InputSignature[]} The signatures, none while the scriptSig is empty
 */
function scriptHashSignatures(spend: Readonly<Spend>): InputSignature[] {
  const pushes = scriptOperations(spend.input.scriptSig).flatMap((operation) =>
    operation.data === undefined ? [] : [operation.data],
  );
  const redeem = pushes.at(-1);
  if (redeem === undefined) return [];
  const program = witnessProgram(redeem);
  if (program !== undefined) return witnessSignatures(spend, program);
  return legacySignatures(spend, redeem, pushes.slice(0, -1));
}

/**
 * Reads the hash type of a Schnorr signature: implied by 64 bytes, a trailing byte on 65.
 * @param signature - Key path signature
 * @returns {number} The hash type
 * @throws {RangeError} When the length is off or 65 bytes end in 0
 */
function taprootHashType(signature: Uint8Array): number {
  if (signature.length === 64) return 0;
  const hashType = signature.length === 65 ? (signature[64] ?? 0) : 0;
  if (hashType === 0) {
    throw new RangeError("A Taproot signature takes 64 bytes, or 65 with a hash type other than 0");
  }
  return hashType;
}

/**
 * Reads a Taproot key path spend.
 * @param spend - The input
 * @param outputKey - x-only output key from the spent script
 * @returns {InputSignature[]} The one signature
 * @throws {RangeError} When the witness is a script path or the signature is malformed
 */
function taprootSignatures(spend: Readonly<Spend>, outputKey: Uint8Array): InputSignature[] {
  const { witness } = spend.input;
  if (witness.length === 0) return [];
  const last = witness.at(-1);
  const annex = witness.length >= 2 && last?.[0] === ANNEX_TAG ? last : undefined;
  const stack = annex === undefined ? witness : witness.slice(0, -1);
  const [signature] = stack;
  if (stack.length !== 1 || signature === undefined) {
    throw new RangeError(
      "Only Taproot key path spends are read, and this witness is a script path",
    );
  }
  const hashType = taprootHashType(signature);
  const z = taprootSighash(spend.transaction, spend.index, spend.spent, hashType, annex);
  const verified = schnorr.verify(signature.subarray(0, 64), z, outputKey);
  return [
    {
      type: "schnorr",
      r: signature.subarray(0, 32).toHex(),
      s: signature.subarray(32, 64).toHex(),
      z: z.toHex(),
      hashType,
      ...(verified ? { publicKey: outputKey.toHex() } : {}),
    },
  ];
}

/**
 * Reads r, s and the sighash z of each signature on an input, by the rules its spent script picks.
 * @param transaction - Raw signed transaction hex, with or without witnesses
 * @param index - Input to read, from 0
 * @param spent - The output this input spends, or one per input in order; a Taproot input
 *   needs every one unless it signs with `ANYONECANPAY`
 * @returns {InputSignature[]} Each signature in the order the input holds them, empty when none
 * @throws {TypeError} When a hex argument or a value is malformed
 * @throws {RangeError} When the transaction does not decode, the index or spent outputs do not
 *   fit it, or the input is a Taproot script path or a script with `OP_CODESEPARATOR`
 */
export function extractSignatures(
  transaction: string,
  index: number,
  spent: readonly Readonly<SpentOutput>[],
): InputSignature[] {
  const spend = readSpend(transaction, index, spent);
  const { script } = spend.output;
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
    return taprootSignatures(spend, script.subarray(2));
  }
  const program = witnessProgram(script);
  if (program !== undefined) return witnessSignatures(spend, program);
  if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
    return scriptHashSignatures(spend);
  }
  return legacySignatures(spend, script, scriptPushes(spend.input.scriptSig));
}
