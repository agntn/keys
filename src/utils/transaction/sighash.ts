import { sha256 } from "@agntn/hashes";
import { taggedHash } from "../address.ts";
import { concatBytes } from "../bytes.ts";
import { scriptOperations } from "./script.ts";
import {
  hash256,
  outpoint,
  serializeOutput,
  serializeTransaction,
  uint32,
  uint64,
  varBytes,
  type Transaction,
  type TransactionInput,
  type TransactionOutput,
} from "./transaction.ts";

/** The hash type a 64-byte Taproot signature implies, committing like `SIGHASH_ALL`. */
export const SIGHASH_DEFAULT = 0x00;

/** Signs every input and output; the one type BIP322 takes from an ECDSA signature. */
export const SIGHASH_ALL = 0x01;

/** Signs no output. */
export const SIGHASH_NONE = 0x02;

/** Signs the one output at the index of the input. */
export const SIGHASH_SINGLE = 0x03;

/** Signs this input alone, so others can join the transaction. */
export const SIGHASH_ANYONECANPAY = 0x80;

/** What the legacy sighash of a `SIGHASH_SINGLE` input past the last output signs: one. */
const SINGLE_BUG_DIGEST = Uint8Array.of(1, ...new Uint8Array(31));

const OP_CODESEPARATOR = 0xab;

/** How a hash type picks inputs and outputs. */
interface HashTypeParts {
  readonly base: number;
  readonly anyoneCanPay: boolean;
}

/**
 * Splits a hash type into its output rule and the `ANYONECANPAY` flag.
 * @param hashType - Hash type, the byte after a signature
 * @param mask - Bits that pick the output rule: 0x1f for legacy and BIP143, 0x03 for Taproot
 * @returns {HashTypeParts} The output rule and the flag
 */
function hashTypeParts(hashType: number, mask: number): HashTypeParts {
  return { base: hashType & mask, anyoneCanPay: (hashType & SIGHASH_ANYONECANPAY) !== 0 };
}

/**
 * Drops every `OP_CODESEPARATOR` from a script code, as the legacy serializer does.
 * @param script - Script code
 * @returns {Uint8Array} The script without them
 */
export function withoutCodeSeparators(script: Uint8Array): Uint8Array {
  const operations = scriptOperations(script);
  const read = operations.reduce((total, operation) => total + operation.bytes.length, 0);
  const kept = operations.filter((operation) => operation.opcode !== OP_CODESEPARATOR);
  return concatBytes(...kept.map((operation) => operation.bytes), script.subarray(read));
}

/**
 * The inputs a legacy sighash serializes: the signed one with the script code, others blank.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @param scriptCode - Script code for that input
 * @param parts - The hash type rules
 * @returns {TransactionInput[]} Inputs in the order they are hashed
 */
function legacyInputs(
  transaction: Readonly<Transaction>,
  index: number,
  scriptCode: Uint8Array,
  parts: Readonly<HashTypeParts>,
): TransactionInput[] {
  const blankSequence = parts.base === SIGHASH_NONE || parts.base === SIGHASH_SINGLE;
  const inputs = transaction.inputs.map((input, position) => ({
    ...input,
    scriptSig: position === index ? scriptCode : new Uint8Array(0),
    sequence: position !== index && blankSequence ? 0 : input.sequence,
    witness: [],
  }));
  return parts.anyoneCanPay ? inputs.slice(index, index + 1) : inputs;
}

/**
 * The outputs a legacy sighash serializes under the hash type.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @param base - Output rule of the hash type
 * @returns {readonly TransactionOutput[]} Outputs in the order they are hashed
 */
function legacyOutputs(
  transaction: Readonly<Transaction>,
  index: number,
  base: number,
): readonly TransactionOutput[] {
  if (base === SIGHASH_NONE) return [];
  if (base !== SIGHASH_SINGLE) return transaction.outputs;
  return transaction.outputs
    .slice(0, index + 1)
    .map((output, position) =>
      position === index ? output : { value: 0xffff_ffff_ffff_ffffn, script: new Uint8Array(0) },
    );
}

/**
 * Legacy sighash of one input, any hash type, Core's `SIGHASH_SINGLE` bug included.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @param scriptCode - Script of the output it spends, or the P2SH redeem script
 * @param hashType - Hash type, `SIGHASH_ALL` by default; the whole 32-bit value goes into the hash
 * @returns {Uint8Array} The digest ECDSA signs; one for `SIGHASH_SINGLE` past the last output
 * @throws {RangeError} When the transaction has no input at the index
 */
export function legacySighash(
  transaction: Readonly<Transaction>,
  index: number,
  scriptCode: Uint8Array,
  hashType: number = SIGHASH_ALL,
): Uint8Array {
  if (transaction.inputs[index] === undefined) {
    throw new RangeError(`Transaction has no input ${index}`);
  }
  const parts = hashTypeParts(hashType, 0x1f);
  if (parts.base === SIGHASH_SINGLE && index >= transaction.outputs.length) {
    return SINGLE_BUG_DIGEST.slice();
  }
  const code = withoutCodeSeparators(scriptCode);
  const unsigned = serializeTransaction(
    {
      ...transaction,
      inputs: legacyInputs(transaction, index, code, parts),
      outputs: legacyOutputs(transaction, index, parts.base),
    },
    false,
  );
  return hash256(concatBytes(unsigned, uint32(hashType >>> 0)));
}

/**
 * The output hash BIP143 and BIP341 commit to: every output, the one at the index, or none.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @param base - Output rule of the hash type
 * @returns {Uint8Array | undefined} Serialized outputs to hash, undefined when none are signed
 */
function signedOutputs(
  transaction: Readonly<Transaction>,
  index: number,
  base: number,
): Uint8Array | undefined {
  if (base === SIGHASH_SINGLE) {
    const output = transaction.outputs[index];
    return output === undefined ? undefined : serializeOutput(output);
  }
  if (base === SIGHASH_NONE) return undefined;
  return concatBytes(...transaction.outputs.map((output) => serializeOutput(output)));
}

/**
 * The prevout and sequence hashes of BIP143, zero where the hash type leaves them out.
 * @param transaction - Spending transaction
 * @param parts - The hash type rules
 * @returns {[Uint8Array, Uint8Array]} `hashPrevouts` and `hashSequence`
 */
function segwitInputHashes(
  transaction: Readonly<Transaction>,
  parts: Readonly<HashTypeParts>,
): [Uint8Array, Uint8Array] {
  const zero = new Uint8Array(32);
  if (parts.anyoneCanPay) return [zero, zero];
  const prevouts = hash256(concatBytes(...transaction.inputs.map((each) => outpoint(each))));
  if (parts.base === SIGHASH_NONE || parts.base === SIGHASH_SINGLE) return [prevouts, zero];
  const sequences = concatBytes(...transaction.inputs.map((each) => uint32(each.sequence)));
  return [prevouts, hash256(sequences)];
}

/**
 * BIP143 sighash of one SegWit v0 input.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @param scriptCode - Script code of the input, the P2PKH script of the key hash for P2WPKH
 * @param amount - Value of the output it spends
 * @param hashType - Hash type, `SIGHASH_ALL` by default
 * @returns {Uint8Array} The digest ECDSA signs
 * @throws {RangeError} When the transaction has no input at the index
 */
export function segwitSighash(
  transaction: Readonly<Transaction>,
  index: number,
  scriptCode: Uint8Array,
  amount: bigint,
  hashType: number = SIGHASH_ALL,
): Uint8Array {
  const input = transaction.inputs[index];
  if (input === undefined) throw new RangeError(`Transaction has no input ${index}`);
  const parts = hashTypeParts(hashType, 0x1f);
  const [hashPrevouts, hashSequence] = segwitInputHashes(transaction, parts);
  const outputs = signedOutputs(transaction, index, parts.base);
  return hash256(
    concatBytes(
      uint32(transaction.version),
      hashPrevouts,
      hashSequence,
      outpoint(input),
      varBytes(scriptCode),
      uint64(amount),
      uint32(input.sequence),
      outputs === undefined ? new Uint8Array(32) : hash256(outputs),
      uint32(transaction.lockTime),
      uint32(hashType >>> 0),
    ),
  );
}

/**
 * The prevout, amount, script and sequence hashes BIP341 signs without `ANYONECANPAY`.
 * @param transaction - Spending transaction
 * @param spent - The outputs every input spends, in input order
 * @returns {Uint8Array} The four hashes in order
 * @throws {RangeError} When `spent` does not hold one output per input
 */
function taprootInputHashes(
  transaction: Readonly<Transaction>,
  spent: readonly TransactionOutput[],
): Uint8Array {
  if (spent.length !== transaction.inputs.length) {
    throw new RangeError("Taproot sighash needs the spent output of every input");
  }
  const prevouts = concatBytes(...transaction.inputs.map((each) => outpoint(each)));
  const amounts = concatBytes(...spent.map((output) => uint64(output.value)));
  const scripts = concatBytes(...spent.map((output) => varBytes(output.script)));
  const sequences = concatBytes(...transaction.inputs.map((each) => uint32(each.sequence)));
  return concatBytes(sha256(prevouts), sha256(amounts), sha256(scripts), sha256(sequences));
}

/**
 * What BIP341 signs about the input: its whole prevout under `ANYONECANPAY`, else its index.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @param spent - Spent outputs, every input's or the one at the index alone
 * @param anyoneCanPay - Whether the hash type carries `ANYONECANPAY`
 * @returns {Uint8Array} Those bytes
 * @throws {RangeError} When the input or its spent output is missing
 */
function taprootInputData(
  transaction: Readonly<Transaction>,
  index: number,
  spent: readonly TransactionOutput[],
  anyoneCanPay: boolean,
): Uint8Array {
  if (!anyoneCanPay) return uint32(index);
  const input = transaction.inputs[index];
  const output = spent.length === 1 ? spent[0] : spent[index];
  if (input === undefined || output === undefined) {
    throw new RangeError(`Transaction has no input ${index} with a spent output`);
  }
  return concatBytes(
    outpoint(input),
    uint64(output.value),
    varBytes(output.script),
    uint32(input.sequence),
  );
}

/**
 * The hash of the one output `SIGHASH_SINGLE` signs in BIP341.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @returns {Uint8Array} sha256 of the output
 * @throws {RangeError} When no output sits at the index, which leaves nothing to sign
 */
function taprootSingleOutput(transaction: Readonly<Transaction>, index: number): Uint8Array {
  const output = signedOutputs(transaction, index, SIGHASH_SINGLE);
  if (output === undefined) {
    throw new RangeError(`SIGHASH_SINGLE needs an output ${index}, and Taproot has no fallback`);
  }
  return sha256(output);
}

/**
 * Tells a hash type BIP341 takes: 0x00 to 0x03 and 0x81 to 0x83.
 * @param hashType - Hash type
 * @returns {boolean} Whether a Taproot signature may carry it
 */
function isTaprootHashType(hashType: number): boolean {
  return hashType <= SIGHASH_SINGLE || (hashType >= 0x81 && hashType <= 0x83);
}

/**
 * BIP341 sighash of a Taproot key path spend.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @param spent - The outputs every input spends, in input order; under `ANYONECANPAY` the one
 *   at the index is enough
 * @param hashType - `SIGHASH_DEFAULT`, `SIGHASH_ALL`, `SIGHASH_NONE` or `SIGHASH_SINGLE`, each
 *   but the default also with `ANYONECANPAY`
 * @param annex - The annex the witness ends with, 0x50 first, when it has one
 * @returns {Uint8Array} The digest Schnorr signs
 * @throws {RangeError} When the hash type is none of those, an input or output it signs is
 *   missing, or `spent` is short
 */
export function taprootSighash(
  transaction: Readonly<Transaction>,
  index: number,
  spent: readonly TransactionOutput[],
  hashType: number,
  annex?: Uint8Array,
): Uint8Array {
  if (!isTaprootHashType(hashType)) {
    throw new RangeError(`Taproot takes no hash type 0x${hashType.toString(16)}`);
  }
  const parts = hashTypeParts(hashType, 0x03);
  const outputs =
    parts.base <= SIGHASH_ALL ? signedOutputs(transaction, index, SIGHASH_ALL) : undefined;
  const message = concatBytes(
    Uint8Array.of(0, hashType),
    uint32(transaction.version),
    uint32(transaction.lockTime),
    parts.anyoneCanPay ? new Uint8Array(0) : taprootInputHashes(transaction, spent),
    outputs === undefined ? new Uint8Array(0) : sha256(outputs),
    Uint8Array.of(annex === undefined ? 0 : 1),
    taprootInputData(transaction, index, spent, parts.anyoneCanPay),
    annex === undefined ? new Uint8Array(0) : sha256(varBytes(annex)),
    parts.base === SIGHASH_SINGLE ? taprootSingleOutput(transaction, index) : new Uint8Array(0),
  );
  return taggedHash("TapSighash", message);
}
