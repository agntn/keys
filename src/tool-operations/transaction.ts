import {
  MAX_SPENT_SCRIPT_HEX_LENGTH,
  MAX_TRANSACTION_HEX_LENGTH,
  MAX_INPUT_INDEX,
  MAX_SPENT_OUTPUTS,
  MAX_SPENT_SCRIPTS_HEX_LENGTH,
} from "../tool-parameters.ts";
import { type InputSignature, extractSignatures } from "../utils/transaction/index.ts";
import {
  closedObject,
  requiredString,
  HEX_BYTES,
  optionalIndex,
  boundedArray,
} from "./arguments.ts";
import { type ToolResult, content } from "./results.ts";

/** What the transaction tool reads from one input. */
export interface TransactionSignaturesDetails {
  index: number;
  signatures: InputSignature[];
}

const HASH_TYPE_NAMES: Readonly<Record<number, string>> = {
  0: "SIGHASH_DEFAULT",
  1: "SIGHASH_ALL",
  2: "SIGHASH_NONE",
  3: "SIGHASH_SINGLE",
};

/**
 * Names a hash type byte.
 * @param hashType - The byte
 * @returns {string} Its name, with |ANYONECANPAY when that bit is set, or the hex of an unknown one
 */
function hashTypeName(hashType: number): string {
  const base = hashType & 0x7f;
  const name = Object.hasOwn(HASH_TYPE_NAMES, base) ? HASH_TYPE_NAMES[base] : undefined;
  if (name === undefined) return `hash type 0x${hashType.toString(16).padStart(2, "0")}`;
  return (hashType & 0x80) === 0 ? name : `${name}|ANYONECANPAY`;
}

/**
 * Reads one spent output of the transaction tool.
 * @param value - Raw item
 * @param position - Its place, for the error
 * @returns {{ script: string; value: number }} The script hex and the value
 */
function spentOutput(value: unknown, position: number): { script: string; value: number } {
  const item = closedObject(value, { name: `spent[${position}]`, keys: ["script", "value"] });
  const script = requiredString(item["script"], `spent[${position}].script`);
  if (script.length > MAX_SPENT_SCRIPT_HEX_LENGTH || !HEX_BYTES.test(script)) {
    throw new TypeError(
      `spent[${position}].script must be hex without 0x, at most ${MAX_SPENT_SCRIPT_HEX_LENGTH} digits`,
    );
  }
  const amount = optionalIndex(item["value"], {
    name: `spent[${position}].value`,
    maximum: Number.MAX_SAFE_INTEGER,
  });
  if (amount === undefined) throw new TypeError(`spent[${position}].value must be satoshis`);
  return { script, value: amount };
}

/**
 * One signature as the transaction tool writes it.
 * @param signature - The signature
 * @param position - Its place in the input, from 1
 * @returns {string} Its lines
 */
export function signatureText(signature: Readonly<InputSignature>, position: number): string {
  const key =
    signature.publicKey ?? "none of the keys in the input or the spent script verifies it";
  return [
    `${position}. ${signature.type} ${hashTypeName(signature.hashType)}`,
    `   r: ${signature.r}`,
    `   s: ${signature.s}`,
    `   z: ${signature.z}`,
    `   key: ${key}`,
  ].join("\n");
}

/** The input the transaction tool reads and the outputs it spends, as the host passed them. */
export interface TransactionSignaturesArguments {
  readonly index?: unknown;
  readonly spent?: unknown;
}

/**
 * Read the signatures of one transaction input with the sighash each one signs.
 * @param transactionValue - Raw signed transaction hex.
 * @param options - The input `index` to read and the `spent` outputs, one or one per input.
 * @returns {ToolResult<TransactionSignaturesDetails>} r, s, z, hash type and key of each signature.
 */
export function extractTransactionSignatures(
  transactionValue: unknown,
  options: TransactionSignaturesArguments,
): ToolResult<TransactionSignaturesDetails> {
  const { index: indexValue, spent: spentValue } = options;
  const transaction = requiredString(transactionValue, "Transaction");
  if (transaction.length > MAX_TRANSACTION_HEX_LENGTH || !HEX_BYTES.test(transaction)) {
    throw new TypeError(
      `Transaction must be hex without 0x, at most ${MAX_TRANSACTION_HEX_LENGTH} digits`,
    );
  }
  const index = optionalIndex(indexValue, { name: "Index", maximum: MAX_INPUT_INDEX });
  if (index === undefined) throw new TypeError("Index must be the input to read");
  const outputs = boundedArray(spentValue, {
    name: "spent",
    minimum: 1,
    maximum: MAX_SPENT_OUTPUTS,
  });
  const spent = outputs.map((item, position) => spentOutput(item, position));
  if (
    spent.reduce((total, output) => total + output.script.length, 0) > MAX_SPENT_SCRIPTS_HEX_LENGTH
  ) {
    throw new RangeError(
      `spent scripts together take at most ${MAX_SPENT_SCRIPTS_HEX_LENGTH} hex digits`,
    );
  }
  const signatures = extractSignatures(transaction, index, spent);
  const text =
    signatures.length === 0
      ? `Input ${index} carries no signature, or none this tool reads`
      : [
          `Input ${index}: ${signatures.length} signature${signatures.length === 1 ? "" : "s"}`,
          ...signatures.map((signature, position) => signatureText(signature, position + 1)),
        ].join("\n");
  return { content: content(text), details: { index, signatures } };
}
