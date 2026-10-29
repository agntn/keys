import {
  MAX_SPENT_SCRIPT_HEX_LENGTH,
  MAX_TRANSACTION_HEX_LENGTH,
  MAX_TRANSACTION_JSON_LENGTH,
  MAX_INPUT_INDEX,
  MAX_SPENT_OUTPUTS,
  MAX_SPENT_SCRIPTS_HEX_LENGTH,
} from "../tool-parameters.ts";
import {
  type EvmTransactionJson,
  type InputSignature,
  type TransactionSigner,
  extractSignatures,
  recoverSigner,
} from "../utils/transaction/index.ts";
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
  const signatures = extractSignatures(transaction, { index, spent });
  const text =
    signatures.length === 0
      ? `Input ${index} carries no signature, or none this tool reads`
      : [
          `Input ${index}: ${signatures.length} signature${signatures.length === 1 ? "" : "s"}`,
          ...signatures.map((signature, position) => signatureText(signature, position + 1)),
        ].join("\n");
  return { content: content(text), details: { index, signatures } };
}

/** What the EVM signer tool gives back: the signer and the signature it left. */
export interface TransactionSignerDetails {
  transactionType: 0 | 1 | 2;
  /** Decimal, since a chain id may outgrow a JSON number. Absent before EIP-155. */
  chainId?: string;
  hash: string;
  publicKey: string;
  address: string;
  r: string;
  s: string;
  z: string;
}

/**
 * Reads the transaction argument: JSON when it opens with a brace, raw hex otherwise.
 * @param value - Raw hex or eth_getTransactionByHash output as text
 * @returns {string | EvmTransactionJson} What `recoverSigner` takes
 */
function signedTransaction(value: unknown): string | EvmTransactionJson {
  const text = requiredString(value, "Transaction").trim();
  if (!text.startsWith("{")) {
    if (text.length > MAX_TRANSACTION_HEX_LENGTH + 2) {
      throw new RangeError(`Transaction must not exceed ${MAX_TRANSACTION_HEX_LENGTH} hex digits`);
    }
    return text;
  }
  if (text.length > MAX_TRANSACTION_JSON_LENGTH) {
    throw new RangeError(
      `Transaction JSON must not exceed ${MAX_TRANSACTION_JSON_LENGTH} characters`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError("Transaction JSON does not parse");
  }
  return parsed as EvmTransactionJson;
}

/**
 * Names the signing rule a transaction follows.
 * @param signer - The recovered signer
 * @returns {string} Its type line
 */
function typeLine(signer: Readonly<TransactionSigner>): string {
  const { transactionType: type, chainId } = signer;
  if (chainId === undefined) return "Type: legacy, signed before EIP-155, so no chain id";
  const chain = `chain ${chainId.toString()}`;
  if (type === 0) return `Type: legacy with EIP-155, ${chain}`;
  return `Type: ${type === 1 ? "1 (EIP-2930)" : "2 (EIP-1559)"}, ${chain}`;
}

/**
 * Recover the signer of a signed EVM transaction, with r, s and the digest z it signed.
 * @param transactionValue - Raw hex, 0x optional, or the eth_getTransactionByHash object as JSON.
 * @returns {ToolResult<TransactionSignerDetails>} Public key, address, hash, r, s and z.
 */
export function recoverTransactionSigner(
  transactionValue: unknown,
): ToolResult<TransactionSignerDetails> {
  const signer = recoverSigner(signedTransaction(transactionValue));
  const { chainId, ...rest } = signer;
  const details: TransactionSignerDetails =
    chainId === undefined ? rest : { ...rest, chainId: chainId.toString() };
  const text = [
    typeLine(signer),
    `Hash: ${signer.hash}`,
    `Public key: ${signer.publicKey}`,
    `Address: ${signer.address}`,
    `r: ${signer.r}`,
    `s: ${signer.s}`,
    `z: ${signer.z}`,
  ].join("\n");
  return { content: content(text), details };
}
