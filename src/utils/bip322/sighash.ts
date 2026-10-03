import { sha256 } from "@agntn/hashes";
import { taggedHash } from "../address.ts";
import { concatBytes } from "../bytes.ts";
import {
  hash256,
  outpoint,
  serializeOutput,
  serializeTransaction,
  uint32,
  uint64,
  varBytes,
  type Transaction,
  type TransactionOutput,
} from "./transaction.ts";

/** The hash type a 64-byte Taproot signature implies, committing like `SIGHASH_ALL`. */
export const SIGHASH_DEFAULT = 0x00;

/** Signs every input and output; the one type BIP322 takes from an ECDSA signature. */
export const SIGHASH_ALL = 0x01;

/**
 * Legacy sighash of one input under `SIGHASH_ALL`: the transaction with that input's script code
 * in place of every scriptSig, then the hash type.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @param scriptCode - Script of the output it spends
 * @returns {Uint8Array} The digest ECDSA signs
 */
export function legacySighash(
  transaction: Readonly<Transaction>,
  index: number,
  scriptCode: Uint8Array,
): Uint8Array {
  const inputs = transaction.inputs.map((input, position) => ({
    ...input,
    scriptSig: position === index ? scriptCode : new Uint8Array(0),
    witness: [],
  }));
  const unsigned = serializeTransaction({ ...transaction, inputs }, false);
  return hash256(concatBytes(unsigned, uint32(SIGHASH_ALL)));
}

/**
 * BIP143 sighash of one SegWit v0 input under `SIGHASH_ALL`.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @param scriptCode - Script code of the input, the P2PKH script of the key hash for P2WPKH
 * @param amount - Value of the output it spends
 * @returns {Uint8Array} The digest ECDSA signs
 */
export function segwitSighash(
  transaction: Readonly<Transaction>,
  index: number,
  scriptCode: Uint8Array,
  amount: bigint,
): Uint8Array {
  const input = transaction.inputs[index];
  if (input === undefined) throw new RangeError(`Transaction has no input ${index}`);
  const prevouts = concatBytes(...transaction.inputs.map((each) => outpoint(each)));
  const sequences = concatBytes(...transaction.inputs.map((each) => uint32(each.sequence)));
  const outputs = concatBytes(...transaction.outputs.map((output) => serializeOutput(output)));
  return hash256(
    concatBytes(
      uint32(transaction.version),
      hash256(prevouts),
      hash256(sequences),
      outpoint(input),
      varBytes(scriptCode),
      uint64(amount),
      uint32(input.sequence),
      hash256(outputs),
      uint32(transaction.lockTime),
      uint32(SIGHASH_ALL),
    ),
  );
}

/**
 * BIP341 sighash of a Taproot key path spend under `SIGHASH_DEFAULT` or `SIGHASH_ALL`, no annex.
 * @param transaction - Spending transaction
 * @param index - Input being signed
 * @param spent - The outputs every input spends, in input order
 * @param hashType - `SIGHASH_DEFAULT` or `SIGHASH_ALL`
 * @returns {Uint8Array} The digest Schnorr signs
 */
export function taprootSighash(
  transaction: Readonly<Transaction>,
  index: number,
  spent: readonly TransactionOutput[],
  hashType: number,
): Uint8Array {
  if (spent.length !== transaction.inputs.length) {
    throw new RangeError("Taproot sighash needs the spent output of every input");
  }
  const prevouts = concatBytes(...transaction.inputs.map((each) => outpoint(each)));
  const amounts = concatBytes(...spent.map((output) => uint64(output.value)));
  const scripts = concatBytes(...spent.map((output) => varBytes(output.script)));
  const sequences = concatBytes(...transaction.inputs.map((each) => uint32(each.sequence)));
  const outputs = concatBytes(...transaction.outputs.map((output) => serializeOutput(output)));
  const message = concatBytes(
    Uint8Array.of(0, hashType),
    uint32(transaction.version),
    uint32(transaction.lockTime),
    sha256(prevouts),
    sha256(amounts),
    sha256(scripts),
    sha256(sequences),
    sha256(outputs),
    Uint8Array.of(0),
    uint32(index),
  );
  return taggedHash("TapSighash", message);
}
