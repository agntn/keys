import { sha256 } from "@agntn/hashes";
import { encodeCompactSize } from "../bitcoin.ts";
import { concatBytes } from "../bytes.ts";

/** One transaction input; `txid` keeps the byte order of the hash, not the reversed hex. */
export interface TransactionInput {
  readonly txid: Uint8Array;
  readonly vout: number;
  readonly scriptSig: Uint8Array;
  readonly sequence: number;
  readonly witness: readonly Uint8Array[];
}

/** One transaction output, its value in satoshis. */
export interface TransactionOutput {
  readonly value: bigint;
  readonly script: Uint8Array;
}

/** A Bitcoin transaction as the network serializes it. */
export interface Transaction {
  readonly version: number;
  readonly inputs: readonly TransactionInput[];
  readonly outputs: readonly TransactionOutput[];
  readonly lockTime: number;
}

/**
 * Hashes twice with SHA-256, the hash of txids and of legacy and BIP143 sighashes.
 * @param data - Bytes to hash
 * @returns {Uint8Array} 32-byte digest
 */
export function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/**
 * Writes a number as 4 bytes, little endian.
 * @param value - Unsigned 32-bit integer
 * @returns {Uint8Array} The 4 bytes
 */
export function uint32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}

/**
 * Writes an amount as 8 bytes, little endian.
 * @param value - Unsigned 64-bit integer
 * @returns {Uint8Array} The 8 bytes
 */
export function uint64(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, true);
  return bytes;
}

/**
 * Prefixes bytes with their length as a CompactSize.
 * @param bytes - Bytes to frame
 * @returns {Uint8Array} Length, then the bytes
 */
export function varBytes(bytes: Uint8Array): Uint8Array {
  return concatBytes(encodeCompactSize(bytes.length), bytes);
}

/**
 * Serializes an outpoint: the txid bytes, then the output index.
 * @param input - Input whose outpoint to write
 * @returns {Uint8Array} 36 bytes
 */
export function outpoint(input: Readonly<TransactionInput>): Uint8Array {
  return concatBytes(input.txid, uint32(input.vout));
}

/**
 * Serializes one output: value, then the script with its length.
 * @param output - Output to write
 * @returns {Uint8Array} The output bytes
 */
export function serializeOutput(output: Readonly<TransactionOutput>): Uint8Array {
  return concatBytes(uint64(output.value), varBytes(output.script));
}

/**
 * Serializes a witness stack: the item count, then each item with its length.
 * @param stack - Witness items
 * @returns {Uint8Array} The stack bytes, the form a BIP322 simple signature takes
 */
export function encodeWitness(stack: readonly Uint8Array[]): Uint8Array {
  return concatBytes(encodeCompactSize(stack.length), ...stack.map((item) => varBytes(item)));
}

/**
 * Serializes a transaction, with the BIP144 marker and witnesses when asked and any input has one.
 * @param transaction - Transaction to write
 * @param withWitness - Whether to write witnesses; the txid leaves them out
 * @returns {Uint8Array} The transaction bytes
 */
export function serializeTransaction(
  transaction: Readonly<Transaction>,
  withWitness: boolean,
): Uint8Array {
  const segwit = withWitness && transaction.inputs.some((input) => input.witness.length > 0);
  const inputs = transaction.inputs.map((input) =>
    concatBytes(outpoint(input), varBytes(input.scriptSig), uint32(input.sequence)),
  );
  return concatBytes(
    uint32(transaction.version),
    segwit ? Uint8Array.of(0, 1) : new Uint8Array(0),
    encodeCompactSize(inputs.length),
    ...inputs,
    encodeCompactSize(transaction.outputs.length),
    ...transaction.outputs.map((output) => serializeOutput(output)),
    ...(segwit ? transaction.inputs.map((input) => encodeWitness(input.witness)) : []),
    uint32(transaction.lockTime),
  );
}

/**
 * Hashes a transaction without its witnesses, the txid in the byte order an outpoint holds.
 * @param transaction - Transaction to hash
 * @returns {Uint8Array} 32 bytes, reversed against the hex an explorer prints
 */
export function transactionId(transaction: Readonly<Transaction>): Uint8Array {
  return hash256(serializeTransaction(transaction, false));
}

/** Reads consensus encoded bytes front to back, refusing a short read. */
class ByteReader {
  readonly #bytes: Uint8Array;
  #offset = 0;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Whether every byte was read.
   * @returns {boolean} True at the end
   */
  get done(): boolean {
    return this.#offset === this.#bytes.length;
  }

  /**
   * Reads the next bytes.
   * @param length - How many
   * @returns {Uint8Array} A copy of them
   */
  read(length: number): Uint8Array {
    if (this.#offset + length > this.#bytes.length) throw new RangeError("ends early");
    const bytes = this.#bytes.slice(this.#offset, this.#offset + length);
    this.#offset += length;
    return bytes;
  }

  /**
   * Reads one byte.
   * @returns {number} The byte
   */
  byte(): number {
    return this.read(1)[0] ?? 0;
  }

  /**
   * Looks at the next byte without reading it.
   * @returns {number | undefined} The byte, undefined at the end
   */
  peek(): number | undefined {
    return this.#bytes[this.#offset];
  }

  /**
   * Reads 4 bytes, little endian.
   * @returns {number} The unsigned integer
   */
  uint32(): number {
    const bytes = this.read(4);
    return new DataView(bytes.buffer).getUint32(0, true);
  }

  /**
   * Reads 8 bytes, little endian.
   * @returns {bigint} The unsigned integer
   */
  uint64(): bigint {
    const bytes = this.read(8);
    return new DataView(bytes.buffer).getBigUint64(0, true);
  }

  /**
   * Reads a CompactSize, refusing a longer form than the value needs, as Core does.
   * @returns {number} The value
   */
  compactSize(): number {
    const first = this.byte();
    if (first < 0xfd) return first;
    const width = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
    const bytes = this.read(width);
    let value = 0;
    for (let index = width - 1; index >= 0; index--) value = value * 256 + (bytes[index] ?? 0);
    const floor = first === 0xfd ? 0xfd : first === 0xfe ? 0x10000 : 0x100000000;
    if (value < floor) throw new RangeError("holds a non-canonical length");
    return value;
  }

  /**
   * Reads bytes framed by their CompactSize length.
   * @returns {Uint8Array} The bytes
   */
  varBytes(): Uint8Array {
    return this.read(this.compactSize());
  }

  /**
   * Reads a witness stack.
   * @returns {Uint8Array[]} The items
   */
  witness(): Uint8Array[] {
    const count = this.compactSize();
    const stack: Uint8Array[] = [];
    for (let index = 0; index < count; index++) stack.push(this.varBytes());
    return stack;
  }

  /**
   * Reads the inputs without their witnesses.
   * @returns {TransactionInput[]} The inputs, witnesses empty
   */
  inputs(): TransactionInput[] {
    const count = this.compactSize();
    const inputs: TransactionInput[] = [];
    for (let index = 0; index < count; index++) {
      const txid = this.read(32);
      const vout = this.uint32();
      const scriptSig = this.varBytes();
      inputs.push({ txid, vout, scriptSig, sequence: this.uint32(), witness: [] });
    }
    return inputs;
  }

  /**
   * Reads the outputs.
   * @returns {TransactionOutput[]} The outputs
   */
  outputs(): TransactionOutput[] {
    const count = this.compactSize();
    const outputs: TransactionOutput[] = [];
    for (let index = 0; index < count; index++) {
      outputs.push({ value: this.uint64(), script: this.varBytes() });
    }
    return outputs;
  }

  /**
   * Reads the BIP144 marker and flag when they follow the version.
   * @returns {boolean} Whether the transaction carries witnesses
   */
  segwitMarker(): boolean {
    if (this.peek() !== 0) return false;
    this.read(1);
    if (this.byte() !== 1) throw new RangeError("has an unknown witness flag");
    return true;
  }

  /**
   * Reads the witness of every input, refusing the marker over witnesses that are all empty.
   * @param inputs - Inputs in order
   * @returns {TransactionInput[]} The inputs with their witnesses
   */
  witnesses(inputs: readonly TransactionInput[]): TransactionInput[] {
    const withWitness = inputs.map((input) => ({ ...input, witness: this.witness() }));
    if (withWitness.every((input) => input.witness.length === 0)) {
      throw new RangeError("has a witness marker without witnesses");
    }
    return withWitness;
  }
}

/**
 * Reads a consensus serialized transaction, with or without BIP144 witnesses.
 * @param bytes - The transaction bytes
 * @returns {Transaction} The transaction
 * @throws {RangeError} When the bytes end early, run past it or break the encoding
 */
export function decodeTransaction(bytes: Uint8Array): Transaction {
  const reader = new ByteReader(bytes);
  const version = reader.uint32();
  const segwit = reader.segwitMarker();
  const inputs = reader.inputs();
  if (inputs.length === 0) throw new RangeError("has no inputs");
  const outputs = reader.outputs();
  const witnessed = segwit ? reader.witnesses(inputs) : inputs;
  const lockTime = reader.uint32();
  if (!reader.done) throw new RangeError("has bytes past its end");
  return { version, inputs: witnessed, outputs, lockTime };
}

/**
 * Reads a serialized witness stack, the body of a BIP322 simple signature.
 * @param bytes - The stack bytes
 * @returns {Uint8Array[]} The items
 * @throws {RangeError} When the bytes end early or run past the stack
 */
export function decodeWitness(bytes: Uint8Array): Uint8Array[] {
  const reader = new ByteReader(bytes);
  const stack = reader.witness();
  if (!reader.done) throw new RangeError("has bytes past its end");
  return stack;
}
