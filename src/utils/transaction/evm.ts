import { rlp, type RlpInput, type RlpItem } from "@agntn/encodings/rlp";
import { keccak256 } from "@agntn/hashes";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { generateAddress } from "../evm-address.ts";

/** A signed transaction as `eth_getTransactionByHash` returns it, quantities and data as 0x hex. */
export interface EvmTransactionJson {
  /** EIP-2718 type, `0x0` for legacy. A node older than typed transactions leaves it out. */
  readonly type?: string;
  readonly chainId?: string;
  readonly nonce: string;
  readonly gasPrice?: string;
  readonly maxPriorityFeePerGas?: string;
  readonly maxFeePerGas?: string;
  readonly gas: string;
  /** Recipient, `null` for a contract creation. */
  readonly to?: string | null;
  readonly value: string;
  readonly input: string;
  readonly accessList?: readonly Readonly<EvmAccessListEntry>[];
  readonly v?: string;
  readonly yParity?: string;
  readonly r: string;
  readonly s: string;
  /** Checked against the rebuilt transaction when present. */
  readonly hash?: string;
  /** Checked against the recovered address when present. */
  readonly from?: string;
}

/** One EIP-2930 access list entry. */
export interface EvmAccessListEntry {
  readonly address: string;
  readonly storageKeys: readonly string[];
}

/** Who signed an EVM transaction, with the r, s and z of the signature. */
export interface TransactionSigner {
  /** EIP-2718 type, 0 for legacy. Not `type`, which `recoverReusedNonce` reads as the scheme. */
  readonly transactionType: 0 | 1 | 2;
  /** Absent only for a legacy transaction from before EIP-155. */
  readonly chainId?: bigint;
  /** Transaction hash, 0x and 64 hex digits. */
  readonly hash: string;
  readonly r: string;
  readonly s: string;
  /** The digest the signature signs: keccak256 of the unsigned transaction, 64 hex digits. */
  readonly z: string;
  /** Uncompressed SEC1 public key as hex. */
  readonly publicKey: string;
  /** EIP-55 address. */
  readonly address: string;
}

/** A decoded RLP item, read only. */
type ReadItem = Uint8Array | readonly ReadItem[];

/** A transaction split into what was signed and the signature over it. */
interface SignedPayload {
  readonly type: 0 | 1 | 2;
  /** Every field before the signature, in RLP order. */
  readonly fields: readonly RlpInput[];
  readonly chainId?: bigint;
  readonly recovery: 0 | 1;
  readonly r: bigint;
  readonly s: bigint;
}

/** Fields before the signature, per type. */
const FIELD_COUNTS = { 0: 6, 1: 8, 2: 9 } as const;
/** Where each typed transaction keeps its access list. */
const ACCESS_LIST_INDEX = { 1: 7, 2: 8 } as const;
const QUANTITY = /^0x[0-9a-f]+$/iu;
const DATA = /^0x(?:[0-9a-f]{2})*$/iu;
const UNSUPPORTED_TYPES: Readonly<Record<string, string>> = {
  3: "Type 3 blob transactions are not supported yet",
  4: "Type 4 set code transactions are not supported yet",
};

/**
 * Reads an RLP integer.
 * @param bytes - Big endian bytes, empty for 0
 * @returns {bigint} The integer
 */
function toBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt(`0x${bytes.toHex()}`);
}

/**
 * Writes an integer as 64 hex digits.
 * @param value - The integer
 * @returns {string} Zero padded hex
 */
function toHex32(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

/**
 * Names a typed transaction prefix this module does not read.
 * @param type - The first byte
 * @returns {string} The refusal
 */
function unsupportedType(type: bigint): string {
  const key = type.toString();
  return Object.hasOwn(UNSUPPORTED_TYPES, key)
    ? (UNSUPPORTED_TYPES[key] ?? "")
    : `Transaction type 0x${type.toString(16).padStart(2, "0")} is not an EVM transaction this reads`;
}

/**
 * Splits `v` of a legacy transaction into the chain id and the recovery bit.
 * @param v - 27 or 28 before EIP-155, chainId * 2 + 35 or 36 after
 * @returns {{ chainId?: bigint; recovery: 0 | 1 }} The chain id, absent before EIP-155
 */
function splitLegacyV(v: bigint): { chainId?: bigint; recovery: 0 | 1 } {
  if (v === 27n || v === 28n) return { recovery: v === 27n ? 0 : 1 };
  if (v < 35n) throw new RangeError("v must be 27, 28, or chainId * 2 + 35 or 36");
  return { chainId: (v - 35n) / 2n, recovery: (v - 35n) % 2n === 0n ? 0 : 1 };
}

/**
 * Reads the recovery bit of a typed transaction.
 * @param value - yParity
 * @returns {0 | 1} The bit
 */
function parity(value: bigint): 0 | 1 {
  if (value !== 0n && value !== 1n) throw new RangeError("yParity must be 0 or 1");
  return value === 0n ? 0 : 1;
}

/**
 * Reads one RLP field that has to be bytes, not a list.
 * @param item - The decoded field
 * @param position - Its place, for the error
 * @returns {Uint8Array} The bytes
 */
function bytesField(item: ReadItem | undefined, position: number): Uint8Array {
  if (!(item instanceof Uint8Array)) {
    throw new TypeError(`Transaction field ${position} must be bytes, not a list`);
  }
  return item;
}

/**
 * Reads an r or s value, which has to fit 32 bytes.
 * @param item - The decoded field
 * @param position - Its place, for the error
 * @returns {bigint} The value
 */
function scalarField(item: ReadItem | undefined, position: number): bigint {
  const bytes = bytesField(item, position);
  if (bytes.length > 32) throw new RangeError(`Transaction field ${position} exceeds 32 bytes`);
  return toBigInt(bytes);
}

/**
 * Checks the fields before the signature: bytes everywhere except a typed access list.
 * @param items - The decoded fields
 * @param type - The transaction type
 * @returns {readonly ReadItem[]} The same fields
 */
function payloadFields(items: readonly ReadItem[], type: 0 | 1 | 2): readonly ReadItem[] {
  const count = FIELD_COUNTS[type];
  if (items.length !== count + 3) {
    throw new RangeError(
      `A type ${type} transaction has ${count + 3} fields, this one has ${items.length}`,
    );
  }
  const fields = items.slice(0, count);
  const listIndex = type === 0 ? -1 : ACCESS_LIST_INDEX[type];
  for (const [position, item] of fields.entries()) {
    if (position === listIndex) {
      if (item instanceof Uint8Array) throw new TypeError("Access list must be a list");
    } else bytesField(item, position);
  }
  return fields;
}

/**
 * Decodes the RLP list of a transaction body.
 * @param bytes - The body
 * @returns {readonly RlpItem[]} Its fields
 */
function decodeList(bytes: Uint8Array): readonly RlpItem[] {
  let item: RlpItem;
  try {
    item = rlp.decode(bytes);
  } catch (error) {
    throw new RangeError(
      `Transaction is not canonical RLP: ${error instanceof Error ? error.message : "unreadable"}`,
      { cause: error },
    );
  }
  if (item instanceof Uint8Array) throw new TypeError("Transaction must be an RLP list");
  return item;
}

/**
 * Splits a raw legacy transaction.
 * @param bytes - The RLP list
 * @returns {SignedPayload} Its parts
 */
function legacyPayload(bytes: Uint8Array): SignedPayload {
  const items = decodeList(bytes);
  const fields = payloadFields(items, 0);
  const { chainId, recovery } = splitLegacyV(toBigInt(bytesField(items[6], 6)));
  const signature = { recovery, r: scalarField(items[7], 7), s: scalarField(items[8], 8) };
  return chainId === undefined
    ? { type: 0, fields, ...signature }
    : { type: 0, fields, chainId, ...signature };
}

/**
 * Splits a raw EIP-2930 or EIP-1559 transaction.
 * @param type - 1 or 2
 * @param body - The RLP list after the type byte
 * @returns {SignedPayload} Its parts
 */
function typedPayload(type: 1 | 2, body: Uint8Array): SignedPayload {
  const items = decodeList(body);
  const fields = payloadFields(items, type);
  const at = FIELD_COUNTS[type];
  return {
    type,
    fields,
    chainId: toBigInt(bytesField(items[0], 0)),
    recovery: parity(toBigInt(bytesField(items[at], at))),
    r: scalarField(items[at + 1], at + 1),
    s: scalarField(items[at + 2], at + 2),
  };
}

/**
 * Reads raw transaction hex, as `eth_getRawTransactionByHash` returns it.
 * @param transaction - Hex, 0x optional
 * @returns {Uint8Array} The bytes
 */
function rawBytes(transaction: string): Uint8Array {
  const digits = transaction.startsWith("0x") ? transaction.slice(2) : transaction;
  if (digits.length === 0 || !/^(?:[0-9a-f]{2})+$/iu.test(digits)) {
    throw new TypeError("Transaction must be hex, 0x optional");
  }
  return Uint8Array.fromHex(digits);
}

/**
 * Splits a raw transaction by the EIP-2718 envelope.
 * @param bytes - The raw transaction
 * @returns {SignedPayload} Its parts
 */
function rawPayload(bytes: Uint8Array): SignedPayload {
  const [first = 0] = bytes;
  if (first >= 0xc0) return legacyPayload(bytes);
  if (first === 1 || first === 2) return typedPayload(first, bytes.subarray(1));
  if (first >= 0x80) throw new TypeError("Transaction must be an RLP list or a typed envelope");
  throw new RangeError(unsupportedType(BigInt(first)));
}

/**
 * Reads a JSON quantity.
 * @param value - 0x hex
 * @param name - The field, for the error
 * @returns {bigint} The integer
 */
function quantity(value: unknown, name: string): bigint {
  if (typeof value !== "string" || !QUANTITY.test(value)) {
    throw new TypeError(`${name} must be a 0x hex quantity`);
  }
  return BigInt(value);
}

/**
 * Reads JSON data, optionally of a fixed length.
 * @param value - 0x hex
 * @param name - The field, for the error
 * @param length - Byte length it must have
 * @returns {Uint8Array} The bytes
 */
function data(value: unknown, name: string, length?: number): Uint8Array {
  if (typeof value !== "string" || !DATA.test(value)) {
    throw new TypeError(`${name} must be 0x hex bytes`);
  }
  const bytes = Uint8Array.fromHex(value.slice(2));
  if (length !== undefined && bytes.length !== length) {
    throw new RangeError(`${name} must be ${length} bytes`);
  }
  return bytes;
}

/**
 * Reads the recipient, empty for a contract creation.
 * @param value - Address or null
 * @returns {Uint8Array} 20 bytes, or none
 */
function recipient(value: unknown): Uint8Array {
  return value === null || value === undefined ? new Uint8Array() : data(value, "to", 20);
}

/**
 * Reads an EIP-2930 access list into its RLP shape.
 * @param value - The JSON list
 * @returns {RlpInput} `[[address, [key, ...]], ...]`
 */
function accessList(value: unknown): RlpInput {
  if (!Array.isArray(value)) throw new TypeError("accessList must be an array");
  return value.map((entry: unknown, position): RlpInput => {
    if (typeof entry !== "object" || entry === null) {
      throw new TypeError(`accessList[${position}] must be an object`);
    }
    const { address, storageKeys } = entry as Partial<EvmAccessListEntry>;
    if (!Array.isArray(storageKeys)) {
      throw new TypeError(`accessList[${position}].storageKeys must be an array`);
    }
    return [
      data(address, `accessList[${position}].address`, 20),
      storageKeys.map((key: unknown) => data(key, `accessList[${position}].storageKeys`, 32)),
    ];
  });
}

/**
 * Reads the JSON type field.
 * @param value - `0x0`, `0x1`, `0x2`, or absent for legacy
 * @returns {0 | 1 | 2} The type
 */
function jsonType(value: unknown): 0 | 1 | 2 {
  if (value === undefined) return 0;
  const type = quantity(value, "type");
  if (type === 0n || type === 1n || type === 2n) return Number(type) as 0 | 1 | 2;
  throw new RangeError(unsupportedType(type));
}

/**
 * Lists the JSON fields before the signature, in RLP order.
 * @param json - The transaction
 * @param type - Its type
 * @returns {readonly RlpInput[]} The fields
 */
function jsonFields(json: Readonly<EvmTransactionJson>, type: 0 | 1 | 2): readonly RlpInput[] {
  const head = type === 0 ? [] : [quantity(json.chainId, "chainId")];
  const nonce = quantity(json.nonce, "nonce");
  const fees =
    type === 2
      ? [
          quantity(json.maxPriorityFeePerGas, "maxPriorityFeePerGas"),
          quantity(json.maxFeePerGas, "maxFeePerGas"),
        ]
      : [quantity(json.gasPrice, "gasPrice")];
  const body = [
    quantity(json.gas, "gas"),
    recipient(json.to),
    quantity(json.value, "value"),
    data(json.input, "input"),
  ];
  return type === 0
    ? [nonce, ...fees, ...body]
    : [...head, nonce, ...fees, ...body, accessList(json.accessList)];
}

/**
 * Reads the chain id and recovery bit a JSON transaction signs with.
 * @param json - The transaction
 * @param type - Its type
 * @returns {{ chainId?: bigint; recovery: 0 | 1 }} The chain id, absent before EIP-155
 */
function jsonSignature(
  json: Readonly<EvmTransactionJson>,
  type: 0 | 1 | 2,
): { chainId?: bigint; recovery: 0 | 1 } {
  if (type !== 0) {
    const bit = json.yParity ?? json.v;
    return {
      chainId: quantity(json.chainId, "chainId"),
      recovery: parity(quantity(bit, "yParity")),
    };
  }
  const split = splitLegacyV(quantity(json.v, "v"));
  if (
    split.chainId !== undefined &&
    json.chainId !== undefined &&
    quantity(json.chainId, "chainId") !== split.chainId
  ) {
    throw new RangeError(`chainId disagrees with v, which signs for chain ${split.chainId}`);
  }
  return split;
}

/**
 * Splits a JSON transaction.
 * @param json - The transaction
 * @returns {SignedPayload} Its parts
 */
function jsonPayload(json: Readonly<EvmTransactionJson>): SignedPayload {
  const type = jsonType(json.type);
  const fields = jsonFields(json, type);
  const { chainId, recovery } = jsonSignature(json, type);
  const signature = { recovery, r: quantity(json.r, "r"), s: quantity(json.s, "s") };
  return chainId === undefined
    ? { type, fields, ...signature }
    : { type, fields, chainId, ...signature };
}

/**
 * Prepends the EIP-2718 type byte to a typed transaction.
 * @param type - The transaction type
 * @param body - The RLP list
 * @returns {Uint8Array} The envelope, or the list itself for legacy
 */
function envelope(type: 0 | 1 | 2, body: Uint8Array): Uint8Array {
  if (type === 0) return body;
  const bytes = new Uint8Array(body.length + 1);
  bytes[0] = type;
  bytes.set(body, 1);
  return bytes;
}

/**
 * The bytes the signer hashed: EIP-155 appends the chain id and two zeros to a legacy list.
 * @param payload - The transaction
 * @returns {Uint8Array} The unsigned transaction
 */
function unsignedBytes(payload: Readonly<SignedPayload>): Uint8Array {
  const { type, fields, chainId } = payload;
  const list = type === 0 && chainId !== undefined ? [...fields, chainId, 0n, 0n] : fields;
  return envelope(type, rlp.encode(list));
}

/**
 * The transaction as the network carries it.
 * @param payload - The transaction
 * @returns {Uint8Array} The signed transaction
 */
function signedBytes(payload: Readonly<SignedPayload>): Uint8Array {
  const { type, fields, chainId, recovery, r, s } = payload;
  const legacyV = chainId === undefined ? 27n : chainId * 2n + 35n;
  const v = BigInt(recovery) + (type === 0 ? legacyV : 0n);
  return envelope(type, rlp.encode([...fields, v, r, s]));
}

/**
 * Recovers the public key behind a signature over a digest.
 * @param digest - The signed digest
 * @param payload - The signature
 * @returns {string} Uncompressed SEC1 hex
 */
function recoverPublicKey(digest: Uint8Array, payload: Readonly<SignedPayload>): string {
  try {
    return new secp256k1.Signature(payload.r, payload.s, payload.recovery)
      .recoverPublicKey(digest)
      .toHex(false);
  } catch {
    throw new RangeError("Signature recovers no public key");
  }
}

/**
 * Checks the hash and sender a JSON transaction states against what it rebuilds to.
 * @param json - The transaction
 * @param signer - What the rebuild gave
 */
function checkStated(
  json: Readonly<EvmTransactionJson>,
  signer: Readonly<TransactionSigner>,
): void {
  if (json.hash !== undefined && String(json.hash).toLowerCase() !== signer.hash) {
    throw new RangeError(
      `The fields rebuild to ${signer.hash}, not the stated hash: a field is missing or altered`,
    );
  }
  if (json.from !== undefined && String(json.from).toLowerCase() !== signer.address.toLowerCase()) {
    throw new RangeError(`The signature recovers ${signer.address}, not the stated from`);
  }
}

/**
 * Recovers who signed an EVM transaction: legacy, EIP-155, EIP-2930 (type 1) or EIP-1559
 * (type 2). Types 3 and 4 are refused. A JSON transaction is rebuilt and must match its own
 * `hash` and `from` when it states them.
 *
 * @param transaction - Raw hex as `eth_getRawTransactionByHash` returns it, or the object
 * `eth_getTransactionByHash` returns.
 * @returns {TransactionSigner} The signer's key and address, with r, s and the digest z.
 * @throws {TypeError} When the input is no transaction.
 * @throws {RangeError} When a field is out of range, the type unsupported, or a stated field
 * disagrees.
 */
export function recoverSigner(
  transaction: string | Readonly<EvmTransactionJson>,
): TransactionSigner {
  if (
    typeof transaction !== "string" &&
    (typeof transaction !== "object" || transaction === null)
  ) {
    throw new TypeError("Transaction must be raw hex or the eth_getTransactionByHash object");
  }
  const raw = typeof transaction === "string" ? rawBytes(transaction) : undefined;
  const payload =
    raw === undefined ? jsonPayload(transaction as EvmTransactionJson) : rawPayload(raw);
  const digest = keccak256(unsignedBytes(payload));
  const publicKey = recoverPublicKey(digest, payload);
  const signer: TransactionSigner = {
    transactionType: payload.type,
    ...(payload.chainId === undefined ? {} : { chainId: payload.chainId }),
    hash: `0x${keccak256(raw ?? signedBytes(payload)).toHex()}`,
    r: toHex32(payload.r),
    s: toHex32(payload.s),
    z: digest.toHex(),
    publicKey,
    address: generateAddress(publicKey),
  };
  if (raw === undefined) checkStated(transaction as EvmTransactionJson, signer);
  return signer;
}
