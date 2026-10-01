import { keccak256 } from "@agntn/hashes";
import { concatBytes } from "./bytes.ts";

/** One member of an EIP-712 struct, as `types` lists it. */
export interface TypedDataField {
  name: string;
  type: string;
}

/** EIP-712 typed data in the shape `eth_signTypedData_v4` takes. */
export interface TypedData {
  /** Struct definitions by name; `EIP712Domain` is inferred from `domain` when left out. */
  types: Readonly<Record<string, readonly Readonly<TypedDataField>[]>>;
  primaryType: string;
  domain: Readonly<Record<string, unknown>>;
  message: Readonly<Record<string, unknown>>;
}

const DOMAIN_TYPE = "EIP712Domain";

/** Domain fields in the order ethers infers them when `types` has no `EIP712Domain`. */
const DOMAIN_FIELDS: readonly Readonly<TypedDataField>[] = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" },
  { name: "salt", type: "bytes32" },
];

/** Nesting of structs and arrays a value may reach, far past any real message. */
const MAX_DEPTH = 64;

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
const TYPE_TEXT = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\[\d*\])*$/u;
const ARRAY_SUFFIX = /^(.+)\[(\d*)\]$/u;
const INTEGER_TYPE = /^(u?)int(\d*)$/u;
const FIXED_BYTES_TYPE = /^bytes(\d+)$/u;
const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/iu;
const ADDRESS = /^0x[0-9a-f]{40}$/iu;
const INTEGER_TEXT = /^(-?)(0x[0-9a-f]+|\d+)$/iu;

const WORD = 32;
const TWO_256 = 1n << 256n;

type Types = Readonly<Record<string, readonly Readonly<TypedDataField>[]>>;

/**
 * Quote a caller's name in an error only when it is identifier text, never a line break or bidi.
 * @param value - Name from the typed data
 * @param pattern - Shape the name must have to be quoted
 * @returns {string} The quoted name, or a placeholder
 */
function quoted(value: unknown, pattern: Readonly<RegExp> = IDENTIFIER): string {
  return typeof value === "string" && pattern.test(value)
    ? JSON.stringify(value)
    : "(not an identifier)";
}

/**
 * Field types of a struct, or undefined when the name is not one of `types`.
 * @param types - Struct definitions
 * @param name - Type name
 * @returns {readonly Readonly<TypedDataField>[] | undefined} The fields in order
 */
function structFields(types: Types, name: string): readonly Readonly<TypedDataField>[] | undefined {
  return Object.hasOwn(types, name) ? types[name] : undefined;
}

/**
 * Name of the struct a field type refers to, with any array suffixes taken off.
 * @param type - Field type such as `Person[2][]`
 * @returns {string} The element type, `Person` here
 */
function baseType(type: string): string {
  let current = type;
  for (let match = ARRAY_SUFFIX.exec(current); match; match = ARRAY_SUFFIX.exec(current)) {
    current = match[1] ?? "";
  }
  return current;
}

/**
 * Width and sign of an integer type, or undefined for anything else, `uint7` included.
 * @param type - Field type
 * @returns {{ signed: boolean; bits: bigint } | undefined} The integer's shape
 */
function integerType(type: string): { signed: boolean; bits: bigint } | undefined {
  const match = INTEGER_TYPE.exec(type);
  if (!match) return undefined;
  const bits = match[2] === "" ? 256 : Number(match[2]);
  if (bits < 8 || bits > 256 || bits % 8 !== 0) return undefined;
  return { signed: match[1] === "", bits: BigInt(bits) };
}

/**
 * Length of a `bytesN` type, or undefined for anything else.
 * @param type - Field type
 * @returns {number | undefined} N, from 1 to 32
 */
function fixedBytesLength(type: string): number | undefined {
  const length = Number(FIXED_BYTES_TYPE.exec(type)?.[1]);
  return length >= 1 && length <= WORD ? length : undefined;
}

/**
 * Tell the atomic and dynamic types EIP-712 encodes in place from struct names.
 * @param type - Field type without array suffixes
 * @returns {boolean} True for `address`, `bool`, `string`, `bytes`, `bytesN` and integers
 */
function isAtomic(type: string): boolean {
  return (
    Object.hasOwn(SIMPLE_ENCODERS, type) ||
    integerType(type) !== undefined ||
    fixedBytesLength(type) !== undefined
  );
}

/**
 * Tell a `{ name, type }` field from anything else a caller put in `types`.
 * @param value - One entry of a struct's field list
 * @returns {boolean} True when both are strings
 */
function isField(value: unknown): value is TypedDataField {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof Reflect.get(value, "name") === "string" &&
    typeof Reflect.get(value, "type") === "string"
  );
}

/**
 * Check one struct's fields, so a typo fails before hashing instead of hashing something else.
 * @param types - Struct definitions with the domain resolved
 * @param name - Struct name
 * @param fields - Its field list as given
 * @returns {void} Nothing; it throws on the first bad field
 */
function checkFields(types: Types, name: string, fields: unknown): void {
  if (!Array.isArray(fields)) throw new TypeError(`Type ${name} must list its fields`);
  const list: readonly unknown[] = fields;
  for (const field of list) {
    if (!isField(field)) {
      throw new TypeError(`Type ${name} has a field without a string name and type`);
    }
    if (!IDENTIFIER.test(field.name)) {
      throw new TypeError(`Type ${name} has a field name that is not an identifier`);
    }
    const element = baseType(field.type);
    if (
      !TYPE_TEXT.test(field.type) ||
      (structFields(types, element) === undefined && !isAtomic(element))
    ) {
      throw new TypeError(
        `Field "${field.name}" of ${name} has unknown type ${quoted(field.type, TYPE_TEXT)}`,
      );
    }
  }
}

/**
 * Check every struct name and field before anything is hashed.
 * @param types - Struct definitions with the domain resolved
 * @returns {void} Nothing; it throws on the first bad definition
 */
function checkTypes(types: Types): void {
  for (const [name, fields] of Object.entries(types)) {
    if (!IDENTIFIER.test(name)) throw new TypeError(`Type name ${quoted(name)} is invalid`);
    checkFields(types, name, fields);
  }
}

/**
 * The struct and every struct it reaches, the primary first and the rest sorted by name.
 * @param types - Struct definitions
 * @param primary - Struct to start from
 * @returns {string[]} Type names in `encodeType` order
 */
function dependencies(types: Types, primary: string): string[] {
  const found = new Set<string>();
  const pending = [primary];
  for (let name = pending.pop(); name !== undefined; name = pending.pop()) {
    const fields = structFields(types, name);
    if (fields === undefined || found.has(name)) continue;
    found.add(name);
    for (const field of fields) pending.push(baseType(field.type));
  }
  found.delete(primary);
  return [primary, ...[...found].toSorted()];
}

/**
 * The `encodeType` string, such as `Mail(Person from,Person to,string contents)Person(...)`.
 * @param types - Struct definitions
 * @param primary - Struct name
 * @returns {string} The canonical type string
 */
function encodeType(types: Types, primary: string): string {
  return dependencies(types, primary)
    .map(
      (name) =>
        `${name}(${(structFields(types, name) ?? []).map((field) => `${field.type} ${field.name}`).join(",")})`,
    )
    .join("");
}

/**
 * Read an integer from a number, bigint, decimal text or 0x hex text.
 * @param value - Raw value
 * @param path - Field path for the error
 * @returns {bigint} The integer
 */
function readInteger(value: unknown, path: string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  if (typeof value === "string") {
    const match = INTEGER_TEXT.exec(value.trim());
    if (match) {
      const magnitude = BigInt(match[2] ?? "");
      return match[1] === "-" ? -magnitude : magnitude;
    }
  }
  throw new TypeError(`${path} must be an integer, as a safe number or decimal or 0x hex text`);
}

/**
 * Read 0x hex text as bytes.
 * @param value - Raw value
 * @param path - Field path for the error
 * @returns {Uint8Array} The bytes
 */
function readHex(value: unknown, path: string): Uint8Array {
  if (typeof value !== "string" || !HEX_DATA.test(value)) {
    throw new TypeError(`${path} must be 0x hex with whole bytes`);
  }
  return Uint8Array.fromHex(value.slice(2));
}

/**
 * Write an integer as one big endian word, two's complement when negative.
 * @param value - Integer already checked against its type's range
 * @returns {Uint8Array} 32 bytes
 */
function word(value: bigint): Uint8Array {
  const unsigned = value < 0n ? value + TWO_256 : value;
  return Uint8Array.fromHex(unsigned.toString(16).padStart(WORD * 2, "0"));
}

/**
 * Hash a string as its UTF-8 bytes.
 * @param value - Raw value
 * @param path - Field path for the error
 * @returns {Uint8Array} 32 bytes
 */
function encodeString(value: unknown, path: string): Uint8Array {
  if (typeof value !== "string") throw new TypeError(`${path} must be a string`);
  return keccak256(new TextEncoder().encode(value));
}

/**
 * Write a boolean as 0 or 1.
 * @param value - Raw value
 * @param path - Field path for the error
 * @returns {Uint8Array} 32 bytes
 */
function encodeBool(value: unknown, path: string): Uint8Array {
  if (typeof value !== "boolean") throw new TypeError(`${path} must be true or false`);
  return word(value ? 1n : 0n);
}

/**
 * Write a 20-byte address left padded, in any letter case.
 * @param value - Raw value
 * @param path - Field path for the error
 * @returns {Uint8Array} 32 bytes
 */
function encodeAddress(value: unknown, path: string): Uint8Array {
  if (typeof value !== "string" || !ADDRESS.test(value)) {
    throw new TypeError(`${path} must be a 0x address of 20 bytes`);
  }
  return word(BigInt(value));
}

/** Atomic types whose encoding needs nothing but the value. */
const SIMPLE_ENCODERS: Readonly<Record<string, (value: unknown, path: string) => Uint8Array>> = {
  string: encodeString,
  bytes: (value, path) => keccak256(readHex(value, path)),
  bool: encodeBool,
  address: encodeAddress,
};

/**
 * Write `bytesN` right padded.
 * @param type - The `bytesN` type, for the error
 * @param length - N
 * @param value - Raw value
 * @param path - Field path for the error
 * @returns {Uint8Array} 32 bytes
 */
function encodeFixedBytes(type: string, length: number, value: unknown, path: string): Uint8Array {
  const bytes = readHex(value, path);
  if (bytes.length !== length) throw new TypeError(`${path} must be ${length} bytes for ${type}`);
  const padded = new Uint8Array(WORD);
  padded.set(bytes);
  return padded;
}

/**
 * Write an integer after checking it fits its type.
 * @param type - The integer type, for the error
 * @param shape - Its sign and width
 * @param shape.signed - Whether it is `intN`
 * @param shape.bits - N
 * @param value - Raw value
 * @param path - Field path for the error
 * @returns {Uint8Array} 32 bytes
 */
function encodeInteger(
  type: string,
  shape: Readonly<{ signed: boolean; bits: bigint }>,
  value: unknown,
  path: string,
): Uint8Array {
  const number = readInteger(value, path);
  const minimum = shape.signed ? -(1n << (shape.bits - 1n)) : 0n;
  const maximum = shape.signed ? (1n << (shape.bits - 1n)) - 1n : (1n << shape.bits) - 1n;
  if (number < minimum || number > maximum)
    throw new RangeError(`${path} is out of range for ${type}`);
  return word(number);
}

/**
 * Encode one atomic value as the 32 bytes `encodeData` puts in its place.
 * @param type - Atomic type
 * @param value - Raw value
 * @param path - Field path for the error
 * @returns {Uint8Array} 32 bytes
 */
function encodeAtomic(type: string, value: unknown, path: string): Uint8Array {
  const simple = Object.hasOwn(SIMPLE_ENCODERS, type) ? SIMPLE_ENCODERS[type] : undefined;
  if (simple) return simple(value, path);
  const length = fixedBytesLength(type);
  if (length !== undefined) return encodeFixedBytes(type, length, value, path);
  const integer = integerType(type);
  if (integer === undefined)
    throw new TypeError(`${path} has unknown type ${quoted(type, TYPE_TEXT)}`);
  return encodeInteger(type, integer, value, path);
}

/**
 * Encode a value of any field type as the 32 bytes its struct hashes.
 * @param types - Struct definitions
 * @param type - Field type
 * @param value - Raw value
 * @param path - Field path for the error
 * @param depth - Structs and arrays above this value
 * @returns {Uint8Array} 32 bytes
 */
function encodeValue(
  types: Types,
  type: string,
  value: unknown,
  path: string,
  depth: number,
): Uint8Array {
  if (depth > MAX_DEPTH) throw new RangeError(`${path} nests deeper than ${MAX_DEPTH} levels`);
  const array = ARRAY_SUFFIX.exec(type);
  if (array) {
    if (!Array.isArray(value)) throw new TypeError(`${path} must be an array`);
    const items: readonly unknown[] = value;
    if (array[2] !== "" && items.length !== Number(array[2])) {
      throw new TypeError(`${path} must hold ${array[2]} items for ${type}`);
    }
    const element = array[1] ?? "";
    return keccak256(
      concatBytes(
        ...items.map((item, index) =>
          encodeValue(types, element, item, `${path}[${index}]`, depth + 1),
        ),
      ),
    );
  }
  if (structFields(types, type) !== undefined) {
    return hashStruct(types, type, value, path, depth + 1);
  }
  return encodeAtomic(type, value, path);
}

/**
 * `hashStruct`: keccak256 of the type hash and every field's encoding.
 * @param types - Struct definitions
 * @param name - Struct name
 * @param value - Raw struct value
 * @param path - Field path for the error
 * @param depth - Structs and arrays above this value
 * @returns {Uint8Array} 32 bytes
 */
function hashStruct(
  types: Types,
  name: string,
  value: unknown,
  path: string,
  depth: number,
): Uint8Array {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object for ${name}`);
  }
  const record: Readonly<Record<string, unknown>> = Object.fromEntries(Object.entries(value));
  const encoded = (structFields(types, name) ?? []).map((field) => {
    const fieldPath = `${path}.${field.name}`;
    if (!Object.hasOwn(record, field.name)) throw new TypeError(`${fieldPath} is missing`);
    return encodeValue(types, field.type, record[field.name], fieldPath, depth);
  });
  return keccak256(
    concatBytes(keccak256(new TextEncoder().encode(encodeType(types, name))), ...encoded),
  );
}

/**
 * Struct definitions with `EIP712Domain` filled in from the domain's own fields when missing.
 * @param typedData - Typed data as given
 * @returns {Types} Definitions that hold the domain type
 */
function withDomainType(typedData: Readonly<TypedData>): Types {
  if (typeof typedData.types !== "object" || typedData.types === null) {
    throw new TypeError("Typed data must hold types");
  }
  if (Object.hasOwn(typedData.types, DOMAIN_TYPE)) return typedData.types;
  if (typeof typedData.domain !== "object" || typedData.domain === null) {
    throw new TypeError("Typed data must hold a domain object");
  }
  const keys = Object.keys(typedData.domain);
  const unknown = keys.find((key) => !DOMAIN_FIELDS.some((field) => field.name === key));
  if (unknown !== undefined) {
    throw new TypeError(`Domain field ${quoted(unknown)} needs an EIP712Domain entry in types`);
  }
  return {
    ...typedData.types,
    [DOMAIN_TYPE]: DOMAIN_FIELDS.filter((field) => keys.includes(field.name)),
  };
}

/**
 * Hash EIP-712 typed data into the digest `eth_signTypedData_v4` signs.
 * A primary type of `EIP712Domain` hashes the domain alone, as MetaMask does.
 * @param typedData - Types, primary type, domain and message
 * @returns {Uint8Array} The 32-byte digest
 * @throws {TypeError} When a type is unknown or a value does not fit its type
 * @throws {RangeError} When an integer is out of range or the value nests too deep
 */
export function hashTypedData(typedData: Readonly<TypedData>): Uint8Array {
  if (typeof typedData !== "object" || typedData === null) {
    throw new TypeError("Typed data must be an object");
  }
  const types = withDomainType(typedData);
  checkTypes(types);
  const { primaryType } = typedData;
  if (typeof primaryType !== "string" || structFields(types, primaryType) === undefined) {
    throw new TypeError(`Primary type ${quoted(primaryType)} is not one of types`);
  }
  const domain = hashStruct(types, DOMAIN_TYPE, typedData.domain, "domain", 0);
  const parts = [Uint8Array.of(0x19, 0x01), domain];
  if (primaryType !== DOMAIN_TYPE) {
    parts.push(hashStruct(types, primaryType, typedData.message, "message", 0));
  }
  return keccak256(concatBytes(...parts));
}
