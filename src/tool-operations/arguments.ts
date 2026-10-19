import {
  PRIVATE_KEY_SCHEMA_PATTERN,
  SIGNING_KEY_SCHEMA_PATTERN,
  CHAIN_PUBLIC_KEY_SCHEMA_PATTERN,
  MONERO_SEED_SCHEMA_PATTERN,
  KDF_COST_LIMITS,
  HEX_BYTES_SCHEMA_PATTERN,
  MAX_MONERO_SUBADDRESS_INDEX,
} from "../tool-parameters.ts";

export function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string`);
  return value;
}

export const PRIVATE_KEY_HEX = new RegExp(PRIVATE_KEY_SCHEMA_PATTERN, "u");

const SIGNING_KEY_HEX = new RegExp(SIGNING_KEY_SCHEMA_PATTERN, "u");

const CHAIN_PUBLIC_KEY = new RegExp(CHAIN_PUBLIC_KEY_SCHEMA_PATTERN, "u");

export const MONERO_SEED = new RegExp(MONERO_SEED_SCHEMA_PATTERN, "u");

/** Monero's spend and view pair, the one 64-byte key the tools take. */
const MONERO_PUBLIC_KEY = /^[0-9A-Fa-f]{128}$/u;

/** A hex argument: its name for the error, the schema's pattern and the form the error states. */
export interface HexArgument {
  readonly name: string;
  readonly pattern: Readonly<RegExp>;
  readonly shape: string;
}

/**
 * Applies a schema's hex pattern for hosts that skip the schema, so a `0x` prefix fails as input
 * instead of reaching a verifier that reports it as a bad signature. The value is never echoed.
 * @param value - Raw argument.
 * @param argument - Name, pattern and accepted form.
 * @returns {string} The argument unchanged.
 */
export function hexArgument(value: unknown, argument: HexArgument): string {
  const { name, pattern, shape } = argument;
  const text = requiredString(value, name);
  if (!pattern.test(text)) throw new TypeError(`${name} must be ${shape} without 0x`);
  return text;
}

/**
 * Reads a hex private key, on polkadot also the 64-byte sr25519 secret of a derived account.
 * @param value - Argument as the host passed it.
 * @param chain - Name of the chain the key belongs to.
 * @returns {string} The key as given.
 * @throws {TypeError} On any other shape.
 */
export function chainPrivateKey(value: unknown, chain: string): string {
  if (chain !== "polkadot") {
    return hexArgument(value, {
      name: "Private key",
      pattern: PRIVATE_KEY_HEX,
      shape: "64 hex characters",
    });
  }
  return hexArgument(value, {
    name: "Private key",
    pattern: SIGNING_KEY_HEX,
    shape: "64 hex characters, or 128 for the sr25519 secret of a derived account,",
  });
}

/**
 * Reads the key for an address or a signature check, the `ed25519:` form on near only.
 * @param value - Argument as the host passed it.
 * @param chain - Name of the chain that reads the key.
 * @returns {string} The key as given.
 * @throws {TypeError} On a bad shape, or the `ed25519:` form on another chain.
 */
export function chainPublicKey(value: unknown, chain: string): string {
  const publicKey = hexArgument(value, {
    name: "Public key",
    pattern: CHAIN_PUBLIC_KEY,
    shape:
      "a 32-byte ed25519 key, XRPL's ED form of one, NEAR's ed25519: form, Monero's 64-byte spend and view pair, or a SEC1 secp256k1 key in hex",
  });
  if (chain !== "near" && publicKey.startsWith("ed25519:")) {
    throw new TypeError(
      `ed25519: and base58 is how NEAR writes a key. Give ${chain} the key in hex`,
    );
  }
  if ((chain === "monero") !== MONERO_PUBLIC_KEY.test(publicKey)) {
    throw new TypeError(
      chain === "monero"
        ? "A Monero public key is 64 bytes of hex: the public spend key, then the public view key"
        : `64 bytes of hex is Monero's spend and view pair. Give ${chain} its own public key`,
    );
  }
  return publicKey;
}

export function optionalString(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined;
  return requiredString(value, name);
}

/**
 * Tells whether an optional name such as a network or an address type was left out.
 * OMP sends every property of the schema, so an option the model leaves alone arrives as `""`.
 * Passphrases skip this check, because spaces are a passphrase of their own.
 * @param value - Argument as the host passed it.
 * @returns {boolean} True when the argument is missing or a blank string.
 */
export function isUnset(value: unknown): boolean {
  return value === undefined || (typeof value === "string" && value.trim() === "");
}

/**
 * Tells whether a cost was left out. OMP sends 0 for an unused number, which no KDF takes.
 * @param value - Raw argument
 * @returns {boolean} True for a missing, zero or blank value
 */
export function isUnsetCost(value: unknown): boolean {
  return value === 0 || isUnset(value);
}

export function optionalName(value: unknown, name: string): string | undefined {
  return isUnset(value) ? undefined : requiredString(value, name);
}

/** An index argument: its name for the error and the largest value it takes, uint31 by default. */
export interface IndexArgument {
  readonly name: string;
  readonly maximum?: number;
}

export function optionalIndex(
  value: unknown,
  { name, maximum = 0x7fffffff }: IndexArgument,
): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > maximum) {
    throw new RangeError(`${name} must be an integer between 0 and ${maximum}`);
  }
  return value;
}

/** Account and index of a Monero subaddress. */
export interface SubaddressIndices {
  readonly account: number;
  readonly index: number;
}

/** Account and address index of a Monero subaddress, as the host passed them. */
export interface SubaddressArguments {
  readonly account?: unknown;
  readonly addressIndex?: unknown;
}

/**
 * Reads the account and index of a Monero subaddress, each 0 when only the other is given.
 * @param chain - Name of the chain the wallet is on
 * @param indices - Raw account and address index arguments
 * @returns {SubaddressIndices | undefined} The indices, undefined when neither is given
 * @throws {RangeError} When either is no uint32, or the chain is not monero
 */
export function subaddressIndices(
  chain: string,
  indices: SubaddressArguments,
): SubaddressIndices | undefined {
  const maximum = MAX_MONERO_SUBADDRESS_INDEX;
  const account = optionalIndex(indices.account, { name: "account", maximum });
  const index = optionalIndex(indices.addressIndex, { name: "addressIndex", maximum });
  if (account === undefined && index === undefined) return undefined;
  if (chain !== "monero") {
    throw new RangeError(
      `account and addressIndex pick a Monero subaddress; ${chain} takes neither here`,
    );
  }
  return { account: account ?? 0, index: index ?? 0 };
}

export function stringArray(value: unknown, name: string): readonly string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new TypeError(`${name} must be an array of strings`);
  }
  return value;
}

export function integerArray(value: unknown, name: string): readonly number[] {
  if (!Array.isArray(value)) throw new TypeError(`${name} must be an array of integers`);
  const integers: number[] = [];
  for (const item of value) {
    if (typeof item !== "number" || !Number.isInteger(item)) {
      throw new TypeError(`${name} must be an array of integers`);
    }
    integers.push(item);
  }
  return integers;
}

/** A closed set argument: its name for the error and the values it takes. */
export interface ChoiceArgument<Value extends string> {
  readonly name: string;
  readonly allowed: readonly Value[];
}

/**
 * Picks one value out of a closed set, naming the set when the value is not in it.
 * @param value - Raw argument
 * @param argument - Name and the values it takes
 * @returns {Value} The matched value
 */
export function oneOf<const Value extends string>(
  value: unknown,
  argument: ChoiceArgument<Value>,
): Value {
  const { name, allowed } = argument;
  const matched = allowed.find((candidate) => candidate === value);
  if (matched === undefined) throw new RangeError(`${name} must be one of ${allowed.join(", ")}`);
  return matched;
}

/** A KDF cost: its key in `KDF_COST_LIMITS` and the smallest value the KDF takes, 1 by default. */
export interface CostArgument {
  readonly name: keyof typeof KDF_COST_LIMITS;
  readonly minimum?: number;
}

/**
 * Reads one cost parameter against the ceiling the KDF tools set.
 * @param value - Raw argument
 * @param argument - Name and smallest value
 * @returns {number} The parameter
 */
export function costArgument(value: unknown, argument: CostArgument): number {
  const { name, minimum = 1 } = argument;
  const maximum = KDF_COST_LIMITS[name];
  if (typeof value !== "number" || !Number.isInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

export const HEX_BYTES = new RegExp(HEX_BYTES_SCHEMA_PATTERN, "u");

/** An object argument: its name for the error and the keys the schema lists. */
export interface ObjectArgument {
  readonly name: string;
  readonly keys: readonly string[];
}

/**
 * Reads an object argument, refusing any key the schema does not list.
 * @param value - Raw argument
 * @param argument - Name and keys
 * @returns {Readonly<Record<string, unknown>>} The object
 */
export function closedObject(
  value: unknown,
  argument: ObjectArgument,
): Readonly<Record<string, unknown>> {
  const { name, keys } = argument;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object with ${keys.join(", ")}`);
  }
  if (Object.keys(value).some((key) => !keys.includes(key))) {
    throw new TypeError(`${name} takes only ${keys.join(", ")}`);
  }
  return Object.fromEntries(Object.entries(value));
}

/** An array argument: its name for the error and the fewest and most items it takes. */
export interface ArrayArgument {
  readonly name: string;
  readonly minimum: number;
  readonly maximum: number;
}

/**
 * Reads an array argument with a length range.
 * @param value - Raw argument
 * @param argument - Name and length range
 * @returns {readonly unknown[]} The items
 */
export function boundedArray(value: unknown, argument: ArrayArgument): readonly unknown[] {
  const { name, minimum, maximum } = argument;
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    const count = minimum === maximum ? `${minimum}` : `${minimum} to ${maximum}`;
    throw new RangeError(`${name} must be an array of ${count} items`);
  }
  return value;
}
