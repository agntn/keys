import {
  PRIVATE_KEY_SCHEMA_PATTERN,
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

const CHAIN_PUBLIC_KEY = new RegExp(CHAIN_PUBLIC_KEY_SCHEMA_PATTERN, "u");

export const MONERO_SEED = new RegExp(MONERO_SEED_SCHEMA_PATTERN, "u");

/** Monero's spend and view pair, the one 64-byte key the tools take. */
const MONERO_PUBLIC_KEY = /^[0-9A-Fa-f]{128}$/u;

/**
 * Applies a schema's hex pattern for hosts that skip the schema, so a `0x` prefix fails as input
 * instead of reaching a verifier that reports it as a bad signature. The value is never echoed.
 * @param value - Raw argument.
 * @param name - Argument name for the error.
 * @param pattern - Pattern the shared schema advertises.
 * @param shape - Accepted form, as the error states it.
 * @returns {string} The argument unchanged.
 */
export function hexArgument(
  value: unknown,
  name: string,
  pattern: Readonly<RegExp>,
  shape: string,
): string {
  const text = requiredString(value, name);
  if (!pattern.test(text)) throw new TypeError(`${name} must be ${shape} without 0x`);
  return text;
}

/**
 * Reads the key for an address or a signature check, the `ed25519:` form on near only.
 * @param value - Argument as the host passed it.
 * @param chain - Name of the chain that reads the key.
 * @returns {string} The key as given.
 * @throws {TypeError} On a bad shape, or the `ed25519:` form on another chain.
 */
export function chainPublicKey(value: unknown, chain: string): string {
  const publicKey = hexArgument(
    value,
    "Public key",
    CHAIN_PUBLIC_KEY,
    "a 32-byte ed25519 key, XRPL's ED form of one, NEAR's ed25519: form, Monero's 64-byte spend and view pair, or a SEC1 secp256k1 key in hex",
  );
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

export function optionalName(value: unknown, name: string): string | undefined {
  return isUnset(value) ? undefined : requiredString(value, name);
}

export function optionalIndex(
  value: unknown,
  name: string,
  maximum = 0x7fffffff,
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

/**
 * Reads the account and index of a Monero subaddress, each 0 when only the other is given.
 * @param chain - Name of the chain the wallet is on
 * @param accountValue - Raw account argument
 * @param indexValue - Raw address index argument
 * @returns {SubaddressIndices | undefined} The indices, undefined when neither is given
 * @throws {RangeError} When either is no uint32, or the chain is not monero
 */
export function subaddressIndices(
  chain: string,
  accountValue: unknown,
  indexValue: unknown,
): SubaddressIndices | undefined {
  const account = optionalIndex(accountValue, "account", MAX_MONERO_SUBADDRESS_INDEX);
  const index = optionalIndex(indexValue, "addressIndex", MAX_MONERO_SUBADDRESS_INDEX);
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

/**
 * Picks one value out of a closed set, naming the set when the value is not in it.
 * @param value - Raw argument
 * @param name - Argument name for the error
 * @param allowed - Values the argument takes
 * @returns {Value} The matched value
 */
export function oneOf<const Value extends string>(
  value: unknown,
  name: string,
  allowed: readonly Value[],
): Value {
  const matched = allowed.find((candidate) => candidate === value);
  if (matched === undefined) throw new RangeError(`${name} must be one of ${allowed.join(", ")}`);
  return matched;
}

/**
 * Reads one cost parameter against the ceiling the KDF tools set.
 * @param value - Raw argument
 * @param name - Parameter name, a key of `KDF_COST_LIMITS`
 * @param minimum - Smallest value the KDF takes
 * @returns {number} The parameter
 */
export function costArgument(
  value: unknown,
  name: keyof typeof KDF_COST_LIMITS,
  minimum = 1,
): number {
  const maximum = KDF_COST_LIMITS[name];
  if (typeof value !== "number" || !Number.isInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

export const HEX_BYTES = new RegExp(HEX_BYTES_SCHEMA_PATTERN, "u");

/**
 * Reads an object argument, refusing any key the schema does not list.
 * @param value - Raw argument
 * @param name - Argument name for the error
 * @param keys - Keys the schema lists
 * @returns {Readonly<Record<string, unknown>>} The object
 */
export function closedObject(
  value: unknown,
  name: string,
  keys: readonly string[],
): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object with ${keys.join(", ")}`);
  }
  if (Object.keys(value).some((key) => !keys.includes(key))) {
    throw new TypeError(`${name} takes only ${keys.join(", ")}`);
  }
  return Object.fromEntries(Object.entries(value));
}

/**
 * Reads an array argument with a length range.
 * @param value - Raw argument
 * @param name - Argument name for the error
 * @param minimum - Fewest items
 * @param maximum - Most items
 * @returns {readonly unknown[]} The items
 */
export function boundedArray(
  value: unknown,
  name: string,
  minimum: number,
  maximum: number,
): readonly unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    const count = minimum === maximum ? `${minimum}` : `${minimum} to ${maximum}`;
    throw new RangeError(`${name} must be an array of ${count} items`);
  }
  return value;
}
