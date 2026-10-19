import type { DerivationPathOptions } from "../types.ts";

/**
 * Whether the options are an object whose named fields all hold strings.
 * @param options - The caller's options
 * @param fields - The fields that must be strings
 * @returns {boolean} Whether every field is a string
 */
function hasStrings(options: unknown, fields: readonly string[]): boolean {
  if (typeof options !== "object" || options === null) return false;
  return fields.every((field) => typeof Reflect.get(options, field) === "string");
}

/**
 * Whether the options are a plain object, not an array, bytes or a value a positional call passes.
 * @param options - The caller's options
 * @returns {boolean} Whether they can be read as options
 */
function isOptionsObject(options: unknown): options is object {
  if (typeof options !== "object" || options === null) return false;
  return !Array.isArray(options) && !ArrayBuffer.isView(options);
}

/**
 * Refuses what a positional JS call passes as options, so it throws instead of running on defaults.
 * @param options - The caller's options
 * @param usage - The call in its new shape, for the error
 * @throws {TypeError} When the options are neither left out nor an object
 */
export function assertOptions(options: unknown, usage: string): void {
  if (options === undefined || isOptionsObject(options)) return;
  throw new TypeError(`Pass the options as an object: ${usage}`);
}

/**
 * Refuses `signMessage` options without the key, which is what a JS call still written as
 * `signMessage(message, privateKey)` hands over.
 * @param options - The caller's options
 * @throws {TypeError} When the options carry no private key string
 */
export function assertSignOptions(options: unknown): void {
  if (hasStrings(options, ["privateKey"])) return;
  throw new TypeError(
    "signMessage takes the private key in its options: signMessage(message, { privateKey })",
  );
}

/**
 * Refuses `verifyMessage` options without the signature or the key, so a JS call still written
 * as `verifyMessage(message, signature, publicKey)` throws instead of reading as a bad signature.
 * @param options - The caller's options
 * @throws {TypeError} When the options carry no signature or public key string
 */
export function assertVerifyOptions(options: unknown): void {
  if (hasStrings(options, ["signature", "publicKey"])) return;
  throw new TypeError(
    "verifyMessage takes the signature and the key in its options: verifyMessage(message, { signature, publicKey })",
  );
}

/**
 * Refuses keystore `encrypt` options without the password, which is what a JS call still written
 * as `encrypt(privateKey, password)` hands over.
 * @param options - The caller's options
 * @throws {TypeError} When the options carry no password string
 */
export function assertEncryptOptions(options: unknown): void {
  if (hasStrings(options, ["password"])) return;
  throw new TypeError(
    "encrypt takes the password in its options: encrypt(privateKey, { password })",
  );
}

/**
 * Reads derivation path options, refusing the account number a JS call still written as
 * `getDerivationPath(account, change, addressIndex)` passes, which would quietly give account 0.
 * @param options - The caller's options
 * @returns {DerivationPathOptions} The options, an empty object when left out
 * @throws {TypeError} When the options are neither left out nor an object
 */
export function readPathOptions(options: unknown): DerivationPathOptions {
  if (options === undefined) return {};
  if (isOptionsObject(options)) return options;
  throw new TypeError(
    "Derivation paths take their levels in an options object: { account, change, addressIndex }",
  );
}
