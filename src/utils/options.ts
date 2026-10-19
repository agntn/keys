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
 * Reads derivation path options, refusing the account number a JS call still written as
 * `getDerivationPath(account, change, addressIndex)` passes, which would quietly give account 0.
 * @param options - The caller's options
 * @returns {DerivationPathOptions} The options, an empty object when left out
 * @throws {TypeError} When the options are neither left out nor an object
 */
export function readPathOptions(options: unknown): DerivationPathOptions {
  if (options === undefined) return {};
  if (typeof options === "object" && options !== null && !Array.isArray(options)) return options;
  throw new TypeError(
    "Derivation paths take their levels in an options object: { account, change, addressIndex }",
  );
}
