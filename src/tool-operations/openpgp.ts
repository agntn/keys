import { MAX_OPENPGP_LENGTH } from "../tool-parameters.ts";
import {
  type OpenPGPKey,
  type OpenPGPKeyInspection,
  type OpenPGPMessageInspection,
  type OpenPGPVerification,
  inspect,
  verify,
} from "../utils/openpgp/index.ts";
import { optionalName, requiredString } from "./arguments.ts";
import { type ToolResult, content } from "./results.ts";

/** A key block or a signed message, the signed text renamed so AI SDK keeps its own `text`. */
export type OpenPGPInspectionDetails =
  | OpenPGPKeyInspection
  | (Omit<OpenPGPMessageInspection, "text"> & { signedText: string });

/** The verdict, the signed text renamed for the same reason. */
export type OpenPGPVerificationDetails = Omit<OpenPGPVerification, "text"> & { signedText: string };

/** What OpenPGP verification takes past the message, as the host passed it. */
export interface OpenPGPVerifyArguments {
  readonly publicKey?: unknown;
  readonly fingerprint?: unknown;
}

/** Said after every verdict: a valid signature names a key, not a person. */
const TRUST_LINE =
  "Trust: only the math and the key's own bindings were checked. Who holds the key is what the fingerprint is for";

/**
 * Writes one UTF-16 code unit as a JSON escape.
 * @param unit - Code unit
 * @returns {string} `\\u` and four hex digits
 */
function escapeUnit(unit: number): string {
  return `\\u${unit.toString(16).padStart(4, "0")}`;
}

/**
 * Escapes one character as JSON does, a surrogate pair for one past the BMP.
 * @param char - One code point
 * @returns {string} Its escape
 */
function escapeChar(char: string): string {
  const point = char.codePointAt(0) ?? 0;
  if (point <= 0xffff) return escapeUnit(point);
  const offset = point - 0x10000;
  return escapeUnit(0xd800 + (offset >> 10)) + escapeUnit(0xdc00 + (offset & 0x3ff));
}

/**
 * Quotes text on one line, escaping what JSON leaves raw: C1, U+2028, bidi controls.
 * @param text - User ID or signed text
 * @returns {string} A JSON string literal
 */
function quoted(text: string): string {
  return JSON.stringify(text).replaceAll(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, escapeChar);
}

/**
 * Reads an armored argument, refusing one past the cap.
 * @param value - Raw argument
 * @param name - Its name for the error
 * @returns {string} The text
 */
function armoredArgument(value: unknown, name: string): string {
  const text = requiredString(value, name);
  if (text.length > MAX_OPENPGP_LENGTH)
    throw new RangeError(`${name} must not exceed ${MAX_OPENPGP_LENGTH} characters`);
  return text;
}

/**
 * One line about a key, its facts in a fixed order.
 * @param label - `Primary key` or `Subkey`
 * @param key - The key
 * @returns {string} The line
 */
function keyLine(label: string, key: OpenPGPKey): string {
  const flags = key.flags === undefined ? "flags unknown" : key.flags.join(", ") || "no flags";
  const parts = [`v${key.version}`, key.algorithm, `created ${key.created}`, flags];
  if (key.expires !== undefined) parts.push(`expires ${key.expires}`);
  if (key.revoked !== undefined)
    parts.push(
      `revoked ${key.revoked.at}${key.revoked.reason === undefined ? "" : ` (${key.revoked.reason})`}`,
    );
  return `${label}: ${key.fingerprint} (${parts.join(", ")})`;
}

/**
 * Lines describing a key block, user IDs quoted.
 * @param inspection - The key block
 * @returns {string[]} Lines
 */
function keyLines(inspection: OpenPGPKeyInspection): string[] {
  return [
    keyLine("Primary key", inspection.primary),
    ...inspection.userIds.map((id) => `User ID: ${quoted(id)}`),
    ...(inspection.uncertifiedUserIds > 0
      ? [`Left out ${inspection.uncertifiedUserIds} user IDs the key never certified`]
      : []),
    ...inspection.subkeys.map(
      (subkey) => `${keyLine("Subkey", subkey)}${subkey.bound ? "" : ", not bound"}`,
    ),
  ];
}

/**
 * Lines describing a signed message, the text quoted on one line.
 * @param inspection - The message
 * @returns {string[]} Lines
 */
function messageLines(inspection: OpenPGPMessageInspection): string[] {
  return [
    `Signed text: ${quoted(inspection.text)}`,
    ...inspection.signatures.map(
      (signature) =>
        `Signature: v${signature.version} ${signature.algorithm} over ${signature.hash}, made ${signature.created} by ${signature.issuer ?? "an unnamed key"}`,
    ),
    ...inspection.warnings.map((warning) => `Warning: ${warning}`),
  ];
}

/**
 * Reads an OpenPGP public key block or cleartext signed message without verifying anything else.
 * @param armorValue - The armored block
 * @returns {ToolResult<OpenPGPInspectionDetails>} Keys and user IDs, or signed text and signers
 */
export function inspectOpenpgp(armorValue: unknown): ToolResult<OpenPGPInspectionDetails> {
  const inspection = inspect(armoredArgument(armorValue, "Armor"));
  if (inspection.kind === "public-key") {
    return { content: content(keyLines(inspection).join("\n")), details: inspection };
  }
  const { text, ...rest } = inspection;
  return {
    content: content(messageLines(inspection).join("\n")),
    details: { ...rest, signedText: text },
  };
}

/**
 * The first line of a verdict.
 * @param verdict - The verification
 * @returns {string} State, algorithm and hash, with the reason when not valid
 */
function verdictLine(verdict: OpenPGPVerification): string {
  const head = `Signature is ${verdict.state} (v${verdict.version} ${verdict.algorithm}, ${verdict.hash})`;
  return verdict.reason === undefined ? head : `${head}: ${verdict.reason}`;
}

/**
 * The identity line: what the expected fingerprint says about this key.
 * @param verdict - The verification
 * @returns {string} One line
 */
function identityLine(verdict: OpenPGPVerification): string {
  if (verdict.identity === "match")
    return "Identity: match, the key has the fingerprint you expected";
  if (verdict.identity === "mismatch")
    return "Identity: mismatch, this is not the key you expected";
  return "Identity: unchecked, pass the fingerprint you trust to tie the key to someone";
}

/**
 * Verifies a cleartext signed message against a key block and an optional fingerprint.
 * @param messageValue - The signed message
 * @param options - Armored public key and expected fingerprint
 * @returns {ToolResult<OpenPGPVerificationDetails>} Verdict, identity, fingerprints and warnings
 */
export function verifyOpenpgp(
  messageValue: unknown,
  options: OpenPGPVerifyArguments,
): ToolResult<OpenPGPVerificationDetails> {
  const message = armoredArgument(messageValue, "Message");
  const publicKey = armoredArgument(options.publicKey, "Public key");
  const fingerprint = optionalName(options.fingerprint, "Fingerprint");
  const verdict = verify(message, {
    publicKey,
    ...(fingerprint === undefined ? {} : { fingerprint }),
  });
  const lines = [
    verdictLine(verdict),
    identityLine(verdict),
    `Primary key: ${verdict.primaryFingerprint}`,
    ...(verdict.signingFingerprint === undefined ||
    verdict.signingFingerprint === verdict.primaryFingerprint
      ? []
      : [`Signing subkey: ${verdict.signingFingerprint}`]),
    ...(verdict.signingFingerprint === undefined && verdict.issuer !== undefined
      ? [`Issuer: ${verdict.issuer}`]
      : []),
    `Signed: ${verdict.created}`,
    ...verdict.warnings.map((warning) => `Warning: ${warning}`),
    TRUST_LINE,
  ];
  const { text, ...rest } = verdict;
  return { content: content(lines.join("\n")), details: { ...rest, signedText: text } };
}
