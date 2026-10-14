import {
  PUBLIC_KEY_SCHEMA_PATTERN,
  NONCE_SIGNATURE_TYPES,
  NONCE_SCALAR_SCHEMA_PATTERN,
} from "../tool-parameters.ts";
import {
  convertPublicKey as convertSecp256k1PublicKey,
  recoverReusedNonce,
} from "../utils/secp256k1/index.ts";
import {
  requiredString,
  closedObject,
  hexArgument,
  isUnset,
  oneOf,
  boundedArray,
} from "./arguments.ts";
import { type ToolResult, content } from "./results.ts";

const PUBLIC_KEY_HEX = new RegExp(PUBLIC_KEY_SCHEMA_PATTERN, "u");

/** Output from a SEC1 public key conversion. */
export interface ConvertedPublicKeyDetails {
  publicKey: string;
  compressed: boolean;
}

/**
 * Convert a public secp256k1 point between SEC1 encodings.
 * @param publicKeyValue - SEC1 hex input.
 * @param compressedValue - Optional output compression flag.
 * @returns {ToolResult<ConvertedPublicKeyDetails>} Converted public key and output encoding.
 */
export function convertPublicKey(
  publicKeyValue: unknown,
  compressedValue?: unknown,
): ToolResult<ConvertedPublicKeyDetails> {
  const compressed = compressedValue === undefined ? true : compressedValue;
  if (typeof compressed !== "boolean") throw new TypeError("Compressed must be a boolean");
  const publicKey = convertSecp256k1PublicKey(requiredString(publicKeyValue, "Public key"), {
    compressed,
  });
  const details = { publicKey, compressed };
  return { content: content(JSON.stringify(details)), details };
}

/** What the nonce tool answers; the private key stays in the library. */
export interface RecoveredNonceDetails {
  type: (typeof NONCE_SIGNATURE_TYPES)[number];
  publicKey: string;
}

const NONCE_SCALAR = new RegExp(NONCE_SCALAR_SCHEMA_PATTERN, "u");

/**
 * Reads one signature of the nonce tool.
 * @param value - Raw item
 * @param position - Its place, for the error
 * @returns {{ r: string; s: string; z: string }} Its hex parts
 */
function nonceSignature(value: unknown, position: number): { r: string; s: string; z: string } {
  const item = closedObject(value, `signatures[${position}]`, ["r", "s", "z"]);
  const [r, s, z] = ["r", "s", "z"].map((key) =>
    hexArgument(item[key], `signatures[${position}].${key}`, NONCE_SCALAR, "1 to 64 hex digits"),
  );
  return { r: r ?? "", s: s ?? "", z: z ?? "" };
}

/**
 * Recover the key behind two signatures that share a nonce and answer with its public key only.
 * @param typeValue - ecdsa or schnorr, ecdsa when blank.
 * @param signaturesValue - Two signatures with r, s and z.
 * @param publicKeyValue - Optional key the result must match.
 * @returns {ToolResult<RecoveredNonceDetails>} The public key both signatures verify under.
 */
export function recoverSecp256k1Nonce(
  typeValue: unknown,
  signaturesValue: unknown,
  publicKeyValue?: unknown,
): ToolResult<RecoveredNonceDetails> {
  const type = isUnset(typeValue) ? "ecdsa" : oneOf(typeValue, "type", NONCE_SIGNATURE_TYPES);
  const [first, second] = boundedArray(signaturesValue, "signatures", 2, 2).map((item, position) =>
    nonceSignature(item, position),
  );
  const publicKey = isUnset(publicKeyValue)
    ? undefined
    : hexArgument(publicKeyValue, "Public key", PUBLIC_KEY_HEX, "SEC1 or x-only hex");
  const recovered = recoverReusedNonce(
    { type, ...(first ?? { r: "", s: "", z: "" }) },
    { type, ...(second ?? { r: "", s: "", z: "" }) },
    publicKey === undefined ? {} : { publicKey },
  );
  const lines = [
    `Recovered the private key of ${recovered.publicKey}: both signatures verify under it${publicKey === undefined ? "" : ", and it matches publicKey"}.`,
    "The key stays out of this answer; recoverReusedNonce from @agntn/keys/secp256k1 returns it with the nonce.",
  ];
  return {
    content: content(lines.join("\n")),
    details: { type, publicKey: recovered.publicKey },
  };
}
