import {
  PUBLIC_KEY_SCHEMA_PATTERN,
  SEC1_PUBLIC_KEY_SCHEMA_PATTERN,
  NONCE_SIGNATURE_TYPES,
  NONCE_SCALAR_SCHEMA_PATTERN,
} from "../tool-parameters.ts";
import {
  convertPublicKey as convertSecp256k1PublicKey,
  recoverKnownNonce,
  recoverReusedNonce,
} from "../utils/secp256k1/index.ts";
import {
  requiredString,
  closedObject,
  hexArgument,
  type HexArgument,
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
  const item = closedObject(value, { name: `signatures[${position}]`, keys: ["r", "s", "z"] });
  const [r, s, z] = ["r", "s", "z"].map((key) =>
    hexArgument(item[key], {
      name: `signatures[${position}].${key}`,
      pattern: NONCE_SCALAR,
      shape: "1 to 64 hex digits",
    }),
  );
  return { r: r ?? "", s: s ?? "", z: z ?? "" };
}

/**
 * Reads the public key a nonce tool compares against.
 * @param value - Raw argument
 * @param form - The pattern and the form the error states
 * @returns {string | undefined} The key, undefined when left out
 */
function expectedPublicKey(
  value: unknown,
  form: Readonly<Omit<HexArgument, "name">>,
): string | undefined {
  return isUnset(value) ? undefined : hexArgument(value, { name: "Public key", ...form });
}

/** Options of the nonce tool, as the host passed them. */
export interface NonceArguments {
  readonly type?: unknown;
  readonly publicKey?: unknown;
}

/**
 * Recover the key behind two signatures that share a nonce and answer with its public key only.
 * @param signaturesValue - Two signatures with r, s and z.
 * @param options - `type`, ecdsa when blank, and the `publicKey` the result must match.
 * @returns {ToolResult<RecoveredNonceDetails>} The public key both signatures verify under.
 */
export function recoverSecp256k1Nonce(
  signaturesValue: unknown,
  options: NonceArguments,
): ToolResult<RecoveredNonceDetails> {
  const type = isUnset(options.type)
    ? "ecdsa"
    : oneOf(options.type, { name: "type", allowed: NONCE_SIGNATURE_TYPES });
  const signatures = boundedArray(signaturesValue, { name: "signatures", minimum: 2, maximum: 2 });
  const [first, second] = signatures.map((item, position) => nonceSignature(item, position));
  const publicKey = expectedPublicKey(options.publicKey, {
    pattern: PUBLIC_KEY_HEX,
    shape: "SEC1 or x-only hex",
  });
  const recovered = recoverReusedNonce(
    [
      { type, ...(first ?? { r: "", s: "", z: "" }) },
      { type, ...(second ?? { r: "", s: "", z: "" }) },
    ],
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

/** One key the known nonce tool names, without its private half. */
export interface KnownNonceCandidate {
  publicKey: string;
  flipped: boolean;
}

/** What the known nonce tool answers; the private keys stay in the library. */
export interface KnownNonceDetails {
  candidates: KnownNonceCandidate[];
  matched: boolean;
}

/** Arguments of the known nonce tool besides the signature, as the host passed them. */
export interface KnownNonceArguments {
  readonly nonce?: unknown;
  readonly publicKey?: unknown;
}

const SEC1_PUBLIC_KEY = new RegExp(SEC1_PUBLIC_KEY_SCHEMA_PATTERN, "u");

/**
 * Says which s the nonce signed for a candidate.
 * @param flipped - Whether s was negated after signing
 * @returns {string} The clause for the answer
 */
function reading(flipped: boolean): string {
  return flipped
    ? "the nonce signed n - s and s was flipped afterwards"
    : "the nonce signed s as given";
}

/**
 * Recover the key behind one ECDSA signature with a known nonce and answer with public keys only.
 * @param signatureValue - One signature with r, s and z.
 * @param options - The `nonce`, and the `publicKey` the result must match.
 * @returns {ToolResult<KnownNonceDetails>} The key or the two candidates, public halves only.
 */
export function recoverSecp256k1KnownNonce(
  signatureValue: unknown,
  options: KnownNonceArguments,
): ToolResult<KnownNonceDetails> {
  const item = closedObject(signatureValue, { name: "signature", keys: ["r", "s", "z"] });
  const [r, s, z, nonce] = [
    ["signature.r", item["r"]],
    ["signature.s", item["s"]],
    ["signature.z", item["z"]],
    ["nonce", options.nonce],
  ].map(([name, value]) =>
    hexArgument(value, { name: String(name), pattern: NONCE_SCALAR, shape: "1 to 64 hex digits" }),
  );
  const publicKey = expectedPublicKey(options.publicKey, {
    pattern: SEC1_PUBLIC_KEY,
    shape: "SEC1 hex",
  });
  const keys = recoverKnownNonce(
    { r: r ?? "", s: s ?? "", z: z ?? "" },
    { nonce: nonce ?? "", ...(publicKey === undefined ? {} : { publicKey }) },
  );
  const candidates = keys.map(({ publicKey: key, flipped }) => ({ publicKey: key, flipped }));
  const lines =
    publicKey === undefined
      ? [
          "The nonce gives r. The signature verifies under:",
          ...candidates.map((each) => `${each.publicKey} if ${reading(each.flipped)}`),
          "Pass publicKey to settle which one signed.",
        ]
      : candidates.map(
          (each) =>
            `Recovered the private key of ${each.publicKey}, which matches publicKey: ${reading(each.flipped)}.`,
        );
  lines.push(
    "The key stays out of this answer; recoverKnownNonce from @agntn/keys/secp256k1 returns it.",
  );
  return {
    content: content(lines.join("\n")),
    details: { candidates, matched: publicKey !== undefined },
  };
}
