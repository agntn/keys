import {
  BIP322_SIGNATURE_SCHEMA_PATTERN,
  BIP322_SIGNING_TYPES,
  MAX_ADDRESS_LENGTH,
  MAX_BIP322_SIGNATURE_LENGTH,
} from "../tool-parameters.ts";
import {
  type BIP322SigningType,
  type BIP322State,
  type BIP322Format,
  sign as signBIP322Message,
  type BIP322Verification,
  verify as verifyBIP322Message,
} from "../utils/bip322/index.ts";
import { requiredString, hexArgument, PRIVATE_KEY_HEX } from "./arguments.ts";
import { parseNetwork, getBlockchain } from "./blockchain.ts";
import { type ToolResult, content } from "./results.ts";

/** A BIP322 signature written for a key's address. */
export interface BIP322SignatureDetails {
  chain: "bitcoin";
  network: string;
  addressType: BIP322SigningType;
  address: string;
  format: "simple" | "full";
  signature: string;
}

/** The verdict on a BIP322 signature. */
export interface BIP322VerificationDetails {
  chain: "bitcoin";
  network: string;
  state: BIP322State;
  format: BIP322Format;
  addressType: string;
  reason?: string;
  publicKey?: string;
  lockTime?: number;
  sequence?: number;
}

const BIP322_SIGNATURE = new RegExp(BIP322_SIGNATURE_SCHEMA_PATTERN, "u");

/**
 * Read the address type a BIP322 signature is written for.
 * @param value - Raw argument.
 * @returns {BIP322SigningType} legacy, p2sh, segwit or taproot.
 */
function bip322SigningType(value: unknown): BIP322SigningType {
  const type = BIP322_SIGNING_TYPES.find((candidate) => candidate === value);
  if (type === undefined) {
    throw new RangeError(`Address type must be one of ${BIP322_SIGNING_TYPES.join(", ")}`);
  }
  return type;
}

/** What BIP322 signing takes past the message, as the host passed it. */
export interface Bip322SignArguments {
  readonly privateKey?: unknown;
  /** legacy, p2sh, segwit or taproot. */
  readonly addressType?: unknown;
  readonly network?: unknown;
  /** Legacy only: whether the address takes the compressed key. */
  readonly compressed?: unknown;
}

/**
 * Sign a message by BIP322 for the Bitcoin address of a private key.
 * @param messageValue - Message to sign.
 * @param options - Private key as 64 hex characters, address type, network and compression.
 * @returns {Promise<ToolResult<BIP322SignatureDetails>>} The signature and the address it proves.
 */
export async function signBip322(
  messageValue: unknown,
  options: Bip322SignArguments,
): Promise<ToolResult<BIP322SignatureDetails>> {
  const compressedValue = options.compressed;
  const message = requiredString(messageValue, "Message");
  const privateKey = hexArgument(options.privateKey, {
    name: "Private key",
    pattern: PRIVATE_KEY_HEX,
    shape: "64 hex characters",
  });
  const addressType = bip322SigningType(options.addressType);
  const network = parseNetwork(options.network);
  if (compressedValue !== undefined && typeof compressedValue !== "boolean") {
    throw new TypeError("compressed must be a boolean");
  }
  if (compressedValue !== undefined && addressType !== "legacy") {
    throw new TypeError(
      "compressed applies to legacy only; the other types take the compressed key",
    );
  }
  const signature = signBIP322Message(message, privateKey, addressType, {
    network,
    ...(compressedValue === undefined ? {} : { compressed: compressedValue }),
  });
  const { blockchain } = await getBlockchain("bitcoin", { network });
  const publicKey = blockchain.getKeyPublic(privateKey, { compressed: compressedValue !== false });
  const address = blockchain.getAddress(publicKey, addressType);
  const format = signature.startsWith("ful") ? "full" : "simple";
  return {
    content: content(`Signature: ${signature}\nAddress: ${address} (${addressType}, ${format})`),
    details: { chain: "bitcoin", network, addressType, address, format, signature },
  };
}

/**
 * First line of a BIP322 verdict, with the format and the address type.
 * @param verdict - The verification.
 * @returns {string} One line, the reason after a colon when the signature is not valid.
 */
function bip322VerdictLine(verdict: Readonly<BIP322Verification>): string {
  const head = `Signature is ${verdict.state} (${verdict.format}, ${verdict.addressType})`;
  return verdict.reason === undefined ? head : `${head}: ${verdict.reason}`;
}

/** What BIP322 verification takes past the address, as the host passed it. */
export interface Bip322VerifyArguments {
  readonly message?: unknown;
  /** Prefixed base64, unprefixed base64, or signmessage's base64. */
  readonly signature?: unknown;
  readonly network?: unknown;
}

/**
 * Verify a BIP322 signature of a message by a Bitcoin address.
 * @param addressValue - Address that signed.
 * @param options - Message that was signed, its signature and an optional network name.
 * @returns {ToolResult<BIP322VerificationDetails>} Valid, invalid or inconclusive, with the reason.
 */
export function verifyBip322(
  addressValue: unknown,
  options: Bip322VerifyArguments,
): ToolResult<BIP322VerificationDetails> {
  const address = requiredString(addressValue, "Address");
  if (Array.from(address).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Address must not exceed ${MAX_ADDRESS_LENGTH} characters`);
  }
  const message = requiredString(options.message, "Message");
  const signature = requiredString(options.signature, "Signature");
  if (signature.length > MAX_BIP322_SIGNATURE_LENGTH || !BIP322_SIGNATURE.test(signature)) {
    throw new TypeError(
      `Signature must be base64 of at most ${MAX_BIP322_SIGNATURE_LENGTH} characters, after an optional smp, ful or pof`,
    );
  }
  const network = parseNetwork(options.network);
  const verdict = verifyBIP322Message(address, message, signature, { network });
  const lines = [bip322VerdictLine(verdict)];
  if (verdict.publicKey !== undefined) lines.push(`Public key: ${verdict.publicKey}`);
  if ((verdict.lockTime ?? 0) > 0 || (verdict.sequence ?? 0) > 0) {
    lines.push(`Valid from lock time ${verdict.lockTime} and sequence ${verdict.sequence}`);
  }
  return {
    content: content(lines.join("\n")),
    details: { chain: "bitcoin", network, ...verdict },
  };
}
