import type { AbstractBlockchain } from "../blockchain.ts";
import {
  SIGNATURE_SCHEMA_PATTERN,
  DER_SIGNATURE_SCHEMA_PATTERN,
  CORE_SIGNATURE_SCHEMA_PATTERN,
  MONERO_SIGNATURE_SCHEMA_PATTERN,
  RECOVERABLE_SIGNATURE_SCHEMA_PATTERN,
  DIGEST_SCHEMA_PATTERN,
  MONERO_SIGNING_KEYS,
  MAX_ADDRESS_LENGTH,
  MAX_TYPED_DATA_LENGTH,
} from "../tool-parameters.ts";
import type { MoneroSigningKey, MessageSigner, SigningOptions } from "../types.ts";
import { type TypedData, hashTypedData } from "../utils/eip712.ts";
import { sameAddress } from "./address.ts";
import {
  requiredString,
  hexArgument,
  PRIVATE_KEY_HEX,
  optionalName,
  chainPublicKey,
  type SubaddressArguments,
  type SubaddressIndices,
  subaddressIndices,
} from "./arguments.ts";
import { getBlockchain } from "./blockchain.ts";
import { type ToolResult, content } from "./results.ts";

/** Signature generated without retaining the private key or message. */
export interface SignatureDetails {
  chain: string;
  network: string;
  signature: string;
  /** True for the recoverable form: `r||s||v` hex on EVM and TRON, base64 on the Core family. */
  recovered: boolean;
}

/** Signature verification result. */
export interface SignatureVerificationDetails {
  chain: string;
  network: string;
  valid: boolean;
}

/** Recovered signer, compared with an address when one was given. */
export interface MessageSignerDetails {
  chain: string;
  network: string;
  /** What the signature covers. */
  signed: "message" | "typedData" | "digest";
  /** EIP-712 digest the typed data hashed to; only for `typedData`. */
  digest?: string;
  publicKey: string;
  /** Address type the Core signature header names; absent on EVM chains and TRON. */
  addressType?: string;
  /** Address of that type for the recovered key. */
  address: string;
  /** Whether the given address belongs to the recovered key; absent without an address. */
  matches?: boolean;
  /** Address type the given address matched, SegWit included under a P2PKH header. */
  matchedType?: string;
}

const SIGNATURE_HEX = new RegExp(SIGNATURE_SCHEMA_PATTERN, "u");

const DER_SIGNATURE = new RegExp(DER_SIGNATURE_SCHEMA_PATTERN, "u");

const CORE_SIGNATURE = new RegExp(CORE_SIGNATURE_SCHEMA_PATTERN, "u");

const MONERO_SIGNATURE = new RegExp(MONERO_SIGNATURE_SCHEMA_PATTERN, "u");

const RECOVERABLE_SIGNATURE = new RegExp(RECOVERABLE_SIGNATURE_SCHEMA_PATTERN, "u");

const DIGEST_HEX = new RegExp(DIGEST_SCHEMA_PATTERN, "u");

/** Signing tool arguments besides the chain, raw until the executor checks them. */
export interface SignMessageArguments extends SubaddressArguments {
  readonly message?: unknown;
  /** Private key as hexadecimal text. */
  readonly privateKey?: unknown;
  readonly network?: unknown;
  /** Append the recovery byte as `v`, default false. */
  readonly recovered?: unknown;
  readonly prefix?: unknown;
  /** Monero key that signs, spend or view; spend when left out. */
  readonly signingKey?: unknown;
}

/**
 * Sign a message without retaining the private key or message in result details.
 * @param chainValue - Blockchain name.
 * @param args - Message, key, recovery flag and the Monero key or subaddress that signs.
 * @returns {Promise<ToolResult<SignatureDetails>>} Generated signature.
 */
export async function signMessage(
  chainValue: unknown,
  args: SignMessageArguments,
): Promise<ToolResult<SignatureDetails>> {
  const recoveredValue = args.recovered;
  if (recoveredValue !== undefined && typeof recoveredValue !== "boolean") {
    throw new TypeError("recovered must be a boolean");
  }
  const recovered = recoveredValue ?? false;
  const { blockchain } = await getBlockchain(chainValue, {
    network: args.network,
    prefix: args.prefix,
  });
  const signingKey = moneroSigningKey(args.signingKey, blockchain.name);
  const subaddress = subaddressIndices(blockchain.name, args);
  const message = requiredString(args.message, "Message");
  const privateKey = hexArgument(args.privateKey, {
    name: "Private key",
    pattern: PRIVATE_KEY_HEX,
    shape: "64 hex characters",
  });
  const signature = blockchain.signMessage(message, {
    privateKey,
    ...signingOptions({ recovered, signingKey, subaddress }),
  });
  return {
    content: content(`Signature: ${signature}`),
    details: { chain: blockchain.name, network: blockchain.network, signature, recovered },
  };
}

/**
 * Only builds options when one is set, so every other chain keeps its current defaults.
 * @param signing - Recovery byte flag, and the Monero key and subaddress that sign.
 * @param signing.recovered - Whether to append the recovery byte.
 * @param signing.signingKey - Monero key that signs.
 * @param signing.subaddress - Monero subaddress that signs.
 * @returns {SigningOptions | undefined} The options, undefined when none is set.
 */
function signingOptions({
  recovered,
  signingKey,
  subaddress,
}: {
  readonly recovered: boolean;
  readonly signingKey: MoneroSigningKey | undefined;
  readonly subaddress: SubaddressIndices | undefined;
}): SigningOptions | undefined {
  if (!recovered && signingKey === undefined && subaddress === undefined) return undefined;
  return { recovered, signingKey, account: subaddress?.account, addressIndex: subaddress?.index };
}

/**
 * Read the Monero key a signature should come from, refused on every other chain.
 * @param value - `spend`, `view`, or blank and missing for the default.
 * @param chain - Chain the message is signed on.
 * @returns {MoneroSigningKey | undefined} The key, or undefined for the chain's default.
 */
function moneroSigningKey(value: unknown, chain: string): MoneroSigningKey | undefined {
  const name = optionalName(value, "signingKey");
  if (name === undefined) return undefined;
  if (chain !== "monero") {
    throw new TypeError(`signingKey picks a Monero key; ${chain} signs with its one key, omit it`);
  }
  const key = MONERO_SIGNING_KEYS.find((candidate) => candidate === name);
  if (key === undefined) {
    throw new RangeError(`signingKey must be spend or view, not ${JSON.stringify(name)}`);
  }
  return key;
}

/**
 * Refuse a base64 signature the chain never writes or whose header is out of range, so neither
 * reads as invalid. One that recovers no key stays a verdict, as in Core.
 * @param blockchain - Chain the signature is checked on.
 * @param signed - Signed message and its base64 signature.
 * @param signed.message - Signed message.
 * @param signed.signature - Base64 signature.
 * @returns {void} Nothing; it throws on unreadable input.
 */
function assertReadableSignature(
  blockchain: Readonly<AbstractBlockchain>,
  { message, signature }: { readonly message: string; readonly signature: string },
): void {
  try {
    blockchain.recoverMessageSigner(message, signature);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
  }
}

/** Verification tool arguments besides the chain, raw until the executor checks them. */
export interface VerifyMessageArguments {
  /** Original message. */
  readonly message?: unknown;
  /** Signature as hexadecimal text. */
  readonly signature?: unknown;
  /** Public key as hexadecimal text. */
  readonly publicKey?: unknown;
  readonly network?: unknown;
  readonly prefix?: unknown;
}

/**
 * Verify a signature against a message and public key.
 * @param chainValue - Blockchain name.
 * @param args - Message, signature and public key, with the chain's network and prefix.
 * @returns {Promise<ToolResult<SignatureVerificationDetails>>} Signature verdict.
 */
export async function verifyMessage(
  chainValue: unknown,
  args: VerifyMessageArguments,
): Promise<ToolResult<SignatureVerificationDetails>> {
  const { blockchain } = await getBlockchain(chainValue, {
    network: args.network,
    prefix: args.prefix,
  });
  const message = requiredString(args.message, "Message");
  const signatureText = requiredString(args.signature, "Signature");
  const core = CORE_SIGNATURE.test(signatureText);
  const monero = MONERO_SIGNATURE.test(signatureText);
  if (monero !== (blockchain.name === "monero")) {
    throw new TypeError(
      monero
        ? `SigV2 and SigV1 are Monero signatures. Give ${blockchain.name} its own signature`
        : "A Monero signature is SigV2 or SigV1 and 88 characters of base58, as its wallets print it",
    );
  }
  const signature =
    core || monero
      ? signatureText
      : hexArgument(signatureText, {
          name: "Signature",
          pattern: DER_SIGNATURE.test(signatureText) ? DER_SIGNATURE : SIGNATURE_HEX,
          shape: "64 or 65 bytes of hex, or DER on xrpl,",
        });
  const publicKey = chainPublicKey(args.publicKey, blockchain.name);
  if (core) assertReadableSignature(blockchain, { message, signature });
  const valid = blockchain.verifyMessage(message, { signature, publicKey });
  return {
    content: content(valid ? "Signature is valid" : "Signature is invalid"),
    details: { chain: blockchain.name, network: blockchain.network, valid },
  };
}

/**
 * Read the optional address a recovered signer is compared with.
 * @param value - Raw argument.
 * @returns {string | undefined} The address, or undefined when it was left out.
 */
function expectedAddress(value: unknown): string | undefined {
  const address = optionalName(value, "Address");
  if (address !== undefined && Array.from(address).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Address must not exceed ${MAX_ADDRESS_LENGTH} characters`);
  }
  return address;
}

/**
 * Address types a signer may hold, as Electrum checks them for the header.
 * @param signer - Key and header type from the signature.
 * @returns {(string | undefined)[]} Types to compare, `[undefined]` on EVM and TRON.
 */
function signerAddressTypes(signer: Readonly<MessageSigner>): (string | undefined)[] {
  if (signer.addressType !== "legacy" || signer.publicKey.length !== 66)
    return [signer.addressType];
  return ["legacy", "p2sh", "segwit"];
}

/**
 * Line that reports the comparison, empty when no address was given.
 * @param expected - Address the caller passed.
 * @param details - Whether it belongs to the recovered key, and the address type it matched.
 * @returns {string[]} Zero or one line.
 */
function comparisonLines(
  expected: string | undefined,
  details: Readonly<MessageSignerDetails>,
): string[] {
  const { matches, matchedType } = details;
  if (expected === undefined) return [];
  if (matches !== true) return ["Given address: no match"];
  return [
    matchedType === undefined ? "Given address: match" : `Given address: match (${matchedType})`,
  ];
}

/** What a recover call checks the signature against: the message, or a digest it hashed to. */
type SignedInput =
  | { signed: "message"; message: string }
  | { signed: "typedData" | "digest"; digest: Uint8Array };

/**
 * Tell typed data from any other JSON before hashing, so `hashTypedData` gets its own shape.
 * @param value - Parsed JSON.
 * @returns {boolean} True for an object with types, primaryType, domain and message.
 */
function isTypedData(value: unknown): value is TypedData {
  if (typeof value !== "object" || value === null) return false;
  const shape = (key: string): unknown =>
    Object.hasOwn(value, key) ? Reflect.get(value, key) : undefined;
  const isObject = (field: unknown): boolean =>
    typeof field === "object" && field !== null && !Array.isArray(field);
  return (
    isObject(shape("types")) &&
    typeof shape("primaryType") === "string" &&
    isObject(shape("domain")) &&
    isObject(shape("message"))
  );
}

/**
 * Take exactly one of the message, the typed data and the digest.
 * @param input - Message, EIP-712 JSON and digest hex, each as the caller passed it.
 * @returns {SignedInput} The message, or the digest to recover against.
 */
function signedInput(input: RecoverSignerArguments): SignedInput {
  const { message: messageValue, typedData: typedDataValue, digest: digestValue } = input;
  const given = [messageValue, typedDataValue, digestValue].filter((value) => value !== undefined);
  if (given.length !== 1) {
    throw new TypeError("Pass exactly one of message, typedData and digest");
  }
  if (messageValue !== undefined) {
    return { signed: "message", message: requiredString(messageValue, "Message") };
  }
  if (digestValue !== undefined) {
    const digest = hexArgument(digestValue, {
      name: "Digest",
      pattern: DIGEST_HEX,
      shape: "32 bytes of hex",
    });
    return { signed: "digest", digest: Uint8Array.fromHex(digest) };
  }
  const text = requiredString(typedDataValue, "Typed data");
  if (text.length > MAX_TYPED_DATA_LENGTH) {
    throw new RangeError(`Typed data must not exceed ${MAX_TYPED_DATA_LENGTH} characters`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError("Typed data must be JSON");
  }
  if (!isTypedData(parsed)) {
    throw new TypeError(
      "Typed data must be a JSON object with types, primaryType, domain and message",
    );
  }
  return { signed: "typedData", digest: hashTypedData(parsed) };
}

/**
 * Find the address type of the recovered key that the given address names.
 * @param blockchain - Chain the signature was recovered on.
 * @param comparison - The recovered key and header type, and the address the caller passed.
 * @param comparison.signer - The recovered key and header type.
 * @param comparison.expected - Address the caller passed.
 * @returns {{ matches: boolean; matchedType?: string }} The verdict and the matched type.
 */
function matchSigner(
  blockchain: Readonly<AbstractBlockchain>,
  { signer, expected }: { readonly signer: Readonly<MessageSigner>; readonly expected: string },
): { matches: boolean; matchedType?: string } {
  const types = signerAddressTypes(signer);
  const index = types.findIndex((type) => {
    try {
      return sameAddress(blockchain.getAddress(signer.publicKey, type), expected);
    } catch {
      return false;
    }
  });
  if (index === -1) return { matches: false };
  const matchedType = types[index];
  return matchedType === undefined ? { matches: true } : { matches: true, matchedType };
}

/**
 * Text lines of a recovered signer.
 * @param details - The signer and the comparison.
 * @param expected - Address the caller passed, if any.
 * @returns {string[]} One line per fact.
 */
function signerLines(
  details: Readonly<MessageSignerDetails>,
  expected: string | undefined,
): string[] {
  return [
    `Chain: ${details.chain} (${details.network})`,
    ...(details.digest === undefined ? [] : [`EIP-712 digest: ${details.digest}`]),
    `Public key: ${details.publicKey}`,
    details.addressType === undefined
      ? `Address: ${details.address}`
      : `Address: ${details.address} (${details.addressType})`,
    ...comparisonLines(expected, details),
  ];
}

/** Recovery tool arguments besides the chain, raw until the executor checks them. */
export interface RecoverSignerArguments {
  /** Message that was signed, or undefined beside typed data or a digest. */
  readonly message?: unknown;
  /** Base64 of the header byte, then `r` and `s`, or `r||s||v` hex. */
  readonly signature?: unknown;
  /** Address to compare with. */
  readonly address?: unknown;
  readonly network?: unknown;
  /** EIP-712 typed data as JSON, in place of the message. */
  readonly typedData?: unknown;
  /** 32-byte digest as hex, in place of the message. */
  readonly digest?: unknown;
}

/**
 * Recover the signer of a message, EIP-712 typed data or a digest, and say whether it holds a
 * given address. The Bitcoin family and Decred read Core's base64, EVM chains and TRON `r||s||v`.
 * @param chainValue - Blockchain name.
 * @param args - What was signed, the signature, an address to compare with and the network.
 * @returns {Promise<ToolResult<MessageSignerDetails>>} The signer and the comparison.
 */
export async function recoverMessageSigner(
  chainValue: unknown,
  args: RecoverSignerArguments,
): Promise<ToolResult<MessageSignerDetails>> {
  const { blockchain } = await getBlockchain(chainValue, { network: args.network });
  const input = signedInput(args);
  const signature = requiredString(args.signature, "Signature");
  if (!RECOVERABLE_SIGNATURE.test(signature)) {
    throw new TypeError(
      "Signature must be 65 bytes: r||s||v as 130 hex characters without 0x, or signmessage's base64",
    );
  }
  const expected = expectedAddress(args.address);
  if (expected !== undefined && !blockchain.validateAddress(expected)) {
    throw new TypeError(`Address is not a valid ${blockchain.name} ${blockchain.network} address`);
  }
  const signer =
    input.signed === "message"
      ? blockchain.recoverMessageSigner(input.message, signature)
      : blockchain.recoverDigestSigner(input.digest, signature);
  const details: MessageSignerDetails = {
    chain: blockchain.name,
    network: blockchain.network,
    signed: input.signed,
    ...(input.signed === "typedData" ? { digest: input.digest.toHex() } : {}),
    publicKey: signer.publicKey,
    ...(signer.addressType === undefined ? {} : { addressType: signer.addressType }),
    address: blockchain.getAddress(signer.publicKey, signer.addressType),
    ...(expected === undefined ? {} : matchSigner(blockchain, { signer, expected })),
  };
  return { content: content(signerLines(details, expected).join("\n")), details };
}
