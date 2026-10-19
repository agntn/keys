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

/**
 * Sign a message without retaining the private key or message in result details.
 * @param chainValue - Blockchain name.
 * @param messageValue - Message to sign.
 * @param privateKeyValue - Private key as hexadecimal text.
 * @param networkValue - Optional network name.
 * @param recoveredValue - Append the recovery byte as `v`, default false.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @param signingKeyValue - Monero key that signs, spend or view; spend when left out.
 * @param accountValue - Account of the Monero subaddress that signs.
 * @param addressIndexValue - Index of that subaddress within its account.
 * @returns {Promise<ToolResult<SignatureDetails>>} Generated signature.
 */
export async function signMessage(
  chainValue: unknown,
  messageValue: unknown,
  privateKeyValue: unknown,
  networkValue?: unknown,
  recoveredValue?: unknown,
  prefixValue?: unknown,
  signingKeyValue?: unknown,
  accountValue?: unknown,
  addressIndexValue?: unknown,
): Promise<ToolResult<SignatureDetails>> {
  if (recoveredValue !== undefined && typeof recoveredValue !== "boolean") {
    throw new TypeError("recovered must be a boolean");
  }
  const recovered = recoveredValue ?? false;
  const { blockchain } = await getBlockchain(chainValue, networkValue, undefined, prefixValue);
  const signingKey = moneroSigningKey(signingKeyValue, blockchain.name);
  const subaddress = subaddressIndices(blockchain.name, accountValue, addressIndexValue);
  const message = requiredString(messageValue, "Message");
  const privateKey = hexArgument(
    privateKeyValue,
    "Private key",
    PRIVATE_KEY_HEX,
    "64 hex characters",
  );
  const options = signingOptions(recovered, signingKey, subaddress);
  const signature =
    options === undefined
      ? blockchain.signMessage(message, privateKey)
      : blockchain.signMessage(message, privateKey, options);
  return {
    content: content(`Signature: ${signature}`),
    details: { chain: blockchain.name, network: blockchain.network, signature, recovered },
  };
}

/**
 * Only builds options when one is set, so every other chain keeps its current defaults.
 * @param recovered - Whether to append the recovery byte.
 * @param signingKey - Monero key that signs.
 * @param subaddress - Monero subaddress that signs.
 * @returns {SigningOptions | undefined} The options, undefined when none is set.
 */
function signingOptions(
  recovered: boolean,
  signingKey: MoneroSigningKey | undefined,
  subaddress: SubaddressIndices | undefined,
): SigningOptions | undefined {
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
 * @param message - Signed message.
 * @param signature - Base64 signature.
 * @returns {void} Nothing; it throws on unreadable input.
 */
function assertReadableSignature(
  blockchain: Readonly<AbstractBlockchain>,
  message: string,
  signature: string,
): void {
  try {
    blockchain.recoverMessageSigner(message, signature);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
  }
}

/**
 * Verify a signature against a message and public key.
 * @param chainValue - Blockchain name.
 * @param messageValue - Original message.
 * @param signatureValue - Signature as hexadecimal text.
 * @param publicKeyValue - Public key as hexadecimal text.
 * @param networkValue - Optional network name.
 * @param prefixValue - Optional bech32 prefix on cosmos, SS58 number on polkadot.
 * @returns {Promise<ToolResult<SignatureVerificationDetails>>} Signature verdict.
 */
export async function verifyMessage(
  chainValue: unknown,
  messageValue: unknown,
  signatureValue: unknown,
  publicKeyValue: unknown,
  networkValue?: unknown,
  prefixValue?: unknown,
): Promise<ToolResult<SignatureVerificationDetails>> {
  const { blockchain } = await getBlockchain(chainValue, networkValue, undefined, prefixValue);
  const message = requiredString(messageValue, "Message");
  const signatureText = requiredString(signatureValue, "Signature");
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
      : hexArgument(
          signatureText,
          "Signature",
          DER_SIGNATURE.test(signatureText) ? DER_SIGNATURE : SIGNATURE_HEX,
          "64 or 65 bytes of hex, or DER on xrpl,",
        );
  const publicKey = chainPublicKey(publicKeyValue, blockchain.name);
  if (core) assertReadableSignature(blockchain, message, signature);
  const valid = blockchain.verifyMessage(message, signature, publicKey);
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
 * @param matches - Whether it belongs to the recovered key.
 * @param matchedType - Address type it matched, if the chain has types.
 * @returns {string[]} Zero or one line.
 */
function comparisonLines(
  expected: string | undefined,
  matches: boolean,
  matchedType: string | undefined,
): string[] {
  if (expected === undefined) return [];
  if (!matches) return ["Given address: no match"];
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
 * @param messageValue - Message as the caller passed it.
 * @param typedDataValue - EIP-712 JSON as the caller passed it.
 * @param digestValue - Digest hex as the caller passed it.
 * @returns {SignedInput} The message, or the digest to recover against.
 */
function signedInput(
  messageValue: unknown,
  typedDataValue: unknown,
  digestValue: unknown,
): SignedInput {
  const given = [messageValue, typedDataValue, digestValue].filter((value) => value !== undefined);
  if (given.length !== 1) {
    throw new TypeError("Pass exactly one of message, typedData and digest");
  }
  if (messageValue !== undefined) {
    return { signed: "message", message: requiredString(messageValue, "Message") };
  }
  if (digestValue !== undefined) {
    const digest = hexArgument(digestValue, "Digest", DIGEST_HEX, "32 bytes of hex");
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
 * @param signer - The recovered key and header type.
 * @param expected - Address the caller passed.
 * @returns {{ matches: boolean; matchedType?: string }} The verdict and the matched type.
 */
function matchSigner(
  blockchain: Readonly<AbstractBlockchain>,
  signer: Readonly<MessageSigner>,
  expected: string,
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
    ...comparisonLines(expected, details.matches === true, details.matchedType),
  ];
}

/**
 * Recover the signer of a message, EIP-712 typed data or a digest, and say whether it holds a
 * given address. The Bitcoin family and Decred read Core's base64, EVM chains and TRON `r||s||v`.
 * @param chainValue - Blockchain name.
 * @param messageValue - Message that was signed, or undefined beside typed data or a digest.
 * @param signatureValue - Base64 of the header byte, then `r` and `s`, or `r||s||v` hex.
 * @param addressValue - Optional address to compare with.
 * @param networkValue - Optional network name.
 * @param typedDataValue - EIP-712 typed data as JSON, in place of the message.
 * @param digestValue - 32-byte digest as hex, in place of the message.
 * @returns {Promise<ToolResult<MessageSignerDetails>>} The signer and the comparison.
 */
export async function recoverMessageSigner(
  chainValue: unknown,
  messageValue: unknown,
  signatureValue: unknown,
  addressValue?: unknown,
  networkValue?: unknown,
  typedDataValue?: unknown,
  digestValue?: unknown,
): Promise<ToolResult<MessageSignerDetails>> {
  const { blockchain } = await getBlockchain(chainValue, networkValue);
  const input = signedInput(messageValue, typedDataValue, digestValue);
  const signature = requiredString(signatureValue, "Signature");
  if (!RECOVERABLE_SIGNATURE.test(signature)) {
    throw new TypeError(
      "Signature must be 65 bytes: r||s||v as 130 hex characters without 0x, or signmessage's base64",
    );
  }
  const expected = expectedAddress(addressValue);
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
    ...(expected === undefined ? {} : matchSigner(blockchain, signer, expected)),
  };
  return { content: content(signerLines(details, expected).join("\n")), details };
}
