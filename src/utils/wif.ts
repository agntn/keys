import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake256 } from "@noble/hashes/blake1.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { equalBytes } from "@noble/curves/utils.js";
import { base58 } from "@scure/base";
import { decodeBase58Check, encodeBase58Check } from "./encoding.ts";

/** Chains in keys with native WIF support. */
export type WIFChain = "bitcoin" | "litecoin" | "dash" | "decred" | "dogecoin";

/** Expected chain and network; Bitcoin, Litecoin and Dash testnet WIFs are indistinguishable. */
export interface WIFNetworkOptions {
  readonly chain: WIFChain;
  readonly network?: "mainnet" | "testnet";
}

/** Decred accepts only compressed ECDSA keys in this API. */
export type WIFOptions = WIFNetworkOptions & { readonly compressed?: boolean };

/** Private key and effective wallet options, not proof of chain ownership. */
export interface DecodedWIF {
  readonly privateKey: string;
  readonly chain: WIFChain;
  readonly network: "mainnet" | "testnet";
  readonly compressed: boolean;
}

/**
 * Native WIF prefixes from Bitcoin Core, Litecoin Core, Dash Core v23.1.8, dcrd chaincfg and
 * Dogecoin Core v1.14.9.
 */
const PREFIXES = {
  bitcoin: { mainnet: new Uint8Array([0x80]), testnet: new Uint8Array([0xef]) },
  litecoin: { mainnet: new Uint8Array([0xb0]), testnet: new Uint8Array([0xef]) },
  dash: { mainnet: new Uint8Array([0xcc]), testnet: new Uint8Array([0xef]) },
  decred: { mainnet: new Uint8Array([0x22, 0xde]), testnet: new Uint8Array([0x23, 0x0e]) },
  dogecoin: { mainnet: new Uint8Array([0x9e]), testnet: new Uint8Array([0xf1]) },
};

/**
 * Resolve only supported chain/network pairs, without a fallback to Bitcoin.
 * @param options - Expected chain and network
 * @returns {object} Validated context and native prefix
 */
function resolveNetwork(options: WIFNetworkOptions) {
  const { chain, network = "mainnet" } = options;
  if (!Object.hasOwn(PREFIXES, chain)) {
    throw new Error("Unsupported WIF chain");
  }
  if (network !== "mainnet" && network !== "testnet") {
    throw new Error("Unsupported WIF network");
  }
  return { chain, network, prefix: PREFIXES[chain][network] };
}

/**
 * Parse hex without letting dependency errors expose private material.
 * @param privateKey - Hex private key
 * @returns {Uint8Array} Valid secp256k1 scalar
 */
function parsePrivateKey(privateKey: string): Uint8Array {
  if (
    typeof privateKey !== "string" ||
    privateKey.length !== 64 ||
    !/^[0-9a-fA-F]{64}$/.test(privateKey)
  ) {
    throw new Error("WIF private key must be 32 bytes of hex without a prefix");
  }
  const key = hexToBytes(privateKey);
  if (!secp256k1.utils.isValidSecretKey(key)) {
    throw new Error("Invalid WIF private key scalar");
  }
  return key;
}

/**
 * Verify Decred's single BLAKE-256 checksum, not its address checksum algorithm.
 * @param wif - Decred WIF string
 * @returns {Uint8Array} Network, scheme and private key bytes
 */
function decodeDecred(wif: string): Uint8Array {
  const bytes = base58.decode(wif);
  if (bytes.length !== 39) {
    throw new Error("Invalid WIF payload length");
  }
  const payload = bytes.slice(0, -4);
  if (!equalBytes(bytes.slice(-4), blake256(payload).slice(0, 4))) {
    throw new Error("Invalid WIF checksum");
  }
  return payload;
}

/**
 * Bound decoding work and keep dependency errors from exposing the WIF.
 * @param wif - WIF string
 * @param chain - Determines the checksum algorithm
 * @returns {Uint8Array} Payload with a verified checksum
 */
function readPayload(wif: string, chain: WIFChain): Uint8Array {
  if (typeof wif !== "string" || wif.length === 0 || wif.length > 54) {
    throw new Error("Invalid WIF length");
  }
  try {
    return chain === "decred" ? decodeDecred(wif) : decodeBase58Check(wif);
  } catch {
    throw new Error("Invalid WIF encoding or checksum");
  }
}

/**
 * Read the compression marker or require Decred's supported ECDSA scheme.
 * @param payload - Verified payload
 * @param chain - Expected chain
 * @returns {boolean} Whether the WIF represents a compressed public key
 */
function readCompression(payload: Uint8Array, chain: WIFChain): boolean {
  if (chain === "decred") {
    if (payload[2] !== 0) {
      throw new Error("Decred WIF supports ECDSA secp256k1 only");
    }
    return true;
  }
  if (payload.length !== 33 && payload.length !== 34) {
    throw new Error("Invalid WIF payload length");
  }
  const compressed = payload.length === 34;
  if (compressed && payload[33] !== 1) {
    throw new Error("Invalid WIF compression flag");
  }
  return compressed;
}

/**
 * Encode a private key for the selected chain, defaulting to mainnet and compressed keys.
 * @param privateKey - Exactly 32 bytes of hex without a prefix
 * @param options - Chain, network and compression flag
 * @returns {string} Native WIF, not encrypted
 */
export function encodeWIF(privateKey: string, options: WIFOptions): string {
  const { chain, prefix } = resolveNetwork(options);
  const { compressed = true } = options;
  if (typeof compressed !== "boolean") {
    throw new TypeError("WIF compressed must be a boolean");
  }
  const key = parsePrivateKey(privateKey);
  if (chain === "decred") {
    if (!compressed) {
      throw new Error("Decred WIF requires a compressed public key");
    }
    const payload = concatBytes(prefix, new Uint8Array([0]), key);
    return base58.encode(concatBytes(payload, blake256(payload).slice(0, 4)));
  }
  const payload = concatBytes(prefix, key, compressed ? new Uint8Array([1]) : new Uint8Array());
  return encodeBase58Check(payload);
}

/**
 * Decode WIF against an explicit chain and network instead of guessing from its prefix.
 * @param wif - Native WIF string
 * @param options - Expected chain and network, defaulting to mainnet
 * @returns {DecodedWIF} Hex private key and effective wallet options
 */
export function decodeWIF(wif: string, options: WIFNetworkOptions): DecodedWIF {
  const { chain, network, prefix } = resolveNetwork(options);
  const payload = readPayload(wif, chain);
  const compressed = readCompression(payload, chain);
  if (!equalBytes(payload.subarray(0, prefix.length), prefix)) {
    throw new Error("WIF does not match the expected chain/network");
  }
  const offset = chain === "decred" ? 3 : 1;
  const key = payload.slice(offset, offset + 32);
  if (!secp256k1.utils.isValidSecretKey(key)) {
    throw new Error("Invalid WIF private key scalar");
  }
  return { privateKey: bytesToHex(key), chain, network, compressed };
}
