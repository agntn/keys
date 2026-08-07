import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { AbstractBlockchain } from "../blockchain.ts";
import { generateKeyPublic as getSecp256k1KeyPublic } from "./secp256k1.ts";
import { signMessage, verifyMessage } from "./signing.ts";
import type { KeyOptions, SigningOptions } from "../types.ts";

/**
 * Generate an EVM compatible address from a public key
 * The address is the last 20 bytes of the Keccak-256 hash of the public key
 *
 * @param keyPublic - The public key as a hex string
 * @returns The EVM address (0x-prefixed with EIP-55 checksum)
 */
export function generateAddress(keyPublic: string): string {
  // Convert public key to bytes
  const keyPublicBytes = hexToBytes(keyPublic);

  // For EVM addresses, we need to:
  // 1. Convert to uncompressed format if compressed
  // 2. Remove the first byte (0x04) from uncompressed key
  // 3. Hash with keccak-256
  // 4. Take the last 20 bytes
  let publicKeyForHashing: Uint8Array;

  if (keyPublicBytes.length === 33) {
    // Compressed format (33 bytes starting with 02 or 03)
    // We need to decompress it manually without trying to regenerate from private key
    const point = secp256k1.Point.fromBytes(keyPublicBytes);
    const uncompressedKey = point.toBytes(false); // false = uncompressed
    publicKeyForHashing = uncompressedKey.slice(1); // Remove the 0x04 prefix
  } else if (keyPublicBytes.length === 65) {
    // Already uncompressed (65 bytes starting with 04)
    publicKeyForHashing = keyPublicBytes.slice(1); // Remove the 0x04 prefix
  } else {
    throw new Error(`Invalid public key length: ${keyPublicBytes.length} bytes`);
  }

  // Apply Keccak-256 hash to the public key
  const keccakHash = keccak_256(publicKeyForHashing);

  // Take the last 20 bytes of the hash result
  const addressBytes = keccakHash.slice(-20);

  // Convert to hex string
  const addressHex = bytesToHex(addressBytes);

  // Apply EIP-55 checksum and return with 0x prefix
  return "0x" + toChecksumAddress(addressHex);
}

/**
 * Calculate the EIP-55 checksummed version of an EVM address
 *
 * @param address - The address to checksum (without 0x prefix)
 * @returns The checksummed address (without 0x prefix)
 */
export function toChecksumAddress(address: string): string {
  // Convert address to lowercase
  const lowercaseAddress = address.toLowerCase();

  // Hash the lowercase address (keccak_256 requires Uint8Array in v2)
  const addressHash = bytesToHex(keccak_256(new TextEncoder().encode(lowercaseAddress)));

  // Apply checksum rules - using array for better performance
  const result = Array.from({ length: lowercaseAddress.length });

  // Use for...of with entries to get both index and character
  for (const [i, char] of [...lowercaseAddress].entries()) {
    const hashChar = addressHash[i];
    if (hashChar === undefined) {
      throw new Error(`Invalid hash character at index ${i}`);
    }

    // If the ith character in the hash is 8 or higher, uppercase the ith character in the address
    result[i] = Number.parseInt(hashChar, 16) >= 8 ? char.toUpperCase() : char;
  }

  return result.join("");
}

/**
 * Validate an EVM address including EIP-55 checksum if mixed case
 *
 * @param address - The address to validate
 * @returns Whether the address is valid
 */
export function validateAddress(address: string): boolean {
  if (!address.startsWith("0x")) {
    return false;
  }

  // EVM addresses should be 42 characters (0x + 40 hex chars)
  if (address.length !== 42) {
    return false;
  }

  // Check if the address contains only valid hex characters
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    return false;
  }

  // Remove the 0x prefix
  const addressWithoutPrefix = address.slice(2);

  // If the address is all lowercase or all uppercase, it's considered valid
  // This is for backward compatibility with pre-EIP-55 addresses
  if (
    addressWithoutPrefix === addressWithoutPrefix.toLowerCase() ||
    addressWithoutPrefix === addressWithoutPrefix.toUpperCase()
  ) {
    return true;
  }

  // If mixed case, validate EIP-55 checksum
  return toChecksumAddress(addressWithoutPrefix) === addressWithoutPrefix;
}

/**
 * Hashes a message with EVM preamble using keccak256
 * Standard format: "\x19Ethereum Signed Message:\n" + length + message
 *
 * @param message - The message to hash
 * @returns The keccak256 hash of the prefixed message
 */
function hashWithPreamble(message: string | Uint8Array): Uint8Array {
  const preamble = "\u0019Ethereum Signed Message:\n";
  const messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  const preambleBytes = new TextEncoder().encode(preamble + messageBytes.length.toString());
  const fullMessage = new Uint8Array(preambleBytes.length + messageBytes.length);
  fullMessage.set(preambleBytes);
  fullMessage.set(messageBytes, preambleBytes.length);
  return keccak_256(fullMessage);
}

/**
 * Signs a message using secp256k1 for EVM chains
 * For Ethereum, generally uses the keccak256 hash and a specific preamble
 *
 * @param message - The message to sign
 * @param keyPrivate - The private key
 * @param options - Optional parameters
 * @returns The signature as a hex string
 */
export function evmSignMessage(
  message: string | Uint8Array,
  keyPrivate: string,
  options: SigningOptions = {},
): string {
  const hash = hashWithPreamble(message);

  return signMessage(hash, keyPrivate, {
    curve: "secp256k1",
    hash: false,
    ...options,
  });
}

/**
 * Verifies a message signature for EVM chains
 *
 * @param message - The original message
 * @param signature - The signature to verify
 * @param keyPublic - The public key
 * @param options - Optional parameters
 * @returns Whether the signature is valid
 */
export function evmVerifyMessage(
  message: string | Uint8Array,
  signature: string,
  keyPublic: string,
  options: SigningOptions = {},
): boolean {
  const hash = hashWithPreamble(message);

  try {
    return verifyMessage(hash, signature, keyPublic, {
      curve: "secp256k1",
      hash: false,
      ...options,
    });
  } catch {
    return false;
  }
}

/**
 * Shared implementation for EVM-compatible blockchains.
 */
export abstract class AbstractEVMBlockchain extends AbstractBlockchain {
  override readonly curve = "secp256k1";

  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    return getSecp256k1KeyPublic(keyPrivate, options);
  }

  override getAddress(keyPublic: string): string {
    return generateAddress(keyPublic);
  }

  override validateAddress(address: string): boolean {
    return validateAddress(address);
  }

  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: SigningOptions,
  ): string {
    return evmSignMessage(message, keyPrivate, options);
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: SigningOptions,
  ): boolean {
    return evmVerifyMessage(message, signature, keyPublic, options);
  }
}
