import { keccak256 } from "@agntn/hashes";
import { decodePublicPoint } from "./secp256k1/decode.ts";

/* EVM addresses apart from the chain classes, so a module that needs only an address skips them. */

/**
 * Generate an EVM compatible address from a public key
 * The address is the last 20 bytes of the Keccak-256 hash of the public key
 *
 * @param keyPublic - The public key as a hex string
 * @returns {string} The EVM address (0x-prefixed with EIP-55 checksum)
 */
export function generateAddress(keyPublic: string): string {
  const publicKeyForHashing = decodePublicPoint(keyPublic).toBytes(false).slice(1);

  // Apply Keccak-256 hash to the public key
  const keccakHash = keccak256(publicKeyForHashing);

  // Take the last 20 bytes of the hash result
  const addressBytes = keccakHash.slice(-20);

  // Convert to hex string
  const addressHex = addressBytes.toHex();

  // Apply EIP-55 checksum and return with 0x prefix
  return "0x" + toChecksumAddress(addressHex);
}

/**
 * Calculate the EIP-55 checksummed version of an EVM address.
 * The input is ASCII hex, so the per-character split cannot hit surrogate pairs.
 *
 * @param address - The address to checksum (without 0x prefix)
 * @returns {string} The checksummed address (without 0x prefix)
 */
export function toChecksumAddress(address: string): string {
  // Convert address to lowercase
  const lowercaseAddress = address.toLowerCase();

  // Hash the lowercase address (keccak_256 requires Uint8Array in v2)
  const addressHash = keccak256(new TextEncoder().encode(lowercaseAddress)).toHex();

  // Apply checksum rules - using array for better performance
  const result = Array.from({ length: lowercaseAddress.length });

  // Use for...of with entries to get both index and character
  for (const [i, char] of lowercaseAddress.split("").entries()) {
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
 * @returns {boolean} Whether the address is valid
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
