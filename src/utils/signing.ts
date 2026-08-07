import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { SigningOptions } from "../types.ts";

export type { SigningOptions } from "../types.ts";

/**
 * Signs a message using the appropriate elliptic curve
 *
 * @param message - The message to sign as a string or Uint8Array
 * @param keyPrivate - The private key as a hex string
 * @param options - Options for signature generation including curve type
 * @returns The signature as a hex string
 */
export function signMessage(
  message: string | Uint8Array,
  keyPrivate: string,
  options: SigningOptions = {},
): string {
  // Default to secp256k1 if not specified
  const curve = options.curve || "secp256k1";

  // Convert message to Uint8Array if it's a string
  let messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

  // Convert private key from hex string to Uint8Array
  const keyPrivateBytes = hexToBytes(keyPrivate);

  // Different handling based on curve type
  if (curve === "secp256k1") {
    // For secp256k1, we typically hash the message first with SHA-256
    // Unless options.hash is explicitly set to false
    if (options.hash !== false) {
      messageBytes = sha256(messageBytes);
    }

    // In @noble/curves v2, sign() returns Uint8Array directly (compact format)
    const signature = secp256k1.sign(messageBytes, keyPrivateBytes);
    return bytesToHex(signature);
  } else if (curve === "ed25519") {
    // Ed25519 doesn't typically prehash the message
    const signature = ed25519.sign(messageBytes, keyPrivateBytes);
    return bytesToHex(signature);
  }

  throw new Error(`Unsupported curve: ${curve}`);
}

/**
 * Verifies a signature using the appropriate elliptic curve
 *
 * @param message - The original message as a string or Uint8Array
 * @param signature - The signature as a hex string
 * @param keyPublic - The public key as a hex string
 * @param options - Options for signature verification including curve type
 * @returns True if the signature is valid, false otherwise
 */
export function verifyMessage(
  message: string | Uint8Array,
  signature: string,
  keyPublic: string,
  options: SigningOptions = {},
): boolean {
  // Default to secp256k1 if not specified
  const curve = options.curve || "secp256k1";

  // Convert message to Uint8Array if it's a string
  let messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

  // Different handling based on curve type
  if (curve === "secp256k1") {
    // For secp256k1, we typically hash the message first with SHA-256
    // Unless options.hash is explicitly set to false
    if (options.hash !== false) {
      messageBytes = sha256(messageBytes);
    }

    try {
      const keyPublicBytes = hexToBytes(keyPublic);
      // In @noble/curves v2, verify() accepts Uint8Array signature directly
      const signatureBytes = hexToBytes(signature);
      return secp256k1.verify(signatureBytes, messageBytes, keyPublicBytes);
    } catch {
      return false;
    }
  } else if (curve === "ed25519") {
    // Ed25519 doesn't typically prehash the message
    try {
      const keyPublicBytes = hexToBytes(keyPublic);
      return ed25519.verify(hexToBytes(signature), messageBytes, keyPublicBytes);
    } catch {
      return false;
    }
  }

  throw new Error(`Unsupported curve: ${curve}`);
}
