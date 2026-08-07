import { signMessage, verifyMessage } from "./signing.ts";
import type { SigningOptions } from "../types.ts";

/**
 * Signs a message using Ed25519 for Ed25519-based blockchains
 *
 * @param message - The message to sign
 * @param keyPrivate - The private key
 * @param options - Optional parameters
 * @returns The signature as a hex string
 */
export function ed25519SignMessage(
  message: string | Uint8Array,
  keyPrivate: string,
  options: SigningOptions = {},
): string {
  // Ed25519 signatures are simpler than EVM signatures because they don't use a preamble
  // We just directly sign the message with the Ed25519 curve
  return signMessage(message, keyPrivate, {
    curve: "ed25519",
    ...options,
  });
}

/**
 * Verifies a signature for Ed25519-based blockchains
 *
 * @param message - The original message
 * @param signature - The signature to verify
 * @param keyPublic - The public key
 * @param options - Optional parameters
 * @returns Whether the signature is valid
 */
export function ed25519VerifyMessage(
  message: string | Uint8Array,
  signature: string,
  keyPublic: string,
  options: SigningOptions = {},
): boolean {
  // Just directly verify the signature with the Ed25519 curve
  return verifyMessage(message, signature, keyPublic, {
    curve: "ed25519",
    ...options,
  });
}
