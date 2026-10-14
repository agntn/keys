import { AbstractBlockchain } from "../blockchain.ts";
import { generateKeyPublic } from "./ed25519.ts";
import { signMessage, verifyMessage } from "./signing.ts";
import type { Curve, KeyOptions } from "../types.ts";

/**
 * Signs the message bytes with ed25519 as they are, no preamble and no prehash
 *
 * @param message - The message to sign
 * @param keyPrivate - The private key
 * @param options - Optional parameters
 * @returns {string} The signature as a hex string
 */
export function ed25519SignMessage(
  message: string | Uint8Array,
  keyPrivate: string,
  options: KeyOptions = {},
): string {
  return signMessage(message, keyPrivate, {
    ...options,
    curve: "ed25519",
  });
}

/**
 * Verifies a signature for Ed25519-based blockchains
 *
 * @param message - The original message
 * @param signature - The signature to verify
 * @param keyPublic - The public key
 * @param options - Optional parameters
 * @returns {boolean} Whether the signature is valid, false for malformed hex too
 */
export function ed25519VerifyMessage(
  message: string | Uint8Array,
  signature: string,
  keyPublic: string,
  options: KeyOptions = {},
): boolean {
  return verifyMessage(message, signature, keyPublic, {
    ...options,
    curve: "ed25519",
  });
}

/** Base for ed25519 chains. It signs the bytes raw, so a chain that wraps or hashes them first calls `super`. */
export abstract class AbstractEd25519Blockchain extends AbstractBlockchain {
  override readonly curve: Curve = "ed25519";

  override getKeyPublic(keyPrivate: string, _options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate);
  }

  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: KeyOptions,
  ): string {
    return ed25519SignMessage(message, keyPrivate, options);
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean {
    return ed25519VerifyMessage(message, signature, keyPublic, options);
  }
}
