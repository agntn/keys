import { AbstractBlockchain } from "../blockchain.ts";
import { generateKeyPublic } from "./ed25519.ts";
import { assertSignOptions, assertVerifyOptions } from "./options.ts";
import { signMessage, verifyMessage } from "./signing.ts";
import type { Curve, KeyOptions, SignMessageOptions, VerifyMessageOptions } from "../types.ts";

/**
 * Signs the message bytes with ed25519 as they are, no preamble and no prehash
 *
 * @param message - The message to sign
 * @param options - The private key
 * @returns {string} The signature as a hex string
 */
export function ed25519SignMessage(
  message: string | Uint8Array,
  options: SignMessageOptions<KeyOptions>,
): string {
  assertSignOptions(options);
  const { privateKey, ...keyOptions } = options;
  return signMessage(message, privateKey, {
    ...keyOptions,
    curve: "ed25519",
  });
}

/**
 * Verifies a signature for Ed25519-based blockchains
 *
 * @param message - The original message
 * @param options - The signature and the public key
 * @returns {boolean} Whether the signature is valid, false for malformed hex too
 */
export function ed25519VerifyMessage(
  message: string | Uint8Array,
  options: VerifyMessageOptions<KeyOptions>,
): boolean {
  assertVerifyOptions(options);
  const { signature, publicKey, ...keyOptions } = options;
  return verifyMessage(message, signature, publicKey, {
    ...keyOptions,
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
    options: SignMessageOptions<KeyOptions>,
  ): string {
    return ed25519SignMessage(message, options);
  }

  override verifyMessage(
    message: string | Uint8Array,
    options: VerifyMessageOptions<KeyOptions>,
  ): boolean {
    return ed25519VerifyMessage(message, options);
  }
}
