import { MAX_ARWEAVE_KEY_LENGTH } from "../tool-parameters.ts";
import { type ArweaveJWK, getAddress, validateAddress } from "../utils/arweave/index.ts";
import { optionalName, requiredString } from "./arguments.ts";
import { type ToolResult, content } from "./results.ts";

/** The derived address, and the target verdict when one was given. */
export interface ArweaveAddressDetails {
  chain: "arweave";
  address: string;
  matches?: boolean;
}

/**
 * Keyfile JSON when it opens with a brace, else the modulus. Parse errors never quote the key.
 * @param key - Keyfile JSON or modulus `n`.
 * @returns {string | ArweaveJWK} What `getAddress` takes.
 */
function parseKey(key: string): string | ArweaveJWK {
  const text = key.trim();
  if (!text.startsWith("{")) return text;
  try {
    return JSON.parse(text) as ArweaveJWK;
  } catch {
    throw new TypeError("Arweave keyfile must be valid JSON");
  }
}

/**
 * Derives an Arweave address and checks it against a target, refusing one that could never match.
 * @param keyValue - Keyfile JSON or modulus `n`.
 * @param targetValue - Optional address to compare with.
 * @returns {ToolResult<ArweaveAddressDetails>} Address and verdict.
 */
export function getArweaveAddress(
  keyValue: unknown,
  targetValue?: unknown,
): ToolResult<ArweaveAddressDetails> {
  const key = requiredString(keyValue, "Key");
  if (key.length > MAX_ARWEAVE_KEY_LENGTH) {
    throw new RangeError(`Key must not exceed ${MAX_ARWEAVE_KEY_LENGTH} characters`);
  }
  const target = optionalName(targetValue, "Target");
  if (target !== undefined && !validateAddress(target)) {
    throw new TypeError(
      "Target must be a canonical Arweave address, 43 characters without a suffix",
    );
  }
  const address = getAddress(parseKey(key));
  if (target === undefined) {
    return { content: content(`Address: ${address}`), details: { chain: "arweave", address } };
  }
  const matches = address === target;
  return {
    content: content(`Address: ${address}\nTarget: ${matches ? "match" : "no match"}`),
    details: { chain: "arweave", address, matches },
  };
}
