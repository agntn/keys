import { HDKey } from "@scure/bip32";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { decodeExtendedKey, extendedKeyVersion } from "../extended-key.ts";
import { HARDENED_OFFSET } from "../hd-index.ts";
import { decodePublicPoint } from "../secp256k1/decode.ts";
import { decode as decodeWIF } from "../wif/index.ts";
import type { ScriptNetwork } from "../script/script.ts";

/** Where a key lands: any script, segwit v0 with compressed keys only, or Taproot. */
export type KeyContext = "legacy" | "segwit" | "taproot";

/** A key expression, read once and derived per index. */
export interface DescriptorKey {
  /** Whether the key ends in a `/*` step. */
  readonly ranged: boolean;
  /** The SEC1 key at an index, x-only in Taproot; the index matters only when ranged. */
  readonly at: (index: number) => Uint8Array;
}

/** Version bytes of the extended keys Core reads on each network. */
const EXTENDED_VERSIONS = {
  mainnet: { public: 0x0488b21e, private: 0x0488ade4 },
  testnet: { public: 0x043587cf, private: 0x04358394 },
} as const;

const ORIGIN = /^\[[0-9A-Fa-f]{8}(?:\/[0-9]+['h]?)*\]/u;
const STEP = /^([0-9]+)(['h]?)$/u;
const HEX = /^[0-9A-Fa-f]+$/u;

/** One derivation step after an extended key. */
interface Step {
  readonly index: number;
  readonly hardened: boolean;
}

/**
 * Reads a `NUM` or `NUMh` step, refusing an index of 2^31 or more.
 * @param text - The step
 * @returns {Step} Its index and whether it is hardened
 */
function readStep(text: string): Step {
  if (text.startsWith("<")) throw new TypeError("Multipath <a;b> steps are not supported");
  const match = STEP.exec(text);
  const index = Number(match?.[1] ?? Number.NaN);
  if (match === null || !(index < HARDENED_OFFSET)) {
    throw new RangeError(
      "Key has a derivation step that is not a number below 2^31, with an optional h",
    );
  }
  return { index, hardened: match[2] !== "" };
}

/**
 * Checks the key origin, whose steps must read like any other but change nothing.
 * @param text - Key expression
 * @returns {string} The expression without its origin
 */
function withoutOrigin(text: string): string {
  if (!text.startsWith("[")) return text;
  const origin = ORIGIN.exec(text)?.[0];
  if (origin === undefined) {
    throw new TypeError(
      "Key origin must be [ and 8 hex characters, then /NUM or /NUMh steps, then ]",
    );
  }
  for (const step of origin.slice(9, -1).split("/").slice(1)) readStep(step);
  const rest = text.slice(origin.length);
  if (rest === "") throw new TypeError("Key origin has no key after it");
  if (rest.startsWith("[")) throw new TypeError("Key has more than one origin");
  return rest;
}

/**
 * Narrows a full key to what the context takes.
 * @param key - Compressed or uncompressed SEC1 key
 * @param context - Where the key lands
 * @returns {Uint8Array} The key as the script holds it
 */
function fitKey(key: Uint8Array, context: KeyContext): Uint8Array {
  if (key.length === 65 && context !== "legacy") {
    throw new RangeError("Uncompressed keys are not allowed in segwit or Taproot");
  }
  return context === "taproot" ? key.subarray(1) : key;
}

/**
 * Reads a hex public key: compressed, uncompressed, or x-only in Taproot.
 * @param text - The key hex
 * @param context - Where the key lands
 * @returns {Uint8Array} The key as the script holds it
 */
function hexKey(text: string, context: KeyContext): Uint8Array {
  if (text.length === 64) {
    if (context !== "taproot") throw new RangeError("x-only keys belong in tr() only");
    return decodePublicPoint(`02${text}`).toBytes(true).subarray(1);
  }
  if (text.length !== 66 && text.length !== 130) {
    throw new RangeError("Hex key must be 66 characters, 130 uncompressed, or 64 x-only in tr()");
  }
  decodePublicPoint(text);
  return fitKey(Uint8Array.fromHex(text), context);
}

/**
 * Reads a WIF private key into its public key.
 * @param text - The WIF
 * @param context - Where the key lands
 * @param network - Network the WIF must be for
 * @returns {Uint8Array} The key as the script holds it
 */
function wifKey(text: string, context: KeyContext, network: ScriptNetwork): Uint8Array {
  let decoded;
  try {
    decoded = decodeWIF(text, { chain: "bitcoin", network });
  } catch {
    throw new TypeError(
      `Key is not hex, a ${network} WIF or an extended key${text.includes("<") ? "; multipath <a;b> steps are not supported" : ""}`,
    );
  }
  const publicKey = secp256k1.getPublicKey(
    Uint8Array.fromHex(decoded.privateKey),
    decoded.compressed,
  );
  return fitKey(publicKey, context);
}

/**
 * Splits the steps after an extended key from a final `/*` or `/*h`.
 * @param rest - Steps after the key
 * @returns {{ steps: Step[]; wildcard: number | undefined }} The steps and the offset a range adds
 */
function readPath(rest: readonly string[]): { steps: Step[]; wildcard: number | undefined } {
  const last = rest.at(-1) ?? "";
  if (!/^\*['h]?$/u.test(last))
    return { steps: rest.map((step) => readStep(step)), wildcard: undefined };
  const wildcard = last.length > 1 ? HARDENED_OFFSET : 0;
  return { steps: rest.slice(0, -1).map((step) => readStep(step)), wildcard };
}

/**
 * Checks that an extended key is for the network and tells whether it is private.
 * @param encoded - Base58Check extended key
 * @param network - Network it must be for
 * @returns {boolean} True for an xprv or tprv
 */
function isPrivateKey(encoded: string, network: ScriptNetwork): boolean {
  const versions = EXTENDED_VERSIONS[network];
  const version = extendedKeyVersion(decodeExtendedKey(encoded));
  if (version !== versions.public && version !== versions.private) {
    const accepted = network === "mainnet" ? "an xpub or xprv" : "a tpub or tprv";
    throw new RangeError(`Extended key on ${network} must be ${accepted}`);
  }
  return version === versions.private;
}

/**
 * Reads an extended key and its steps, deriving the fixed part once.
 * @param text - The key and its steps
 * @param context - Where the key lands
 * @param network - Network the extended key must be for
 * @returns {DescriptorKey} The key, ranged when the last step is `*`
 */
function extendedKey(text: string, context: KeyContext, network: ScriptNetwork): DescriptorKey {
  const [encoded = "", ...rest] = text.split("/");
  const isPrivate = isPrivateKey(encoded, network);
  const { steps, wildcard } = readPath(rest);
  if (!isPrivate && (steps.some((step) => step.hardened) || wildcard === HARDENED_OFFSET)) {
    throw new RangeError("Hardened steps need the extended private key");
  }
  const parent = steps.reduce(
    (node, step) => node.deriveChild(step.index + (step.hardened ? HARDENED_OFFSET : 0)),
    HDKey.fromExtendedKey(encoded, EXTENDED_VERSIONS[network]),
  );
  const publicKeyAt = (node: HDKey): Uint8Array => {
    if (node.publicKey === null) throw new Error("Extended key has no public key");
    return fitKey(node.publicKey, context);
  };
  if (wildcard === undefined) {
    const fixed = publicKeyAt(parent);
    return { ranged: false, at: () => fixed };
  }
  return { ranged: true, at: (index) => publicKeyAt(parent.deriveChild(index + wildcard)) };
}

/**
 * Reads a BIP380 key expression: an origin, then hex, a WIF, or an extended key with steps.
 * @param expression - Key expression
 * @param context - Where the key lands
 * @param network - Network a WIF or extended key must be for
 * @returns {DescriptorKey} The key
 */
export function parseKey(
  expression: string,
  context: KeyContext,
  network: ScriptNetwork,
): DescriptorKey {
  const text = withoutOrigin(expression);
  if (/^[xt](?:pub|prv)/u.test(text)) return extendedKey(text, context, network);
  if (text.includes("/")) throw new TypeError("Only extended keys take derivation steps");
  const key = HEX.test(text) ? hexKey(text, context) : wifKey(text, context, network);
  return { ranged: false, at: () => key };
}
