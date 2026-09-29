import { HDKey } from "@scure/bip32";
import { decodeBase58Check } from "./encoding.ts";
import { HARDENED_OFFSET } from "./hd-index.ts";
import type { AddressType } from "../types.ts";

/** Version bytes of one extended public key prefix and the address type it stands for. */
export interface ExtendedKeyFormat {
  readonly version: number;
  /** Absent where the chain has a single address format. */
  readonly addressType?: AddressType;
}

/** Extended public key prefixes a chain accepts on one network, keyed by prefix. */
export type ExtendedKeyFormats = Readonly<Record<string, ExtendedKeyFormat>>;

/** SLIP-0132 single signature public versions, shared by Bitcoin and the chains that copy them. */
export const SLIP132_FORMATS = {
  xpub: { version: 0x0488b21e, addressType: "legacy" },
  ypub: { version: 0x049d7cb2, addressType: "p2sh" },
  zpub: { version: 0x04b24746, addressType: "segwit" },
  tpub: { version: 0x043587cf, addressType: "legacy" },
  upub: { version: 0x044a5262, addressType: "p2sh" },
  vpub: { version: 0x045f1cf6, addressType: "segwit" },
} as const satisfies ExtendedKeyFormats;

/** BIP32 serialization: version, depth, fingerprint, index, chain code, then the key. */
const EXTENDED_KEY_LENGTH = 78;
const KEY_OFFSET = 45;
/** A serialized key is 111 or 112 characters; the cap keeps base58 decoding cheap. */
const MAX_EXTENDED_KEY_LENGTH = 128;

/** What an extended public key yields at one path below it. */
export interface ExtendedPublicChild {
  /** Prefix of the key it came from, such as `zpub`. */
  readonly prefix: string;
  /** Address type the prefix stands for, when it names one. */
  readonly addressType?: AddressType;
  /** Compressed SEC1 public key as hex. */
  readonly publicKey: string;
}

/**
 * Refuses a path a public key cannot walk: hardened levels need the private key.
 * @param path - Levels below the extended key
 * @returns {void} Nothing; it throws on a hardened or malformed path
 */
function assertNormalPath(path: string): void {
  const levels = /^m(\/\d+)+$/u.test(path) ? path.slice(2).split("/") : [];
  if (levels.length === 0 || levels.some((level) => Number(level) >= HARDENED_OFFSET)) {
    throw new RangeError(
      "Path must be normal levels below the extended key, such as m/0/5; hardened levels need the private key",
    );
  }
}

/**
 * Decodes the 78 serialized bytes and refuses a private key before anything reads it.
 * @param extendedKey - Base58Check extended key
 * @returns {Uint8Array} The serialized public key
 */
function decodeExtendedPublicKey(extendedKey: string): Uint8Array {
  let bytes: Uint8Array | undefined;
  try {
    if (extendedKey.length <= MAX_EXTENDED_KEY_LENGTH) bytes = decodeBase58Check(extendedKey);
  } catch {
    bytes = undefined;
  }
  if (bytes?.length !== EXTENDED_KEY_LENGTH) {
    throw new Error("Invalid extended key encoding or checksum");
  }
  if (bytes[KEY_OFFSET] === 0) {
    throw new Error("Extended private keys are not accepted; pass the public key of the account");
  }
  return bytes;
}

/**
 * Walks an extended public key down normal levels, so this path stays watch-only.
 * @param extendedKey - Base58Check extended public key, such as an account `xpub`
 * @param path - Normal levels below the key, such as `m/0/5`
 * @param formats - Prefixes the chain accepts on its network
 * @param label - Chain and network for error messages
 * @returns {ExtendedPublicChild} The child public key and what the prefix says about it
 */
export function deriveExtendedPublicChild(
  extendedKey: string,
  path: string,
  formats: ExtendedKeyFormats,
  label: string,
): ExtendedPublicChild {
  assertNormalPath(path);
  const bytes = decodeExtendedPublicKey(extendedKey);
  const version = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0, false);
  const entry = Object.entries(formats).find(([, format]) => format.version === version);
  if (entry === undefined) {
    throw new RangeError(
      `Extended key ${JSON.stringify(extendedKey.slice(0, 4))} is not accepted for ${label}. Accepted: ${Object.keys(formats).join(", ")}`,
    );
  }
  const [prefix, format] = entry;
  const key = HDKey.fromExtendedKey(extendedKey, { public: version, private: 0 }).derive(path);
  if (key.publicKey === null) {
    throw new Error(`No public key at ${path}`);
  }
  return {
    prefix,
    ...(format.addressType === undefined ? {} : { addressType: format.addressType }),
    publicKey: key.publicKey.toHex(),
  };
}
