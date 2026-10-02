import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import { HDKey } from "@scure/bip32";
import { Sha512Hasher, hmac } from "@agntn/hashes";
import { concatBytes } from "../bytes.ts";
import { KEY_OFFSET, decodeExtendedKey, extendedKeyVersion } from "../extended-key.ts";
import { HARDENED_OFFSET } from "../hd-index.ts";

/** Private versions of the public prefixes SLIP-0132 lists for Bitcoin and Litecoin. */
const PRIVATE_VERSIONS: ReadonlyMap<number, { readonly prefix: string; readonly version: number }> =
  new Map([
    [0x0488b21e, { prefix: "xpub", version: 0x0488ade4 }],
    [0x049d7cb2, { prefix: "ypub", version: 0x049d7878 }],
    [0x04b24746, { prefix: "zpub", version: 0x04b2430c }],
    [0x043587cf, { prefix: "tpub", version: 0x04358394 }],
    [0x044a5262, { prefix: "upub", version: 0x044a4e28 }],
    [0x045f1cf6, { prefix: "vpub", version: 0x045f18bc }],
    [0x019da462, { prefix: "Ltub", version: 0x019d9cfe }],
    [0x01b26ef6, { prefix: "Mtub", version: 0x01b26792 }],
    [0x0436f6e1, { prefix: "ttub", version: 0x0436ef7d }],
  ]);

/** Thrown when the child key does not come from the extended public key at that index. */
export class BIP32ChildMismatchError extends Error {
  /** Index the child was checked at. */
  readonly index: number;

  constructor(message: string, index: number) {
    super(message);
    this.name = "BIP32ChildMismatchError";
    this.index = index;
  }
}

/** The recovered parent and the child index that gave it away. */
export interface RecoveredParent {
  /** Parent node with its private key, serialized with the private prefix of its xpub. */
  readonly parent: HDKey;
  /** Index of the child below the parent. */
  readonly index: number;
}

/**
 * Reads the extended public key and the private version its prefix pairs with.
 * @param extendedKey - Base58Check extended public key
 * @returns {{ parent: HDKey; privateVersion: number }} The public node and its private version
 */
function readParent(extendedKey: string): { parent: HDKey; privateVersion: number } {
  const bytes = decodeExtendedKey(extendedKey, "extended public key");
  if (bytes[KEY_OFFSET] === 0) {
    throw new Error("Pass the extended public key of the parent, not a private one");
  }
  const version = extendedKeyVersion(bytes);
  const pair = PRIVATE_VERSIONS.get(version);
  if (pair === undefined) {
    const accepted = [...PRIVATE_VERSIONS.values()].map(({ prefix }) => prefix).join(", ");
    throw new RangeError(
      `Extended key ${JSON.stringify(extendedKey.slice(0, 4))} is not accepted. Accepted: ${accepted}`,
    );
  }
  const parent = HDKey.fromExtendedKey(extendedKey, { public: version, private: pair.version });
  return { parent, privateVersion: pair.version };
}

/** A child key with the index it sits at, and its chain code when an xprv gave it. */
interface ChildKey {
  readonly key: Uint8Array;
  readonly index: number;
  readonly chainCode?: Uint8Array;
}

/**
 * Refuses an index a public key cannot have come down through.
 * @param index - Child index
 * @returns {void} Nothing; it throws on a hardened or malformed index
 */
function assertNormalIndex(index: number): void {
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new RangeError("Index must be a non-negative integer");
  }
  if (index >= HARDENED_OFFSET) {
    throw new RangeError("A hardened child does not reveal its parent; use a normal index");
  }
}

/**
 * Reads a bare child private key, which needs its index from the caller.
 * @param key - 32 byte private key
 * @param index - Child index
 * @returns {ChildKey} The key and its index
 */
function readBareChild(key: Uint8Array, index: number | undefined): ChildKey {
  if (index === undefined) throw new TypeError("A bare child key needs its index");
  if (!secp256k1.utils.isValidSecretKey(key)) {
    throw new Error("Child private key must be a valid 32 byte secp256k1 scalar");
  }
  return { key, index };
}

/**
 * Reads a child xprv and checks it against the parent it claims.
 * @param child - Child extended private key
 * @param index - Optional index the xprv must carry
 * @param parent - Parent public node
 * @param privateVersion - Private version the parent prefix pairs with
 * @returns {ChildKey} The key, its index and chain code
 */
function readExtendedChild(
  child: string,
  index: number | undefined,
  parent: HDKey,
  privateVersion: number,
): ChildKey {
  const bytes = decodeExtendedKey(child, "child extended private key");
  if (bytes[KEY_OFFSET] !== 0) {
    throw new Error("Pass the extended private key of the child, not a public one");
  }
  const version = extendedKeyVersion(bytes);
  const node = HDKey.fromExtendedKey(child, { public: 0, private: version });
  if (index !== undefined && index !== node.index) {
    throw new RangeError(`Index ${index} does not match the child key, which is at ${node.index}`);
  }
  if (version !== privateVersion) {
    throw new BIP32ChildMismatchError(
      "The child prefix does not pair with the parent prefix",
      node.index,
    );
  }
  if (node.depth !== parent.depth + 1 || node.parentFingerprint !== parent.fingerprint) {
    throw new BIP32ChildMismatchError(
      "The child key is not a direct child of this parent",
      node.index,
    );
  }
  if (node.privateKey === null || node.chainCode === null) {
    throw new Error("The child key holds no private key");
  }
  return { key: node.privateKey, index: node.index, chainCode: node.chainCode };
}

/**
 * Subtracts the public tweak of the child's index from its key, then checks the result.
 * @param parent - Parent public node
 * @param child - Child key and index
 * @returns {Uint8Array} The parent private key
 */
function subtractTweak(parent: HDKey, child: ChildKey): Uint8Array {
  const { publicKey, chainCode } = parent;
  if (publicKey === null || chainCode === null) {
    throw new Error("The extended public key holds no public key");
  }
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, child.index, false);
  const digest = hmac(() => new Sha512Hasher(), chainCode, concatBytes(publicKey, indexBytes));
  const { Fn } = secp256k1.Point;
  const parentKey = Fn.sub(Fn.fromBytes(child.key), Fn.fromBytes(digest.subarray(0, 32)));
  const keyMatches =
    !Fn.is0(parentKey) &&
    equalBytes(secp256k1.getPublicKey(Fn.toBytes(parentKey), true), publicKey);
  const chainMatches =
    child.chainCode === undefined || equalBytes(child.chainCode, digest.subarray(32));
  if (!keyMatches || !chainMatches) {
    throw new BIP32ChildMismatchError(
      `The child key does not derive from this extended public key at index ${child.index}`,
      child.index,
    );
  }
  return Fn.toBytes(parentKey);
}

/**
 * Recovers the parent private key from its xpub and one normal child private key.
 * @param extendedKey - Parent extended public key, such as an account `xpub`
 * @param child - Child xprv, or its 32 byte private key
 * @param index - Child index; required for a bare key, optional for an xprv, which carries it
 * @returns {RecoveredParent} The parent node with its private key, and the child index
 */
export function recoverParent(
  extendedKey: string,
  child: string | Uint8Array,
  index?: number,
): RecoveredParent {
  if (index !== undefined) assertNormalIndex(index);
  const { parent, privateVersion } = readParent(extendedKey);
  const read =
    typeof child === "string"
      ? readExtendedChild(child, index, parent, privateVersion)
      : readBareChild(child, index);
  assertNormalIndex(read.index);
  return {
    parent: new HDKey({
      versions: { public: parent.versions.public, private: privateVersion },
      depth: parent.depth,
      index: parent.index,
      parentFingerprint: parent.parentFingerprint,
      chainCode: parent.chainCode ?? undefined,
      privateKey: subtractTweak(parent, read),
    }),
    index: read.index,
  };
}
