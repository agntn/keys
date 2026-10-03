import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { Bitcoin } from "../../blockchains/bitcoin.ts";
import { hash160, taggedHash } from "../address.ts";
import { concatBytes } from "../bytes.ts";
import { decodeKeyPrivate } from "../secp256k1/decode.ts";
import { challengeOf, p2pkhScript, toSign, toSpend, type ChallengeNetwork } from "./challenge.ts";
import { push } from "./script.ts";
import {
  SIGHASH_ALL,
  SIGHASH_DEFAULT,
  legacySighash,
  segwitSighash,
  taprootSighash,
} from "./sighash.ts";
import { encodeWitness, serializeTransaction } from "./transaction.ts";

/** Address types `sign` writes a signature for. */
export type BIP322SigningType = "legacy" | "p2sh" | "segwit" | "taproot";

/** Network and key form of the signing address. */
export interface BIP322SignOptions {
  /** Default: mainnet. */
  readonly network?: ChallengeNetwork;
  /** Legacy only: sign for the address of the compressed key. Default: true. */
  readonly compressed?: boolean;
}

const SIGNING_TYPES: readonly string[] = ["legacy", "p2sh", "segwit", "taproot"];

/**
 * ECDSA over a sighash, low S and DER encoded, with the `SIGHASH_ALL` byte appended.
 * @param digest - Sighash
 * @param key - Private key bytes
 * @returns {Uint8Array} The signature a script pushes
 */
function ecdsaSignature(digest: Uint8Array, key: Uint8Array): Uint8Array {
  const der = secp256k1.sign(digest, key, { prehash: false, format: "der" });
  return concatBytes(der, Uint8Array.of(SIGHASH_ALL));
}

/**
 * Tweaks a private key by BIP341 for a key path spend with no script tree.
 * @param key - Private key bytes
 * @returns {Uint8Array} The key behind the Taproot output key
 */
function tweakKey(key: Uint8Array): Uint8Array {
  const { Fn } = secp256k1.Point;
  const point = secp256k1.Point.BASE.multiply(Fn.fromBytes(key));
  const even = point.toBytes(true)[0] === 2;
  const secret = even ? Fn.fromBytes(key) : Fn.neg(Fn.fromBytes(key));
  const tweak = Fn.fromBytes(taggedHash("TapTweak", point.toBytes(true).subarray(1)));
  return Fn.toBytes(Fn.add(secret, tweak));
}

/**
 * Tells an address type `sign` writes for.
 * @param type - Argument value
 * @returns {boolean} True for legacy, p2sh, segwit and taproot
 */
function isSigningType(type: unknown): type is BIP322SigningType {
  return typeof type === "string" && SIGNING_TYPES.includes(type);
}

/**
 * Writes the full `to_sign` of a scriptSig spend: P2PKH, or P2SH-P2WPKH with its witness.
 * @param key - Private key bytes
 * @param type - legacy or p2sh
 * @param context - `to_spend` and the public key
 * @returns {Uint8Array} The signed `to_sign`
 */
function signFull(
  key: Uint8Array,
  type: "legacy" | "p2sh",
  context: Readonly<{
    spend: ReturnType<typeof toSpend>;
    publicKey: Uint8Array;
    script: Uint8Array;
  }>,
): Uint8Array {
  const keyHash = hash160(context.publicKey);
  if (type === "legacy") {
    const digest = legacySighash(toSign(context.spend), 0, context.script);
    const scriptSig = concatBytes(push(ecdsaSignature(digest, key)), push(context.publicKey));
    return serializeTransaction(toSign(context.spend, { scriptSig }), true);
  }
  const scriptSig = push(Uint8Array.of(0, 20, ...keyHash));
  const unsigned = toSign(context.spend, { scriptSig });
  const digest = segwitSighash(unsigned, 0, p2pkhScript(keyHash), 0n);
  const witness = [ecdsaSignature(digest, key), context.publicKey];
  return serializeTransaction(toSign(context.spend, { scriptSig, witness }), true);
}

/**
 * Writes the witness of a native SegWit spend: P2WPKH, or a Taproot key path.
 * @param key - Private key bytes
 * @param type - segwit or taproot
 * @param context - `to_spend` and the public key
 * @returns {Uint8Array} The serialized witness stack
 */
function signSimple(
  key: Uint8Array,
  type: "segwit" | "taproot",
  context: Readonly<{
    spend: ReturnType<typeof toSpend>;
    publicKey: Uint8Array;
    script: Uint8Array;
  }>,
): Uint8Array {
  const unsigned = toSign(context.spend);
  if (type === "taproot") {
    const spent = [{ value: 0n, script: context.script }];
    const digest = taprootSighash(unsigned, 0, spent, SIGHASH_DEFAULT);
    return encodeWitness([schnorr.sign(digest, tweakKey(key))]);
  }
  const digest = segwitSighash(unsigned, 0, p2pkhScript(hash160(context.publicKey)), 0n);
  return encodeWitness([ecdsaSignature(digest, key), context.publicKey]);
}

/**
 * Signs a message by BIP322 for the address of a key: simple (`smp`) for P2WPKH and a Taproot key
 * path, full (`ful`) for P2SH-P2WPKH and P2PKH, the formats BIP322 lets each of them take.
 * @param message - Message as text, read as UTF-8, or bytes
 * @param privateKey - 32-byte private key as hex
 * @param addressType - legacy, p2sh, segwit or taproot
 * @param options - Network, and for legacy whether the key is compressed
 * @returns {string} The signature, prefixed by its format
 * @throws {RangeError} When the address type is not one of those four or the key is out of range
 */
export function sign(
  message: string | Uint8Array,
  privateKey: string,
  addressType: BIP322SigningType,
  options: Readonly<BIP322SignOptions> = {},
): string {
  if (!isSigningType(addressType)) {
    throw new RangeError(`BIP322 signing takes address type ${SIGNING_TYPES.join(", ")}`);
  }
  const network = options.network ?? "mainnet";
  const key = decodeKeyPrivate(privateKey);
  const compressed = addressType !== "legacy" || options.compressed !== false;
  const publicKey = secp256k1.getPublicKey(key, compressed);
  const address = new Bitcoin({ network }).getAddress(publicKey.toHex(), addressType);
  const challenge = challengeOf(address, network);
  const context = { spend: toSpend(message, challenge), publicKey, script: challenge.script };
  if (addressType === "legacy" || addressType === "p2sh") {
    return `ful${signFull(key, addressType, context).toBase64()}`;
  }
  return `smp${signSimple(key, addressType, context).toBase64()}`;
}
