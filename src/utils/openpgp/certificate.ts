import { equalBytes } from "@noble/curves/utils.js";
import { concatBytes } from "../bytes.ts";
import { checkMath, hashAlgorithm, minimumDigestBits } from "./algorithms.ts";
import {
  type Certificate,
  type PublicKey,
  type UserId,
  frameKey,
  frameUserAttribute,
  frameUserId,
} from "./keys.ts";
import { type Signature, signatureDigest, tryReadSignature } from "./signatures.ts";

/** What the self-signatures say about one key. */
export interface KeyState {
  readonly key: PublicKey;
  /** First byte of the key flags, undefined when no self-signature carries them. */
  readonly flags?: number;
  /** Expiry in seconds since 1970. */
  readonly expires?: number;
  readonly revoked?: { readonly at: number; readonly code?: number };
  /** MD5, SHA1 or RIPEMD160 when the self-signature this state comes from uses one. */
  readonly weakHash?: string;
}

/** The primary key, plus whether any self-signature on it holds up. */
export interface PrimaryState extends KeyState {
  readonly selfSigned: boolean;
}

/** A subkey, plus whether the primary binds it and, for signing, whether it signs back. */
export interface SubkeyState extends KeyState {
  readonly bound: boolean;
  readonly backSigned: boolean;
}

/** The certificate after every self-signature was checked. */
export interface CertificateState {
  readonly primary: PrimaryState;
  /** User IDs the primary key certifies, UTF-8 decoded. */
  readonly userIds: readonly string[];
  /** User IDs with no valid self-certification, which say nothing about the key. */
  readonly uncertifiedUserIds: number;
  readonly subkeys: readonly SubkeyState[];
}

/** Most self-signature checks per key block. Forged ones cost real math, 128 is about a second. */
const MAX_CHECKS = 128;

/** Checks a self-signature against a key and the data it signs, within the block's budget. */
type Check = (signature: Signature, key: PublicKey, data: Uint8Array) => boolean;

/** Runs the math of a self-signature once per call, throwing once the call used up its budget. */
export type Budget = Check;

/** Public key algorithms that sign, RFC 9580 Table 18. RSA Encrypt-Only (2) is not one. */
const SIGNING_ALGORITHMS = new Set([1, 3, 17, 19, 22, 27, 28]);

/** Key flag 0x02: the key may sign data. */
export const SIGN_FLAG = 0x02;

/**
 * Whether a signature names the key as its issuer. One that names no issuer gets tried anyway.
 * @param signature - The signature
 * @param key - Candidate issuer
 * @returns {boolean} Whether the key may have made it
 */
export function issuedBy(signature: Signature, key: PublicKey): boolean {
  if (signature.issuerFingerprint !== undefined)
    return equalBytes(signature.issuerFingerprint, key.fingerprint);
  if (signature.issuerKeyId !== undefined) return equalBytes(signature.issuerKeyId, key.keyId);
  return true;
}

/**
 * Whether the signature algorithm signs and fits the key: RSA as 1 or 3, the rest as themselves.
 * @param key - Signing key
 * @param algorithm - Algorithm ID on the signature
 * @returns {boolean} Whether they fit
 */
export function fitsKey(key: PublicKey, algorithm: number): boolean {
  if (!SIGNING_ALGORITHMS.has(algorithm)) return false;
  if (key.algorithm === 1 || key.algorithm === 3) return algorithm === 1 || algorithm === 3;
  return algorithm === key.algorithm;
}

/**
 * Why a signature fails, whatever its type. Undefined when it holds.
 * @param signature - The signature
 * @param key - Key that should have made it
 * @param data - Signed data
 * @returns {string | undefined} Why it fails, undefined when it holds
 * @throws {RangeError} When its hash isn't one this module computes
 */
export function failure(
  signature: Signature,
  key: PublicKey,
  data: Uint8Array,
): string | undefined {
  if (signature.unknownCritical !== undefined) {
    return `The signature carries a critical subpacket of type ${signature.unknownCritical} that this verifier doesn't know`;
  }
  if (signature.version !== key.version) {
    return `A version ${signature.version} signature can't come from a version ${key.version} key`;
  }
  if (!fitsKey(key, signature.algorithm)) return "The signature algorithm doesn't match the key";
  if (signature.created < key.created) return "The signature is older than the key that made it";
  const digest = signatureDigest(signature, data);
  if (!equalBytes(digest.slice(0, 2), signature.left16))
    return "The text doesn't match what was signed";
  const hash = hashAlgorithm(signature.hashId);
  const floor = minimumDigestBits(key.material);
  if (digest.length * 8 < floor) {
    return `${hash.name} is too short for this key, RFC 9580 asks for at least ${floor} bits`;
  }
  return checkMath(key.material, signature.algorithm, signature.value, digest, hash)
    ? undefined
    : "The signature doesn't verify against this key";
}

/**
 * Whether a signature holds, treating a hash this module can't compute as not holding.
 * @param signature - The signature
 * @param key - Key that should have made it
 * @param data - Signed data
 * @returns {boolean} Whether it holds
 */
function holds(signature: Signature, key: PublicKey, data: Uint8Array): boolean {
  try {
    return failure(signature, key, data) === undefined;
  } catch {
    return false;
  }
}

/**
 * Starts the budget for one call, shared by every evaluation in it. A signature already checked
 * against the same key and data costs nothing the second time.
 * @returns {Budget} The memoized check
 * @throws {RangeError} From the check, past 128 distinct signatures
 */
export function createBudget(): Budget {
  const known = new Map<string, boolean>();
  return (signature, key, data) => {
    const parts = [key.fingerprint, data, signature.hashedBody, signature.value];
    const id = parts.map((bytes) => bytes.toHex()).join(":");
    const cached = known.get(id);
    if (cached !== undefined) return cached;
    if (known.size === MAX_CHECKS) {
      throw new RangeError(`OpenPGP key block needs more than ${MAX_CHECKS} self-signature checks`);
    }
    const result = holds(signature, key, data);
    known.set(id, result);
    return result;
  };
}

/**
 * Whether a signature had expired by the given time, from its subpacket 3.
 * @param signature - The signature
 * @param at - Seconds since 1970
 * @returns {boolean} Whether it no longer counts then
 */
export function expiredAt(signature: Signature, at: number): boolean {
  const after = signature.expiresAfter ?? 0;
  return after > 0 && signature.created + after <= at;
}

/**
 * Drops self-signatures expired by `at`, not ones made after it: GnuPG keeps only the renewed one.
 * @param at - Time the key is judged at, seconds since 1970
 * @param budget - The call's budget
 * @returns {Check} The check
 */
function createCheck(at: number, budget: Budget): Check {
  return (signature, key, data) => !expiredAt(signature, at) && budget(signature, key, data);
}

/**
 * The newest signature of the given types that the primary key made and that holds.
 * @param signatures - Candidates
 * @param types - Signature Type IDs to accept
 * @param primary - The primary key
 * @param data - What they sign
 * @param check - The block's budgeted check
 * @returns {Signature | undefined} The newest valid one
 */
function newestSelf(
  signatures: readonly Signature[],
  types: readonly number[],
  primary: PublicKey,
  data: Uint8Array,
  check: Check,
): Signature | undefined {
  return signatures
    .filter((signature) => types.includes(signature.type) && issuedBy(signature, primary))
    .toSorted((a, b) => b.created - a.created)
    .find((signature) => check(signature, primary, data));
}

/**
 * Flags, expiry and revocation from a self-signature and a revocation.
 * @param key - The key they describe
 * @param binding - Self-signature with the key's properties
 * @param revocation - Valid revocation, if any
 * @returns {KeyState} The key's state
 */
function stateOf(
  key: PublicKey,
  binding: Signature | undefined,
  revocation: Signature | undefined,
): KeyState {
  const expiresAfter = binding?.keyExpiresAfter ?? 0;
  return {
    key,
    ...(binding?.keyFlags === undefined ? {} : { flags: binding.keyFlags }),
    ...(expiresAfter > 0 ? { expires: key.created + expiresAfter } : {}),
    ...(revocation === undefined ? {} : { revoked: revokedAt(revocation) }),
    ...weakHashOf(binding),
  };
}

/**
 * Names the weak hash of a self-signature.
 * @param binding - The self-signature, if any
 * @returns {{ weakHash?: string }} The hash name when it's one RFC 9580 calls weak
 */
function weakHashOf(binding: Signature | undefined): { weakHash?: string } {
  if (binding === undefined) return {};
  const hash = hashAlgorithm(binding.hashId);
  return hash.weak ? { weakHash: hash.name } : {};
}

/**
 * When a revocation was made, and why.
 * @param revocation - The revocation signature
 * @returns {{ at: number; code?: number }} Time and reason code
 */
function revokedAt(revocation: Signature): { at: number; code?: number } {
  return revocation.revocationCode === undefined
    ? { at: revocation.created }
    : { at: revocation.created, code: revocation.revocationCode };
}

/** Certification types, 0x10 to 0x13, RFC 9580 §5.2.1. */
const CERTIFICATIONS = [0x10, 0x11, 0x12, 0x13];

/** A certified user ID or User Attribute and the self-signature that certifies it. */
interface Certified {
  readonly id: UserId;
  readonly signature: Signature;
}

/**
 * Newest valid self-signature of the types, unless a newer 0x30 revokes it (§5.2.1.13, §5.2.3.20).
 * @param signatures - Candidates and their revocations
 * @param types - Signature Type IDs to accept
 * @param data - What they sign
 * @param context - Primary key and the block's budgeted check
 * @returns {Signature | undefined} The signature that stands
 */
function standing(
  signatures: readonly Signature[],
  types: readonly number[],
  data: Uint8Array,
  context: { readonly primary: PublicKey; readonly check: Check },
): Signature | undefined {
  const signature = newestSelf(signatures, types, context.primary, data, context.check);
  if (signature === undefined || !signature.revocable) return signature;
  const revocation = newestSelf(signatures, [0x30], context.primary, data, context.check);
  return revocation !== undefined && revocation.created >= signature.created
    ? undefined
    : signature;
}

/**
 * User IDs or User Attributes with a standing self-certification.
 * @param components - User IDs or User Attributes
 * @param frame - Their framing, 0xB4 or 0xD1
 * @param context - Primary key and the block's budgeted check
 * @returns {Certified[]} The certified ones
 */
function certifiedOf(
  components: readonly UserId[],
  frame: (body: Uint8Array) => Uint8Array,
  context: { readonly primary: PublicKey; readonly check: Check },
): Certified[] {
  const framedKey = frameKey(context.primary);
  return components.flatMap((id) => {
    const signature = standing(
      id.signatures,
      CERTIFICATIONS,
      concatBytes(framedKey, frame(id.id)),
      context,
    );
    return signature === undefined ? [] : [{ id, signature }];
  });
}

/**
 * Self-signature with the primary key's flags and expiry, RFC 9580 §5.2.3.10. A version 6 key
 * must have a standing direct key signature; version 4 prefers the primary user ID's.
 * @param certificate - The certificate
 * @param certified - Certified user IDs, then User Attributes
 * @param check - The block's budgeted check
 * @returns {Signature | undefined} The signature to read properties from
 */
function primaryBinding(
  certificate: Certificate,
  certified: readonly Certified[],
  check: Check,
): Signature | undefined {
  const { primary } = certificate;
  const direct = standing(certificate.direct, [0x1f], frameKey(primary), { primary, check });
  if (primary.version === 6) return direct;
  const fromUserId = (certified.find((entry) => entry.signature.primaryUserId) ?? certified[0])
    ?.signature;
  return fromUserId ?? direct;
}

/**
 * Whether a signing subkey signs back with an embedded 0x19, which RFC 9580 §5.2.1.9 requires.
 * @param binding - The subkey binding signature
 * @param subkey - The subkey
 * @param data - Framed primary key and subkey
 * @param check - The block's budgeted check
 * @returns {boolean} Whether the subkey signs back
 */
function signsBack(binding: Signature, subkey: PublicKey, data: Uint8Array, check: Check): boolean {
  return binding.embedded.some((body) => {
    const back = tryReadSignature(body);
    return back?.type === 0x19 && issuedBy(back, subkey) && check(back, subkey, data);
  });
}

/**
 * Checks a subkey's binding, back signature and revocation.
 * @param certificate - The certificate
 * @param subkey - Which subkey
 * @param check - The block's budgeted check
 * @returns {SubkeyState} The subkey's state
 */
function subkeyState(
  certificate: Certificate,
  subkey: Certificate["subkeys"][number],
  check: Check,
): SubkeyState {
  const data = concatBytes(frameKey(certificate.primary), frameKey(subkey.key));
  const binding = newestSelf(subkey.signatures, [0x18], certificate.primary, data, check);
  const revocation = newestSelf(subkey.signatures, [0x28], certificate.primary, data, check);
  const state = stateOf(subkey.key, binding, revocation);
  const signs = state.flags === undefined || (state.flags & SIGN_FLAG) !== 0;
  return {
    ...state,
    bound: binding !== undefined,
    backSigned: binding !== undefined && signs && signsBack(binding, subkey.key, data, check),
  };
}

/**
 * Checks every self-signature as of one moment. Third-party ones need keys the caller didn't pass.
 * @param certificate - The certificate
 * @param options - When to judge the key, and the call's budget
 * @returns {CertificateState} What the key's own signatures establish
 * @throws {RangeError} When the block needs more than 128 self-signature checks
 */
export function evaluateCertificate(
  certificate: Certificate,
  options: { readonly at: number; readonly budget: Budget },
): CertificateState {
  const check = createCheck(options.at, options.budget);
  const context = { primary: certificate.primary, check };
  const certified = certifiedOf(certificate.userIds, frameUserId, context);
  const attributes = certifiedOf(certificate.userAttributes, frameUserAttribute, context);
  const binding = primaryBinding(certificate, [...certified, ...attributes], check);
  const revocation = newestSelf(
    certificate.direct,
    [0x20],
    certificate.primary,
    frameKey(certificate.primary),
    check,
  );
  const decoder = new TextDecoder();
  return {
    primary: {
      ...stateOf(certificate.primary, binding, revocation),
      selfSigned: binding !== undefined,
    },
    userIds: certified.map((entry) => decoder.decode(entry.id.id)),
    uncertifiedUserIds: certificate.userIds.length - certified.length,
    subkeys: certificate.subkeys.map((subkey) => subkeyState(certificate, subkey, check)),
  };
}
