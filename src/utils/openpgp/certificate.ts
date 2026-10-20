import { equalBytes } from "@noble/curves/utils.js";
import { concatBytes } from "../bytes.ts";
import { checkMath, hashAlgorithm } from "./algorithms.ts";
import { type Certificate, type PublicKey, type UserId, frameKey, frameUserId } from "./keys.ts";
import { type Signature, signatureDigest, tryReadSignature } from "./signatures.ts";

/** What the self-signatures say about one key. */
export interface KeyState {
  readonly key: PublicKey;
  /** First byte of the key flags, undefined when no self-signature carries them. */
  readonly flags?: number;
  /** Expiry in seconds since 1970. */
  readonly expires?: number;
  readonly revoked?: { readonly at: number; readonly code?: number };
  /** Whether the self-signature this state comes from uses MD5, SHA-1 or RIPEMD-160. */
  readonly weakHash: boolean;
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

/** Spends one self-signature check, throwing once a call has used them all. */
export type Budget = () => void;

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
 * Starts the budget of self-signature checks for one call, shared by every evaluation in it.
 * @returns {Budget} A spender that throws past 128 checks
 * @throws {RangeError} From the spender, past 128 checks
 */
export function createBudget(): Budget {
  let left = MAX_CHECKS;
  return () => {
    if (left === 0) {
      throw new RangeError(`OpenPGP key block needs more than ${MAX_CHECKS} self-signature checks`);
    }
    left--;
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
 * A check that drops self-signatures expired at the given time and spends the budget on the rest.
 * @param at - Time the key is judged at, seconds since 1970
 * @param budget - The call's budget
 * @returns {Check} The check
 */
function createCheck(at: number, budget: Budget): Check {
  return (signature, key, data) => {
    if (expiredAt(signature, at)) return false;
    budget();
    return holds(signature, key, data);
  };
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
    weakHash: binding !== undefined && hashAlgorithm(binding.hashId).weak,
  };
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

/**
 * The newest valid certification of each user ID, left out when a newer revocation stands.
 * @param certificate - The certificate
 * @param check - The block's budgeted check
 * @returns {{ id: UserId; signature: Signature }[]} Certified user IDs and their certifications
 */
function certifiedUserIds(
  certificate: Certificate,
  check: Check,
): { id: UserId; signature: Signature }[] {
  const framedKey = frameKey(certificate.primary);
  return certificate.userIds.flatMap((id) => {
    const data = concatBytes(framedKey, frameUserId(id.id));
    const signature = newestSelf(
      id.signatures,
      [0x10, 0x11, 0x12, 0x13],
      certificate.primary,
      data,
      check,
    );
    const revocation = newestSelf(id.signatures, [0x30], certificate.primary, data, check);
    if (
      signature === undefined ||
      (revocation !== undefined && revocation.created >= signature.created)
    ) {
      return [];
    }
    return [{ id, signature }];
  });
}

/**
 * Self-signature with the primary key's flags and expiry, picked by version per RFC 9580 §5.2.3.10.
 * @param certificate - The certificate
 * @param certified - Certified user IDs
 * @param check - The block's budgeted check
 * @returns {Signature | undefined} The signature to read properties from
 */
function primaryBinding(
  certificate: Certificate,
  certified: readonly { readonly id: UserId; readonly signature: Signature }[],
  check: Check,
): Signature | undefined {
  const direct = newestSelf(
    certificate.direct,
    [0x1f],
    certificate.primary,
    frameKey(certificate.primary),
    check,
  );
  const fromUserId = (certified.find((entry) => entry.signature.primaryUserId) ?? certified[0])
    ?.signature;
  return certificate.primary.version === 6 ? (direct ?? fromUserId) : (fromUserId ?? direct);
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
  const certified = certifiedUserIds(certificate, check);
  const binding = primaryBinding(certificate, certified, check);
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
