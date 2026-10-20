import { assertOptions } from "../options.ts";
import { algorithmName, hashAlgorithm, hashName } from "./algorithms.ts";
import { type Cleartext, readArmor, readCleartext } from "./armor.ts";
import {
  type CertificateState,
  type KeyState,
  SIGN_FLAG,
  type SubkeyState,
  createBudget,
  evaluateCertificate,
  failure,
  issuedBy,
} from "./certificate.ts";
import { type Certificate, type PublicKey, readCertificate } from "./keys.ts";
import { isIgnorable, readPackets } from "./packets.ts";
import { type Signature, readSignature } from "./signatures.ts";

/** What a key may do, from its key flags. */
export type OpenPGPKeyFlag = "certify" | "sign" | "encrypt" | "authenticate";

/** One key of a certificate, as its own signatures describe it. */
export interface OpenPGPKey {
  /** Full fingerprint, uppercase hex: 40 digits for version 4, 64 for version 6. */
  readonly fingerprint: string;
  readonly keyId: string;
  readonly version: 4 | 6;
  /** Algorithm with its size or curve, `RSA 3072` or `EdDSALegacy Ed25519Legacy`. */
  readonly algorithm: string;
  /** Creation time, ISO 8601. */
  readonly created: string;
  readonly expires?: string;
  readonly revoked?: { readonly at: string; readonly reason?: string };
  /** Left out when no valid self-signature carries key flags. */
  readonly flags?: readonly OpenPGPKeyFlag[];
}

/** A subkey, and whether the primary key binds it. */
export interface OpenPGPSubkey extends OpenPGPKey {
  readonly bound: boolean;
}

/** What a public key block holds, after its self-signatures were checked. */
export interface OpenPGPKeyInspection {
  readonly kind: "public-key";
  readonly primary: OpenPGPKey;
  /** User IDs the primary key certifies. Anybody can attach others, so those are only counted. */
  readonly userIds: readonly string[];
  readonly uncertifiedUserIds: number;
  readonly subkeys: readonly OpenPGPSubkey[];
}

/** One signature of a signed message, read but not verified. */
export interface OpenPGPSignatureInfo {
  readonly version: 4 | 6;
  readonly algorithm: string;
  readonly hash: string;
  readonly created: string;
  /** Issuer fingerprint, or the 16-digit key ID when that's all the signature names. */
  readonly issuer?: string;
}

/** What a cleartext signed message holds. */
export interface OpenPGPMessageInspection {
  readonly kind: "signed-message";
  /** The text the signatures cover, dash escapes undone and trailing whitespace cut. */
  readonly text: string;
  readonly hashHeaders: readonly string[];
  readonly signatures: readonly OpenPGPSignatureInfo[];
  readonly warnings: readonly string[];
}

/** Either kind of block `inspect` reads. */
export type OpenPGPInspection = OpenPGPKeyInspection | OpenPGPMessageInspection;

/**
 * The math. `inconclusive` holds over MD5, SHA-1 or RIPEMD-160, which RFC 9580 refuses.
 */
export type OpenPGPState = "valid" | "invalid" | "inconclusive";

/** Whether the key is the one the caller expected, by full fingerprint. */
export type OpenPGPIdentity = "match" | "mismatch" | "unchecked";

/** What `verify` takes beside the message. */
export interface OpenPGPVerifyOptions {
  /** ASCII-armored public key block. Nothing gets fetched or imported anywhere. */
  readonly publicKey: string;
  /** Full fingerprint you trust, spaces allowed. Without it, identity stays unchecked. */
  readonly fingerprint?: string;
}

/** The verdict on a cleartext signed message, with the trust questions kept apart from the math. */
export interface OpenPGPVerification {
  readonly state: OpenPGPState;
  /** Why the signature is invalid or inconclusive. */
  readonly reason?: string;
  readonly identity: OpenPGPIdentity;
  readonly primaryFingerprint: string;
  /** The key that made the signature, the primary or a subkey. Absent when none of them did. */
  readonly signingFingerprint?: string;
  /** Who the signature says made it: a fingerprint or a key ID. */
  readonly issuer?: string;
  /** Signature creation time, ISO 8601. */
  readonly created: string;
  readonly hash: string;
  readonly algorithm: string;
  readonly version: 4 | 6;
  /** The text the signature covers, dash escapes undone and trailing whitespace cut. */
  readonly text: string;
  /** Revocations, expirations and text outside the signed block. None of them changes `state`. */
  readonly warnings: readonly string[];
}

const SIGNED_MESSAGE = /^-----BEGIN PGP SIGNED MESSAGE-----\s*$/mu;
const FINGERPRINT = /^[0-9A-F]+$/u;

/** Most signatures one cleartext message may carry. Real ones have one, each costs math. */
const MAX_SIGNATURES = 16;

/** Reason for revocation codes, RFC 9580 §5.2.3.31. */
const REVOCATION_REASONS: Readonly<Record<number, string>> = {
  0: "no reason given",
  1: "superseded",
  2: "compromised",
  3: "retired",
  32: "user ID no longer valid",
};

/**
 * Formats seconds since 1970 as ISO 8601.
 * @param seconds - Unix time
 * @returns {string} The date
 */
function iso(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

/**
 * Formats a fingerprint or key ID the way GnuPG prints it with `--with-colons`.
 * @param bytes - The fingerprint or key ID
 * @returns {string} Uppercase hex
 */
function upper(bytes: Uint8Array): string {
  return bytes.toHex().toUpperCase();
}

/**
 * Names a key's algorithm with its size or curve.
 * @param key - The key
 * @returns {string} For example `RSA 3072`, `ECDSA secp256k1` or `Ed25519`
 */
function describeKey(key: PublicKey): string {
  const name = algorithmName(key.algorithm);
  const material = key.material;
  if (material.kind === "rsa" || material.kind === "dsa") return `${name} ${material.bits}`;
  if (material.kind === "ecdsa") return `${name} ${material.curve}`;
  if (material.kind === "eddsa") return key.algorithm === 22 ? `${name} Ed25519Legacy` : name;
  const detail = material.curve ?? material.bits;
  return detail === undefined ? name : `${name} ${detail}`;
}

/**
 * Turns the first key flags byte into names.
 * @param flags - Key flags
 * @returns {OpenPGPKeyFlag[]} What the key may do
 */
function flagNames(flags: number): OpenPGPKeyFlag[] {
  const names: [number, OpenPGPKeyFlag][] = [
    [0x01, "certify"],
    [SIGN_FLAG, "sign"],
    [0x0c, "encrypt"],
    [0x20, "authenticate"],
  ];
  return names.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name);
}

/**
 * Names a revocation reason.
 * @param code - Reason code
 * @returns {string} Its name, or the code
 */
function reasonName(code: number): string {
  return (
    (Object.hasOwn(REVOCATION_REASONS, code) ? REVOCATION_REASONS[code] : undefined) ??
    `reason ${code}`
  );
}

/**
 * Describes one key for the caller.
 * @param state - What its self-signatures say
 * @returns {OpenPGPKey} The public description
 */
function keyOf(state: KeyState): OpenPGPKey {
  const { key, revoked } = state;
  return {
    fingerprint: upper(key.fingerprint),
    keyId: upper(key.keyId),
    version: key.version,
    algorithm: describeKey(key),
    created: iso(key.created),
    ...(state.expires === undefined ? {} : { expires: iso(state.expires) }),
    ...(revoked === undefined ? {} : { revoked: revocationOf(revoked) }),
    ...(state.flags === undefined ? {} : { flags: flagNames(state.flags) }),
  };
}

/**
 * Describes a revocation.
 * @param revoked - Time and reason code
 * @returns {{ at: string; reason?: string }} ISO time and reason name
 */
function revocationOf(revoked: NonNullable<KeyState["revoked"]>): { at: string; reason?: string } {
  return revoked.code === undefined
    ? { at: iso(revoked.at) }
    : { at: iso(revoked.at), reason: reasonName(revoked.code) };
}

/**
 * Who a signature says made it.
 * @param signature - The signature
 * @returns {string | undefined} Fingerprint, else key ID
 */
function issuerOf(signature: Signature): string | undefined {
  if (signature.issuerFingerprint !== undefined) return upper(signature.issuerFingerprint);
  return signature.issuerKeyId === undefined ? undefined : upper(signature.issuerKeyId);
}

/**
 * Reads every signature packet of a dearmored signature block.
 * @param bytes - Dearmored packets
 * @returns {Signature[]} The signatures
 * @throws {TypeError} When the block holds anything but signatures
 * @throws {RangeError} When it holds more than 16
 */
function readSignatures(bytes: Uint8Array): Signature[] {
  const packets = readPackets(bytes).filter((packet) => !isIgnorable(packet.tag));
  if (packets.length > MAX_SIGNATURES) {
    throw new RangeError(`A cleartext message may carry at most ${MAX_SIGNATURES} signatures`);
  }
  return packets.map((packet) => {
    if (packet.tag !== 2) {
      throw new TypeError("OpenPGP signature block holds a packet that isn't a signature");
    }
    return readSignature(packet.body);
  });
}

/**
 * Warnings about the frame of a cleartext message.
 * @param cleartext - The parsed message
 * @returns {string[]} Warnings
 */
function frameWarnings(cleartext: Cleartext): string[] {
  return [
    ...(cleartext.outside ? ["Text outside the signed block isn't covered by the signature"] : []),
    ...(cleartext.unescapedDash ? ["A line starts with a dash but isn't dash-escaped"] : []),
  ];
}

/**
 * Reads a public key block and checks its self-signatures.
 * @param armored - The armored block
 * @returns {OpenPGPKeyInspection} Keys, certified user IDs and subkeys
 */
function inspectKey(armored: string): OpenPGPKeyInspection {
  const state = evaluateCertificate(readCertificate(readArmor(armored, "PUBLIC KEY BLOCK")), {
    at: Math.floor(Date.now() / 1000),
    budget: createBudget(),
  });
  return {
    kind: "public-key",
    primary: keyOf(state.primary),
    userIds: state.userIds,
    uncertifiedUserIds: state.uncertifiedUserIds,
    subkeys: state.subkeys.map((subkey) => ({ ...keyOf(subkey), bound: subkey.bound })),
  };
}

/**
 * Reads a cleartext signed message without verifying it.
 * @param armored - The message
 * @returns {OpenPGPMessageInspection} The signed text and what each signature claims
 */
function inspectMessage(armored: string): OpenPGPMessageInspection {
  const cleartext = readCleartext(armored);
  const signatures = readSignatures(cleartext.signature).map((signature) => {
    const issuer = issuerOf(signature);
    return {
      version: signature.version,
      algorithm: algorithmName(signature.algorithm),
      hash: hashName(signature.hashId),
      created: iso(signature.created),
      ...(issuer === undefined ? {} : { issuer }),
    };
  });
  return {
    kind: "signed-message",
    text: cleartext.text,
    hashHeaders: cleartext.hashHeaders,
    signatures,
    warnings: frameWarnings(cleartext),
  };
}

/**
 * Reads an armored public key block or cleartext signed message. No keyring, no fetch.
 * @param armored - A `PUBLIC KEY BLOCK` or a `SIGNED MESSAGE`
 * @returns {OpenPGPInspection} Fingerprints, user IDs and subkeys, or the signed text and signers
 * @throws {TypeError} When the block is neither, malformed or a private key
 * @throws {RangeError} For a key or signature version this module doesn't read
 * @example
 * inspect(publicKey).primary.fingerprint; // "82463E7DE654EB03C1C11767C20FCF8B1FD20A24"
 */
export function inspect(armored: string): OpenPGPInspection {
  if (typeof armored !== "string") throw new TypeError("Armored text must be a string");
  return SIGNED_MESSAGE.test(armored) ? inspectMessage(armored) : inspectKey(armored);
}

/**
 * Normalizes an expected fingerprint, refusing a short key ID: those are easy to collide.
 * @param fingerprint - Hex with optional spaces
 * @returns {string} Uppercase hex
 * @throws {TypeError} When it isn't hex, or is a key ID
 * @throws {RangeError} When it is neither 40 nor 64 digits
 */
function readFingerprint(fingerprint: string): string {
  const digits = fingerprint.replaceAll(" ", "").toUpperCase();
  if (!FINGERPRINT.test(digits)) throw new TypeError("Fingerprint must be hex");
  if (digits.length === 16)
    throw new TypeError("Pass the full fingerprint, not a key ID: key IDs collide");
  if (digits.length !== 40 && digits.length !== 64) {
    throw new RangeError(
      "Fingerprint must be 40 hex digits for a version 4 key or 64 for version 6",
    );
  }
  return digits;
}

/** A signature and the key of the certificate that its issuer names. */
interface Match {
  readonly signature: Signature;
  readonly signer: KeyState;
  readonly subkey?: SubkeyState;
}

/**
 * Why the signer can't sign for this certificate, past the math.
 * @param match - Signature and signer
 * @param certificate - Checked certificate
 * @returns {string | undefined} The reason, undefined when the key may sign
 */
function signerFailure(match: Match, certificate: CertificateState): string | undefined {
  if (!certificate.primary.selfSigned)
    return "The key has no valid self-signature, so nothing ties it together";
  const { subkey } = match;
  if (subkey === undefined) {
    const flags = certificate.primary.flags;
    return flags === undefined || (flags & SIGN_FLAG) !== 0
      ? undefined
      : "The key isn't marked for signing";
  }
  if (!subkey.bound) return "The signing subkey isn't bound to this primary key";
  if (subkey.flags !== undefined && (subkey.flags & SIGN_FLAG) === 0)
    return "The subkey isn't marked for signing";
  return subkey.backSigned
    ? undefined
    : "The signing subkey has no valid back signature (type 0x19)";
}

/**
 * The cryptographic verdict on one signature from a key of the certificate.
 * @param match - Signature and signer
 * @param certificate - Checked certificate
 * @param canonical - Canonical text bytes
 * @returns {{ state: OpenPGPState; reason?: string }} The verdict
 * @throws {TypeError} When it isn't a text signature
 * @throws {RangeError} When the key's algorithm or the hash isn't supported here
 */
function judge(
  match: Match,
  certificate: CertificateState,
  canonical: Uint8Array,
): { state: OpenPGPState; reason?: string } {
  const { signature, signer } = match;
  if (signature.type !== 0x01) {
    throw new TypeError(
      `A cleartext signature must be a text signature (type 0x01), not 0x${signature.type.toString(16)}`,
    );
  }
  if (signer.key.material.kind === "none") {
    throw new RangeError(`${describeKey(signer.key)} signatures aren't supported yet`);
  }
  const reason = failure(signature, signer.key, canonical) ?? signerFailure(match, certificate);
  if (reason !== undefined) return { state: "invalid", reason };
  const hash = hashAlgorithm(signature.hashId);
  if (!hash.weak) return { state: "valid" };
  return {
    state: "inconclusive",
    reason: `The math checks out, but it's ${hash.name}, which RFC 9580 tells verifiers not to accept`,
  };
}

/**
 * Warns about a key that expired or was revoked.
 * @param state - The key's state
 * @param label - `key` or `signing subkey`
 * @param signedAt - Signature creation time
 * @returns {string[]} Warnings
 */
function keyWarnings(state: KeyState, label: string, signedAt: number): string[] {
  const warnings: string[] = [];
  if (state.revoked !== undefined) {
    const { at, reason } = revocationOf(state.revoked);
    warnings.push(`The ${label} was revoked on ${at}${reason === undefined ? "" : ` (${reason})`}`);
  }
  if (state.expires !== undefined && state.expires <= signedAt) {
    warnings.push(`The ${label} had expired when this was signed, on ${iso(state.expires)}`);
  } else if (state.expires !== undefined && state.expires * 1000 <= Date.now()) {
    warnings.push(`The ${label} expired on ${iso(state.expires)}`);
  }
  if (state.weakHash)
    warnings.push(`The ${label}'s self-signature uses a hash RFC 9580 calls weak`);
  return warnings;
}

/**
 * Everything worth knowing beside the verdict.
 * @param match - Signature and signer
 * @param certificate - Checked certificate
 * @param cleartext - The parsed message
 * @returns {string[]} Warnings
 */
function warningsOf(match: Match, certificate: CertificateState, cleartext: Cleartext): string[] {
  const { signature, subkey } = match;
  const expiresAfter = signature.expiresAfter ?? 0;
  const expired = expiresAfter > 0 && (signature.created + expiresAfter) * 1000 <= Date.now();
  return [
    ...keyWarnings(certificate.primary, "key", signature.created),
    ...(subkey === undefined ? [] : keyWarnings(subkey, "signing subkey", signature.created)),
    ...(expired ? [`The signature expired on ${iso(signature.created + expiresAfter)}`] : []),
    ...frameWarnings(cleartext),
  ];
}

/**
 * Pairs every signature with the keys of the certificate its issuer names.
 * @param signatures - Signatures of the message
 * @param certificate - Checked certificate
 * @returns {Match[]} Candidate pairs, primary key first
 */
function matchesOf(signatures: readonly Signature[], certificate: CertificateState): Match[] {
  return signatures.flatMap((signature) => [
    ...(issuedBy(signature, certificate.primary.key)
      ? [{ signature, signer: certificate.primary }]
      : []),
    ...certificate.subkeys
      .filter((subkey) => issuedBy(signature, subkey.key))
      .map((subkey) => ({ signature, signer: subkey, subkey })),
  ]);
}

/**
 * Whether the expected fingerprint names this certificate's primary key or the signing key.
 * @param expected - Normalized fingerprint, if the caller gave one
 * @param fingerprints - Fingerprints it may match
 * @returns {OpenPGPIdentity} The identity verdict
 */
function identityOf(
  expected: string | undefined,
  fingerprints: readonly string[],
): OpenPGPIdentity {
  if (expected === undefined) return "unchecked";
  return fingerprints.includes(expected) ? "match" : "mismatch";
}

/**
 * The verdict when no key of the certificate made any signature.
 * @param signatures - Signatures of the message
 * @param certificate - The certificate
 * @param cleartext - The parsed message
 * @param expected - Normalized expected fingerprint
 * @returns {OpenPGPVerification} An invalid verdict naming the issuer
 */
function strangerVerdict(
  signatures: readonly Signature[],
  certificate: Certificate,
  cleartext: Cleartext,
  expected: string | undefined,
): OpenPGPVerification {
  const [signature] = signatures;
  if (signature === undefined) throw new TypeError("OpenPGP signature block holds no signature");
  const issuer = issuerOf(signature);
  const primaryFingerprint = upper(certificate.primary.fingerprint);
  return {
    state: "invalid",
    reason: `Signed by ${issuer ?? "an unnamed key"}, which this key block doesn't hold`,
    identity: identityOf(expected, [primaryFingerprint]),
    primaryFingerprint,
    ...(issuer === undefined ? {} : { issuer }),
    created: iso(signature.created),
    hash: hashName(signature.hashId),
    algorithm: algorithmName(signature.algorithm),
    version: signature.version,
    text: cleartext.text,
    warnings: frameWarnings(cleartext),
  };
}

/**
 * Builds the verdict for one signature and signer.
 * @param match - Signature and signer
 * @param certificate - Checked certificate
 * @param cleartext - The parsed message
 * @param expected - Normalized expected fingerprint
 * @returns {OpenPGPVerification} The verdict
 */
function verdictOf(
  match: Match,
  certificate: CertificateState,
  cleartext: Cleartext,
  expected: string | undefined,
): OpenPGPVerification {
  const { signature, signer } = match;
  const verdict = judge(match, certificate, cleartext.canonical);
  const primaryFingerprint = upper(certificate.primary.key.fingerprint);
  const signingFingerprint = upper(signer.key.fingerprint);
  const issuer = issuerOf(signature);
  return {
    ...verdict,
    identity: identityOf(expected, [primaryFingerprint, signingFingerprint]),
    primaryFingerprint,
    signingFingerprint,
    ...(issuer === undefined ? {} : { issuer }),
    created: iso(signature.created),
    hash: hashName(signature.hashId),
    algorithm: describeKey(signer.key),
    version: signature.version,
    text: cleartext.text,
    warnings: warningsOf(match, certificate, cleartext),
  };
}

/**
 * Judges the certificate as of each signature's time, once per time, on one shared budget.
 * @param certificate - The certificate
 * @returns {(at: number) => CertificateState} The state at a time, seconds since 1970
 */
function statesOf(certificate: Certificate): (at: number) => CertificateState {
  const budget = createBudget();
  const states = new Map<number, CertificateState>();
  return (at) => {
    const known = states.get(at);
    if (known !== undefined) return known;
    const state = evaluateCertificate(certificate, { at, budget });
    states.set(at, state);
    return state;
  };
}

/**
 * Verifies a cleartext signed message, with math, identity and warnings as separate answers.
 * @param message - The whole `-----BEGIN PGP SIGNED MESSAGE-----` message
 * @param options - The armored public key, and the fingerprint you expect it to have
 * @returns {OpenPGPVerification} Verdict, identity, fingerprints and warnings
 * @throws {TypeError} For a malformed argument, a private key or a signature that isn't over text
 * @throws {RangeError} For a version, algorithm or hash this module doesn't support
 * @example
 * verify(signedMessage, { publicKey, fingerprint: "8246 3E7D ..." }).state; // "valid"
 */
export function verify(
  message: string,
  options: Readonly<OpenPGPVerifyOptions>,
): OpenPGPVerification {
  assertOptions(options, "verify(message, { publicKey, fingerprint })");
  if (typeof message !== "string") throw new TypeError("Message must be a string");
  if (typeof options?.publicKey !== "string")
    throw new TypeError("Public key must be an armored string");
  const expected =
    options.fingerprint === undefined ? undefined : readFingerprint(options.fingerprint);
  const cleartext = readCleartext(message);
  const signatures = readSignatures(cleartext.signature);
  const certificate = readCertificate(readArmor(options.publicKey, "PUBLIC KEY BLOCK"));
  const stateAt = statesOf(certificate);
  const verdicts = signatures.flatMap((signature) => {
    const state = stateAt(signature.created);
    return matchesOf([signature], state).map((match) =>
      verdictOf(match, state, cleartext, expected),
    );
  });
  const best =
    verdicts.find((verdict) => verdict.state === "valid") ??
    verdicts.find((verdict) => verdict.state === "inconclusive") ??
    verdicts[0];
  return best ?? strangerVerdict(signatures, certificate, cleartext, expected);
}
