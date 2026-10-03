import { sha256 } from "@agntn/hashes";
import { schnorr } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import { Bitcoin } from "../../blockchains/bitcoin.ts";
import { hash160 } from "../address.ts";
import {
  TO_SIGN_OUTPUT,
  challengeOf,
  p2pkhScript,
  toSign,
  toSpend,
  type Challenge,
  type ChallengeNetwork,
  type ChallengeType,
} from "./challenge.ts";
import { isStrictPublicKey, push, readPushes, splitEcdsa, verifyEcdsa } from "./script.ts";
import {
  SIGHASH_ALL,
  SIGHASH_DEFAULT,
  legacySighash,
  segwitSighash,
  taprootSighash,
} from "../transaction/sighash.ts";
import { scriptPathMismatch, withoutAnnex } from "./taproot.ts";
import {
  decodeTransaction,
  decodeWitness,
  serializeTransaction,
  transactionId,
  type Transaction,
  type TransactionInput,
  type TransactionOutput,
} from "../transaction/transaction.ts";

/** What a verifier concludes: BIP322's valid, invalid and inconclusive. */
export type BIP322State = "valid" | "invalid" | "inconclusive";

/** How the signature was encoded: `smp`, `ful` or `pof`, or Core's base64 for legacy. */
export type BIP322Format = "legacy" | "simple" | "full" | "proof-of-funds";

/** The verdict on a BIP322 signature. */
export interface BIP322Verification {
  readonly state: BIP322State;
  readonly format: BIP322Format;
  /** Type of the address: legacy, p2sh, segwit, p2wsh, taproot, or witness for a later version. */
  readonly addressType: ChallengeType;
  /** Why the signature is invalid or inconclusive. */
  readonly reason?: string;
  /** Key the signature checks against: the SEC1 key it carries, or Taproot's x-only output key. */
  readonly publicKey?: string;
  /** `nLockTime` of `to_sign`, the time T a valid signature is valid at. */
  readonly lockTime?: number;
  /** `nSequence` of its first input, the age S. */
  readonly sequence?: number;
}

/** Network the address belongs to. */
export interface BIP322Options {
  /** Default: mainnet. */
  readonly network?: ChallengeNetwork;
}

/** A checked input: the key behind a valid signature, or why it fails. */
type Outcome =
  | { readonly state: "valid"; readonly publicKey: string }
  | { readonly state: "invalid" | "inconclusive"; readonly reason: string };

/** A signature split from its prefix, or why it could not be read. */
type Decoded =
  | { readonly format: BIP322Format; readonly bytes: Uint8Array; readonly prefixed: boolean }
  | { readonly format: BIP322Format; readonly reason: string };

const PREFIXES: Readonly<Record<string, BIP322Format>> = {
  smp: "simple",
  ful: "full",
  pof: "proof-of-funds",
};

/** Header bytes Core's `signmessage` writes, 27 to 34, and the BIP137 ones up to 42. */
const LEGACY_HEADERS = { first: 27, last: 42 } as const;

/**
 * Reads the network option.
 * @param network - Option value
 * @returns {ChallengeNetwork} mainnet unless testnet is named
 */
function readNetwork(network: unknown): ChallengeNetwork {
  if (network === undefined) return "mainnet";
  if (network === "mainnet" || network === "testnet") return network;
  throw new RangeError("Network must be mainnet or testnet");
}

/**
 * Tells Core's 65-byte signature from an unprefixed witness stack.
 * @param bytes - Decoded signature
 * @returns {boolean} True for a header byte, then `r` and `s`
 */
function isLegacy(bytes: Uint8Array): boolean {
  const header = bytes[0] ?? 0;
  return bytes.length === 65 && header >= LEGACY_HEADERS.first && header <= LEGACY_HEADERS.last;
}

/**
 * Splits the variant prefix from the base64; a prefix always wins. Without one it reads as simple,
 * or as Core's legacy signature when the address is P2PKH.
 * @param signature - Signature text
 * @param legacyAddress - Whether the address is P2PKH
 * @returns {Decoded} Format and bytes, or why the text is not base64
 */
function decodeSignature(signature: string, legacyAddress: boolean): Decoded {
  const prefix = signature.slice(0, 3);
  const named = Object.hasOwn(PREFIXES, prefix) ? PREFIXES[prefix] : undefined;
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.fromBase64(named === undefined ? signature : signature.slice(3));
  } catch {
    return { format: named ?? "simple", reason: "Signature is not base64" };
  }
  if (named !== undefined) return { format: named, bytes, prefixed: true };
  const legacy = legacyAddress && isLegacy(bytes);
  return { format: legacy ? "legacy" : "simple", bytes, prefixed: false };
}

/**
 * Checks Core's `signmessage` signature, which BIP322 keeps for P2PKH only.
 * @param address - P2PKH address
 * @param message - Signed message
 * @param signature - Base64 of a header byte, then `r` and `s`
 * @param network - Network of the address
 * @returns {Outcome} The key that signed, or why it does not hold the address
 */
function checkLegacy(
  address: string,
  message: string | Uint8Array,
  signature: string,
  network: ChallengeNetwork,
): Outcome {
  const bitcoin = new Bitcoin({ network });
  let signer: ReturnType<Bitcoin["recoverMessageSigner"]>;
  try {
    signer = bitcoin.recoverMessageSigner(message, signature);
  } catch (error) {
    return invalid(error instanceof Error ? error.message : String(error));
  }
  if (signer.addressType !== "legacy") {
    return invalid(`Header byte names a ${signer.addressType} key, not P2PKH`);
  }
  if (bitcoin.getAddress(signer.publicKey, "legacy") !== address) {
    return invalid("Signature recovers a key that does not hold the address");
  }
  return { state: "valid", publicKey: signer.publicKey };
}

/**
 * An invalid verdict.
 * @param reason - The rule the signature breaks
 * @returns {Outcome} The verdict
 */
function invalid(reason: string): Outcome {
  return { state: "invalid", reason };
}

/**
 * An inconclusive verdict.
 * @param reason - What the verifier cannot check
 * @returns {Outcome} The verdict
 */
function inconclusive(reason: string): Outcome {
  return { state: "inconclusive", reason };
}

/**
 * Names the reason a decoder threw, after the part that failed.
 * @param part - What was being decoded
 * @param error - What the decoder threw
 * @returns {Outcome} An invalid verdict
 */
function undecodable(part: string, error: unknown): Outcome {
  return invalid(`${part} ${error instanceof Error ? error.message : "does not decode"}`);
}

/**
 * Checks an ECDSA signature from a script: `SIGHASH_ALL`, strict DER, low S and the sighash.
 * @param signature - DER signature, then its hash type byte
 * @param publicKey - SEC1 key the script pairs it with
 * @param digest - Sighash of the input
 * @returns {Outcome} The key, or the rule the signature breaks
 */
function checkEcdsa(signature: Uint8Array, publicKey: Uint8Array, digest: Uint8Array): Outcome {
  const { der, hashType } = splitEcdsa(signature);
  if (hashType !== SIGHASH_ALL) return invalid("Signature must use SIGHASH_ALL");
  if (!verifyEcdsa(der, digest, publicKey)) return invalid("ECDSA signature does not verify");
  return { state: "valid", publicKey: publicKey.toHex() };
}

/**
 * Splits a signature and a key out of two stack items.
 * @param items - Witness or scriptSig pushes
 * @returns {[Uint8Array, Uint8Array] | undefined} The pair, undefined unless exactly two items
 */
function signatureAndKey(items: readonly Uint8Array[]): [Uint8Array, Uint8Array] | undefined {
  const [signature, publicKey] = items;
  if (items.length !== 2 || signature === undefined || publicKey === undefined) return undefined;
  return [signature, publicKey];
}

/**
 * Checks a P2WPKH spend: a low S `SIGHASH_ALL` signature and the compressed key it hashes.
 * @param transaction - `to_sign`
 * @param keyHash - The 20-byte witness program
 * @returns {Outcome} The key, or the rule the witness breaks
 */
function checkWitnessKeyHash(transaction: Readonly<Transaction>, keyHash: Uint8Array): Outcome {
  const pair = signatureAndKey(transaction.inputs[0]?.witness ?? []);
  if (pair === undefined) return invalid("P2WPKH witness must hold a signature and a public key");
  const [signature, publicKey] = pair;
  if (!isStrictPublicKey(publicKey, true)) {
    return invalid("P2WPKH witness key must be 33 bytes, compressed");
  }
  if (!equalBytes(hash160(publicKey), keyHash)) {
    return invalid("Witness key does not hash to the address");
  }
  return checkEcdsa(signature, publicKey, segwitSighash(transaction, 0, p2pkhScript(keyHash), 0n));
}

/**
 * Checks a native SegWit v0 key hash spend, which leaves the scriptSig empty.
 * @param transaction - `to_sign`
 * @param challenge - The P2WPKH address
 * @returns {Outcome} The key, or the rule the input breaks
 */
function checkSegwit(transaction: Readonly<Transaction>, challenge: Readonly<Challenge>): Outcome {
  if ((transaction.inputs[0]?.scriptSig.length ?? 0) > 0) {
    return invalid("A native SegWit input must have an empty scriptSig");
  }
  return checkWitnessKeyHash(transaction, challenge.program);
}

/**
 * Reads a redeem script that BIP141 treats as a witness program: `OP_0` to `OP_16`, 2 to 40 bytes.
 * @param redeem - Redeem script
 * @returns {{ version: number; program: Uint8Array } | undefined} The program, undefined otherwise
 */
function nestedProgram(redeem: Uint8Array): { version: number; program: Uint8Array } | undefined {
  const opcode = redeem[0] ?? -1;
  const length = redeem[1] ?? 0;
  const version = opcode === 0 ? 0 : opcode - 0x50;
  const wraps = version >= 0 && version <= 16 && length >= 2 && length <= 40;
  return wraps && redeem.length === length + 2
    ? { version, program: redeem.subarray(2) }
    : undefined;
}

/**
 * Checks the witness a wrapped program asks for; version 0 must be 20 or 32 bytes.
 * @param transaction - `to_sign`
 * @param nested - Version and program of the redeem script
 * @returns {Outcome} The verdict on the witness
 */
function checkNestedProgram(
  transaction: Readonly<Transaction>,
  nested: Readonly<{ version: number; program: Uint8Array }>,
): Outcome {
  if (nested.version > 0) {
    return inconclusive(
      "Witness programs other than version 0 and Taproot are reserved for upgrades",
    );
  }
  if (nested.program.length === 20) return checkWitnessKeyHash(transaction, nested.program);
  if (nested.program.length === 32) return checkWitnessScript(transaction, nested.program);
  return invalid("A version 0 witness program must be 20 or 32 bytes");
}

/**
 * Checks P2SH-P2WPKH: the scriptSig pushes the redeem script the address hashes, then the witness.
 * @param transaction - `to_sign`
 * @param challenge - The P2SH address
 * @returns {Outcome} The key, or the rule the input breaks
 */
function checkNested(transaction: Readonly<Transaction>, challenge: Readonly<Challenge>): Outcome {
  const read = readPushes(transaction.inputs[0]?.scriptSig ?? new Uint8Array(0));
  if ("reason" in read) return invalid(`BIP16: ${read.reason}`);
  const redeem = read.pushes.at(-1);
  if (redeem === undefined || !equalBytes(hash160(redeem), challenge.program)) {
    return invalid("scriptSig does not end with a redeem script the address hashes");
  }
  const nested = nestedProgram(redeem);
  if (nested === undefined) return checkLegacyScript(transaction);
  if (read.pushes.length !== 1) {
    return invalid("A wrapped SegWit scriptSig must push just the redeem script");
  }
  return checkNestedProgram(transaction, nested);
}

/**
 * Checks a P2SH spend whose redeem script wraps no SegWit, which leaves no room for a witness.
 * @param transaction - `to_sign`
 * @returns {Outcome} Invalid with a witness, inconclusive otherwise
 */
function checkLegacyScript(transaction: Readonly<Transaction>): Outcome {
  if ((transaction.inputs[0]?.witness.length ?? 0) > 0) {
    return invalid("A P2SH spend that wraps no SegWit carries no witness");
  }
  return inconclusive("P2SH scripts other than wrapped SegWit need a script interpreter");
}

/**
 * Checks what a P2WSH spend commits to: the last witness item hashes to the program. Stack and
 * script size limits belong to execution, so a spend past them stays inconclusive, never valid.
 * @param transaction - `to_sign`
 * @param scriptHash - The 32-byte witness program
 * @returns {Outcome} Invalid on a broken commitment, inconclusive otherwise
 */
function checkWitnessScript(transaction: Readonly<Transaction>, scriptHash: Uint8Array): Outcome {
  const script = transaction.inputs[0]?.witness.at(-1);
  if (script === undefined) return invalid("P2WSH witness is empty");
  if (!equalBytes(sha256(script), scriptHash)) {
    return invalid("Witness script does not hash to the address");
  }
  return inconclusive("P2WSH scripts need a script interpreter");
}

/**
 * Checks the parts of a native SegWit spend that need no interpreter: an empty scriptSig, then
 * the P2WSH commitment; a version past 1 stays inconclusive by the upgradeable rule.
 * @param transaction - `to_sign`
 * @param challenge - The P2WSH address or the later witness version
 * @returns {Outcome} Invalid on a broken rule, inconclusive otherwise
 */
function checkWitnessProgram(
  transaction: Readonly<Transaction>,
  challenge: Readonly<Challenge>,
): Outcome {
  if ((transaction.inputs[0]?.scriptSig.length ?? 0) > 0) {
    return invalid("A native SegWit input must have an empty scriptSig");
  }
  if (challenge.type === "p2wsh") return checkWitnessScript(transaction, challenge.program);
  return inconclusive(
    "Witness programs other than version 0 and Taproot are reserved for upgrades",
  );
}

/**
 * Checks a P2PKH spend: a scriptSig pushing a `SIGHASH_ALL` signature and the hashed key.
 * @param transaction - `to_sign`
 * @param challenge - The P2PKH address
 * @returns {Outcome} The key, or the rule the input breaks
 */
function checkKeyHash(transaction: Readonly<Transaction>, challenge: Readonly<Challenge>): Outcome {
  const input = transaction.inputs[0];
  if (input === undefined || input.witness.length > 0) {
    return invalid("A P2PKH input carries no witness");
  }
  const read = readPushes(input.scriptSig);
  if ("reason" in read) return read;
  const pair = signatureAndKey(read.pushes);
  if (pair === undefined) return invalid("P2PKH scriptSig must push a signature and a public key");
  const [signature, publicKey] = pair;
  if (!isStrictPublicKey(publicKey, false) || !equalBytes(hash160(publicKey), challenge.program)) {
    return invalid("scriptSig key does not hash to the address");
  }
  return checkEcdsa(signature, publicKey, legacySighash(transaction, 0, challenge.script));
}

/**
 * Reads the hash type of a Schnorr signature: implied by 64 bytes, a trailing byte on 65.
 * @param signature - Witness signature
 * @returns {number | undefined} `SIGHASH_DEFAULT` or `SIGHASH_ALL`, undefined for any other
 */
function taprootHashType(signature: Uint8Array): number | undefined {
  if (signature.length === 64) return SIGHASH_DEFAULT;
  return signature.length === 65 && signature[64] === SIGHASH_ALL ? SIGHASH_ALL : undefined;
}

/**
 * Takes the signature of a key path spend; a script path only gets its commitment checked.
 * @param input - First input of `to_sign`
 * @param outputKey - x-only output key the address holds
 * @returns {Uint8Array | Outcome} The signature, or why the input is no key path spend
 */
function keyPathSignature(
  input: Readonly<TransactionInput> | undefined,
  outputKey: Uint8Array,
): Uint8Array | Outcome {
  if (input === undefined || input.scriptSig.length > 0) {
    return invalid("A native SegWit input must have an empty scriptSig");
  }
  const stack = withoutAnnex(input.witness);
  const [signature] = stack;
  if (signature === undefined) return invalid("Taproot witness is empty");
  if (stack.length > 1) {
    const mismatch = scriptPathMismatch(stack, outputKey);
    if (mismatch !== undefined) return invalid(mismatch);
    return inconclusive("Taproot script paths need a script interpreter");
  }
  if (stack.length < input.witness.length) return inconclusive("Taproot annexes are not read");
  return signature;
}

/**
 * Checks a Taproot key path spend against the output key the address holds.
 * @param transaction - `to_sign`
 * @param challenge - The P2TR address
 * @returns {Outcome} The output key, or the rule the witness breaks
 */
function checkTaproot(transaction: Readonly<Transaction>, challenge: Readonly<Challenge>): Outcome {
  const signature = keyPathSignature(transaction.inputs[0], challenge.program);
  if (!(signature instanceof Uint8Array)) return signature;
  const hashType = taprootHashType(signature);
  if (hashType === undefined) return invalid("Signature must use SIGHASH_DEFAULT or SIGHASH_ALL");
  const spent = [{ value: 0n, script: challenge.script }];
  const digest = taprootSighash(transaction, 0, spent, hashType);
  if (!schnorr.verify(signature.subarray(0, 64), digest, challenge.program)) {
    return invalid("Schnorr signature does not verify");
  }
  return { state: "valid", publicKey: challenge.program.toHex() };
}

/**
 * Checks the first input of `to_sign` by the script of the address. Inconclusive comes only
 * after every rule that needs no script execution, push only, witness placement and commitments.
 * @param transaction - `to_sign`
 * @param challenge - The address
 * @returns {Outcome} The verdict on its spend
 */
function checkInput(transaction: Readonly<Transaction>, challenge: Readonly<Challenge>): Outcome {
  switch (challenge.type) {
    case "legacy":
      return checkKeyHash(transaction, challenge);
    case "p2sh":
      return checkNested(transaction, challenge);
    case "segwit":
      return checkSegwit(transaction, challenge);
    case "taproot":
      return checkTaproot(transaction, challenge);
    default:
      return checkWitnessProgram(transaction, challenge);
  }
}

/**
 * Builds `to_sign` from a simple signature. An unprefixed one for P2SH-P2WPKH gets the scriptSig
 * its witness key implies, as signers wrote it before the BIP was final.
 * @param spend - `to_spend`
 * @param challenge - The address
 * @param bytes - Serialized witness stack
 * @returns {Transaction | Outcome} `to_sign`, or why the signature cannot make one
 */
function simpleToSign(
  spend: Readonly<Transaction>,
  challenge: Readonly<Challenge>,
  bytes: Uint8Array,
): Transaction | Outcome {
  if (challenge.type === "legacy") {
    return invalid("A P2PKH address has no witness; it takes a full or legacy signature");
  }
  let witness: Uint8Array[];
  try {
    witness = decodeWitness(bytes);
  } catch (error) {
    return undecodable("Witness stack", error);
  }
  const key = witness[1];
  const scriptSig =
    challenge.type === "p2sh" && key !== undefined
      ? push(Uint8Array.of(0, 20, ...hash160(key)))
      : new Uint8Array(0);
  return toSign(spend, { witness, scriptSig });
}

/**
 * Tells the one output `to_sign` must have: nothing paid to `OP_RETURN`.
 * @param outputs - Outputs of the transaction
 * @returns {boolean} True for exactly that output
 */
function hasToSignOutput(outputs: readonly TransactionOutput[]): boolean {
  const [output] = outputs;
  return (
    outputs.length === 1 &&
    output !== undefined &&
    output.value === 0n &&
    equalBytes(output.script, TO_SIGN_OUTPUT.script)
  );
}

/**
 * Checks that a decoded transaction is the `to_sign` of this `to_spend`.
 * @param transaction - Decoded full signature
 * @param spend - `to_spend`
 * @returns {Outcome | undefined} Why it is not, undefined when it is
 */
function shapeOutcome(
  transaction: Readonly<Transaction>,
  spend: Readonly<Transaction>,
): Outcome | undefined {
  const [input] = transaction.inputs;
  if (input === undefined || !equalBytes(input.txid, transactionId(spend)) || input.vout !== 0) {
    return invalid("Transaction does not spend to_spend of this message and address");
  }
  if (!hasToSignOutput(transaction.outputs)) {
    return invalid("Transaction must have one output paying nothing to OP_RETURN");
  }
  const broken = contextFreeBreak(transaction);
  if (broken !== undefined) return invalid(broken);
  if (transaction.inputs.length > 1) {
    return inconclusive("Extra inputs need the outputs they spend, as a proof of funds carries");
  }
  return undefined;
}

/** Largest transaction without witnesses that Core's `CheckTransaction` takes, in bytes. */
const MAX_STRIPPED_SIZE = 1_000_000;

/**
 * Applies the input rules of Core's `CheckTransaction` that need no UTXO; `to_sign` pays one
 * zero output, so the value rules hold already.
 * @param transaction - `to_sign`
 * @returns {string | undefined} The broken rule, undefined when all hold
 */
function contextFreeBreak(transaction: Readonly<Transaction>): string | undefined {
  const outpoints = transaction.inputs.map((input) => `${input.txid.toHex()}:${input.vout}`);
  if (new Set(outpoints).size !== outpoints.length) return "Transaction spends one output twice";
  const nullPrevout = `${"00".repeat(32)}:${0xffffffff}`;
  if (outpoints.includes(nullPrevout)) return "Transaction spends a null prevout";
  if (serializeTransaction(transaction, false).length > MAX_STRIPPED_SIZE) {
    return "Transaction is larger than a block allows";
  }
  return undefined;
}

/**
 * Reads a full signature and checks that it is the `to_sign` of this message and address.
 * @param spend - `to_spend`
 * @param bytes - Serialized `to_sign`
 * @returns {Transaction | Outcome} `to_sign`, or the field that breaks the shape
 */
function fullToSign(spend: Readonly<Transaction>, bytes: Uint8Array): Transaction | Outcome {
  let transaction: Transaction;
  try {
    transaction = decodeTransaction(bytes);
  } catch (error) {
    return undecodable("Transaction", error);
  }
  return shapeOutcome(transaction, spend) ?? transaction;
}

/**
 * Builds `to_sign` for the decoded format.
 * @param spend - `to_spend`
 * @param challenge - The address
 * @param decoded - Format and bytes of the signature
 * @returns {Transaction | Outcome} `to_sign`, or why the signature cannot make one
 */
function signingTransaction(
  spend: Readonly<Transaction>,
  challenge: Readonly<Challenge>,
  decoded: Readonly<{ format: BIP322Format; bytes: Uint8Array; prefixed: boolean }>,
): Transaction | Outcome {
  if (decoded.format === "proof-of-funds") {
    return inconclusive("Proof of funds PSBTs are not read");
  }
  if (decoded.prefixed && decoded.format === "simple" && challenge.type === "p2sh") {
    return invalid("An smp signature is for native SegWit; P2SH takes a full one");
  }
  return decoded.format === "full"
    ? fullToSign(spend, decoded.bytes)
    : simpleToSign(spend, challenge, decoded.bytes);
}

/**
 * Checks `to_sign` and applies BIP322's upgradeable rule on the version after the required ones.
 * @param transaction - `to_sign`
 * @param challenge - The address
 * @returns {BIP322Verification fields} The verdict with time and age on success
 */
function checkTransaction(
  transaction: Readonly<Transaction>,
  challenge: Readonly<Challenge>,
): Omit<BIP322Verification, "format" | "addressType"> {
  const outcome = checkInput(transaction, challenge);
  if (outcome.state !== "valid") return outcome;
  if (transaction.version !== 0 && transaction.version !== 2) {
    return { state: "inconclusive", reason: "to_sign version must be 0 or 2" };
  }
  return {
    state: "valid",
    publicKey: outcome.publicKey,
    lockTime: transaction.lockTime,
    sequence: transaction.inputs[0]?.sequence ?? 0,
  };
}

/**
 * Verifies a BIP322 signature by a Bitcoin address. P2WPKH, P2TR key path, P2SH-P2WPKH and P2PKH
 * get the full check; scripts that need an interpreter and proof of funds come back inconclusive.
 * @param address - Bitcoin address that signed
 * @param message - Message as text, read as UTF-8, or bytes
 * @param signature - Signature text, prefixed `smp`, `ful` or `pof`, or Core's base64
 * @param options - Network of the address
 * @returns {BIP322Verification} Valid, invalid or inconclusive, with the reason when not valid
 * @throws {TypeError} When the address is not a valid Bitcoin address on the network
 */
export function verify(
  address: string,
  message: string | Uint8Array,
  signature: string,
  options: Readonly<BIP322Options> = {},
): BIP322Verification {
  const network = readNetwork(options.network);
  if (typeof signature !== "string") throw new TypeError("Signature must be a string");
  if (typeof message !== "string" && !(message instanceof Uint8Array)) {
    throw new TypeError("Message must be a string or bytes");
  }
  const challenge = challengeOf(address, network);
  const decoded = decodeSignature(signature, challenge.type === "legacy");
  const base = { format: decoded.format, addressType: challenge.type };
  if ("reason" in decoded) return { ...base, state: "invalid", reason: decoded.reason };
  if (decoded.format === "legacy") {
    return { ...base, ...checkLegacy(address, message, signature, network) };
  }
  const spend = toSpend(message, challenge);
  const transaction = signingTransaction(spend, challenge, decoded);
  if ("state" in transaction) return { ...base, ...transaction };
  return { ...base, ...checkTransaction(transaction, challenge) };
}
