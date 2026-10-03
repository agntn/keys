import { segwit } from "@agntn/encodings/bech32";
import { Bitcoin } from "../../blockchains/bitcoin.ts";
import { taggedHash } from "../address.ts";
import { concatBytes } from "../bytes.ts";
import { decodeBase58Check } from "../encoding.ts";
import { transactionId, type Transaction } from "./transaction.ts";

/** Address types BIP322 names, `witness` for a SegWit version past Taproot. */
export type ChallengeType = "legacy" | "p2sh" | "segwit" | "p2wsh" | "taproot" | "witness";

/** The script an address pays to, which a BIP322 signature has to spend. */
export interface Challenge {
  readonly type: ChallengeType;
  /** scriptPubKey, the `message_challenge` of `to_spend`. */
  readonly script: Uint8Array;
  /** Hash or witness program the script commits to. */
  readonly program: Uint8Array;
}

/** Networks Bitcoin addresses come in. */
export type ChallengeNetwork = "mainnet" | "testnet";

const OP_0 = 0x00;
const OP_1 = 0x51;
const OP_RETURN = 0x6a;
const OP_DUP = 0x76;
const OP_EQUAL = 0x87;
const OP_EQUALVERIFY = 0x88;
const OP_HASH160 = 0xa9;
const OP_CHECKSIG = 0xac;

/**
 * P2PKH script, also the script code a P2WPKH input signs.
 * @param hash - HASH160 of the public key
 * @returns {Uint8Array} `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`
 */
export function p2pkhScript(hash: Uint8Array): Uint8Array {
  return concatBytes(
    Uint8Array.of(OP_DUP, OP_HASH160, hash.length),
    hash,
    Uint8Array.of(OP_EQUALVERIFY, OP_CHECKSIG),
  );
}

/**
 * SegWit output script.
 * @param version - Witness version, 0 to 16
 * @param program - Witness program
 * @returns {Uint8Array} `OP_n <program>`
 */
export function witnessScript(version: number, program: Uint8Array): Uint8Array {
  const opcode = version === 0 ? OP_0 : OP_1 + version - 1;
  return concatBytes(Uint8Array.of(opcode, program.length), program);
}

/**
 * Reads the script a Bitcoin address pays to.
 * @param address - Bitcoin address
 * @param network - Network the address must belong to
 * @returns {Challenge} Its type, script and program
 * @throws {TypeError} When the address is not a valid address on that network
 */
export function challengeOf(address: string, network: ChallengeNetwork): Challenge {
  const future = futureWitness(address, network);
  if (future !== undefined) return future;
  if (!new Bitcoin({ network }).validateAddress(address)) {
    throw new TypeError(`Address is not a valid bitcoin ${network} address`);
  }
  const hrp = network === "mainnet" ? "bc1" : "tb1";
  if (address.toLowerCase().startsWith(hrp)) {
    const { version, program } = segwit.decode(address);
    return {
      type: witnessType(version, program.length),
      script: witnessScript(version, program),
      program,
    };
  }
  const hash = decodeBase58Check(address).subarray(1);
  if (/^[23]/u.test(address)) {
    const script = concatBytes(
      Uint8Array.of(OP_HASH160, hash.length),
      hash,
      Uint8Array.of(OP_EQUAL),
    );
    return { type: "p2sh", script, program: hash };
  }
  return { type: "legacy", script: p2pkhScript(hash), program: hash };
}

/**
 * Reads a BIP350 address of SegWit version 2 to 16, which the chain class refuses to validate.
 * @param address - Bitcoin address
 * @param network - Network the address must belong to
 * @returns {Challenge | undefined} The challenge, undefined for any other address
 */
function futureWitness(address: string, network: ChallengeNetwork): Challenge | undefined {
  try {
    const { prefix, version, program } = segwit.decode(address);
    const hrp = network === "mainnet" ? "bc" : "tb";
    if (prefix !== hrp || version < 2 || program.length < 2 || program.length > 40)
      return undefined;
    return { type: "witness", script: witnessScript(version, program), program };
  } catch {
    return undefined;
  }
}

/**
 * Names the output type of a witness program.
 * @param version - Witness version
 * @param length - Program length in bytes
 * @returns {ChallengeType} segwit, p2wsh, taproot or witness
 */
function witnessType(version: number, length: number): ChallengeType {
  if (version === 0) return length === 20 ? "segwit" : "p2wsh";
  return version === 1 ? "taproot" : "witness";
}

/**
 * Tagged hash of the message, the `message_hash` that `to_spend` commits to.
 * @param message - Message as text, read as UTF-8, or bytes
 * @returns {Uint8Array} 32-byte digest
 */
export function messageHash(message: string | Uint8Array): Uint8Array {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  return taggedHash("BIP0322-signed-message", bytes);
}

/**
 * The virtual `to_spend`: an input pushing the message hash, an output paying the address.
 * @param message - Signed message
 * @param challenge - Script of the address
 * @returns {Transaction} `to_spend`
 */
export function toSpend(message: string | Uint8Array, challenge: Readonly<Challenge>): Transaction {
  const scriptSig = concatBytes(Uint8Array.of(OP_0, 32), messageHash(message));
  return {
    version: 0,
    inputs: [{ txid: new Uint8Array(32), vout: 0xffffffff, scriptSig, sequence: 0, witness: [] }],
    outputs: [{ value: 0n, script: challenge.script }],
    lockTime: 0,
  };
}

/** What a full signature may set on `to_sign`; a simple one leaves all of it at zero or empty. */
export interface ToSignFields {
  readonly version?: number;
  readonly lockTime?: number;
  readonly sequence?: number;
  readonly scriptSig?: Uint8Array;
  readonly witness?: readonly Uint8Array[];
}

/** The one output every `to_sign` has: nothing paid to `OP_RETURN`. */
export const TO_SIGN_OUTPUT = { value: 0n, script: Uint8Array.of(OP_RETURN) } as const;

/**
 * The virtual `to_sign` transaction, spending output 0 of `to_spend`.
 * @param spend - `to_spend`
 * @param fields - Version, lock time, sequence, scriptSig and witness of the signature
 * @returns {Transaction} `to_sign`
 */
export function toSign(
  spend: Readonly<Transaction>,
  fields: Readonly<ToSignFields> = {},
): Transaction {
  return {
    version: fields.version ?? 0,
    inputs: [
      {
        txid: transactionId(spend),
        vout: 0,
        scriptSig: fields.scriptSig ?? new Uint8Array(0),
        sequence: fields.sequence ?? 0,
        witness: fields.witness ?? [],
      },
    ],
    outputs: [TO_SIGN_OUTPUT],
    lockTime: fields.lockTime ?? 0,
  };
}
