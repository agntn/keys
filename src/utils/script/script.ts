import { sha256 } from "@agntn/hashes";
import { segwit } from "@agntn/encodings/bech32";
import { hash160 } from "../address.ts";
import { concatBytes } from "../bytes.ts";
import { encodeBase58Check } from "../encoding.ts";
import { decodePublicPoint } from "../secp256k1/decode.ts";
import { pushOf } from "../transaction/script.ts";
import { MAX_MULTISIG_KEYS, MAX_P2SH_SCRIPT_SIZE, MAX_P2WSH_SCRIPT_SIZE } from "./limits.ts";

/** Bitcoin network an address is written for. */
export type ScriptNetwork = "mainnet" | "testnet";

/** How a script is paid to: hashed into P2SH, into P2WSH, or into P2WSH nested in P2SH. */
export type ScriptAddressType = "p2sh" | "p2wsh" | "p2sh-p2wsh";

/** Network of the address. */
export interface ScriptAddressOptions {
  readonly network?: ScriptNetwork;
}

/** Key order of a multisig script. */
export interface MultisigOptions {
  /** Sort the keys by their bytes, as BIP67 and `sortedmulti` do. */
  readonly sorted?: boolean;
}

/** Address version bytes and the bech32 prefix of each network. */
export const SCRIPT_NETWORKS = {
  mainnet: { p2pkh: 0x00, p2sh: 0x05, hrp: "bc" },
  testnet: { p2pkh: 0x6f, p2sh: 0xc4, hrp: "tb" },
} as const;

const OP_0 = 0x00;
const OP_1 = 0x51;
const OP_EQUAL = 0x87;
const OP_HASH160 = 0xa9;
const OP_CHECKMULTISIG = 0xae;

/**
 * Reads the network option, mainnet unless testnet is named.
 * @param network - Option value
 * @returns {ScriptNetwork} The network
 */
export function readNetwork(network: unknown): ScriptNetwork {
  if (network === undefined) return "mainnet";
  if (network === "mainnet" || network === "testnet") return network;
  throw new RangeError("Network must be mainnet or testnet");
}

/**
 * Pushes a number as Core's `CScript() << n` does: `OP_1` to `OP_16`, else its minimal bytes.
 * @param value - Number from 1 up
 * @returns {Uint8Array} The opcode or the push
 */
export function numberPush(value: number): Uint8Array {
  if (value <= 16) return Uint8Array.of(OP_1 + value - 1);
  const bytes: number[] = [];
  for (let rest = value; rest > 0; rest = Math.floor(rest / 256)) bytes.push(rest % 256);
  if ((bytes.at(-1) ?? 0) >= 0x80) bytes.push(0);
  return pushOf(Uint8Array.from(bytes));
}

/**
 * Orders keys by their bytes, the order BIP67 gives compressed keys.
 * @param keys - Public keys
 * @returns {Uint8Array[]} A sorted copy
 */
export function sortKeys(keys: readonly Uint8Array[]): Uint8Array[] {
  return keys.toSorted((left, right) => (left.toHex() < right.toHex() ? -1 : 1));
}

/**
 * Builds `OP_CHECKMULTISIG` over keys already decoded.
 * @param threshold - Signatures it needs, from 1 to the number of keys
 * @param keys - SEC1 public keys, at most 20
 * @returns {Uint8Array} The script
 */
export function multisigScript(threshold: number, keys: readonly Uint8Array[]): Uint8Array {
  if (keys.length === 0 || keys.length > MAX_MULTISIG_KEYS) {
    throw new RangeError(`Multisig takes 1 to ${MAX_MULTISIG_KEYS} keys`);
  }
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > keys.length) {
    throw new RangeError(`Multisig threshold must be an integer from 1 to ${keys.length}`);
  }
  return concatBytes(
    numberPush(threshold),
    ...keys.map((key) => pushOf(key)),
    numberPush(keys.length),
    Uint8Array.of(OP_CHECKMULTISIG),
  );
}

/**
 * Builds an m-of-n `OP_CHECKMULTISIG`, the script a multisig address hashes.
 * @param threshold - Signatures it needs, from 1 to the number of keys
 * @param publicKeys - Compressed or uncompressed SEC1 keys as hex, 1 to 20 of them
 * @param options - Whether to sort the keys
 * @returns {Uint8Array} The script
 */
export function multisig(
  threshold: number,
  publicKeys: readonly string[],
  options: MultisigOptions = {},
): Uint8Array {
  const keys = publicKeys.map((key) => {
    decodePublicPoint(key);
    return Uint8Array.fromHex(key);
  });
  return multisigScript(threshold, options.sorted === true ? sortKeys(keys) : keys);
}

/**
 * Writes the P2SH address of a redeem script.
 * @param script - Redeem script
 * @param network - Network of the address
 * @returns {string} The base58 address
 */
export function p2shAddress(script: Uint8Array, network: ScriptNetwork): string {
  return encodeBase58Check(
    concatBytes(Uint8Array.of(SCRIPT_NETWORKS[network].p2sh), hash160(script)),
  );
}

/**
 * Writes a witness program as a bech32 or bech32m address.
 * @param version - Witness version, 0 or 1
 * @param program - Witness program
 * @param network - Network of the address
 * @returns {string} The address
 */
export function segwitAddress(
  version: number,
  program: Uint8Array,
  network: ScriptNetwork,
): string {
  return segwit.encode(SCRIPT_NETWORKS[network].hrp, version, program);
}

/**
 * The P2WSH output script that pays to a witness script.
 * @param script - Witness script
 * @returns {Uint8Array} `OP_0` and the script's SHA-256
 */
export function p2wshProgram(script: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(OP_0), pushOf(sha256(script)));
}

/**
 * The P2SH output script that pays to a redeem script.
 * @param script - Redeem script
 * @returns {Uint8Array} `OP_HASH160`, the script's HASH160 and `OP_EQUAL`
 */
export function p2shProgram(script: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(OP_HASH160), pushOf(hash160(script)), Uint8Array.of(OP_EQUAL));
}

/**
 * Refuses a script larger than the wrapper can ever spend.
 * @param script - Redeem or witness script
 * @param type - How it is paid to
 * @returns {void} Nothing; it throws when the script is too large
 */
function assertScriptSize(script: Uint8Array, type: ScriptAddressType): void {
  const limit = type === "p2sh" ? MAX_P2SH_SCRIPT_SIZE : MAX_P2WSH_SCRIPT_SIZE;
  if (script.length > limit) {
    throw new RangeError(
      `${type.toUpperCase()} takes a script of at most ${limit} bytes, this one is ${script.length}`,
    );
  }
}

/**
 * Writes the address that pays to a script: P2SH, P2WSH, or P2WSH nested in P2SH.
 * @param script - Redeem or witness script: 520 bytes at most for P2SH, 10,000 for the others
 * @param type - How the script is paid to
 * @param options - Network of the address
 * @returns {string} The address
 */
export function address(
  script: Uint8Array,
  type: ScriptAddressType,
  options: ScriptAddressOptions = {},
): string {
  const network = readNetwork(options.network);
  if (script.length === 0) throw new RangeError("Script must not be empty");
  assertScriptSize(script, type);
  if (type === "p2sh") return p2shAddress(script, network);
  if (type === "p2wsh") return segwitAddress(0, sha256(script), network);
  if (type === "p2sh-p2wsh") return p2shAddress(p2wshProgram(script), network);
  throw new RangeError("Address type must be p2sh, p2wsh or p2sh-p2wsh");
}
