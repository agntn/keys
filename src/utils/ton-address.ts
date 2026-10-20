import { base64 } from "@agntn/encodings/base64";
import { crc16Xmodem, sha256 } from "@agntn/hashes";
import { concatBytes } from "./bytes.ts";

/** Wallet contracts whose address keys can write, oldest first. */
export const TON_WALLET_VERSIONS = ["v3r2", "v4r2", "v5r1"] as const;

/** A wallet contract version. */
export type TonWalletVersion = (typeof TON_WALLET_VERSIONS)[number];

/** What the state init needs from a code cell: its depth and representation hash. */
interface CodeCell {
  readonly depth: number;
  readonly hash: string;
}

/** The address hashes only the depth and hash of a contract's code, so no BOC ships here. */
const WALLET_CODE: Readonly<Record<TonWalletVersion, CodeCell>> = {
  v3r2: { depth: 0, hash: "84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599" },
  v4r2: { depth: 7, hash: "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0" },
  v5r1: { depth: 6, hash: "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f" },
};

/** Subwallet ID of v3 and v4 on the basechain, the same on mainnet and testnet. */
const SUBWALLET_ID = 698_983_191;

/** v5r1 wallet IDs: a client context on the basechain, XORed with the network's global ID. */
const V5_WALLET_ID: Readonly<Record<"mainnet" | "testnet", number>> = {
  mainnet: 0x7f_ff_ff_11,
  testnet: 0x7f_ff_ff_fd,
};

/** Flag byte of a user-friendly address that bounces a transfer to an uninitialized account. */
const BOUNCEABLE = 0x11;

/** Flag byte of a user-friendly address that does not bounce. */
const NON_BOUNCEABLE = 0x51;

/** Bit of the flag byte that marks an address for testnet. */
const TEST_ONLY = 0x80;

/** A raw address: workchain, a colon and the 32-byte account ID in hex. */
const RAW_ADDRESS = /^(0|-1):([0-9A-Fa-f]{64})$/u;

/** A user-friendly address in either base64 alphabet. */
const FRIENDLY_ADDRESS = /^[A-Za-z0-9_\-+/]{48}$/u;

/** How a user-friendly address is written. */
export interface TonAddressForm {
  /** Whether a transfer to an uninitialized account bounces back. */
  readonly bounceable: boolean;
  /** Whether the address carries the testnet flag. */
  readonly testnet: boolean;
}

/** An address read back: the account it names and the form it came in. */
export interface TonAddress extends Partial<TonAddressForm> {
  /** 0 for the basechain, -1 for the masterchain. */
  readonly workchain: number;
  /** The 32-byte account ID, the hash of the account's state init. */
  readonly hash: Uint8Array;
}

/**
 * Writes an unsigned integer big-endian into the bit string of a cell.
 * @param value - The integer
 * @param width - Bits to take
 * @returns {string} The bits as `0` and `1`
 */
function uintBits(value: number, width: number): string {
  return value.toString(2).padStart(width, "0");
}

/**
 * Hashes an ordinary cell from its bits and references, as TVM's representation hash.
 * @param bits - Data bits as `0` and `1`, at most 1023
 * @param refs - Depth and hash of each referenced cell
 * @returns {Uint8Array} The 32-byte cell hash
 */
function cellHash(bits: string, refs: readonly CodeCell[]): Uint8Array {
  const whole = Math.floor(bits.length / 8);
  const padded = bits.length % 8 === 0 ? bits : `${bits}1`.padEnd((whole + 1) * 8, "0");
  const data = Uint8Array.from(padded.match(/.{8}/gu) ?? [], (byte) => Number.parseInt(byte, 2));
  const descriptors = Uint8Array.of(refs.length, whole + Math.ceil(bits.length / 8));
  const depths = refs.map(({ depth }) => Uint8Array.of(depth >> 8, depth & 0xff));
  const hashes = refs.map(({ hash }) => Uint8Array.fromHex(hash));
  return sha256(concatBytes(descriptors, data, ...depths, ...hashes));
}

/**
 * Writes the data cell a wallet deploys with: seqno 0, its ID and the key, versions' own flags.
 * @param version - Wallet contract
 * @param keyPublic - 32-byte ed25519 public key
 * @param network - Network, which only v5r1 folds into its wallet ID
 * @returns {string} The bits as `0` and `1`
 */
function walletData(
  version: TonWalletVersion,
  keyPublic: Uint8Array,
  network: "mainnet" | "testnet",
): string {
  const key = Array.from(keyPublic, (byte) => uintBits(byte, 8)).join("");
  if (version === "v5r1") return `1${uintBits(0, 32)}${uintBits(V5_WALLET_ID[network], 32)}${key}0`;
  const head = `${uintBits(0, 32)}${uintBits(SUBWALLET_ID, 32)}${key}`;
  return version === "v4r2" ? `${head}0` : head;
}

/**
 * Hashes a fresh wallet's state init: `00110` is code and data, no split depth, special or library.
 * @param keyPublic - 32-byte ed25519 public key
 * @param options - Wallet contract and network
 * @returns {Uint8Array} The 32-byte account ID on the basechain
 */
export function getTonAccountId(
  keyPublic: Uint8Array,
  options: { readonly version: TonWalletVersion; readonly network: "mainnet" | "testnet" },
): Uint8Array {
  const { version, network } = options;
  const data = { depth: 0, hash: cellHash(walletData(version, keyPublic, network), []).toHex() };
  return cellHash("00110", [WALLET_CODE[version], data]);
}

/**
 * Writes a basechain account as a user-friendly address: flags, workchain, ID and CRC16, base64url.
 * @param accountId - 32-byte account ID
 * @param form - Bounceable or not, and the testnet flag
 * @returns {string} The 48-character address, `UQ` or `EQ` on mainnet
 */
export function encodeTonAddress(accountId: Uint8Array, form: TonAddressForm): string {
  const flag = (form.bounceable ? BOUNCEABLE : NON_BOUNCEABLE) | (form.testnet ? TEST_ONLY : 0);
  const body = concatBytes(Uint8Array.of(flag, 0), accountId);
  return base64.encode(concatBytes(body, crc16Xmodem(body)), { alphabet: "url" });
}

/**
 * Decodes the 36 bytes of a user-friendly address and checks their CRC16.
 * @param address - 48 characters of base64 in either alphabet
 * @returns {Uint8Array | undefined} The 36 bytes, undefined for bad base64 or a failed checksum
 */
function friendlyBytes(address: string): Uint8Array | undefined {
  if (!FRIENDLY_ADDRESS.test(address)) return undefined;
  let bytes: Uint8Array;
  try {
    bytes = base64.decode(address, { alphabet: /[+/]/u.test(address) ? "standard" : "url" });
  } catch {
    return undefined;
  }
  const checksum = crc16Xmodem(bytes.subarray(0, 34));
  return checksum[0] === bytes[34] && checksum[1] === bytes[35] ? bytes : undefined;
}

/**
 * Reads the user-friendly form: 36 bytes whose CRC16 holds and whose flags TON defines.
 * @param address - 48 characters of base64 in either alphabet
 * @returns {TonAddress | undefined} The account and form, undefined for anything else
 */
function readFriendly(address: string): TonAddress | undefined {
  const bytes = friendlyBytes(address);
  if (bytes === undefined) return undefined;
  const [flag = 0, workchain = 0] = bytes;
  const tag = flag & ~TEST_ONLY;
  if (tag !== BOUNCEABLE && tag !== NON_BOUNCEABLE) return undefined;
  if (workchain !== 0 && workchain !== 0xff) return undefined;
  return {
    workchain: workchain === 0xff ? -1 : 0,
    hash: bytes.slice(2, 34),
    bounceable: tag === BOUNCEABLE,
    testnet: flag !== tag,
  };
}

/**
 * Reads a TON address in its raw form, `0:` and hex, or its user-friendly form.
 * @param address - The address
 * @returns {TonAddress | undefined} The account and its form, undefined for anything else
 */
export function decodeTonAddress(address: string): TonAddress | undefined {
  const raw = RAW_ADDRESS.exec(address);
  if (raw === null) return readFriendly(address);
  const [, workchain = "0", hash = ""] = raw;
  return { workchain: Number(workchain), hash: Uint8Array.fromHex(hash) };
}
