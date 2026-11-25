import {
  type ProgramAddress,
  MAX_PROGRAM_SEED_LENGTH,
  MAX_PROGRAM_SEEDS,
  TOKEN_PROGRAM,
  createProgramAddress,
  decodeSolanaAddress,
  findProgramAddress,
  getAssociatedTokenAddress,
} from "../utils/solana-pda.ts";
import { BUMP_SCHEMA_PATTERN } from "../tool-parameters.ts";
import {
  HEX_BYTES,
  boundedArray,
  closedObject,
  optionalName,
  requiredString,
} from "./arguments.ts";
import { type ToolResult, content } from "./results.ts";

/** A program address, the bump that made it and whether the bump was searched for. */
export interface SolanaProgramAddressDetails {
  chain: "solana";
  programId: string;
  address: string;
  bump: number;
  canonical: boolean;
}

/** A wallet's token account for one mint. */
export interface SolanaTokenAddressDetails {
  chain: "solana";
  owner: string;
  mint: string;
  tokenProgram: string;
  address: string;
  bump: number;
}

const SEED_KINDS = ["text", "hex", "address", "u64"] as const;

const U64_MAX = 2n ** 64n - 1n;

const BUMP = new RegExp(BUMP_SCHEMA_PATTERN, "u");

/**
 * Writes a decimal u64 as Rust's `to_le_bytes` does.
 * @param value - Decimal digits
 * @returns {Uint8Array} 8 bytes
 */
function u64Bytes(value: string): Uint8Array {
  const number = /^(?:0|[1-9]\d{0,19})$/u.test(value) ? BigInt(value) : U64_MAX + 1n;
  if (number > U64_MAX) throw new RangeError("u64 seed must be a decimal integer below 2^64");
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, number, true);
  return bytes;
}

/**
 * Turns one seed object into its bytes.
 * @param value - Raw seed
 * @param index - Its position, for the error
 * @returns {Uint8Array} The bytes
 */
function seedBytes(value: unknown, index: number): Uint8Array {
  const seed = closedObject(value, { name: `Seed ${index}`, keys: SEED_KINDS });
  const given = SEED_KINDS.filter((kind) => seed[kind] !== undefined);
  const [kind] = given;
  if (kind === undefined || given.length > 1) {
    throw new TypeError(`Seed ${index} takes exactly one of ${SEED_KINDS.join(", ")}`);
  }
  const text = requiredString(seed[kind], `Seed ${index} ${kind}`);
  if (kind === "address") return decodeSolanaAddress(text, `Seed ${index} address`);
  if (kind === "u64") return u64Bytes(text);
  if (kind === "hex" && !HEX_BYTES.test(text)) {
    throw new TypeError(`Seed ${index} hex must be whole bytes of hex without 0x`);
  }
  const bytes = kind === "hex" ? Uint8Array.fromHex(text) : new TextEncoder().encode(text);
  if (bytes.length > MAX_PROGRAM_SEED_LENGTH) {
    throw new RangeError(
      `Seed ${index} is ${bytes.length} bytes, past the ${MAX_PROGRAM_SEED_LENGTH} a seed takes`,
    );
  }
  return bytes;
}

/**
 * Reads an optional bump given as decimal text, blank meaning left out.
 * @param value - Raw bump
 * @returns {number | undefined} The bump
 */
function optionalBump(value: unknown): number | undefined {
  const text = optionalName(value, "bump");
  if (text === undefined) return undefined;
  if (!BUMP.test(text)) throw new RangeError("bump must be decimal text from 0 to 255");
  return Number(text);
}

/** Program address arguments besides the program, raw until the executor checks them. */
export interface SolanaProgramAddressArguments {
  readonly seeds?: unknown;
  readonly bump?: unknown;
}

/**
 * Derives a program address, the canonical one or the one a known bump gives.
 * @param programValue - The program, base58
 * @param options - Seeds and an optional bump
 * @returns {ToolResult<SolanaProgramAddressDetails>} The address and its bump
 */
export function getSolanaProgramAddress(
  programValue: unknown,
  options: SolanaProgramAddressArguments,
): ToolResult<SolanaProgramAddressDetails> {
  const programId = requiredString(programValue, "programId");
  decodeSolanaAddress(programId, "programId");
  const raw = boundedArray(options.seeds, {
    name: "seeds",
    minimum: 0,
    maximum: MAX_PROGRAM_SEEDS - 1,
  });
  const seeds = raw.map((seed, index) => seedBytes(seed, index));
  const bump = optionalBump(options.bump);
  const found: ProgramAddress =
    bump === undefined
      ? findProgramAddress(seeds, programId)
      : { address: createProgramAddress([...seeds, Uint8Array.of(bump)], programId), bump };
  const canonical = bump === undefined;
  return {
    content: content(
      [`Address: ${found.address}`, `Bump: ${found.bump}${canonical ? " (canonical)" : ""}`].join(
        "\n",
      ),
    ),
    details: { chain: "solana", programId, ...found, canonical },
  };
}

/** Token account arguments besides the owner, raw until the executor checks them. */
export interface SolanaTokenAddressArguments {
  readonly mint?: unknown;
  readonly tokenProgram?: unknown;
}

/**
 * Derives the associated token account of a wallet for a mint.
 * @param ownerValue - The wallet, base58
 * @param options - The mint and an optional token program
 * @returns {ToolResult<SolanaTokenAddressDetails>} The account
 */
export function getSolanaTokenAddress(
  ownerValue: unknown,
  options: SolanaTokenAddressArguments,
): ToolResult<SolanaTokenAddressDetails> {
  const owner = requiredString(ownerValue, "owner");
  const mint = requiredString(options.mint, "mint");
  const tokenProgram = optionalName(options.tokenProgram, "tokenProgram") ?? TOKEN_PROGRAM;
  const { address, bump } = getAssociatedTokenAddress(owner, { mint, tokenProgram });
  return {
    content: content(`Address: ${address}`),
    details: { chain: "solana", owner, mint, tokenProgram, address, bump },
  };
}
