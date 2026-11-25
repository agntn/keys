import { isValidPoint } from "@agntn/curves/ed25519";
import { base58 } from "@agntn/encodings/base58";
import { sha256 } from "@agntn/hashes";
import { concatBytes } from "./bytes.ts";
import { MAX_PROGRAM_SEED_LENGTH, MAX_PROGRAM_SEEDS } from "./solana-limits.ts";

export { MAX_PROGRAM_SEED_LENGTH, MAX_PROGRAM_SEEDS } from "./solana-limits.ts";

/** The SPL Token program, which owns most mints. */
export const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/** The Token-2022 program, home of mints with extensions. */
export const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/** The program every associated token account belongs to. */
export const ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

const PDA_MARKER = /* @__PURE__ */ new TextEncoder().encode("ProgramDerivedAddress");

/** A program address and the bump that pushed it off the curve. */
export interface ProgramAddress {
  readonly address: string;
  readonly bump: number;
}

/** The wallet's token account for one mint. */
export interface TokenAddressOptions {
  /** The mint, base58. */
  readonly mint: string;
  /** The program that owns the mint. Default: SPL Token. */
  readonly tokenProgram?: string;
}

/**
 * Reads a base58 address into its 32 bytes.
 * @param address - The address
 * @param name - What it is, for the error
 * @returns {Uint8Array} The bytes
 * @throws {RangeError} When it isn't 32 bytes of base58
 */
export function decodeSolanaAddress(address: unknown, name: string): Uint8Array {
  let bytes: Uint8Array | undefined;
  try {
    bytes = typeof address === "string" ? base58.decode(address) : undefined;
  } catch {
    bytes = undefined;
  }
  if (bytes?.length !== 32) {
    throw new RangeError(`${name} must be a Solana address, 32 bytes of base58`);
  }
  return bytes;
}

/**
 * Refuses seeds the runtime refuses.
 * @param seeds - The seeds
 * @param most - How many fit
 * @throws {RangeError} On too many seeds or one that isn't up to 32 bytes
 */
function checkSeeds(seeds: readonly Uint8Array[], most: number): void {
  if (!Array.isArray(seeds as unknown) || seeds.length > most) {
    throw new RangeError(`Seeds must be an array of at most ${most} byte arrays`);
  }
  for (const [index, seed] of seeds.entries()) {
    if (!(seed instanceof Uint8Array) || seed.length > MAX_PROGRAM_SEED_LENGTH) {
      throw new RangeError(
        `Seed ${index} must be a Uint8Array of up to ${MAX_PROGRAM_SEED_LENGTH} bytes`,
      );
    }
  }
}

/**
 * SHA-256 of seeds, program and marker; undefined when that lands on the curve.
 * @param seeds - Seeds, bump included
 * @param program - Program id bytes
 * @returns {string | undefined} The address
 */
function offCurveHash(seeds: readonly Uint8Array[], program: Uint8Array): string | undefined {
  const hash = sha256(concatBytes(...seeds, program, PDA_MARKER));
  return isValidPoint(hash.toHex()) ? undefined : base58.encode(hash);
}

/**
 * The address of seeds that already end in their bump, as `create_program_address` writes it.
 * @param seeds - Up to 16 seeds of up to 32 bytes, the bump last
 * @param programId - The program, base58
 * @returns {string} The address
 * @throws {RangeError} On bad seeds, a bad program id or a hash on the curve
 */
export function createProgramAddress(seeds: readonly Uint8Array[], programId: string): string {
  checkSeeds(seeds, MAX_PROGRAM_SEEDS);
  const address = offCurveHash(seeds, decodeSolanaAddress(programId, "programId"));
  if (address === undefined) {
    throw new RangeError("These seeds land on the ed25519 curve, so no program owns that address");
  }
  return address;
}

/**
 * The canonical program address: the first bump from 255 down that lands off the curve.
 * @param seeds - Up to 15 seeds of up to 32 bytes, without the bump
 * @param programId - The program, base58
 * @returns {ProgramAddress} The address and its bump
 * @throws {RangeError} On bad seeds or a bad program id
 */
export function findProgramAddress(
  seeds: readonly Uint8Array[],
  programId: string,
): ProgramAddress {
  checkSeeds(seeds, MAX_PROGRAM_SEEDS - 1);
  const program = decodeSolanaAddress(programId, "programId");
  for (let bump = 255; bump >= 0; bump--) {
    const address = offCurveHash([...seeds, Uint8Array.of(bump)], program);
    if (address !== undefined) return { address, bump };
  }
  throw new RangeError("No bump takes these seeds off the curve");
}

/**
 * The associated token account of a wallet for a mint.
 * @param owner - The wallet, base58; a program address works too
 * @param options - The mint and its token program
 * @returns {ProgramAddress} The account and its bump
 * @throws {TypeError} When options isn't an object with a mint
 * @throws {RangeError} When an address isn't 32 bytes of base58
 */
export function getAssociatedTokenAddress(
  owner: string,
  options: TokenAddressOptions,
): ProgramAddress {
  if (typeof options !== "object" || options === null || typeof options.mint !== "string") {
    throw new TypeError(
      "getAssociatedTokenAddress takes the mint in its options: (owner, { mint })",
    );
  }
  const { mint, tokenProgram = TOKEN_PROGRAM } = options;
  const seeds = [
    decodeSolanaAddress(owner, "owner"),
    decodeSolanaAddress(tokenProgram, "tokenProgram"),
    decodeSolanaAddress(mint, "mint"),
  ];
  return findProgramAddress(seeds, ASSOCIATED_TOKEN_PROGRAM);
}
