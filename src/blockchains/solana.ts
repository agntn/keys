import { base58 } from "@agntn/encodings/base58";
import { equalBytes } from "../utils/bytes.ts";
import { decodeKeyPublic } from "../utils/ed25519.ts";
import { AbstractEd25519Blockchain } from "../utils/ed25519-chains.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import { BIP44Change, getHardenedPath } from "../utils/bip44/paths.ts";
import { readPathOptions } from "../utils/options.ts";
import {
  type ProgramAddress,
  type TokenAddressOptions,
  createProgramAddress,
  findProgramAddress,
  getAssociatedTokenAddress,
} from "../utils/solana-pda.ts";
import type { AddressType, DerivationPathOptions, Wallet, WalletOptions } from "../types.ts";

/**
 * Reads the 64 bytes of a Solana CLI keypair file.
 * @param text - The file's contents
 * @returns {Uint8Array} The bytes, undefined for anything else
 */
function readKeypairArray(text: string): Uint8Array | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!Array.isArray(parsed) || parsed.length !== 64) return undefined;
  const bytes = parsed.filter(
    (value): value is number => Number.isInteger(value) && value >= 0 && value <= 255,
  );
  return bytes.length === 64 ? Uint8Array.from(bytes) : undefined;
}

/**
 * Reads a 64-byte Solana secret as base58, as Phantom exports it.
 * @param text - The secret
 * @returns {Uint8Array} The bytes, undefined for anything else
 */
function readKeypairBase58(text: string): Uint8Array | undefined {
  try {
    const bytes = base58.decode(text);
    return bytes.length === 64 ? bytes : undefined;
  } catch {
    return undefined;
  }
}

/** Solana blockchain implementation. */
export class Solana extends AbstractEd25519Blockchain {
  override readonly name = "solana";
  override readonly bip44 = BIP44.SOLANA;

  /**
   * Phantom and the Solana CLI put account `a` at `m/44'/501'/a'/change'`, every level hardened
   * and nothing below the change branch, so an address index has nowhere to go.
   * @param options - Account and change branch, 0 in every wallet; `addressIndex` must stay 0
   * @returns {string} The SLIP-10 path
   */
  override getDerivationPath(options?: DerivationPathOptions): string {
    const {
      account = 0,
      change = BIP44Change.EXTERNAL,
      addressIndex = 0,
    } = readPathOptions(options);
    if (addressIndex !== 0) {
      throw new RangeError("Solana paths end at the change branch, so addressIndex must be 0");
    }
    return getHardenedPath(this.bip44, [account, change]);
  }

  override getAddress(keyPublic: string, type?: AddressType): string {
    this.refuseAddressType(type);
    return base58.encode(decodeKeyPublic(keyPublic, "Solana"));
  }

  /**
   * Restores a wallet from `id.json` or Phantom's base58 export: the seed, then its public key.
   * @param seed - The 64-byte secret as a JSON array or base58
   * @param options - Key options of the wallet
   * @returns {Wallet} The wallet, keyed by the 32-byte seed
   * @throws {RangeError} On another shape, or a public half from another key
   */
  override deriveSeedWallet(seed: string, options?: WalletOptions): Wallet {
    const text = seed.trim();
    const bytes = text.startsWith("[") ? readKeypairArray(text) : readKeypairBase58(text);
    if (bytes === undefined) {
      throw new RangeError(
        "A Solana secret is 64 bytes: a JSON array of numbers as in id.json, or base58",
      );
    }
    const wallet = this.deriveWallet(bytes.subarray(0, 32).toHex(), options);
    if (!equalBytes(Uint8Array.fromHex(wallet.keys.public), bytes.subarray(32))) {
      throw new RangeError(
        "The last 32 bytes of this Solana secret are not the public key its seed derives",
      );
    }
    return wallet;
  }

  override validateAddress(address: string): boolean {
    try {
      return base58.decode(address).length === 32;
    } catch {
      return false;
    }
  }

  /**
   * The canonical program derived address, as `find_program_address` gives it.
   * @param seeds - Up to 15 seeds of up to 32 bytes, without the bump
   * @param programId - The program, base58
   * @returns {ProgramAddress} The address and its bump, the first from 255 down off the curve
   * @throws {RangeError} On bad seeds or a bad program id
   */
  findProgramAddress(seeds: readonly Uint8Array[], programId: string): ProgramAddress {
    return findProgramAddress(seeds, programId);
  }

  /**
   * The program address of seeds that already end in their bump.
   * @param seeds - Up to 16 seeds of up to 32 bytes, the bump last
   * @param programId - The program, base58
   * @returns {string} The address
   * @throws {RangeError} On bad seeds, a bad program id or seeds that land on the curve
   */
  createProgramAddress(seeds: readonly Uint8Array[], programId: string): string {
    return createProgramAddress(seeds, programId);
  }

  /**
   * The associated token account of a wallet for a mint, SPL Token unless told otherwise.
   * @param owner - The wallet, base58
   * @param options - The mint and its token program
   * @returns {ProgramAddress} The account and its bump
   * @throws {TypeError} When options carries no mint
   * @throws {RangeError} When an address isn't 32 bytes of base58
   */
  getAssociatedTokenAddress(owner: string, options: TokenAddressOptions): ProgramAddress {
    return getAssociatedTokenAddress(owner, options);
  }
}

export {
  ASSOCIATED_TOKEN_PROGRAM,
  TOKEN_2022_PROGRAM,
  TOKEN_PROGRAM,
  type ProgramAddress,
  type TokenAddressOptions,
} from "../utils/solana-pda.ts";

export default Solana;
