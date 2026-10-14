import {
  MAX_SCRYPT_BLOCKS,
  MAX_BRAINWALLET_INPUT_LENGTH,
  MAX_ADDRESS_LENGTH,
} from "../tool-parameters.ts";
import {
  type BrainwalletKDF,
  type PlainBrainwalletOptions,
  type WarpWalletOptions,
  type BrainwalletRecipe,
  derive as deriveBrainwalletKey,
} from "../utils/brainwallet/index.ts";
import { isUnset, costArgument, oneOf, requiredString, optionalName } from "./arguments.ts";
import { getBlockchain } from "./blockchain.ts";
import { type ToolResult, content } from "./results.ts";

/** Public wallet of a brainwallet, with the target verdict when one was given. */
export interface DerivedBrainwalletDetails {
  chain: BrainwalletChain;
  network: string;
  /** Bitcoin only: always P2PKH. */
  addressType?: "legacy";
  /** Bitcoin only: whether the address hashes the compressed key. */
  compressed?: boolean;
  publicKey: string;
  address: string;
  matches?: boolean;
}

const EVEN_HEX = /^(?:[0-9a-f]{2})*$/iu;

/**
 * Tells whether a cost was left out. OMP sends 0 for an unused number, which no KDF takes.
 * @param value - Raw argument
 * @returns {boolean} True for a missing, zero or blank value
 */
function isUnsetCost(value: unknown): boolean {
  return value === 0 || isUnset(value);
}

/**
 * Reads the KDF and its costs, refusing the other KDF's so no option drops silently.
 * @param kdf - scrypt or pbkdf2
 * @param args - Tool arguments
 * @returns {BrainwalletKDF} The KDF with its parameters
 */
function brainwalletKDF(
  kdf: BrainwalletKDF["kdf"],
  args: Readonly<Record<string, unknown>>,
): BrainwalletKDF {
  const foreign = (kdf === "scrypt" ? ["iterations", "digest"] : ["N", "r", "p"]).filter(
    (name) => !isUnsetCost(args[name]),
  );
  if (foreign.length > 0) throw new RangeError(`${kdf} does not take ${foreign.join(", ")}`);
  if (kdf === "pbkdf2") {
    const iterations = costArgument(args["iterations"], "iterations");
    return { kdf, iterations, digest: oneOf(args["digest"], "digest", ["sha256", "sha512"]) };
  }
  const N = costArgument(args["N"], "N", 2);
  if ((N & (N - 1)) !== 0) throw new RangeError("N must be a power of 2");
  const r = costArgument(args["r"], "r");
  if (N * r > MAX_SCRYPT_BLOCKS) {
    throw new RangeError(`N * r must not exceed ${MAX_SCRYPT_BLOCKS}`);
  }
  return { kdf, N, r, p: costArgument(args["p"], "p") };
}

/**
 * Reads a passphrase or salt under the tool's length limit.
 * @param value - Raw argument
 * @param name - Argument name for the error
 * @returns {string} The text, untouched
 */
function brainwalletText(value: unknown, name: string): string {
  const text = requiredString(value, name);
  if (Array.from(text).length > MAX_BRAINWALLET_INPUT_LENGTH) {
    throw new RangeError(`${name} must not exceed ${MAX_BRAINWALLET_INPUT_LENGTH} characters`);
  }
  return text;
}

/** Arguments a plain brainwallet has no use for. OMP sends 0 or an empty string for each. */
const SALTED_ONLY_ARGUMENTS = [
  "salt",
  "saltEncoding",
  "hashed",
  "N",
  "r",
  "p",
  "digest",
  "keyLength",
];

/**
 * Reads the rounds of a plain brainwallet, refusing every salted recipe argument.
 * @param kdf - Digest the passphrase goes through
 * @param args - Tool arguments
 * @returns {PlainBrainwalletOptions} The digest with its rounds
 */
function plainBrainwalletRecipe(
  kdf: PlainBrainwalletOptions["kdf"],
  args: Readonly<Record<string, unknown>>,
): PlainBrainwalletOptions {
  const foreign = SALTED_ONLY_ARGUMENTS.filter(
    (name) => args[name] !== undefined && args[name] !== "" && args[name] !== 0,
  );
  if (foreign.length > 0) throw new RangeError(`${kdf} does not take ${foreign.join(", ")}`);
  if (isUnsetCost(args["iterations"])) return { kdf };
  return { kdf, iterations: costArgument(args["iterations"], "iterations") };
}

/**
 * Reads the salt a salted recipe or WarpWallet requires, empty for none.
 * @param kdf - KDF name for the error
 * @param args - Tool arguments
 * @returns {Uint8Array | string} Decoded hex bytes, or the text to read as UTF-8
 */
function brainwalletSalt(
  kdf: string,
  args: Readonly<Record<string, unknown>>,
): Uint8Array | string {
  if (args["salt"] === undefined) throw new TypeError(`${kdf} needs a salt, empty for none`);
  const saltText = brainwalletText(args["salt"], "Salt");
  const saltEncoding = oneOf(args["saltEncoding"], "saltEncoding", ["utf8", "hex"]);
  if (saltEncoding === "hex" && !EVEN_HEX.test(saltText)) {
    throw new TypeError("Salt must be hex digit pairs without 0x when saltEncoding is hex");
  }
  return saltEncoding === "hex" ? Uint8Array.fromHex(saltText) : saltText;
}

/** Arguments WarpWallet fixes for itself. OMP sends 0 or an empty string for each. */
const WARP_FIXED_ARGUMENTS = ["hashed", "N", "r", "p", "iterations", "digest", "keyLength"];

/**
 * Reads the salt of a WarpWallet, refusing every cost it fixes for itself.
 * @param args - Tool arguments
 * @returns {WarpWalletOptions} WarpWallet with its salt
 */
function warpWalletRecipe(args: Readonly<Record<string, unknown>>): WarpWalletOptions {
  const foreign = WARP_FIXED_ARGUMENTS.filter((name) => !isUnsetCost(args[name]));
  if (foreign.length > 0) throw new RangeError(`warpwallet does not take ${foreign.join(", ")}`);
  return { kdf: "warpwallet", salt: brainwalletSalt("warpwallet", args) };
}

/**
 * Reads the passphrase and the full recipe, refusing anything the KDF would not run as given.
 * @param args - Tool arguments
 * @returns {{ passphrase: string; options: BrainwalletRecipe }} Passphrase and recipe
 */
function brainwalletRecipe(args: Readonly<Record<string, unknown>>): {
  passphrase: string;
  options: BrainwalletRecipe;
} {
  const passphrase = brainwalletText(args["passphrase"], "Passphrase");
  const kdf = oneOf(args["kdf"], "kdf", ["scrypt", "pbkdf2", "sha256", "keccak256", "warpwallet"]);
  if (kdf === "sha256" || kdf === "keccak256") {
    return { passphrase, options: plainBrainwalletRecipe(kdf, args) };
  }
  if (kdf === "warpwallet") return { passphrase, options: warpWalletRecipe(args) };
  const salt = brainwalletSalt(kdf, args);
  const stretch = brainwalletKDF(kdf, args);
  const hashed = oneOf(args["hashed"], "hashed", ["bytes", "hex"]);
  const options = { ...stretch, salt, hashed };
  if (isUnsetCost(args["keyLength"])) return { passphrase, options };
  return {
    passphrase,
    options: { ...options, keyLength: costArgument(args["keyLength"], "keyLength") },
  };
}

/** Chains the brainwallet tool writes an address for. */
type BrainwalletChain = "bitcoin" | "ethereum";

/**
 * Reads the Bitcoin key form. Ethereum hashes the uncompressed key, so it refuses only true.
 * @param chain - Chain the address is for
 * @param value - Raw argument
 * @returns {boolean | undefined} The Bitcoin key form, undefined on Ethereum
 */
function brainwalletCompressed(chain: BrainwalletChain, value: unknown): boolean | undefined {
  if (chain === "ethereum") {
    if (value === true) throw new RangeError("ethereum does not take compressed");
    if (value !== undefined && value !== false) throw new TypeError("compressed must be a boolean");
    return undefined;
  }
  if (typeof value !== "boolean") throw new TypeError("compressed must be a boolean");
  return value;
}

/**
 * Reads where the address goes: chain, Bitcoin key form and the optional target.
 * @param args - Tool arguments
 * @returns {{ chain: BrainwalletChain; compressed?: boolean; target?: string }} Address settings
 */
function brainwalletAddressing(args: Readonly<Record<string, unknown>>): {
  chain: BrainwalletChain;
  compressed: boolean | undefined;
  target: string | undefined;
} {
  const chain = isUnset(args["chain"])
    ? "bitcoin"
    : oneOf(args["chain"], "chain", ["bitcoin", "ethereum"]);
  const target = optionalName(args["target"], "Target");
  if (target !== undefined && Array.from(target).length > MAX_ADDRESS_LENGTH) {
    throw new RangeError(`Target must not exceed ${MAX_ADDRESS_LENGTH} characters`);
  }
  return { chain, compressed: brainwalletCompressed(chain, args["compressed"]), target };
}

/**
 * Writes the brainwallet answer, one fact per line.
 * @param details - Public wallet and verdict
 * @returns {string} The text the tool returns
 */
function brainwalletAnswer(details: Readonly<DerivedBrainwalletDetails>): string {
  const { compressed, matches } = details;
  return [
    `Chain: ${details.chain} (${details.network})`,
    ...(compressed === undefined
      ? []
      : [`Address type: legacy, ${compressed ? "compressed" : "uncompressed"}`]),
    `Public key: ${details.publicKey}`,
    `Address: ${details.address}`,
    ...(matches === undefined ? [] : [`Target: ${matches ? "match" : "no match"}`]),
  ].join("\n");
}

/**
 * Derives the public wallet of a brainwallet, never echoing its key or passphrase.
 * @param args - Tool arguments, as `DERIVE_BRAINWALLET_PARAMETERS` names them
 * @returns {Promise<ToolResult<DerivedBrainwalletDetails>>} Public key, address and verdict
 */
export async function deriveBrainwallet(
  args: Readonly<Record<string, unknown>>,
): Promise<ToolResult<DerivedBrainwalletDetails>> {
  const { passphrase, options } = brainwalletRecipe(args);
  const { chain, compressed, target } = brainwalletAddressing(args);
  const { blockchain } = await getBlockchain(chain, args["network"]);
  const privateKey = deriveBrainwalletKey(passphrase, options).toHex();
  const wallet =
    compressed === undefined
      ? blockchain.deriveWallet(privateKey)
      : blockchain.deriveWallet(privateKey, { compressed }, "legacy");
  const matches =
    chain === "ethereum"
      ? wallet.address.toLowerCase() === target?.toLowerCase()
      : wallet.address === target;
  const details: DerivedBrainwalletDetails = {
    chain,
    network: blockchain.network,
    ...(compressed === undefined ? {} : { addressType: "legacy", compressed }),
    publicKey: wallet.keys.public,
    address: wallet.address,
    ...(target === undefined ? {} : { matches }),
  };
  return { content: content(brainwalletAnswer(details)), details };
}
