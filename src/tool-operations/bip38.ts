import { MAX_BIP38_ADDRESS_LENGTH, MAX_BIP38_PASSPHRASE_LENGTH } from "../tool-parameters.ts";
import {
  type BIP38Inspection,
  inspect as inspectBIP38,
  type BIP38Mode,
  type DecryptedBIP38,
  decrypt as decryptBIP38Key,
  BIP38PassphraseError,
} from "../utils/bip38/index.ts";
import { optionalName, requiredString } from "./arguments.ts";
import { getBlockchain } from "./blockchain.ts";
import { type ToolResult, content } from "./results.ts";

/**
 * Read the public header of a BIP38 key and optionally check an address against it.
 * No passphrase is taken and nothing is decrypted.
 * @param encryptedValue - BIP38 key starting with `6P`.
 * @param addressValue - Optional address to compare with the stored address hash.
 * @returns {ToolResult<BIP38Inspection>} Mode, flags, address hash and owner entropy.
 */
export function inspectBip38(
  encryptedValue: unknown,
  addressValue?: unknown,
): ToolResult<BIP38Inspection> {
  const address = optionalName(addressValue, "Address");
  if (address !== undefined && Array.from(address).length > MAX_BIP38_ADDRESS_LENGTH) {
    throw new RangeError(`Address must not exceed ${MAX_BIP38_ADDRESS_LENGTH} characters`);
  }
  const details = inspectBIP38(
    requiredString(encryptedValue, "BIP38 key"),
    address === undefined ? {} : { address },
  );
  return { content: content(JSON.stringify(details)), details };
}

/** A BIP38 key's header, and its public wallet when the passphrase opens it. */
export interface DecryptedBip38Details {
  mode: BIP38Mode;
  compressed: boolean;
  lot?: number;
  sequence?: number;
  /** Whether the passphrase gives an address with the stored address hash. */
  unlocked: boolean;
  chain?: "bitcoin";
  publicKey?: string;
  address?: string;
  /** Mainnet WIF, only when the caller asked for it. */
  wif?: string;
}

/**
 * Checks the BIP38 decrypt arguments for hosts that skip the schema, never echoing a value.
 * @param encryptedValue - Raw key argument
 * @param passphraseValue - Raw passphrase argument
 * @param revealKeyValue - Raw revealKey argument
 * @returns {{ encrypted: string; passphrase: string; revealKey: boolean }} The checked arguments
 */
function bip38Arguments(
  encryptedValue: unknown,
  passphraseValue: unknown,
  revealKeyValue: unknown,
): { encrypted: string; passphrase: string; revealKey: boolean } {
  const encrypted = requiredString(encryptedValue, "BIP38 key");
  const passphrase = requiredString(passphraseValue, "Passphrase");
  if (Array.from(passphrase).length > MAX_BIP38_PASSPHRASE_LENGTH) {
    throw new RangeError(`Passphrase must not exceed ${MAX_BIP38_PASSPHRASE_LENGTH} characters`);
  }
  const revealKey = revealKeyValue ?? false;
  if (typeof revealKey !== "boolean") throw new TypeError("revealKey must be a boolean");
  return { encrypted, passphrase, revealKey };
}

/**
 * Reads what a BIP38 key shows without its passphrase, as a text line and details.
 * @param encrypted - BIP38 key starting with `6P`
 * @returns {{ header: string[]; base: Omit<DecryptedBip38Details, "unlocked"> }} The header
 */
function bip38Summary(encrypted: string): {
  header: string[];
  base: Omit<DecryptedBip38Details, "unlocked">;
} {
  const { mode, compressed, lot, sequence } = inspectBIP38(encrypted);
  const lotSequence = lot === undefined ? "" : `, lot ${lot}, sequence ${sequence}`;
  return {
    header: [`BIP38: ${mode}, ${compressed ? "compressed" : "uncompressed"}${lotSequence}`],
    base: { mode, compressed, ...(lot === undefined ? {} : { lot, sequence }) },
  };
}

/**
 * Opens a BIP38 key with its passphrase and gives its Bitcoin wallet, with the WIF only on request.
 * A wrong passphrase is a result, not an error.
 * @param encryptedValue - BIP38 key starting with `6P`
 * @param passphraseValue - Passphrase
 * @param revealKeyValue - Whether to return the WIF, false by default
 * @returns {Promise<ToolResult<DecryptedBip38Details>>} Mode, verdict, public key, address, WIF
 */
export async function decryptBip38(
  encryptedValue: unknown,
  passphraseValue: unknown,
  revealKeyValue?: unknown,
): Promise<ToolResult<DecryptedBip38Details>> {
  const { encrypted, passphrase, revealKey } = bip38Arguments(
    encryptedValue,
    passphraseValue,
    revealKeyValue,
  );
  const { header, base } = bip38Summary(encrypted);
  const { compressed } = base;
  let decrypted: DecryptedBIP38;
  try {
    decrypted = decryptBIP38Key(encrypted, passphrase);
  } catch (error) {
    if (!(error instanceof BIP38PassphraseError)) throw error;
    return {
      content: content(
        [...header, "Passphrase: wrong, the address hash does not match"].join("\n"),
      ),
      details: { ...base, unlocked: false },
    };
  }
  const { blockchain } = await getBlockchain("bitcoin");
  const wallet = blockchain.deriveWallet(decrypted.privateKey.toHex(), { compressed }, "legacy");
  const details: DecryptedBip38Details = {
    ...base,
    unlocked: true,
    chain: "bitcoin",
    publicKey: wallet.keys.public,
    address: wallet.address,
    ...(revealKey ? { wif: decrypted.wif } : {}),
  };
  return {
    content: content(
      [
        ...header,
        "Passphrase: correct",
        `Public key: ${wallet.keys.public}`,
        `Address: ${wallet.address}`,
        ...(revealKey ? [`WIF: ${decrypted.wif}`] : []),
      ].join("\n"),
    ),
    details,
  };
}
