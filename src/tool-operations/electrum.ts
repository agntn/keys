import {
  inspect as inspectElectrumSeed,
  deriveSeed as deriveElectrumSeed,
  deriveOldMasterPublicKey,
  deriveOldPublicKey,
} from "../utils/electrum/index.ts";
import { requiredString, optionalString, optionalIndex, isUnset } from "./arguments.ts";
import { getBlockchain } from "./blockchain.ts";
import { DERIVATION_PATH_PATTERN } from "./hd.ts";
import { type ToolResult, content } from "./results.ts";
import type { DerivedWalletDetails } from "./wallet.ts";

/** Public wallet of an old Electrum seed, which walks a change chain and an index, not a path. */
export interface DerivedOldElectrumWalletDetails {
  chain: "bitcoin";
  network: string;
  scheme: "electrum";
  seedType: "old";
  /** 128 hex digits, x then y, as Electrum shows the MPK of a watching wallet. */
  masterPublicKey: string;
  change: number;
  index: number;
  /** Uncompressed, the key the P2PKH address hashes. */
  publicKey: string;
  address: string;
}

/** Electrum tool arguments besides the phrase, raw until the executor checks them. */
export interface ElectrumWalletArguments {
  /** Exact absolute BIP32 path, for standard and SegWit seeds. */
  readonly path?: unknown;
  /** Electrum passphrase; old seeds take none. */
  readonly passphrase?: unknown;
  readonly network?: unknown;
  /** Old seeds only: 0 for receiving, 1 for change. Default 0. */
  readonly change?: unknown;
  /** Old seeds only: address index. Default 0. */
  readonly index?: unknown;
}

/**
 * Derives public Bitcoin wallet material from a complete Electrum phrase, by path or old index.
 * @param mnemonicValue - Public or disposable Electrum phrase
 * @param options - Path and passphrase, or the change and index of an old seed, and the network
 * @returns {Promise<ToolResult<DerivedWalletDetails | DerivedOldElectrumWalletDetails>>} Public wallet
 */
export async function deriveElectrumWallet(
  mnemonicValue: unknown,
  options: ElectrumWalletArguments,
): Promise<
  ToolResult<
    | (DerivedWalletDetails & { scheme: "electrum"; seedType: "standard" | "segwit" })
    | DerivedOldElectrumWalletDetails
  >
> {
  const mnemonic = requiredString(mnemonicValue, "Electrum mnemonic");
  const passphrase = optionalString(options.passphrase, "Electrum passphrase") ?? "";
  const change = optionalIndex(options.change, { name: "Change", maximum: 1 });
  const index = optionalIndex(options.index, { name: "Index" });
  const { network } = options;
  if (inspectElectrumSeed(mnemonic) === "old") {
    return deriveOldElectrumWallet(mnemonic, {
      path: options.path,
      passphrase,
      change,
      index,
      network,
    });
  }
  const path = electrumPath(options.path, change !== undefined || index !== undefined);
  const { blockchain } = await getBlockchain("bitcoin", { network });
  const seed = deriveElectrumSeed(mnemonic, passphrase);
  const wallet = blockchain.deriveElectrumWallet(seed, { path });
  const { scheme, seedType } = seed;
  const details = {
    chain: "bitcoin",
    network: blockchain.network,
    scheme,
    seedType,
    path,
    publicKey: wallet.keys.public,
    address: wallet.address,
  };
  return {
    content: content(
      `Scheme: ${scheme}\nSeed type: ${seedType}\nChain: bitcoin (${details.network})\nPath: ${path}\nPublic key: ${details.publicKey}\nAddress: ${details.address}`,
    ),
    details,
  };
}

/**
 * Reads the BIP32 path a standard or SegWit seed needs, refusing the old seed arguments.
 * @param pathValue - Raw path argument
 * @param oldArguments - Whether change or index came along
 * @returns {string} The path
 */
function electrumPath(pathValue: unknown, oldArguments: boolean): string {
  if (oldArguments) {
    throw new TypeError("Change and index apply to old Electrum seeds only; pass a BIP32 path");
  }
  if (isUnset(pathValue))
    throw new TypeError("Standard and SegWit Electrum seeds need a BIP32 path");
  const path = requiredString(pathValue, "Derivation path");
  if (path.length > 256 || !DERIVATION_PATH_PATTERN.test(path)) {
    throw new TypeError("Invalid derivation path");
  }
  return path;
}

/** An old seed's arguments, with the passphrase, change and index already read. */
interface OldElectrumWalletArguments {
  /** Raw path argument, which an old seed refuses. */
  readonly path: unknown;
  /** Electrum passphrase, which an old seed refuses. */
  readonly passphrase: string;
  /** 0 for receiving, 1 for change, 0 when left out. */
  readonly change?: number;
  /** Address index, 0 when left out. */
  readonly index?: number;
  readonly network: unknown;
}

/**
 * Derives one P2PKH address of an old seed from its master public key, as Electrum before 2.0 did.
 * @param mnemonic - Old seed words or hex seed
 * @param options - Path and passphrase it refuses, change chain, index and the Bitcoin network
 * @returns {Promise<ToolResult<DerivedOldElectrumWalletDetails>>} MPK, key and address
 */
async function deriveOldElectrumWallet(
  mnemonic: string,
  options: OldElectrumWalletArguments,
): Promise<ToolResult<DerivedOldElectrumWalletDetails>> {
  const { path, passphrase, change = 0, index = 0, network } = options;
  if (!isUnset(path)) {
    throw new TypeError("Old Electrum seeds have no BIP32 path; pass change and index instead");
  }
  if (passphrase !== "") throw new TypeError("Old Electrum seeds take no passphrase");
  const { blockchain } = await getBlockchain("bitcoin", { network });
  const masterPublicKey = deriveOldMasterPublicKey(mnemonic);
  const publicKey = deriveOldPublicKey(masterPublicKey, { change, index }).toHex();
  const details: DerivedOldElectrumWalletDetails = {
    chain: "bitcoin",
    network: blockchain.network,
    scheme: "electrum",
    seedType: "old",
    masterPublicKey: masterPublicKey.toHex(),
    change,
    index,
    publicKey,
    address: blockchain.getAddress(publicKey, "legacy"),
  };
  return {
    content: content(
      [
        "Scheme: electrum",
        "Seed type: old",
        `Chain: bitcoin (${details.network})`,
        `Master public key: ${details.masterPublicKey}`,
        `Change: ${change}`,
        `Index: ${index}`,
        `Public key: ${publicKey}`,
        `Address: ${details.address}`,
      ].join("\n"),
    ),
    details,
  };
}
