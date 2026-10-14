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

/**
 * Derives public Bitcoin wallet material from a complete Electrum phrase, by path or old index.
 * @param mnemonicValue - Public or disposable Electrum phrase
 * @param pathValue - Exact absolute BIP32 path, for standard and SegWit seeds
 * @param passphraseValue - Electrum passphrase; old seeds take none
 * @param networkValue - Bitcoin network
 * @param changeValue - Old seeds only: 0 for receiving, 1 for change. Default 0
 * @param indexValue - Old seeds only: address index. Default 0
 * @returns {Promise<ToolResult<DerivedWalletDetails | DerivedOldElectrumWalletDetails>>} Public wallet
 */
export async function deriveElectrumWallet(
  mnemonicValue: unknown,
  pathValue: unknown,
  passphraseValue?: unknown,
  networkValue?: unknown,
  changeValue?: unknown,
  indexValue?: unknown,
): Promise<
  ToolResult<
    | (DerivedWalletDetails & { scheme: "electrum"; seedType: "standard" | "segwit" })
    | DerivedOldElectrumWalletDetails
  >
> {
  const mnemonic = requiredString(mnemonicValue, "Electrum mnemonic");
  const passphrase = optionalString(passphraseValue, "Electrum passphrase") ?? "";
  const change = optionalIndex(changeValue, "Change", 1);
  const index = optionalIndex(indexValue, "Index");
  if (inspectElectrumSeed(mnemonic) === "old") {
    return deriveOldElectrumWallet(mnemonic, pathValue, passphrase, {
      change,
      index,
      networkValue,
    });
  }
  const path = electrumPath(pathValue, change !== undefined || index !== undefined);
  const { blockchain } = await getBlockchain("bitcoin", networkValue);
  const seed = deriveElectrumSeed(mnemonic, passphrase);
  const wallet = blockchain.deriveElectrumWallet(seed, path);
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

/**
 * Derives one P2PKH address of an old seed from its master public key, as Electrum before 2.0 did.
 * @param mnemonic - Old seed words or hex seed
 * @param pathValue - Raw path argument, which an old seed refuses
 * @param passphrase - Electrum passphrase, which an old seed refuses
 * @param options - Change chain and index, 0 when left out, and the Bitcoin network
 * @param options.change - 0 for receiving, 1 for change
 * @param options.index - Address index
 * @param options.networkValue - Bitcoin network
 * @returns {Promise<ToolResult<DerivedOldElectrumWalletDetails>>} MPK, key and address
 */
async function deriveOldElectrumWallet(
  mnemonic: string,
  pathValue: unknown,
  passphrase: string,
  {
    change = 0,
    index = 0,
    networkValue,
  }: { readonly change?: number; readonly index?: number; readonly networkValue: unknown },
): Promise<ToolResult<DerivedOldElectrumWalletDetails>> {
  if (!isUnset(pathValue)) {
    throw new TypeError("Old Electrum seeds have no BIP32 path; pass change and index instead");
  }
  if (passphrase !== "") throw new TypeError("Old Electrum seeds take no passphrase");
  const { blockchain } = await getBlockchain("bitcoin", networkValue);
  const masterPublicKey = deriveOldMasterPublicKey(mnemonic);
  const publicKey = deriveOldPublicKey(masterPublicKey, change, index).toHex();
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
