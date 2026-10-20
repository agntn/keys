import { BIP44 } from "../utils/bip44/index.ts";
import { getHardenedPath } from "../utils/bip44/paths.ts";
import { decodeKeyPublic } from "../utils/ed25519.ts";
import { AbstractEd25519Blockchain } from "../utils/ed25519-chains.ts";
import { readPathOptions } from "../utils/options.ts";
import {
  TON_WALLET_VERSIONS,
  decodeTonAddress,
  encodeTonAddress,
  getTonAccountId,
  type TonWalletVersion,
} from "../utils/ton-address.ts";
import { decodeTonMnemonic, isTonMnemonic } from "../utils/ton-mnemonic.ts";
import type {
  AddressType,
  DerivationPathOptions,
  HDWalletOptions,
  Wallet,
  WalletOptions,
} from "../types.ts";

/** Address types: a wallet contract, non-bounceable as wallets show it, or its bounceable form. */
const ADDRESS_TYPES: readonly string[] = [
  ...TON_WALLET_VERSIONS,
  ...TON_WALLET_VERSIONS.map((version) => `${version}-bounceable`),
];

/**
 * Splits an address type into the contract and the form.
 * @param type - The address type
 * @returns {{ version: TonWalletVersion; bounceable: boolean }} The contract and whether it bounces
 * @throws {RangeError} When the type names no contract keys knows
 */
function readAddressType(type: string): { version: TonWalletVersion; bounceable: boolean } {
  const [version, form] = type.split("-");
  const known = TON_WALLET_VERSIONS.find((candidate) => candidate === version);
  if (known === undefined || (form !== undefined && form !== "bounceable")) {
    throw new RangeError(
      `Address type ${JSON.stringify(type)} is not supported for ton. Supported: ${ADDRESS_TYPES.join(", ")}`,
    );
  }
  return { version: known, bounceable: form === "bounceable" };
}

/** TON, where the address hashes a wallet contract, so one key gets one address per contract. */
export class Ton extends AbstractEd25519Blockchain {
  override readonly name = "ton";
  override readonly bip44 = BIP44.TON;

  /**
   * v4r2, the contract Ledger and Trust Wallet deploy and most of the chain's wallets still run.
   * @returns {AddressType} The default address type
   */
  override get defaultAddressType(): AddressType {
    return "v4r2";
  }

  /**
   * The path Trust Wallet writes, `m/44'/607'/a'`. Ledger goes deeper: `m/44'/607'/0'/0'/a'/0'`.
   * @param options - Account; `change` and `addressIndex` must stay 0
   * @returns {string} The SLIP-10 path
   */
  override getDerivationPath(options?: DerivationPathOptions): string {
    const { account = 0, change = 0, addressIndex = 0 } = readPathOptions(options);
    if (change !== 0 || addressIndex !== 0) {
      throw new RangeError("TON paths end at the account, so change and addressIndex must be 0");
    }
    return getHardenedPath(this.bip44, [account]);
  }

  /**
   * Writes the address a fresh wallet of the given contract deploys to, on the basechain.
   * @param keyPublic - The 32-byte ed25519 public key as hex
   * @param type - Contract and form, `v4r2` by default; `-bounceable` writes `EQ` in place of `UQ`
   * @returns {string} The 48-character user-friendly address, `kQ` or `0Q` on testnet
   */
  override getAddress(keyPublic: string, type: string = this.defaultAddressType): string {
    const { version, bounceable } = readAddressType(type);
    const testnet = this.network === "testnet";
    const accountId = getTonAccountId(decodeKeyPublic(keyPublic, "TON"), {
      version,
      network: testnet ? "testnet" : "mainnet",
    });
    return encodeTonAddress(accountId, { bounceable, testnet });
  }

  /**
   * Takes raw and user-friendly addresses; the testnet flag has to match the network.
   * @param address - The address to check
   * @returns {boolean} Whether it names a basechain or masterchain account
   */
  override validateAddress(address: string): boolean {
    const decoded = decodeTonAddress(address);
    if (decoded === undefined) return false;
    return decoded.testnet === undefined || decoded.testnet === (this.network === "testnet");
  }

  /**
   * Restores a wallet from the 24 words TON wallets write, which are not BIP39 even though they
   * share its English list: PBKDF2 under `TON default seed`, as `@ton/crypto` does.
   * @param seed - The 24 words
   * @param options - Contract and form of the address
   * @returns {Wallet} The wallet of the phrase
   */
  override deriveSeedWallet(seed: string, options?: WalletOptions): Wallet {
    return this.deriveWallet(decodeTonMnemonic(seed).toHex(), options);
  }

  /**
   * Derives from BIP39 words over SLIP-10; TON's own words get pointed at `deriveSeedWallet`.
   * @param mnemonic - BIP39 words
   * @param options - Path, passphrase, and the contract and form of the address
   * @returns {Wallet} The wallet at the path
   */
  override deriveHDWallet(mnemonic: string, options: HDWalletOptions): Wallet {
    try {
      return super.deriveHDWallet(mnemonic, options);
    } catch (error) {
      if (!isTonMnemonic(mnemonic)) throw error;
      throw new Error(
        "These are TON's own 24 words, not BIP39; restore them as seed words with deriveSeedWallet, or keys_wallet_derive on agent tools",
        { cause: error },
      );
    }
  }
}

export default Ton;
