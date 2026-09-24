import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { hash160 } from "../utils/address.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import { AbstractBitcoinMessageBlockchain } from "../utils/bitcoin.ts";
import { decodeCashAddr, encodeCashAddr } from "../utils/cashaddr.ts";
import type { Options } from "../types.ts";

/** CashAddr prefixes from Bitcoin Cash Node src/chainparams.cpp; testnet3, testnet4, scalenet and chipnet share one. */
const NETWORK_PREFIXES = {
  mainnet: "bitcoincash",
  testnet: "bchtest",
} as const;

/** Hash lengths Bitcoin Cash Node pays to, by type: 0 and 2 hash a key, 1 and 3 a script. */
const HASH_LENGTHS: readonly (readonly number[])[] = [[20], [20, 32], [20], [20, 32]];

/**
 * Bitcoin Cash P2PKH wallets in CashAddr. Keys and signed messages are Bitcoin's, preamble
 * included, since Bitcoin Cash Node kept it. There is no SegWit, and Bitcoin's p2sh type
 * would nest one, so `legacy` is the only address type.
 */
export class BitcoinCash extends AbstractBitcoinMessageBlockchain {
  override readonly name = "bitcoincash";
  override readonly bip44 = BIP44.BITCOIN_CASH;
  protected override readonly messagePreamble = "\u0018Bitcoin Signed Message:\n";

  constructor(options?: Options) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError("Bitcoin Cash supports mainnet and testnet only");
    }
  }

  private get prefix(): string {
    return this.network === "testnet" ? NETWORK_PREFIXES.testnet : NETWORK_PREFIXES.mainnet;
  }

  /**
   * The P2PKH address in CashAddr, prefix written out. The base58 form of the same hash is
   * Bitcoin's legacy address, so it is never produced here.
   * @param keyPublic - Compressed or uncompressed SEC1 public key as hex
   * @param type - `legacy`, the only type, meaning pay-to-pubkey-hash
   * @returns {string} The address, such as `bitcoincash:qz3yjg59ypg6jqpwhaxgvjj44jm4hdx0w5wsxw2qez`
   */
  override getAddress(keyPublic: string, type = "legacy"): string {
    if (type !== "legacy") throw new RangeError("Bitcoin Cash supports legacy P2PKH only");
    const bytesKeyPublic = hexToBytes(keyPublic);
    secp256k1.Point.fromBytes(bytesKeyPublic);
    return encodeCashAddr(this.prefix, 0, hash160(bytesKeyPublic));
  }

  /**
   * CashAddr under this network's prefix, written or not, with the types and hash lengths
   * Bitcoin Cash Node accepts. Base58 is refused, since its bytes are Bitcoin's.
   * @param address - Candidate address
   * @returns {boolean} Whether the address is Bitcoin Cash on this network
   */
  override validateAddress(address: string): boolean {
    const content = decodeCashAddr(address, this.prefix);
    return (
      content !== undefined && HASH_LENGTHS[content.type]?.includes(content.hash.length) === true
    );
  }
}

export default BitcoinCash;
