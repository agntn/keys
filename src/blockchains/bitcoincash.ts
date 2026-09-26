import { BIP44 } from "../utils/bip44/index.ts";
import { AbstractCashAddrBlockchain } from "../utils/bitcoin.ts";
import type { Options } from "../types.ts";

/**
 * Bitcoin Cash Node src/chainparams.cpp for the prefixes; testnet3, testnet4, scalenet and
 * chipnet share one. Types 0 and 2 hash a key, 1 and 3 a script, and CashTokens let scripts
 * hash to 32 bytes as well.
 */
const CASHADDR_PARAMS = {
  prefixes: { mainnet: "bitcoincash", testnet: "bchtest" },
  hashLengths: [[20], [20, 32], [20], [20, 32]],
} as const;

/**
 * Bitcoin Cash P2PKH wallets in CashAddr, such as
 * `bitcoincash:qz3yjg59ypg6jqpwhaxgvjj44jm4hdx0w5wsxw2qez`. Keys and signed messages are
 * Bitcoin's, preamble included, since Bitcoin Cash Node kept it.
 */
export class BitcoinCash extends AbstractCashAddrBlockchain {
  override readonly name = "bitcoincash";
  override readonly bip44 = BIP44.BITCOIN_CASH;
  protected override readonly messagePreamble = "\u0018Bitcoin Signed Message:\n";

  constructor(options?: Options) {
    super(options, "Bitcoin Cash", CASHADDR_PARAMS);
  }
}

export default BitcoinCash;
