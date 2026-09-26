import { BIP44 } from "../utils/bip44/index.ts";
import { AbstractCashAddrBlockchain } from "../utils/bitcoin.ts";
import type { Options } from "../types.ts";

/**
 * Bitcoin ABC src/kernel/chainparams.cpp for the prefixes and src/cashaddrenc.cpp for what it
 * pays to: a 20 byte key hash under type 0 or a 20 byte script hash under type 1. The token
 * types and 32 byte script hashes Bitcoin Cash added later never reached eCash.
 */
const CASHADDR_PARAMS = {
  prefixes: { mainnet: "ecash", testnet: "ectest" },
  hashLengths: [[20], [20]],
} as const;

/**
 * eCash (XEC) P2PKH wallets in CashAddr, such as `ecash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnqdxfumtxd`.
 * Keys and the message digest are Bitcoin's, but Bitcoin ABC signs under its own preamble,
 * so a Bitcoin or Bitcoin Cash signature does not verify here.
 */
export class ECash extends AbstractCashAddrBlockchain {
  override readonly name = "ecash";
  override readonly bip44 = BIP44.ECASH;
  protected override readonly messagePreamble = "\u0016eCash Signed Message:\n";

  constructor(options?: Options) {
    super(options, "eCash", CASHADDR_PARAMS);
  }
}

export default ECash;
