/** One driver as the site presents it: its registry key, display name, curves, icon and page. */
export type ChainEntry = {
  readonly driver: string;
  readonly label: string;
  readonly curve: string;
  readonly icon: string;
  readonly to: string;
  /** The row of `landingStaticRows` that holds this chain's address for private key 1. */
  readonly row: string;
  /** One sentence on what the driver does differently; backticks mark code. */
  readonly blurb: string;
};

/** Every driver in the order the landing and the dossiers number them. */
export const CHAINS: readonly ChainEntry[] = [
  { driver: "bitcoin", label: "Bitcoin", curve: "secp256k1", icon: "i-token-btc", row: "btc-segwit", blurb: "Five address formats, testnet, and a taproot that does the real BIP341 tweak." },
  { driver: "bitcoincash", label: "Bitcoin Cash", curve: "secp256k1", icon: "i-token-bch", row: "bch", blurb: "Bitcoin's key and hash written as CashAddr, `bitcoincash:q...`, and nothing else." },
  { driver: "bitcoingold", label: "Bitcoin Gold", curve: "secp256k1", icon: "i-token-btg", row: "btg-segwit", blurb: "Bitcoin's formats behind `G`, `A` and `btg1q`, and no taproot, because the chain never turned it on." },
  { driver: "bitcoinsv", label: "Bitcoin SV", curve: "secp256k1", icon: "i-token-bsv", row: "bsv", blurb: "Bitcoin's `1` address, byte for byte, and no P2SH since Genesis." },
  { driver: "litecoin", label: "Litecoin", curve: "secp256k1", icon: "i-token-ltc", row: "ltc-segwit", blurb: "Bitcoin's five formats behind `L`, `M` and `ltc1`, plus its own message preamble." },
  { driver: "dash", label: "Dash", curve: "secp256k1", icon: "i-token-dash", row: "dash", blurb: "Bitcoin's P2PKH behind an `X`, a preamble still called DarkCoin, and no SegWit." },
  { driver: "decred", label: "Decred", curve: "secp256k1", icon: "i-token-dcr", row: "dcr", blurb: "BLAKE-256 in every hash, addresses that start with `Ds`, and no HD walk, on purpose." },
  { driver: "dogecoin", label: "Dogecoin", curve: "secp256k1", icon: "i-token-doge", row: "doge", blurb: "Bitcoin's P2PKH behind a `D`, its own preamble, and no SegWit to wrap anything in." },
  { driver: "zcash", label: "Zcash", curve: "secp256k1", icon: "i-token-zec", row: "zec", blurb: "The transparent half only: `t1` behind two version bytes, and nothing shielded." },
  { driver: "ecash", label: "eCash", curve: "secp256k1", icon: "i-token-xec", row: "xec", blurb: "Bitcoin Cash's CashAddr under `ecash:`, its own preamble, and none of the CashTokens types." },
  { driver: "ethereum", label: "Ethereum", curve: "secp256k1", icon: "i-token-eth", row: "eth", blurb: "EIP-55 checksummed hex and the personal_sign preamble." },
  { driver: "base", label: "Base", curve: "secp256k1", icon: "i-token-base", row: "base", blurb: "Same driver as Ethereum under a different name. Same key, same address." },
  { driver: "tron", label: "TRON", curve: "secp256k1", icon: "i-token-trx", row: "tron", blurb: "Ethereum's 20 bytes wrapped in base58check, so it starts with T." },
  { driver: "solana", label: "Solana", curve: "ed25519", icon: "i-token-sol", row: "sol", blurb: "The address is the public key in base58, no hashing at all." },
  { driver: "stellar", label: "Stellar", curve: "ed25519", icon: "i-token-xlm", row: "xlm", blurb: "The public key as a `G` StrKey with a CRC16 checksum, and SEP-53 message signing." },
  { driver: "aptos", label: "Aptos", curve: "ed25519", icon: "i-token-apt", row: "aptos", blurb: "SHA3-256 over the key and a scheme byte, 0x hex out." },
  { driver: "sui", label: "Sui", curve: "ed25519 · secp256k1", icon: "i-token-sui", row: "sui-ed25519", blurb: "Both curves on one chain. Blake2b over a flag byte and the key." },
  { driver: "cardano", label: "Cardano", curve: "ed25519", icon: "i-token-ada", row: "ada-enterprise", blurb: "Base, enterprise and stake addresses in bech32. No mnemonic derivation, on purpose." },
  { driver: "xrpl", label: "XRP Ledger", curve: "secp256k1 · ed25519", icon: "i-token-xrp", row: "xrp", blurb: "Family seeds, both curves, and Bitcoin's base58 shuffled until every account starts with `r`." },
  { driver: "near", label: "NEAR", curve: "ed25519", icon: "i-token-near", row: "near", blurb: "The account is the public key in hex. No hash, no checksum, not even base58." },
  { driver: "cosmos", label: "Cosmos", curve: "secp256k1", icon: "i-token-atom", row: "atom", blurb: "One driver for the Hub, Osmosis, Celestia and the rest. Same key, same path, only the letters before the `1` disagree." },
  { driver: "polkadot", label: "Polkadot", curve: "ed25519", icon: "i-token-dot", row: "dot", blurb: "SS58 under any network prefix, Kusama included. ed25519 for now, sr25519 is still waiting its turn." },
].map((entry) => ({ ...entry, to: `/blockchains/${entry.driver}` }));

/**
 * The entry for a driver key.
 *
 * @param {string} driver - The registry key, `bitcoin` or `bitcoincash`.
 * @returns {ChainEntry | undefined} The entry, or nothing for an unknown key.
 */
export function chainEntry(driver: string): ChainEntry | undefined {
  return CHAINS.find((entry) => entry.driver === driver);
}
