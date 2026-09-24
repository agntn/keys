import type { AddressRow, Derivation } from "./derive";

export const KEY_ONE_HEX = "1".padStart(64, "0");

/** Private key 1 on every landing row, what `deriveAddresses` gives once the library loads. */
export const landingStaticRows: readonly AddressRow[] = [
  {
    id: "btc-segwit",
    chain: "Bitcoin",
    curve: "secp256k1",
    format: "segwit",
    address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
  },
  {
    id: "bch",
    chain: "Bitcoin Cash",
    curve: "secp256k1",
    format: "CashAddr",
    address: "bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h",
  },
  {
    id: "btg-segwit",
    chain: "Bitcoin Gold",
    curve: "secp256k1",
    format: "segwit",
    address: "btg1qw508d6qejxtdg4y5r3zarvary0c5xw7k6w057a",
  },
  {
    id: "bsv",
    chain: "Bitcoin SV",
    curve: "secp256k1",
    format: "legacy",
    address: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
  },
  {
    id: "ltc-segwit",
    chain: "Litecoin",
    curve: "secp256k1",
    format: "segwit",
    address: "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
  },
  {
    id: "dash",
    chain: "Dash",
    curve: "secp256k1",
    format: "legacy",
    address: "XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE",
  },
  {
    id: "dcr",
    chain: "Decred",
    curve: "secp256k1",
    format: "legacy",
    address: "DsmcYVbP1Nmag2H4AS17UTvmWXmGeA7nLDx",
  },
  {
    id: "doge",
    chain: "Dogecoin",
    curve: "secp256k1",
    format: "legacy",
    address: "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE",
  },
  {
    id: "eth",
    chain: "Ethereum",
    curve: "secp256k1",
    format: "EIP-55",
    address: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
  },
  {
    id: "base",
    chain: "Base",
    curve: "secp256k1",
    format: "EIP-55",
    address: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
  },
  {
    id: "tron",
    chain: "TRON",
    curve: "secp256k1",
    format: "base58check",
    address: "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC",
  },
  {
    id: "sol",
    chain: "Solana",
    curve: "ed25519",
    format: "base58",
    address: "6ASf5EcmmEHTgDJ4X4ZT5vT6iHVJBXPg5AN5YoTCpGWt",
  },
  {
    id: "xlm",
    chain: "Stellar",
    curve: "ed25519",
    format: "StrKey",
    address: "GBGLLK7WVV47X5NLXTFPZQTJ3BONEZI62S4ILNMGT4SBV3PQUW5CTECA",
  },
  {
    id: "aptos",
    chain: "Aptos",
    curve: "ed25519",
    format: "hex",
    address: "0xf90391c81027f03cdea491ed8b36ffaced26b6df208a9b569e5baf2590eb9b16",
  },
  {
    id: "sui-ed25519",
    chain: "Sui",
    curve: "ed25519",
    format: "ed25519",
    address: "0xd0c2c91eda34bbfbaec6cfb9c7bb913e57dab3cbec4018a4b3f5e55531cd63af",
  },
  {
    id: "ada-enterprise",
    chain: "Cardano",
    curve: "ed25519",
    format: "enterprise",
    address: "addr1v8qvqahau6y67jdq0kfm9dy0hjmgv4u962nmk9pslsl7ryq5mvnl7",
  },
];

export const LANDING_IDS: ReadonlySet<string> = new Set(landingStaticRows.map((row) => row.id));

export type Pipeline = {
  readonly publicKey: string;
  readonly legacy: string;
  readonly segwit: string;
  readonly taproot: string;
};

export const landingStaticPipeline: Pipeline = {
  publicKey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  legacy: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
  segwit: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
  taproot: "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
};

export function toPipeline(derivation: Derivation): Pipeline {
  const address = (id: string) => derivation.addresses.find((row) => row.id === id)?.address ?? "";
  return {
    publicKey: derivation.secp256k1PublicCompressed,
    legacy: address("btc-legacy"),
    segwit: address("btc-segwit"),
    taproot: address("btc-taproot"),
  };
}

/** Public BIP39 test vector. Never a real wallet. */
export const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

export type HdSample = {
  readonly index: number;
  readonly path: string;
  readonly address: string;
};

export const HD_STATIC: HdSample = {
  index: 0,
  path: "m/44'/60'/0'/0/0",
  address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
};

export function diffBytes(previous: string, next: string): ReadonlySet<number> {
  const changed = new Set<number>();
  for (let index = 0; index < 32; index += 1) {
    if (previous.slice(index * 2, index * 2 + 2) !== next.slice(index * 2, index * 2 + 2)) {
      changed.add(index);
    }
  }
  return changed;
}
