import type {
  AbstractBlockchain,
  KeyOptions,
  blockchains,
  useBlockchain,
} from "../../../src/index.ts";

/** What the explorer needs from the library. Components pass the bundle, tests pass src/. */
export type KeysModule = {
  readonly blockchains: typeof blockchains;
  readonly useBlockchain: typeof useBlockchain;
};

export type AddressRow = {
  readonly id: string;
  readonly chain: string;
  readonly curve: "secp256k1" | "ed25519";
  readonly format: string;
  readonly address: string;
};

export type Derivation = {
  readonly secp256k1PublicCompressed: string;
  readonly secp256k1PublicUncompressed: string;
  readonly ed25519Public: string;
  readonly addresses: readonly AddressRow[];
};

export type ExplorerChains = {
  readonly bitcoin: AbstractBlockchain;
  readonly litecoin: AbstractBlockchain;
  readonly decred: AbstractBlockchain;
  readonly ethereum: AbstractBlockchain;
  readonly base: AbstractBlockchain;
  readonly tron: AbstractBlockchain;
  readonly solana: AbstractBlockchain;
  readonly stellar: AbstractBlockchain;
  readonly aptos: AbstractBlockchain;
  readonly sui: AbstractBlockchain;
  readonly cardano: AbstractBlockchain;
};

/** Constructs every explorer chain. Client only in the app, nothing here runs on the server. */
export async function loadExplorerChains(keys: KeysModule): Promise<ExplorerChains> {
  const load = async (name: keyof ExplorerChains) =>
    keys.useBlockchain(await keys.blockchains[name]()());
  const [bitcoin, litecoin, decred, ethereum, base, tron, solana, stellar, aptos, sui, cardano] =
    await Promise.all([
      load("bitcoin"),
      load("litecoin"),
      load("decred"),
      load("ethereum"),
      load("base"),
      load("tron"),
      load("solana"),
      load("stellar"),
      load("aptos"),
      load("sui"),
      load("cardano"),
    ]);
  return { bitcoin, litecoin, decred, ethereum, base, tron, solana, stellar, aptos, sui, cardano };
}

/**
 * Derives public keys and addresses for one 32-byte secret.
 * secp256k1 rows use the scalar. ed25519 rows use the same bytes as a secret.
 */
export function deriveAddresses(hex: string, chains: ExplorerChains): Derivation {
  const { bitcoin, litecoin, decred, ethereum, base, tron, solana, stellar, aptos, sui, cardano } =
    chains;

  return {
    secp256k1PublicCompressed: bitcoin.getKeyPublic(hex),
    secp256k1PublicUncompressed: bitcoin.getKeyPublic(hex, { compressed: false }),
    ed25519Public: solana.getKeyPublic(hex),
    addresses: [
      addressRow(bitcoin, hex, "btc-legacy", "Bitcoin", "secp256k1", "legacy", undefined, "legacy"),
      addressRow(bitcoin, hex, "btc-p2sh", "Bitcoin", "secp256k1", "p2sh", undefined, "p2sh"),
      addressRow(bitcoin, hex, "btc-segwit", "Bitcoin", "secp256k1", "segwit", undefined, "segwit"),
      addressRow(bitcoin, hex, "btc-p2wsh", "Bitcoin", "secp256k1", "p2wsh", undefined, "p2wsh"),
      addressRow(
        bitcoin,
        hex,
        "btc-taproot",
        "Bitcoin",
        "secp256k1",
        "taproot",
        undefined,
        "taproot",
      ),
      addressRow(litecoin, hex, "ltc-legacy", "Litecoin", "secp256k1", "legacy", undefined, "legacy"),
      addressRow(litecoin, hex, "ltc-p2sh", "Litecoin", "secp256k1", "p2sh", undefined, "p2sh"),
      addressRow(litecoin, hex, "ltc-segwit", "Litecoin", "secp256k1", "segwit", undefined, "segwit"),
      addressRow(litecoin, hex, "ltc-p2wsh", "Litecoin", "secp256k1", "p2wsh", undefined, "p2wsh"),
      addressRow(
        litecoin,
        hex,
        "ltc-taproot",
        "Litecoin",
        "secp256k1",
        "taproot",
        undefined,
        "taproot",
      ),
      addressRow(decred, hex, "dcr", "Decred", "secp256k1", "legacy"),
      addressRow(ethereum, hex, "eth", "Ethereum", "secp256k1", "EIP-55"),
      addressRow(base, hex, "base", "Base", "secp256k1", "EIP-55"),
      addressRow(tron, hex, "tron", "TRON", "secp256k1", "base58check"),
      addressRow(solana, hex, "sol", "Solana", "ed25519", "base58"),
      addressRow(stellar, hex, "xlm", "Stellar", "ed25519", "StrKey"),
      addressRow(aptos, hex, "aptos", "Aptos", "ed25519", "hex"),
      addressRow(sui, hex, "sui-ed25519", "Sui", "ed25519", "ed25519"),
      addressRow(
        sui,
        hex,
        "sui-secp256k1",
        "Sui",
        "secp256k1",
        "secp256k1",
        { scheme: "secp256k1" },
        "secp256k1",
      ),
      addressRow(
        cardano,
        hex,
        "ada-enterprise",
        "Cardano",
        "ed25519",
        "enterprise",
        undefined,
        "enterprise",
      ),
      addressRow(cardano, hex, "ada-stake", "Cardano", "ed25519", "stake", undefined, "stake"),
    ],
  };
}

export function toSnippet(hex: string): string {
  return `import { useBlockchain, blockchains } from "@agntn/keys";

const hex = "${hex}";
const bitcoin = useBlockchain(await blockchains.bitcoin()());
const publicKey = bitcoin.getKeyPublic(hex);
bitcoin.getAddress(publicKey, "segwit");`;
}

function addressRow(
  chain: AbstractBlockchain,
  hex: string,
  id: string,
  label: string,
  curve: AddressRow["curve"],
  format: string,
  options?: KeyOptions,
  addressType?: string,
): AddressRow {
  const publicKey = chain.getKeyPublic(hex, options);
  return {
    id,
    chain: label,
    curve,
    format,
    address: chain.getAddress(publicKey, addressType),
  };
}
