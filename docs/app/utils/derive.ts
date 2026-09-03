import type { AbstractBlockchain, KeyOptions } from "@agntn/keys";

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
  readonly ethereum: AbstractBlockchain;
  readonly base: AbstractBlockchain;
  readonly tron: AbstractBlockchain;
  readonly solana: AbstractBlockchain;
  readonly aptos: AbstractBlockchain;
  readonly sui: AbstractBlockchain;
  readonly cardano: AbstractBlockchain;
};

/**
 * Derives public keys and addresses for one 32-byte secret.
 * secp256k1 rows use the scalar. ed25519 rows use the same bytes as a secret.
 */
export function deriveAddresses(hex: string, chains: ExplorerChains): Derivation {
  const { bitcoin, ethereum, base, tron, solana, aptos, sui, cardano } = chains;

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
      addressRow(ethereum, hex, "eth", "Ethereum", "secp256k1", "EIP-55"),
      addressRow(base, hex, "base", "Base", "secp256k1", "EIP-55"),
      addressRow(tron, hex, "tron", "TRON", "secp256k1", "base58check"),
      addressRow(solana, hex, "sol", "Solana", "ed25519", "base58"),
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
