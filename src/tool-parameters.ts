import type { WIFChain } from "./utils/wif/index.ts";

/** Require either parse mode by itself or generation mode with its optional indices. */
export const BIP44_PATH_MODE_SCHEMA = {
  oneOf: [
    {
      required: ["path"],
      not: {
        anyOf: ["chain", "account", "change", "addressIndex", "addressType"].map((field) => ({
          required: [field],
        })),
      },
    },
    { required: ["chain"], not: { required: ["path"] } },
  ],
} as const;

/**
 * Every tool `keys mcp` lists, in its order. The docs count them from here, so a new tool
 * changes the number on the landing and in the OG image without an edit there.
 */
export const TOOL_NAMES = [
  "keys_electrum_wallet_derive",
  "keys_bip39_seed_derive",
  "keys_secp256k1_public_key_convert",
  "keys_wif_encode",
  "keys_wif_decode",
  "keys_bip38_inspect",
  "keys_generate_wallet",
  "keys_derive_wallet",
  "keys_derive_hd_wallet",
  "keys_derive_xpub_wallet",
  "keys_bip39_generate",
  "keys_bip39_inspect",
  "keys_bip39_entropy_encode",
  "keys_bip39_indices_lookup",
  "keys_bip39_words_lookup",
  "keys_bip39_word_recover",
  "keys_get_address",
  "keys_validate_address",
  "keys_sign_message",
  "keys_verify_message",
  "keys_bip44_path",
] as const;

export type ToolName = (typeof TOOL_NAMES)[number];

/** Maximum text length accepted by the BIP39 seed tool. */
export const MAX_BIP39_SEED_INPUT_LENGTH = 4096;

/** Maximum address length the BIP38 tool hashes against a key. */
export const MAX_BIP38_ADDRESS_LENGTH = 128;

/** Maximum address length the address validation tool checks. */
export const MAX_ADDRESS_LENGTH = 256;

/** Supported BIP39 mnemonic lengths for generation tools. */
export const TOOL_MNEMONIC_WORD_COUNTS: readonly number[] = [12, 15, 18, 21, 24];

/** Every blockchain exposed by the tool surfaces. */
export const TOOL_CHAINS = [
  "bitcoin",
  "bitcoincash",
  "bitcoingold",
  "bitcoinsv",
  "litecoin",
  "dash",
  "decred",
  "dogecoin",
  "zcash",
  "ecash",
  "ethereum",
  "base",
  "solana",
  "stellar",
  "aptos",
  "tron",
  "sui",
  "cardano",
] as const;

/** Blockchain name accepted by the tool surfaces. */
export type ToolChain = (typeof TOOL_CHAINS)[number];

/** Every network exposed by the tool surfaces. */
export const TOOL_NETWORKS = ["mainnet", "testnet"] as const;

/** Network name accepted by the tool surfaces. */
export type ToolNetwork = (typeof TOOL_NETWORKS)[number];

const BITCOIN_ADDRESS_TYPES = ["legacy", "p2sh", "segwit", "p2wsh", "taproot"] as const;
const CARDANO_ADDRESS_TYPES = ["payment", "stake", "enterprise"] as const;
/** Signature schemes Sui takes as its address type. */
export const SUI_ADDRESS_TYPES = ["ed25519", "secp256k1"] as const;

/** Every address type exposed by the tool surfaces. */
export const TOOL_ADDRESS_TYPES = [
  ...BITCOIN_ADDRESS_TYPES,
  ...CARDANO_ADDRESS_TYPES,
  ...SUI_ADDRESS_TYPES,
] as const;

/** Address types accepted for each tool chain. */
export const TOOL_ADDRESS_TYPES_BY_CHAIN: Readonly<Record<ToolChain, readonly string[]>> = {
  bitcoin: BITCOIN_ADDRESS_TYPES,
  bitcoincash: ["legacy"],
  bitcoingold: ["legacy", "p2sh", "segwit", "p2wsh"],
  bitcoinsv: ["legacy"],
  litecoin: BITCOIN_ADDRESS_TYPES,
  dash: ["legacy"],
  decred: ["legacy"],
  dogecoin: ["legacy"],
  zcash: ["legacy"],
  ecash: ["legacy"],
  ethereum: [],
  base: [],
  solana: [],
  stellar: [],
  aptos: [],
  tron: [],
  sui: SUI_ADDRESS_TYPES,
  cardano: CARDANO_ADDRESS_TYPES,
};

/** Native WIF chains exposed by both agent transports. */
export const TOOL_WIF_CHAINS = [
  "bitcoin",
  "litecoin",
  "dash",
  "decred",
  "dogecoin",
] as const satisfies readonly WIFChain[];

/** Maximum number of words or indices accepted by one BIP39 lookup. */
export const MAX_BIP39_LOOKUP_ITEMS = 100;

/** BIP39 entropy byte lengths accepted by the package. */
export const BIP39_ENTROPY_BYTE_LENGTHS: readonly number[] = [16, 20, 24, 28, 32];

/** JSON Schema pattern for a complete BIP39 entropy value. */
export const BIP39_ENTROPY_SCHEMA_PATTERN = `^(?:${BIP39_ENTROPY_BYTE_LENGTHS.map((bytes) => `[0-9A-Fa-f]{${bytes * 2}}`).join("|")})$`;

/** JSON Schema pattern for one non-whitespace BIP39 lookup word. */
export const BIP39_WORD_SCHEMA_PATTERN = "^\\S+$";

/** JSON Schema pattern for an absolute derivation path, hardened levels marked with `'` or `h`. */
export const DERIVATION_PATH_SCHEMA_PATTERN = "^m(/[0-9]+['h]?)+$";

/** JSON Schema pattern for normal levels below an xpub; hardened ones need the private key. */
export const XPUB_PATH_SCHEMA_PATTERN = "^m(/[0-9]+)+$";

/** JSON Schema pattern for a 32-byte private key, the one size every supported chain signs with. */
export const PRIVATE_KEY_SCHEMA_PATTERN = "^[0-9A-Fa-f]{64}$";

/** JSON Schema pattern for a 32-byte ed25519 key or a compressed or uncompressed SEC1 secp256k1 key. */
export const PUBLIC_KEY_SCHEMA_PATTERN =
  "^(?:[0-9A-Fa-f]{64}|0[23][0-9A-Fa-f]{64}|04[0-9A-Fa-f]{128})$";

/** JSON Schema pattern for a 64-byte `r||s` or ed25519 signature, or 65 bytes with the recovery byte. */
export const SIGNATURE_SCHEMA_PATTERN = "^[0-9A-Fa-f]{128}(?:[0-9A-Fa-f]{2})?$";
