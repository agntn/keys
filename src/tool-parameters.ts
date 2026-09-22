import type { WIFChain } from "./utils/wif.ts";

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

/** Maximum text length accepted by the BIP39 seed tool. */
export const MAX_BIP39_SEED_INPUT_LENGTH = 4096;

/** Supported BIP39 mnemonic lengths for generation tools. */
export const TOOL_MNEMONIC_WORD_COUNTS: readonly number[] = [12, 15, 18, 21, 24];

/** Every blockchain exposed by the tool surfaces. */
export const TOOL_CHAINS = [
  "bitcoin",
  "litecoin",
  "decred",
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
  litecoin: BITCOIN_ADDRESS_TYPES,
  decred: ["legacy"],
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
  "decred",
] as const satisfies readonly WIFChain[];

/** Maximum number of words or indices accepted by one BIP39 lookup. */
export const MAX_BIP39_LOOKUP_ITEMS = 100;

/** BIP39 entropy byte lengths accepted by the package. */
export const BIP39_ENTROPY_BYTE_LENGTHS: readonly number[] = [16, 20, 24, 28, 32];

/** JSON Schema pattern for a complete BIP39 entropy value. */
export const BIP39_ENTROPY_SCHEMA_PATTERN = `^(?:${BIP39_ENTROPY_BYTE_LENGTHS.map((bytes) => `[0-9A-Fa-f]{${bytes * 2}}`).join("|")})$`;

/** JSON Schema pattern for one non-whitespace BIP39 lookup word. */
export const BIP39_WORD_SCHEMA_PATTERN = "^\\S+$";

/** JSON Schema pattern for an absolute derivation path. */
export const DERIVATION_PATH_SCHEMA_PATTERN = "^m(/[0-9]+'?)+$";
