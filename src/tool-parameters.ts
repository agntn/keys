import type { WIFChain } from "./utils/wif/index.ts";

/**
 * Every tool `keys mcp` lists, in its order. The docs count them from here, so a new tool
 * changes the number on the landing and in the OG image without an edit there.
 */
export const TOOL_NAMES = [
  "keys_electrum_wallet_derive",
  "keys_brainwallet_derive",
  "keys_bip39_seed_derive",
  "keys_secp256k1_public_key_convert",
  "keys_secp256k1_point_compute",
  "keys_curve_compute",
  "keys_wif_encode",
  "keys_wif_decode",
  "keys_bip38_inspect",
  "keys_bip38_decrypt",
  "keys_store_decrypt",
  "keys_wallet_generate",
  "keys_wallet_derive",
  "keys_hd_wallet_derive",
  "keys_hd_wallet_scan",
  "keys_xpub_wallet_derive",
  "keys_bip32_parent_recover",
  "keys_bip39_generate",
  "keys_bip39_inspect",
  "keys_bip39_entropy_encode",
  "keys_bip39_indices_lookup",
  "keys_bip39_words_lookup",
  "keys_bip39_word_recover",
  "keys_bip39_words_order",
  "keys_bip39_words_repair",
  "keys_address_get",
  "keys_address_validate",
  "keys_message_sign",
  "keys_message_verify",
  "keys_message_recover",
  "keys_bip322_sign",
  "keys_bip322_verify",
  "keys_bip44_parse",
  "keys_bip44_generate",
] as const;

export type ToolName = (typeof TOOL_NAMES)[number];

/** What `keys_secp256k1_point_compute` does with public points. */
export const SECP256K1_POINT_OPERATIONS = [
  "add",
  "subtract",
  "negate",
  "multiply",
  "lift",
  "check",
] as const;

export type Secp256k1PointOperation = (typeof SECP256K1_POINT_OPERATIONS)[number];

/** What `keys_curve_compute` does on a curve the caller defines. */
export const CURVE_OPERATIONS = [
  "add",
  "double",
  "negate",
  "multiply",
  "check",
  "order",
  "count",
  "points",
  "log",
] as const;

export type CurveOperation = (typeof CURVE_OPERATIONS)[number];

/** Longest integer `keys_curve_compute` reads, enough for a 512-bit decimal with a sign. */
export const MAX_CURVE_INTEGER_LENGTH = 160;

/** Most points one `points` call lists. */
export const MAX_CURVE_POINTS_SHOWN = 1000;

/** Points a `points` call lists when it names no limit. */
export const DEFAULT_CURVE_POINTS_SHOWN = 100;

/** Maximum text length accepted by the BIP39 seed tool. */
export const MAX_BIP39_SEED_INPUT_LENGTH = 4096;

/** Maximum passphrase and salt length the brainwallet tool takes, in characters. */
export const MAX_BRAINWALLET_INPUT_LENGTH = 4096;

/** Cost ceilings of the brainwallet and keystore tools, the ones `@agntn/hashes` sets on its own tools. */
export const KDF_COST_LIMITS = {
  N: 2 ** 20,
  r: 32,
  p: 16,
  iterations: 10_000_000,
  keyLength: 1024,
} as const;

/** Largest scrypt `N * r` per call, 256 MiB of blocks, enough for brainwallet.io and a geth keystore. */
export const MAX_SCRYPT_BLOCKS = 2 ** 21;

/** Maximum keystore JSON length the keystore tool reads, room for the extra fields ethers writes. */
export const MAX_KEYSTORE_LENGTH = 16_384;

/** Maximum keystore password length, in characters. */
export const MAX_KEYSTORE_PASSWORD_LENGTH = 4096;

/** Maximum address length the BIP38 tool hashes against a key. */
export const MAX_BIP38_ADDRESS_LENGTH = 128;

/** Maximum BIP38 passphrase length, in characters. */
export const MAX_BIP38_PASSPHRASE_LENGTH = 4096;

/** Maximum length of a Base58Check extended key, which serializes to 111 or 112 characters. */
export const MAX_EXTENDED_KEY_LENGTH = 128;

/** Maximum WIF length; Decred's two byte prefix makes the longest one 53 characters. */
export const MAX_WIF_LENGTH = 54;

/** Maximum phrase length the wallet scan reads, in characters. */
export const MAX_SCAN_MNEMONIC_LENGTH = 4096;

/** Accounts the wallet scan walks by default and at most, from account 0. */
export const SCAN_ACCOUNTS = { default: 3, maximum: 10 } as const;

/** Address indices the wallet scan walks by default and at most; 20 is the BIP44 gap limit. */
export const SCAN_INDICES = { default: 20, maximum: 100 } as const;

/** Maximum address length the address validation tool checks. */
export const MAX_ADDRESS_LENGTH = 256;

/** Maximum EIP-712 typed data JSON length the recover tool hashes, in characters. */
export const MAX_TYPED_DATA_LENGTH = 16_384;

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

/** Most phrases one order or repair call checks against the checksum, about a second of hashing. */
export const MAX_BIP39_CHECKSUM_SEARCH = 1_000_000;

/** Longest template or phrase the order and repair tools take, in characters. */
export const MAX_BIP39_PHRASE_LENGTH = 1024;

/** Most phrases one order or repair call lists. */
export const MAX_BIP39_PHRASES_SHOWN = 100;

/** Phrases the order and repair tools list when the caller sets no limit. */
export const DEFAULT_BIP39_PHRASES_SHOWN = 20;

/** Most words outside the list one `keys_bip39_words_repair` call fixes. */
export const MAX_BIP39_REPAIR_WORDS = 2;

/** Most edits `keys_bip39_words_repair` allows between a word and a suggestion. */
export const MAX_BIP39_REPAIR_DISTANCE = 3;

/** Edits `keys_bip39_words_repair` allows when the caller sets no limit. */
export const DEFAULT_BIP39_REPAIR_DISTANCE = 2;

/** Most caller texts one inspection hashes against the entropy. */
export const MAX_ENTROPY_PREIMAGES = 100;

/** Longest caller text one inspection hashes, in characters. */
export const MAX_ENTROPY_PREIMAGE_LENGTH = 4096;

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

/** JSON Schema pattern for Core's base64 signature: 65 bytes are 87 characters and one `=`. */
export const CORE_SIGNATURE_SCHEMA_PATTERN = "^[A-Za-z0-9+/]{87}=$";

/** JSON Schema pattern for what the recover tool reads: `r||s||v` hex or Core's base64. */
export const RECOVERABLE_SIGNATURE_SCHEMA_PATTERN = "^(?:[0-9A-Fa-f]{130}|[A-Za-z0-9+/]{87}=)$";

/** JSON Schema pattern for a 32-byte digest as hex without 0x. */
export const DIGEST_SCHEMA_PATTERN = "^[0-9A-Fa-f]{64}$";

/** JSON Schema pattern for a signature the verify tool reads: hex as above, or Core's base64. */
export const MESSAGE_SIGNATURE_SCHEMA_PATTERN =
  "^(?:[0-9A-Fa-f]{128}(?:[0-9A-Fa-f]{2})?|[A-Za-z0-9+/]{87}=)$";

/** Address types `keys_bip322_sign` writes for. */
export const BIP322_SIGNING_TYPES = ["legacy", "p2sh", "segwit", "taproot"] as const;

/** Longest BIP322 signature the verify tool reads, room for a full `to_sign` with large pushes. */
export const MAX_BIP322_SIGNATURE_LENGTH = 8192;

/** JSON Schema pattern for a BIP322 signature: an optional `smp`, `ful` or `pof`, then base64. */
export const BIP322_SIGNATURE_SCHEMA_PATTERN = "^(?:smp|ful|pof)?[A-Za-z0-9+/]*={0,2}$";
