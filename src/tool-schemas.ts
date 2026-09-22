import { Type } from "typebox";
import {
  TOOL_CHAINS,
  TOOL_ADDRESS_TYPES,
  SUI_ADDRESS_TYPES,
  MAX_BIP39_LOOKUP_ITEMS,
  BIP39_ENTROPY_SCHEMA_PATTERN,
  BIP39_WORD_SCHEMA_PATTERN,
  DERIVATION_PATH_SCHEMA_PATTERN,
  TOOL_WIF_CHAINS,
  TOOL_NETWORKS,
  TOOL_MNEMONIC_WORD_COUNTS,
  MAX_BIP39_SEED_INPUT_LENGTH,
} from "./tool-parameters.ts";
import { BIP39_LANGUAGES } from "./utils/bip39/languages.ts";

/** The default list is English. Language is never inferred. */
export const BIP39_LANGUAGE_PARAMETER = Type.Optional(
  Type.String({
    enum: BIP39_LANGUAGES,
    minLength: 1,
    maxLength: 19,
    description: "Official BIP39 language key. Default: english",
  }),
);

/** Shared MCP and Pi schema for generating a disposable mnemonic. */
export const GENERATE_MNEMONIC_PARAMETERS = Type.Object(
  {
    language: BIP39_LANGUAGE_PARAMETER,
    words: Type.Optional(
      Type.Integer({
        enum: TOOL_MNEMONIC_WORD_COUNTS,
        description: "Mnemonic word count: 12, 15, 18, 21 or 24. Default: 12",
      }),
    ),
  },
  { additionalProperties: false },
);

const wifContext = {
  chain: Type.String({
    enum: TOOL_WIF_CHAINS,
    description: "Native WIF chain: bitcoin, litecoin or decred",
  }),
  network: Type.Optional(
    Type.String({
      enum: TOOL_NETWORKS,
      description: "Expected network. Default: mainnet; Decred testnet means testnet3",
    }),
  ),
};

/** Shared MCP and Pi schema for exporting a disposable private key. */
export const WIF_ENCODE_PARAMETERS = Type.Object(
  {
    ...wifContext,
    privateKey: Type.String({
      minLength: 64,
      maxLength: 64,
      pattern: "^[0-9A-Fa-f]{64}$",
      description: "Disposable private key as 64 hex characters without 0x",
    }),
    compressed: Type.Optional(
      Type.Boolean({ description: "Compressed public key. Default: true; Decred requires true" }),
    ),
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi schema for reading a disposable WIF. */
export const WIF_DECODE_PARAMETERS = Type.Object(
  {
    ...wifContext,
    wif: Type.String({
      minLength: 1,
      maxLength: 54,
      pattern: "^[1-9A-HJ-NP-Za-km-z]+$",
      description: "Public or disposable WIF string",
    }),
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi schema for SEC1 public key conversion. */
export const CONVERT_PUBLIC_KEY_PARAMETERS = Type.Object(
  {
    publicKey: Type.String({
      minLength: 66,
      maxLength: 130,
      pattern: "^(?:0[23][0-9A-Fa-f]{64}|04[0-9A-Fa-f]{128})$",
      description: "Compressed or uncompressed SEC1 secp256k1 public key as hex, without 0x",
    }),
    compressed: Type.Optional(
      Type.Boolean({ description: "Output compressed SEC1 encoding. Default: true" }),
    ),
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi schema for deriving a disposable BIP39 seed. */
export const DERIVE_BIP39_SEED_PARAMETERS = Type.Object(
  {
    mnemonic: Type.String({
      minLength: 1,
      maxLength: MAX_BIP39_SEED_INPUT_LENGTH,
      pattern: "\\S",
      description: "Public or disposable BIP39 mnemonic; whitespace is collapsed",
    }),
    passphrase: Type.Optional(
      Type.String({
        maxLength: MAX_BIP39_SEED_INPUT_LENGTH,
        description: "BIP39 passphrase. Default: empty. NFKD normalized, never trimmed",
      }),
    ),
    language: BIP39_LANGUAGE_PARAMETER,
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi parameters for an explicitly selected Electrum wallet. */
export const DERIVE_ELECTRUM_WALLET_PARAMETERS = Type.Object(
  {
    mnemonic: Type.String({
      minLength: 1,
      maxLength: 4096,
      pattern: "\\S+",
      description: "Complete public or disposable Electrum standard or SegWit phrase",
    }),
    path: Type.String({
      minLength: 1,
      maxLength: 256,
      pattern: "^m(/[0-9]+'?)+$",
      description: "Exact BIP32 path; no path search or inference",
    }),
    passphrase: Type.Optional(
      Type.String({
        maxLength: 4096,
        description: "Electrum seed extension. Normalized like the phrase; default empty",
      }),
    ),
    network: Type.Optional(
      Type.String({ enum: TOOL_NETWORKS, description: "Bitcoin network. Default: mainnet" }),
    ),
  },
  { additionalProperties: false },
);

const chainArgument = Type.String({
  description: `Blockchain name (${TOOL_CHAINS.join(", ")})`,
  minLength: 1,
  maxLength: 32,
});

const networkArgument = Type.Optional(
  Type.String({
    description: "Network (mainnet or testnet). Default: mainnet",
    enum: TOOL_NETWORKS,
  }),
);

const addressTypeArgument = Type.Optional(
  Type.String({
    description: "Chain-specific address type, such as segwit, taproot, stake, or secp256k1",
    enum: TOOL_ADDRESS_TYPES,
  }),
);

export const GENERATE_WALLET_PARAMETERS = Type.Object(
  { chain: chainArgument, network: networkArgument, addressType: addressTypeArgument },
  { additionalProperties: false },
);

export const DERIVE_WALLET_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    privateKey: Type.String({ description: "Private key as hexadecimal text", minLength: 1 }),
    addressType: addressTypeArgument,
    network: networkArgument,
  },
  { additionalProperties: false },
);

export const DERIVE_HD_WALLET_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    mnemonic: Type.String({
      description: "English BIP39 mnemonic",
      minLength: 1,
      pattern: "\\S",
    }),
    path: Type.String({
      description: "Derivation path such as m/84'/0'/0'/0/0",
      pattern: DERIVATION_PATH_SCHEMA_PATTERN,
    }),
    passphrase: Type.Optional(Type.String({ description: "BIP39 passphrase. Default: empty" })),
    allowInvalidChecksum: Type.Optional(
      Type.Boolean({
        description:
          "Accept an invalid checksum with a warning. English words and BIP39 word counts are still required. Default: false",
      }),
    ),
    addressType: addressTypeArgument,
    network: networkArgument,
  },
  { additionalProperties: false },
);

export const INSPECT_MNEMONIC_PARAMETERS = Type.Object(
  {
    language: BIP39_LANGUAGE_PARAMETER,
    mnemonic: Type.String({
      description: "BIP39 mnemonic candidate",
      minLength: 1,
      pattern: "\\S",
    }),
  },
  { additionalProperties: false },
);

export const ENCODE_BIP39_ENTROPY_PARAMETERS = Type.Object(
  {
    language: BIP39_LANGUAGE_PARAMETER,
    entropy: Type.String({
      description: "BIP39 entropy as 32, 40, 48, 56, or 64 hexadecimal characters",
      pattern: BIP39_ENTROPY_SCHEMA_PATTERN,
    }),
  },
  { additionalProperties: false },
);

export const LOOKUP_BIP39_INDICES_PARAMETERS = Type.Object(
  {
    indices: Type.Array(
      Type.Integer({
        description: "A position from 0 to 2047 for base 0, or 1 to 2048 for base 1",
        minimum: 0,
        maximum: 2048,
      }),
      { minItems: 1, maxItems: MAX_BIP39_LOOKUP_ITEMS },
    ),
    language: BIP39_LANGUAGE_PARAMETER,
    indexBase: Type.Optional(
      Type.Union([Type.Literal(0), Type.Literal(1)], {
        description: "Whether positions start at 0 or 1. Default: 0",
      }),
    ),
  },
  { additionalProperties: false },
);

export const LOOKUP_BIP39_WORDS_PARAMETERS = Type.Object(
  {
    words: Type.Array(
      Type.String({
        description: "A word to check against the selected BIP39 list",
        minLength: 1,
        maxLength: 32,
        pattern: BIP39_WORD_SCHEMA_PATTERN,
      }),
      { minItems: 1, maxItems: MAX_BIP39_LOOKUP_ITEMS },
    ),
    language: BIP39_LANGUAGE_PARAMETER,
  },
  { additionalProperties: false },
);

export const RECOVER_MNEMONIC_WORD_PARAMETERS = Type.Object(
  {
    mnemonic: Type.String({
      description: "English BIP39 mnemonic template containing one ? placeholder",
      minLength: 1,
      pattern: "\\?",
    }),
  },
  { additionalProperties: false },
);

export const GET_ADDRESS_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    publicKey: Type.String({ description: "Public key as hexadecimal text", minLength: 1 }),
    addressType: addressTypeArgument,
    network: networkArgument,
  },
  { additionalProperties: false },
);

export const VALIDATE_ADDRESS_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    address: Type.String({ description: "Address to validate", minLength: 1, maxLength: 256 }),
    network: networkArgument,
  },
  { additionalProperties: false },
);

export const SIGN_MESSAGE_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    message: Type.String({ description: "Message to sign" }),
    privateKey: Type.String({ description: "Private key as hexadecimal text", minLength: 1 }),
    network: networkArgument,
    recovered: Type.Optional(
      Type.Boolean({
        description:
          "Append the recovery byte as v, giving 65-byte r||s||v. Ethereum, base and tron only; that is the form ethers, viem and TronWeb read. Default: false",
      }),
    ),
  },
  { additionalProperties: false },
);

export const VERIFY_MESSAGE_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    message: Type.String({ description: "Original message" }),
    signature: Type.String({ description: "Signature as hexadecimal text", minLength: 1 }),
    publicKey: Type.String({ description: "Public key as hexadecimal text", minLength: 1 }),
    network: networkArgument,
  },
  { additionalProperties: false },
);

/** Plain root for Pi providers; MCP adds BIP44_PATH_MODE_SCHEMA at registration. */
export const BIP44_PATH_PARAMETERS = Type.Object(
  {
    chain: Type.Optional(chainArgument),
    path: Type.Optional(
      Type.String({
        description: "BIP44 path to parse, such as m/44'/0'/0'/0/0",
        minLength: 1,
      }),
    ),
    account: Type.Optional(
      Type.Integer({
        description: "Account index for generation only. Default: 0",
        minimum: 0,
      }),
    ),
    change: Type.Optional(
      Type.Integer({
        description:
          "Change branch for generation only: 0 for external, 1 for internal; on Cardano the CIP-1852 role, up to 5. Default: 0",
        minimum: 0,
      }),
    ),
    addressIndex: Type.Optional(
      Type.Integer({
        description: "Address index for generation only. Default: 0",
        minimum: 0,
      }),
    ),
    addressType: Type.Optional(
      Type.String({
        description:
          "Signature scheme for generation on Sui, ed25519 or secp256k1. Default: ed25519",
        enum: SUI_ADDRESS_TYPES,
      }),
    ),
  },
  { additionalProperties: false },
);
