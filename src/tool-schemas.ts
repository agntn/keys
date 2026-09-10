import { Type } from "typebox";
import {
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
