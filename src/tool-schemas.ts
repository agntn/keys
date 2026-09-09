import { Type } from "typebox";
import { TOOL_WIF_CHAINS, TOOL_NETWORKS, TOOL_MNEMONIC_WORD_COUNTS } from "./tool-parameters.ts";

/** Shared MCP and Pi schema for generating a disposable English mnemonic. */
export const GENERATE_MNEMONIC_PARAMETERS = Type.Object(
  {
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
