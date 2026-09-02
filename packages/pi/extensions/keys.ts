/** Pi extension exposing blockchain key, mnemonic, address, and signing tools. */
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import type * as KeysTools from "../../../dist/tool-operations.d.mts";
import { TOOL_ADDRESS_TYPES, TOOL_CHAINS, TOOL_NETWORKS } from "../../../src/tool-parameters.ts";
import { BIP39_LANGUAGES } from "../../../src/utils/bip39/languages.ts";

const sourceModuleUrl = new URL("../../../src/tool-operations.ts", import.meta.url);
const distributionModuleUrl = new URL("../../../dist/tool-operations.mjs", import.meta.url);
let toolOperationsPromise: Promise<typeof KeysTools> | undefined;

/**
 * Loads the executors shared with the MCP server.
 * @returns {Promise<typeof KeysTools>} Shared tool operations module.
 */
function loadToolOperations(): Promise<typeof KeysTools> {
  toolOperationsPromise ??= import(
    existsSync(fileURLToPath(sourceModuleUrl)) ? sourceModuleUrl.href : distributionModuleUrl.href
  ) as Promise<typeof KeysTools>;
  return toolOperationsPromise;
}

const MAX_BIP39_LOOKUP_ITEMS = 100;
const BIP39_ENTROPY_BYTE_LENGTHS: readonly number[] = [16, 20, 24, 28, 32];
const BIP39_ENTROPY_SCHEMA_PATTERN = `^(?:${BIP39_ENTROPY_BYTE_LENGTHS.map((bytes) => `[0-9A-Fa-f]{${bytes * 2}}`).join("|")})$`;
const BIP39_WORD_SCHEMA_PATTERN = "^\\S+$";
const DERIVATION_PATH_SCHEMA_PATTERN = "^m(/[0-9]+'?)+$";
const NETWORK_PARAMETER = Type.Optional(
  Type.String({
    enum: TOOL_NETWORKS,
    description: "Network (mainnet or testnet). Default: mainnet",
  }),
);
const ADDRESS_TYPE_PARAMETER = Type.Optional(
  Type.String({
    enum: TOOL_ADDRESS_TYPES,
    description: "Address type for the selected chain",
  }),
);

export default function keysExtension(pi: ExtensionAPI) {
  // ─── generate_wallet ────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_generate_wallet",
    label: "Generate Wallet",
    description:
      "Generate a new wallet (private key, public key, and address) for any supported blockchain",
    promptSnippet:
      "Use to create a new wallet with keys and address for Bitcoin, Ethereum, Solana, etc.",
    promptGuidelines: [
      "Provide a chain name (bitcoin, ethereum, base, solana, aptos, tron, sui, cardano)",
      "Optionally specify network (mainnet/testnet) and address type",
      "Bitcoin address types: legacy, p2sh, segwit, p2wsh, taproot",
      "Cardano address types: payment, stake, enterprise",
      "Returns hex private key, hex public key, and address",
    ],
    parameters: Type.Object({
      chain: Type.String({
        description: `Blockchain name (${TOOL_CHAINS.join(", ")})`,
      }),
      network: NETWORK_PARAMETER,
      addressType: ADDRESS_TYPE_PARAMETER,
    }),
    renderCall(args, _theme) {
      return new Text(`🔑 Generate wallet: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).generateWallet(
        params.chain,
        params.network,
        params.addressType,
      );
    },
  });

  pi.registerTool({
    name: "keys_derive_wallet",
    label: "Derive Wallet",
    description: "Derive a public key and address from an existing private key",
    promptSnippet: "Use to derive the public key and address for an existing burner private key.",
    promptGuidelines: [
      "Provide a chain name and private key as hex",
      "Optionally specify network and address type",
      "Bitcoin address types: legacy, p2sh, segwit, p2wsh, taproot",
      "For Sui, use ed25519 or secp256k1 as the address type",
    ],
    parameters: Type.Object({
      chain: Type.String({ description: "Blockchain name" }),
      privateKey: Type.String({ description: "Private key as hex string" }),
      addressType: ADDRESS_TYPE_PARAMETER,
      network: NETWORK_PARAMETER,
    }),
    renderCall(args, _theme) {
      return new Text(`🔐 Derive wallet: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).deriveWallet(
        params.chain,
        params.privateKey,
        params.addressType,
        params.network,
      );
    },
  });

  pi.registerTool({
    name: "keys_derive_hd_wallet",
    label: "Derive HD Wallet",
    description: "Derive a public key and address from a BIP39 mnemonic and derivation path",
    promptSnippet:
      "Use to see which address a public puzzle mnemonic reaches on a given derivation path.",
    promptGuidelines: [
      "Provide a chain, an English BIP39 mnemonic, and a full derivation path",
      "Common paths: Bitcoin m/44'/0'/0'/0/0 (legacy), m/49'/0'/0'/0/0 (p2sh), m/84'/0'/0'/0/0 (segwit), m/86'/0'/0'/0/0 (taproot); Ethereum m/44'/60'/0'/0/0; Solana m/44'/501'/0'/0'; Aptos m/44'/637'/0'/0'/0'; Sui m/44'/784'/0'/0'/0'",
      "Bitcoin picks the address type from the path purpose unless addressType is set",
      "Optionally pass a BIP39 passphrase, a network, or an address type",
      "Cardano is not supported because CIP-1852 derives from entropy, not from the BIP39 seed",
      "Use only public or disposable mnemonics because tool arguments are saved in the transcript",
      "Returns the path, public key, and address, never the mnemonic or private key",
    ],
    parameters: Type.Object({
      chain: Type.String({
        description: `Blockchain name (${TOOL_CHAINS.join(", ")})`,
      }),
      mnemonic: Type.String({
        minLength: 1,
        pattern: "\\S",
        description: "English BIP39 mnemonic",
      }),
      path: Type.String({
        pattern: DERIVATION_PATH_SCHEMA_PATTERN,
        description: "Derivation path such as m/84'/0'/0'/0/0",
      }),
      passphrase: Type.Optional(Type.String({ description: "BIP39 passphrase. Default: empty" })),
      addressType: ADDRESS_TYPE_PARAMETER,
      network: NETWORK_PARAMETER,
    }),
    renderCall(args, _theme) {
      return new Text(`🧩 Derive HD wallet: ${args.chain} ${args.path}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).deriveHdWallet(
        params.chain,
        params.mnemonic,
        params.path,
        params.passphrase,
        params.addressType,
        params.network,
      );
    },
  });

  pi.registerTool({
    name: "keys_inspect_mnemonic",
    label: "Inspect Mnemonic",
    description: "Validate an English BIP39 mnemonic and recover its entropy",
    promptSnippet: "Use to check mnemonic candidates from public crypto puzzles.",
    promptGuidelines: [
      "Provide an English BIP39 mnemonic",
      "Use only public or disposable candidates because tool arguments are saved in the transcript",
      "Returns checksum validity, word count, and entropy for valid mnemonics",
    ],
    parameters: Type.Object({
      mnemonic: Type.String({
        minLength: 1,
        pattern: "\\S",
        description: "English BIP39 mnemonic candidate",
      }),
    }),
    renderCall(_args, _theme) {
      return new Text("🧩 Inspect BIP39 mnemonic", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).inspectMnemonic(params.mnemonic);
    },
  });

  pi.registerTool({
    name: "keys_encode_bip39_entropy",
    label: "Encode BIP39 Entropy",
    description: "Encode hexadecimal entropy as an English BIP39 mnemonic",
    promptSnippet: "Use to turn public puzzle entropy into BIP39 words.",
    promptGuidelines: [
      "Provide 16, 20, 24, 28, or 32 bytes as hexadecimal text",
      "Use only public or disposable entropy because tool arguments are saved in the transcript",
      "Returns the canonical English mnemonic with its word count",
    ],
    parameters: Type.Object({
      entropy: Type.String({
        pattern: BIP39_ENTROPY_SCHEMA_PATTERN,
        description: "BIP39 entropy as 32, 40, 48, 56, or 64 hexadecimal characters",
      }),
    }),
    renderCall(_args, _theme) {
      return new Text("🧩 Encode BIP39 entropy", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).encodeBip39Entropy(params.entropy);
    },
  });

  pi.registerTool({
    name: "keys_lookup_bip39_indices",
    label: "Lookup BIP39 Indices",
    description: "Read words at numeric positions in an official BIP39 list",
    promptSnippet: "Use to map public puzzle indices to BIP39 words.",
    promptGuidelines: [
      "Provide up to 100 integer positions",
      "Set index base to match the puzzle convention. Default: 0",
      "Choose an official BIP39 language when the puzzle is not English",
      "Returns words in the same order as the supplied positions",
    ],
    parameters: Type.Object({
      indices: Type.Array(
        Type.Integer({
          minimum: 0,
          maximum: 2048,
          description: "A position from 0 to 2047 for base 0, or 1 to 2048 for base 1",
        }),
        { minItems: 1, maxItems: MAX_BIP39_LOOKUP_ITEMS },
      ),
      language: Type.Optional(
        Type.String({
          enum: BIP39_LANGUAGES,
          minLength: 1,
          maxLength: 19,
          description: "Official BIP39 language key. Default: english",
        }),
      ),
      indexBase: Type.Optional(
        Type.Union([Type.Literal(0), Type.Literal(1)], {
          description: "Whether positions start at 0 or 1. Default: 0",
        }),
      ),
    }),
    renderCall(args, _theme) {
      return new Text(`🧩 Lookup ${args.indices.length} BIP39 indices`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).lookupBip39Indices(
        params.indices,
        params.language,
        params.indexBase,
      );
    },
  });

  pi.registerTool({
    name: "keys_lookup_bip39_words",
    label: "Lookup BIP39 Words",
    description: "Look up word membership and indices in an official BIP39 list",
    promptSnippet: "Use to map public puzzle words to their BIP39 indices.",
    promptGuidelines: [
      "Provide up to 100 public or disposable words",
      "Choose an official BIP39 language when the puzzle is not English",
      "Returns both zero-based and one-based indices because puzzle conventions differ",
      "Words are matched case-insensitively with Unicode NFKD normalization",
    ],
    parameters: Type.Object({
      words: Type.Array(
        Type.String({
          minLength: 1,
          maxLength: 32,
          pattern: BIP39_WORD_SCHEMA_PATTERN,
          description: "A word to check against the selected BIP39 list",
        }),
        { minItems: 1, maxItems: MAX_BIP39_LOOKUP_ITEMS },
      ),
      language: Type.Optional(
        Type.String({
          enum: BIP39_LANGUAGES,
          minLength: 1,
          maxLength: 19,
          description: "Official BIP39 language key. Default: english",
        }),
      ),
    }),
    renderCall(args, _theme) {
      return new Text(`🧩 Lookup ${args.words.length} BIP39 words`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).lookupBip39Words(params.words, params.language);
    },
  });

  pi.registerTool({
    name: "keys_recover_mnemonic_word",
    label: "Recover Mnemonic Word",
    description: "List English BIP39 words that make the checksum valid for one missing position",
    promptSnippet: "Use to narrow one missing word in a public BIP39 puzzle candidate.",
    promptGuidelines: [
      "Replace exactly one word with ? in a mnemonic containing 12, 15, 18, 21, or 24 words",
      "Use checksum candidates only when the puzzle proves canonical BIP39 generation",
      "Use only public or disposable candidates because tool arguments are saved in the transcript",
      "Returns candidate words, not wallets or target matches",
    ],
    parameters: Type.Object({
      mnemonic: Type.String({
        minLength: 1,
        pattern: "\\?",
        description: "English BIP39 mnemonic template containing one ? placeholder",
      }),
    }),
    renderCall(_args, _theme) {
      return new Text("🧩 Recover BIP39 word", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).recoverMnemonicWord(params.mnemonic);
    },
  });

  // ─── get_address ────────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_get_address",
    label: "Get Address",
    description: "Derive a blockchain address from a public key",
    promptSnippet: "Use to get an address from a public key for any supported blockchain.",
    promptGuidelines: [
      "Provide chain, public key (hex), and optionally address type",
      "Returns the derived address",
    ],
    parameters: Type.Object({
      chain: Type.String({ description: "Blockchain name" }),
      publicKey: Type.String({ description: "Public key as hex string" }),
      addressType: ADDRESS_TYPE_PARAMETER,
      network: NETWORK_PARAMETER,
    }),
    renderCall(args, _theme) {
      return new Text(`📬 Get address: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).getAddress(
        params.chain,
        params.publicKey,
        params.addressType,
        params.network,
      );
    },
  });

  // ─── validate_address ───────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_validate_address",
    label: "Validate Address",
    description: "Check if a blockchain address is valid",
    promptSnippet: "Use to verify an address is valid for a given blockchain.",
    promptGuidelines: ["Provide chain and address to validate", "Returns true/false"],
    parameters: Type.Object({
      chain: Type.String({ description: "Blockchain name" }),
      address: Type.String({ description: "Address to validate" }),
      network: NETWORK_PARAMETER,
    }),
    renderCall(args, _theme) {
      return new Text(`✅ Validate: ${args.address}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).validateAddress(
        params.chain,
        params.address,
        params.network,
      );
    },
  });

  // ─── sign_message ───────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_sign_message",
    label: "Sign Message",
    description: "Sign a message using a blockchain private key",
    promptSnippet: "Use to sign a message with a private key for any supported blockchain.",
    promptGuidelines: [
      "Provide chain, message text, and private key (hex)",
      "Returns the signature as hex string",
      "Bitcoin uses its own message preamble format",
      "Ethereum/Base use EIP-191 prefix",
    ],
    parameters: Type.Object({
      chain: Type.String({ description: "Blockchain name" }),
      message: Type.String({ description: "Message to sign" }),
      privateKey: Type.String({ description: "Private key as hex string" }),
      network: NETWORK_PARAMETER,
    }),
    renderCall(args, _theme) {
      return new Text(`✍️ Sign: "${args.message.slice(0, 30)}…"`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).signMessage(
        params.chain,
        params.message,
        params.privateKey,
        params.network,
      );
    },
  });

  // ─── verify_message ─────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_verify_message",
    label: "Verify Message",
    description: "Verify a message signature using a blockchain public key",
    promptSnippet: "Use to verify that a signature is valid for a given message and public key.",
    promptGuidelines: [
      "Provide chain, original message, signature (hex), and public key (hex)",
      "Returns true if signature is valid, false otherwise",
    ],
    parameters: Type.Object({
      chain: Type.String({ description: "Blockchain name" }),
      message: Type.String({ description: "Original message" }),
      signature: Type.String({ description: "Signature as hex string" }),
      publicKey: Type.String({ description: "Public key as hex string" }),
      network: NETWORK_PARAMETER,
    }),
    renderCall(args, _theme) {
      return new Text(`🔍 Verify: "${args.message.slice(0, 30)}…"`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).verifyMessage(
        params.chain,
        params.message,
        params.signature,
        params.publicKey,
        params.network,
      );
    },
  });

  // ─── bip44_path ─────────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_bip44_path",
    label: "BIP44 Path",
    description: "Get or parse a BIP44 derivation path for a blockchain",
    promptSnippet:
      "Use to generate or parse BIP44 derivation paths (m/44'/coin'/account'/change/index).",
    promptGuidelines: [
      "Provide a path by itself to parse it, or a chain name to generate a path",
      "For generation only: account, change, addressIndex (defaults to 0)",
    ],
    parameters: Type.Object(
      {
        chain: Type.Optional(
          Type.String({
            description: "Blockchain name (to generate a path)",
          }),
        ),
        path: Type.Optional(
          Type.String({
            description: "BIP44 path string to parse (e.g. m/44'/0'/0'/0/0)",
          }),
        ),
        account: Type.Optional(
          Type.Integer({
            description: "Account index for generation only (default 0)",
            minimum: 0,
          }),
        ),
        change: Type.Optional(
          Type.Integer({
            description: "Change level for generation only (0=external, 1=internal, default 0)",
            minimum: 0,
            maximum: 1,
          }),
        ),
        addressIndex: Type.Optional(
          Type.Integer({
            description: "Address index for generation only (default 0)",
            minimum: 0,
          }),
        ),
      },
      { additionalProperties: false },
    ),
    renderCall(args, _theme) {
      return new Text(args.path ? `🛤️ Parse: ${args.path}` : `🛤️ BIP44: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).bip44Path(
        params.chain,
        params.path,
        params.account,
        params.change,
        params.addressIndex,
      );
    },
  });
}
