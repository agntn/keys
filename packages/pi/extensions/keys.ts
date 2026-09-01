/**
 * Pi extension exposing blockchain key, mnemonic, address, and signing tools.
 */
import type { AgentToolResult, ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { BIP39_LANGUAGES, isBIP39Language } from "../../../src/utils/bip39/languages.ts";

/**
 * Lazy-load the library.
 *
 * @returns {Promise<typeof import("@agntn/keys")>} The `@agntn/keys` module (dist build, or the source entry as dev fallback).
 */
async function loadLib() {
  const mod = await import("@agntn/keys").catch(() => {
    // Runtime fallback for dev before dist is built (same package source).
    return import("../../../src/index.ts");
  });
  return mod as typeof import("@agntn/keys");
}

async function loadBIP39() {
  return import("@agntn/keys/bip39").catch(() => import("../../../src/utils/bip39/index.ts"));
}

const CHAINS = [
  "bitcoin",
  "ethereum",
  "base",
  "solana",
  "aptos",
  "tron",
  "sui",
  "cardano",
] as const;
const MAX_BIP39_LOOKUP_ITEMS = 100;
const BIP39_ENTROPY_BYTE_LENGTHS: readonly number[] = [16, 20, 24, 28, 32];
const BIP39_ENTROPY_SCHEMA_PATTERN = `^(?:${BIP39_ENTROPY_BYTE_LENGTHS.map((bytes) => `[0-9A-Fa-f]{${bytes * 2}}`).join("|")})$`;
const BIP39_ENTROPY_PATTERN = /^[0-9a-f]+$/i;
const BIP39_WORD_SCHEMA_PATTERN = "^\\S+$";
const BIP39_WORD_PATTERN = /^[\p{L}\p{M}]+$/u;

type ChainName = (typeof CHAINS)[number];

/**
 * Format a blockchain's curve declaration for display.
 *
 * @param curve - A single curve name or the list of supported curves
 * @returns {string} The curve name, or a comma-separated list of curve names
 */
function formatCurve(curve: string | readonly string[]): string {
  return typeof curve === "string" ? curve : curve.join(", ");
}

function parseBIP39Entropy(entropy: unknown): Uint8Array {
  if (typeof entropy !== "string" || !BIP39_ENTROPY_PATTERN.test(entropy)) {
    throw new TypeError("BIP39 entropy must be a hexadecimal string");
  }
  if (!BIP39_ENTROPY_BYTE_LENGTHS.includes(entropy.length / 2)) {
    throw new RangeError("BIP39 entropy must be 16, 20, 24, 28, or 32 bytes");
  }
  return Buffer.from(entropy, "hex");
}

function assertBIP39IndexBatch(indices: unknown): asserts indices is readonly number[] {
  if (!Array.isArray(indices)) {
    throw new TypeError("BIP39 indices must be an array");
  }
  if (indices.length === 0 || indices.length > MAX_BIP39_LOOKUP_ITEMS) {
    throw new RangeError(`Provide between 1 and ${MAX_BIP39_LOOKUP_ITEMS} indices`);
  }
  if (indices.some((index) => typeof index !== "number" || !Number.isInteger(index))) {
    throw new TypeError("BIP39 indices must be integers");
  }
}

function parseBIP39IndexBase(indexBase: unknown): 0 | 1 {
  if (indexBase === undefined || indexBase === 0) return 0;
  if (indexBase === 1) return 1;
  throw new RangeError("BIP39 index base must be 0 or 1");
}

function assertBIP39IndexRange(indices: readonly number[], indexBase: 0 | 1): void {
  const maximumIndex = 2047 + indexBase;
  if (indices.some((index) => index < indexBase || index > maximumIndex)) {
    throw new RangeError(`BIP39 indices must be between ${indexBase} and ${maximumIndex}`);
  }
}

async function getBlockchain(chain: string, network?: string) {
  const lib = await loadLib();
  const key = chain.toLowerCase() as ChainName;
  if (!Object.hasOwn(lib.blockchains, key)) {
    throw new Error(`Unknown chain "${chain}". Supported: ${CHAINS.join(", ")}`);
  }
  const loadBlockchain = lib.blockchains[key];
  const blockchain = await loadBlockchain({ network: network ?? "mainnet" })();
  return lib.useBlockchain(blockchain);
}

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
        description: `Blockchain name (${CHAINS.join(", ")})`,
      }),
      network: Type.Optional(
        Type.String({
          description: "Network (mainnet or testnet). Default: mainnet",
        }),
      ),
      addressType: Type.Optional(
        Type.String({
          description: "Address type (e.g. segwit for Bitcoin, stake for Cardano)",
        }),
      ),
    }),
    renderCall(args, _theme) {
      return new Text(`🔑 Generate wallet: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const wallet = blockchain.generateWallet({}, params.addressType);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: [
              `Chain: ${blockchain.name} (${blockchain.network ?? "mainnet"})`,
              `Curve: ${formatCurve(blockchain.curve)}`,
              `BIP44: ${blockchain.bip44}`,
              `Private key: ${wallet.keys.private}`,
              `Public key: ${wallet.keys.public}`,
              `Address: ${wallet.address}`,
            ].join("\n"),
          },
        ],
      };
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
      addressType: Type.Optional(
        Type.String({ description: "Address type (e.g. segwit, taproot, secp256k1)" }),
      ),
      network: Type.Optional(Type.String({ description: "Network (mainnet/testnet)" })),
    }),
    renderCall(args, _theme) {
      return new Text(`🔐 Derive wallet: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const wallet = blockchain.deriveWallet(params.privateKey, {}, params.addressType);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: [`Public key: ${wallet.keys.public}`, `Address: ${wallet.address}`].join("\n"),
          },
        ],
      };
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
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const bip39 = await loadBIP39();
      const normalizedMnemonic = params.mnemonic.trim().replaceAll(/\s+/gu, " ");
      const wordCount = normalizedMnemonic === "" ? 0 : normalizedMnemonic.split(" ").length;
      const valid = bip39.validateMnemonic(normalizedMnemonic);
      const lines = [`Valid BIP39: ${valid ? "yes" : "no"}`, `Words: ${wordCount}`];

      if (valid) {
        const entropy = bip39.mnemonicToEntropy(normalizedMnemonic);
        lines.push(`Entropy: ${Buffer.from(entropy).toString("hex")}`);
      }

      return {
        details: undefined,
        content: [{ type: "text", text: lines.join("\n") }],
      };
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
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const entropy = parseBIP39Entropy(params.entropy);
      const bip39 = await loadBIP39();
      const mnemonic = bip39.entropyToMnemonic(entropy);
      const wordCount = mnemonic.split(" ").length;

      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: [`Words: ${wordCount}`, `Mnemonic: ${mnemonic}`].join("\n"),
          },
        ],
      };
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
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      assertBIP39IndexBatch(params.indices);
      const indexBase = parseBIP39IndexBase(params.indexBase);
      assertBIP39IndexRange(params.indices, indexBase);

      const language = params.language ?? "english";
      if (typeof language !== "string" || !isBIP39Language(language)) {
        throw new RangeError(`Unknown BIP39 language. Supported: ${BIP39_LANGUAGES.join(", ")}`);
      }
      const bip39 = await loadBIP39();
      const lookups = await bip39.lookupBIP39Indices(params.indices, language, indexBase);
      const lines = lookups.map((lookup) => `${lookup.index}: ${lookup.word}`);

      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: [`Language: ${language}`, `Index base: ${indexBase}`, ...lines].join("\n"),
          },
        ],
      };
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
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      if (!Array.isArray(params.words)) {
        throw new TypeError("BIP39 lookup words must be an array");
      }
      if (params.words.length === 0 || params.words.length > MAX_BIP39_LOOKUP_ITEMS) {
        throw new RangeError(`Provide between 1 and ${MAX_BIP39_LOOKUP_ITEMS} words`);
      }
      if (params.words.some((word) => typeof word !== "string" || !BIP39_WORD_PATTERN.test(word))) {
        throw new TypeError("BIP39 lookup words must contain letters and combining marks only");
      }

      const language = params.language ?? "english";
      if (typeof language !== "string" || !isBIP39Language(language)) {
        throw new RangeError(`Unknown BIP39 language. Supported: ${BIP39_LANGUAGES.join(", ")}`);
      }
      const bip39 = await loadBIP39();
      const lookups = await bip39.lookupBIP39Words(params.words, language);
      const lines = lookups.map((lookup) =>
        lookup.zeroBasedIndex === null
          ? `${lookup.word}: not in BIP39 (${language})`
          : `${lookup.word}: zero-based ${lookup.zeroBasedIndex}, one-based ${lookup.zeroBasedIndex + 1}`,
      );

      return {
        details: undefined,
        content: [{ type: "text", text: [`Language: ${language}`, ...lines].join("\n") }],
      };
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
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const bip39 = await loadBIP39();
      const normalizedMnemonic = params.mnemonic.trim().replaceAll(/\s+/gu, " ");
      const position = normalizedMnemonic.split(" ").indexOf("?") + 1;
      const candidates = bip39.getMnemonicWordCandidates(normalizedMnemonic);
      const candidateText = candidates.length === 0 ? "none" : candidates.join(", ");

      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: [
              `Position: ${position}`,
              `Candidates (${candidates.length}): ${candidateText}`,
            ].join("\n"),
          },
        ],
      };
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
      addressType: Type.Optional(
        Type.String({ description: "Address type (e.g. segwit, taproot)" }),
      ),
      network: Type.Optional(Type.String({ description: "Network (mainnet/testnet)" })),
    }),
    renderCall(args, _theme) {
      return new Text(`📬 Get address: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const address = blockchain.getAddress(params.publicKey, params.addressType);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: `Address: ${address}`,
          },
        ],
      };
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
      network: Type.Optional(Type.String({ description: "Network (mainnet/testnet)" })),
    }),
    renderCall(args, _theme) {
      return new Text(`✅ Validate: ${args.address}`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const valid = blockchain.validateAddress(params.address);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: valid
              ? `✅ ${params.address} is a valid ${params.chain} address`
              : `❌ ${params.address} is NOT a valid ${params.chain} address`,
          },
        ],
      };
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
      network: Type.Optional(Type.String({ description: "Network (mainnet/testnet)" })),
    }),
    renderCall(args, _theme) {
      return new Text(`✍️ Sign: "${args.message.slice(0, 30)}…"`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const signature = blockchain.signMessage(params.message, params.privateKey);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: `Signature: ${signature}`,
          },
        ],
      };
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
      network: Type.Optional(Type.String({ description: "Network (mainnet/testnet)" })),
    }),
    renderCall(args, _theme) {
      return new Text(`🔍 Verify: "${args.message.slice(0, 30)}…"`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const valid = blockchain.verifyMessage(params.message, params.signature, params.publicKey);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: valid ? "✅ Signature is valid" : "❌ Signature is INVALID",
          },
        ],
      };
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
      "Provide either a chain name to generate a path, or a path string to parse it",
      "Optional: account, change, addressIndex (defaults to 0)",
    ],
    parameters: Type.Object({
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
      account: Type.Optional(Type.Number({ description: "Account index (default 0)" })),
      change: Type.Optional(
        Type.Number({
          description: "Change level (0=external, 1=internal, default 0)",
        }),
      ),
      addressIndex: Type.Optional(Type.Number({ description: "Address index (default 0)" })),
    }),
    renderCall(args, _theme) {
      return new Text(args.path ? `🛤️ Parse: ${args.path}` : `🛤️ BIP44: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const lib = await loadLib();

      // Parse mode
      if (params.path) {
        const parsed = lib.parseBIP44Path(params.path);
        if (!parsed) {
          return {
            details: undefined,
            content: [
              {
                type: "text",
                text: `❌ Invalid BIP44 path: ${params.path}`,
              },
            ],
          };
        }
        return {
          details: undefined,
          content: [
            {
              type: "text",
              text: [
                `Path: ${params.path}`,
                `Purpose: ${parsed.purpose}`,
                `Coin type: ${parsed.coinType}`,
                `Account: ${parsed.account}`,
                `Change: ${parsed.change}`,
                `Address index: ${parsed.addressIndex}`,
              ].join("\n"),
            },
          ],
        };
      }

      // Generate mode
      if (!params.chain) {
        return {
          details: undefined,
          content: [
            {
              type: "text",
              text: "❌ Provide either a chain name or a path string",
            },
          ],
        };
      }

      const key = params.chain.toLowerCase() as ChainName;
      if (!Object.hasOwn(lib.blockchains, key)) {
        return {
          details: undefined,
          content: [
            {
              type: "text",
              text: `Unknown chain "${params.chain}". Supported: ${CHAINS.join(", ")}`,
            },
          ],
        };
      }

      const loadBlockchain = lib.blockchains[key];
      const blockchain = await loadBlockchain()();
      const path = lib.getBlockchainPath(
        blockchain,
        params.account ?? 0,
        params.change ?? 0,
        params.addressIndex ?? 0,
      );

      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: [
              `Chain: ${blockchain.name} (BIP44 coin type: ${blockchain.bip44})`,
              `Path: ${path}`,
            ].join("\n"),
          },
        ],
      };
    },
  });
}
