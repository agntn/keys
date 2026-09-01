import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { Type, type TSchema } from "typebox";
import { Value } from "typebox/value";
import { BIP39_LANGUAGES } from "./utils/bip39/languages.ts";
import {
  BIP39_ENTROPY_SCHEMA_PATTERN,
  BIP39_WORD_SCHEMA_PATTERN,
  bip44Path,
  DERIVATION_PATH_SCHEMA_PATTERN,
  deriveHdWallet,
  deriveWallet,
  encodeBip39Entropy,
  generateWallet,
  getAddress,
  inspectMnemonic,
  lookupBip39Indices,
  lookupBip39Words,
  MAX_BIP39_LOOKUP_ITEMS,
  recoverMnemonicWord,
  sanitizeToolText,
  signMessage,
  TOOL_CHAINS,
  type ToolResult,
  validateAddress,
  verifyMessage,
} from "./tool-operations.ts";
import { version } from "./version.ts";

type ReadonlyObjectSchema = Readonly<TSchema> & {
  readonly type: "object";
  readonly properties: Readonly<Record<string, Readonly<TSchema>>>;
  readonly required?: readonly string[];
};

interface ToolDefinition {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly inputSchema: ReadonlyObjectSchema;
  readonly annotations: Tool["annotations"];
  execute(
    args: Readonly<Record<string, unknown>>,
  ): ToolResult<unknown> | Promise<ToolResult<unknown>>;
}

const LOCAL_READ: Tool["annotations"] = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

const SENSITIVE_CREATE: Tool["annotations"] = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
};

const SENSITIVE_SIGN: Tool["annotations"] = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

const chainArgument = Type.String({
  description: `Blockchain name (${TOOL_CHAINS.join(", ")})`,
  minLength: 1,
  maxLength: 32,
});

const networkArgument = Type.Optional(
  Type.String({
    description: "Network (mainnet or testnet). Default: mainnet",
    minLength: 1,
    maxLength: 32,
  }),
);

const addressTypeArgument = Type.Optional(
  Type.String({
    description: "Chain-specific address type, such as segwit, taproot, stake, or secp256k1",
    minLength: 1,
    maxLength: 32,
  }),
);

const tools: readonly ToolDefinition[] = [
  {
    name: "keys_generate_wallet",
    title: "Generate Wallet",
    description:
      "Generate a disposable private key, public key, and address for a supported blockchain. The plaintext private key enters the MCP transcript, so never use the result for real funds.",
    inputSchema: Type.Object(
      { chain: chainArgument, network: networkArgument, addressType: addressTypeArgument },
      { additionalProperties: false },
    ),
    annotations: SENSITIVE_CREATE,
    execute: (args) => generateWallet(args["chain"], args["network"], args["addressType"]),
  },
  {
    name: "keys_derive_wallet",
    title: "Derive Wallet",
    description:
      "Derive a public key and address from an existing private key. Use only public or disposable keys because tool arguments enter the MCP transcript.",
    inputSchema: Type.Object(
      {
        chain: chainArgument,
        privateKey: Type.String({ description: "Private key as hexadecimal text", minLength: 1 }),
        addressType: addressTypeArgument,
        network: networkArgument,
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) =>
      deriveWallet(args["chain"], args["privateKey"], args["addressType"], args["network"]),
  },
  {
    name: "keys_derive_hd_wallet",
    title: "Derive HD Wallet",
    description:
      "Derive a public key and address from an English BIP39 mnemonic and an absolute derivation path. The mnemonic and optional passphrase enter the MCP transcript, so use only public or disposable material.",
    inputSchema: Type.Object(
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
        addressType: addressTypeArgument,
        network: networkArgument,
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) =>
      deriveHdWallet(
        args["chain"],
        args["mnemonic"],
        args["path"],
        args["passphrase"],
        args["addressType"],
        args["network"],
      ),
  },
  {
    name: "keys_inspect_mnemonic",
    title: "Inspect Mnemonic",
    description:
      "Validate an English BIP39 mnemonic and recover its entropy when valid. The phrase enters the MCP transcript, so use only public or disposable candidates.",
    inputSchema: Type.Object(
      {
        mnemonic: Type.String({
          description: "English BIP39 mnemonic candidate",
          minLength: 1,
          pattern: "\\S",
        }),
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) => inspectMnemonic(args["mnemonic"]),
  },
  {
    name: "keys_encode_bip39_entropy",
    title: "Encode BIP39 Entropy",
    description:
      "Encode 16, 20, 24, 28, or 32 bytes of hexadecimal entropy as an English BIP39 mnemonic. Both forms enter the MCP transcript, so use only public or disposable material.",
    inputSchema: Type.Object(
      {
        entropy: Type.String({
          description: "BIP39 entropy as 32, 40, 48, 56, or 64 hexadecimal characters",
          pattern: BIP39_ENTROPY_SCHEMA_PATTERN,
        }),
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) => encodeBip39Entropy(args["entropy"]),
  },
  {
    name: "keys_lookup_bip39_indices",
    title: "Look Up BIP39 Indices",
    description:
      "Read words at numeric positions in an official BIP39 list, preserving the supplied order and index convention.",
    inputSchema: Type.Object(
      {
        indices: Type.Array(
          Type.Integer({
            description: "A position from 0 to 2047 for base 0, or 1 to 2048 for base 1",
            minimum: 0,
            maximum: 2048,
          }),
          { minItems: 1, maxItems: MAX_BIP39_LOOKUP_ITEMS },
        ),
        language: Type.Optional(
          Type.String({
            description: "Official BIP39 language key. Default: english",
            enum: BIP39_LANGUAGES,
            minLength: 1,
            maxLength: 19,
          }),
        ),
        indexBase: Type.Optional(
          Type.Union([Type.Literal(0), Type.Literal(1)], {
            description: "Whether positions start at 0 or 1. Default: 0",
          }),
        ),
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) => lookupBip39Indices(args["indices"], args["language"], args["indexBase"]),
  },
  {
    name: "keys_lookup_bip39_words",
    title: "Look Up BIP39 Words",
    description:
      "Check word membership in an official BIP39 list and return both zero-based and one-based indices.",
    inputSchema: Type.Object(
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
        language: Type.Optional(
          Type.String({
            description: "Official BIP39 language key. Default: english",
            enum: BIP39_LANGUAGES,
            minLength: 1,
            maxLength: 19,
          }),
        ),
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) => lookupBip39Words(args["words"], args["language"]),
  },
  {
    name: "keys_recover_mnemonic_word",
    title: "Recover Mnemonic Word",
    description:
      "List English BIP39 words that make the checksum valid for one missing position. The partial phrase enters the MCP transcript, so use only public or disposable candidates.",
    inputSchema: Type.Object(
      {
        mnemonic: Type.String({
          description: "English BIP39 mnemonic template containing one ? placeholder",
          minLength: 1,
          pattern: "\\?",
        }),
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) => recoverMnemonicWord(args["mnemonic"]),
  },
  {
    name: "keys_get_address",
    title: "Get Address",
    description: "Derive a blockchain address from a public key.",
    inputSchema: Type.Object(
      {
        chain: chainArgument,
        publicKey: Type.String({ description: "Public key as hexadecimal text", minLength: 1 }),
        addressType: addressTypeArgument,
        network: networkArgument,
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) =>
      getAddress(args["chain"], args["publicKey"], args["addressType"], args["network"]),
  },
  {
    name: "keys_validate_address",
    title: "Validate Address",
    description: "Check whether an address matches one blockchain's format rules.",
    inputSchema: Type.Object(
      {
        chain: chainArgument,
        address: Type.String({ description: "Address to validate", minLength: 1, maxLength: 256 }),
        network: networkArgument,
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) => validateAddress(args["chain"], args["address"], args["network"]),
  },
  {
    name: "keys_sign_message",
    title: "Sign Message",
    description:
      "Sign a message with a blockchain private key. The key, message, and signature enter the MCP transcript, so use only public or disposable material.",
    inputSchema: Type.Object(
      {
        chain: chainArgument,
        message: Type.String({ description: "Message to sign" }),
        privateKey: Type.String({ description: "Private key as hexadecimal text", minLength: 1 }),
        network: networkArgument,
      },
      { additionalProperties: false },
    ),
    annotations: SENSITIVE_SIGN,
    execute: (args) =>
      signMessage(args["chain"], args["message"], args["privateKey"], args["network"]),
  },
  {
    name: "keys_verify_message",
    title: "Verify Message",
    description: "Verify a message signature against a blockchain public key.",
    inputSchema: Type.Object(
      {
        chain: chainArgument,
        message: Type.String({ description: "Original message" }),
        signature: Type.String({ description: "Signature as hexadecimal text", minLength: 1 }),
        publicKey: Type.String({ description: "Public key as hexadecimal text", minLength: 1 }),
        network: networkArgument,
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) =>
      verifyMessage(
        args["chain"],
        args["message"],
        args["signature"],
        args["publicKey"],
        args["network"],
      ),
  },
  {
    name: "keys_bip44_path",
    title: "BIP44 Path",
    description:
      "Parse a BIP44 derivation path, or generate one for a blockchain with explicit account, change branch, and address index values.",
    inputSchema: Type.Object(
      {
        chain: Type.Optional(chainArgument),
        path: Type.Optional(
          Type.String({
            description: "BIP44 path to parse, such as m/44'/0'/0'/0/0",
            minLength: 1,
          }),
        ),
        account: Type.Optional(
          Type.Integer({ description: "Account index. Default: 0", minimum: 0 }),
        ),
        change: Type.Optional(
          Type.Integer({
            description: "Change branch: 0 for external, 1 for internal. Default: 0",
            minimum: 0,
            maximum: 1,
          }),
        ),
        addressIndex: Type.Optional(
          Type.Integer({ description: "Address index. Default: 0", minimum: 0 }),
        ),
      },
      { additionalProperties: false },
    ),
    annotations: LOCAL_READ,
    execute: (args) =>
      bip44Path(args["chain"], args["path"], args["account"], args["change"], args["addressIndex"]),
  },
];

function mcpInputSchema(schema: ReadonlyObjectSchema): Tool["inputSchema"] {
  return {
    ...schema,
    type: "object",
    properties: Object.fromEntries(Object.entries(schema.properties)),
    required: schema.required === undefined ? undefined : [...schema.required],
  };
}

function validationError(schema: ReadonlyObjectSchema, value: unknown): string {
  const first = Value.Errors(schema, value)[0];
  if (!first) return "Invalid arguments";
  return `Invalid arguments at ${first.instancePath || "/"}: ${first.message}`;
}

function errorResult(text: string): CallToolResult {
  return { content: [{ type: "text", text: sanitizeToolText(text) }], isError: true };
}

function toCallToolResult(result: ToolResult<unknown>): CallToolResult {
  return {
    content: result.content,
    ...(result.isError === undefined ? {} : { isError: result.isError }),
  };
}

/**
 * Creates an unconnected MCP server exposing the key and mnemonic tools.
 *
 * The low-level `Server` keeps TypeBox as the single schema definition. The SDK's
 * high-level server accepts Zod schemas, which would duplicate every parameter.
 *
 * @returns {Server} Unconnected MCP server.
 */
export function createMcpServer(): Server {
  const toolsByName = new Map(tools.map((tool) => [tool.name, tool]));
  const server = new Server({ name: "keys", version }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: tools.map((tool): Tool => ({
      name: tool.name,
      title: tool.title,
      description: tool.description,
      inputSchema: mcpInputSchema(tool.inputSchema),
      annotations: tool.annotations,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const tool = toolsByName.get(request.params.name);
    if (!tool) return errorResult(`Unknown keys tool: ${JSON.stringify(request.params.name)}`);

    const args = request.params.arguments ?? {};
    if (!Value.Check(tool.inputSchema, args)) {
      return errorResult(validationError(tool.inputSchema, args));
    }

    try {
      return toCallToolResult(await tool.execute(args));
    } catch (error) {
      return errorResult(
        `${tool.name} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  });

  return server;
}
