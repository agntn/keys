import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Client, InMemoryTransport, type Tool } from "@modelcontextprotocol/client";
import type { TSchema } from "typebox";
import { Value } from "typebox/value";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";
import keysExtension from "../packages/pi/extensions/keys.ts";
import { createMcpServer } from "../src/mcp.ts";
import { ed25519TestVectors, ethereumTestVectors, secp256k1TestVectors } from "./fixtures.ts";

const piSchemas = new Map<string, TSchema>();
await keysExtension({
  registerTool(tool: { readonly name: string; readonly parameters: TSchema }) {
    piSchemas.set(tool.name, tool.parameters);
  },
} as unknown as ExtensionAPI);

const server = createMcpServer();
const client = new Client({ name: "schema-parity", version: "1.0.0" });
const mcpSchemas = new Map<string, Tool["inputSchema"]>();

beforeAll(async () => {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const { tools } = await client.listTools();
  for (const tool of tools) mcpSchemas.set(tool.name, tool.inputSchema);
});

afterAll(async () => {
  await Promise.all([client.close(), server.close()]);
});

const { privateKey, publicKeyCompressed: publicKey } = secp256k1TestVectors;
const ed25519Key = ed25519TestVectors.publicKey;
const signatureWithV = ethereumTestVectors.messages[1][2];
const signature = signatureWithV.slice(0, 128);

describe("MCP and Pi tool parameters", () => {
  it("advertises the same tools on both transports", () => {
    expect([...piSchemas.keys()].sort()).toEqual([...mcpSchemas.keys()].sort());
  });

  it.each([...piSchemas.keys()])("shares the field contract for %s", (name) => {
    const mcp = mcpSchemas.get(name);
    expect(mcp).toBeDefined();
    expect(JSON.parse(JSON.stringify(piSchemas.get(name)))).toEqual(mcp);
  });

  it.each([
    ["keys_wallet_derive", { chain: "bitcoin", privateKey }, "privateKey", `0x${privateKey}`],
    ["keys_address_get", { chain: "bitcoin", publicKey }, "publicKey", publicKey.slice(0, -1)],
    [
      "keys_address_get",
      { chain: "solana", publicKey: ed25519Key },
      "publicKey",
      `0x${ed25519Key}`,
    ],
    ["keys_address_validate", { chain: "bitcoin", address: "a" }, "address", "a".repeat(1024)],
    ["keys_message_sign", { chain: "bitcoin", message: "", privateKey }, "chain", ""],
    [
      "keys_message_verify",
      { chain: "bitcoin", message: "", signature, publicKey },
      "signature",
      `0x${signature}`,
    ],
    [
      "keys_message_verify",
      { chain: "ethereum", message: "", signature: signatureWithV, publicKey },
      "publicKey",
      `0x${publicKey}`,
    ],
  ] as const)("enforces shared boundaries for %s", (name, valid, field, invalid) => {
    const schema = piSchemas.get(name)!;
    expect(Value.Check(schema, valid)).toBe(true);
    expect(Value.Check(schema, { ...valid, [field]: invalid })).toBe(false);
    expect(Value.Check(schema, { ...valid, unexpected: true })).toBe(false);
  });

  it("gives each BIP44 tool its own arguments", () => {
    const parse = piSchemas.get("keys_bip44_parse")!;
    const generate = piSchemas.get("keys_bip44_generate")!;
    expect(Value.Check(parse, { path: "m/44'/0'/0'/0/0" })).toBe(true);
    expect(Value.Check(parse, {})).toBe(false);
    expect(Value.Check(parse, { path: "m/44'/0'/0'/0/0", chain: "bitcoin" })).toBe(false);
    expect(Value.Check(generate, { chain: "cardano", change: 5 })).toBe(true);
    expect(Value.Check(generate, {})).toBe(false);
    expect(Value.Check(generate, { chain: "bitcoin", path: "m/44'/0'/0'/0/0" })).toBe(false);
  });
});
