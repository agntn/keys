import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { TSchema } from "typebox";
import { Value } from "typebox/value";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";
import keysExtension from "../packages/pi/extensions/keys.ts";
import { createMcpServer } from "../src/mcp.ts";
import { ed25519TestVectors, ethereumTestVectors, secp256k1TestVectors } from "./fixtures.ts";

const piSchemas = new Map<string, TSchema>();
keysExtension({
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
    const { oneOf, ...fields } = mcp!;
    expect(JSON.parse(JSON.stringify(piSchemas.get(name)))).toEqual(fields);
    if (name === "keys_bip44_path") {
      expect(oneOf).toBeDefined();
    } else {
      expect(oneOf).toBeUndefined();
    }
  });

  it.each([
    ["keys_derive_wallet", { chain: "bitcoin", privateKey }, "privateKey", `0x${privateKey}`],
    ["keys_get_address", { chain: "bitcoin", publicKey }, "publicKey", publicKey.slice(0, -1)],
    [
      "keys_get_address",
      { chain: "solana", publicKey: ed25519Key },
      "publicKey",
      `0x${ed25519Key}`,
    ],
    ["keys_validate_address", { chain: "bitcoin", address: "a" }, "address", "a".repeat(257)],
    ["keys_sign_message", { chain: "bitcoin", message: "", privateKey }, "chain", ""],
    [
      "keys_verify_message",
      { chain: "bitcoin", message: "", signature, publicKey },
      "signature",
      `0x${signature}`,
    ],
    [
      "keys_verify_message",
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

  it("keeps BIP44 mode validation out of the Pi schema root", () => {
    const schema = piSchemas.get("keys_bip44_path")!;
    expect(schema).not.toHaveProperty("oneOf");
    expect(schema).not.toHaveProperty("anyOf");
    expect(Value.Check(schema, { chain: "cardano", change: 5 })).toBe(true);
    expect(Value.Check(schema, { path: "m/44'/0'/0'/0/0" })).toBe(true);
    expect(Value.Check(schema, {})).toBe(true);
  });
});
