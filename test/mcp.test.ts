import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpServer } from "../src/mcp.ts";

const TOOL_NAMES = [
  "keys_generate_wallet",
  "keys_derive_wallet",
  "keys_derive_hd_wallet",
  "keys_inspect_mnemonic",
  "keys_encode_bip39_entropy",
  "keys_lookup_bip39_indices",
  "keys_lookup_bip39_words",
  "keys_recover_mnemonic_word",
  "keys_get_address",
  "keys_validate_address",
  "keys_sign_message",
  "keys_verify_message",
  "keys_bip44_path",
] as const;

const openConnections: Array<{ close(): Promise<void> }> = [];

async function connectTestClient(): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createMcpServer();
  const client = new Client({ name: "keys-test", version: "1.0.0" });
  openConnections.push(client, server);
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

function text(content: unknown): string {
  return (content as Array<{ type: string; text?: string }>)
    .map((item) => (item.type === "text" ? (item.text ?? "") : ""))
    .join("");
}

afterEach(async () => {
  await Promise.all(openConnections.splice(0).map((connection) => connection.close()));
});

describe("keys MCP server", () => {
  it("advertises every keys tool with explicit safety annotations", async () => {
    const client = await connectTestClient();

    const response = await client.listTools();

    expect(response.tools.map((tool) => tool.name)).toEqual(TOOL_NAMES);
    expect(
      response.tools.find((tool) => tool.name === "keys_generate_wallet")?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    });
    expect(
      response.tools.find((tool) => tool.name === "keys_sign_message")?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    });
    expect(
      response.tools.find((tool) => tool.name === "keys_validate_address")?.annotations,
    ).toMatchObject({
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    });
  });

  it("derives a disposable Bitcoin address from a public mnemonic", async () => {
    const client = await connectTestClient();
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const response = await client.callTool({
      name: "keys_derive_hd_wallet",
      arguments: { chain: "bitcoin", mnemonic, path: "m/84'/0'/0'/0/0" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain("Address: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    expect(text(response.content)).not.toContain(mnemonic);
  });

  it("validates a known Bitcoin address", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_validate_address",
      arguments: { chain: "bitcoin", address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain("is a valid bitcoin address");
  });

  it("rejects arguments that miss the schema", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_validate_address",
      arguments: { chain: "bitcoin" },
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).toContain("Invalid arguments");
  });

  it("rejects prototype property names as unknown tools", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({ name: "toString", arguments: {} });

    expect(response.isError).toBe(true);
    expect(response.content).toEqual([{ type: "text", text: 'Unknown keys tool: "toString"' }]);
  });

  it("removes control bytes from an echoed unknown tool name", async () => {
    const client = await connectTestClient();
    const escape = String.fromCodePoint(27);

    const response = await client.callTool({
      name: `x\nforged${escape}[31m`,
      arguments: {},
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).not.toContain("\n");
    expect(text(response.content)).not.toContain(escape);
  });

  it("removes control bytes from an echoed invalid address", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_validate_address",
      arguments: { chain: "bitcoin", address: "not-an-address\nforged output" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).not.toContain("\n");
    expect(text(response.content)).toContain("is not a valid bitcoin address");
  });

  it("does not echo an invalid private key in errors", async () => {
    const client = await connectTestClient();
    const privateKey = "private-fixture-that-must-not-be-echoed";

    const response = await client.callTool({
      name: "keys_derive_wallet",
      arguments: { chain: "ethereum", privateKey },
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).not.toContain(privateKey);
  });
});
