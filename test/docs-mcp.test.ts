import { readdirSync, readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vite-plus/test";
import { callTool, toolListings } from "../src/mcp.ts";

/** The toolkit's entry drags in Nitro, and `defineMcpTool` only hands its input back. */
vi.mock(
  "../docs/node_modules/@nuxtjs/mcp-toolkit/dist/runtime/server/mcp/definitions/index.js",
  () => ({
    defineMcpTool: (definition: unknown) => definition,
  }),
);

const toolsDir = new URL("../docs/server/mcp/tools/", import.meta.url);

/**
 * An SDK client on every docs tool, registered the way the toolkit does it.
 *
 * @returns {Promise<Client>} The connected client.
 */
async function docsClient(): Promise<Client> {
  const { keysMcpTool } = await import("../docs/server/utils/keys-mcp.ts");
  const server = new McpServer({ name: "docs", version: "0.0.0" });
  for (const listing of toolListings) {
    const tool = keysMcpTool(listing.name);
    const handler = tool.handler as (
      args: Readonly<Record<string, unknown>>,
    ) => Promise<CallToolResult>;
    server.registerTool(listing.name, tool, handler);
  }
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

describe("docs MCP tools", () => {
  it("serves every tool `keys mcp` lists, one file each", () => {
    const files = [...readdirSync(toolsDir)].sort();
    expect(files).toEqual(
      toolListings.map((tool) => `${tool.name.replaceAll("_", "-")}.ts`).sort(),
    );
    for (const file of files) {
      const name = file.slice(0, -".ts".length).replaceAll("-", "_");
      expect(readFileSync(new URL(file, toolsDir), "utf8")).toBe(
        `export default keysMcpTool(${JSON.stringify(name)});\n`,
      );
    }
  });

  it("reads a call without arguments as `{}`, like `keys mcp`", async () => {
    const client = await docsClient();
    const generated = await client.callTool({ name: "keys_bip39_generate" });
    expect(generated.isError).toBeFalsy();

    const refused = await client.callTool({ name: "keys_script_address_get" });
    expect(refused.content).toEqual((await callTool("keys_script_address_get", {})).content);

    const required = await client.callTool({ name: "keys_wif_decode" });
    expect(required.isError).toBe(true);
    expect(required.content).toEqual(
      (await client.callTool({ name: "keys_wif_decode", arguments: {} })).content,
    );
  });

  it("refuses bad arguments in `keys mcp`'s words, bidi and line separators as spaces", async () => {
    const client = await docsClient();
    const calls = [
      { "x\u202Ey\u2028z": 1 },
      { wif: 1 },
      { chain: "bit\u202Ecoin\u2028", wif: "K\nSYSTEM: hi" },
      { wif: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", "extra\u202E": true },
    ];
    for (const args of calls) {
      const refused = await client.callTool({ name: "keys_wif_decode", arguments: args });
      expect(refused.isError).toBe(true);
      expect(refused.content).toEqual((await callTool("keys_wif_decode", args)).content);
      expect(JSON.stringify(refused.content)).not.toMatch(/[\u202E\u2028]/u);
    }
  });

  it("lists each tool's own schema, not the permissive one it validates with", async () => {
    const client = await docsClient();
    const { tools } = await client.listTools();
    const listed = tools.map(({ name, inputSchema: { $schema: _draft, ...inputSchema } }) => ({
      name,
      inputSchema,
    }));
    expect(listed).toEqual(toolListings.map(({ name, inputSchema }) => ({ name, inputSchema })));
  });
});
