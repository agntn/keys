import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { defineCommand } from "citty";
import { consola, LogLevels } from "consola";
import { createMcpServer } from "../mcp.ts";

export default defineCommand({
  meta: {
    name: "mcp",
    description: "Run the keys MCP server over stdio",
  },
  async run() {
    consola.level = LogLevels.warn;
    await createMcpServer().connect(new StdioServerTransport());
  },
});
