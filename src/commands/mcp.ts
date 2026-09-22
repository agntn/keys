import { defineCommand } from "citty";

export default defineCommand({
  meta: {
    name: "mcp",
    description: "Run the keys MCP server over stdio",
  },
  /** citty resolves every subcommand to print the usage, so the server and the SDK load here and `--help` stays light. */
  async run() {
    const [{ createMcpServer }, { StdioServerTransport }] = await Promise.all([
      import("../mcp.ts"),
      import("@modelcontextprotocol/sdk/server/stdio.js"),
    ]);
    await createMcpServer().connect(new StdioServerTransport());
  },
});
