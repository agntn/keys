import { indexTools, invokeTool, ToolInputError, wireSchema } from "@agntn/tools";
import {
  createMcpServer as createToolServer,
  errorResult,
  toolAnnotations,
} from "@agntn/tools/mcp";
import type { CallToolResult, Server, Tool } from "@modelcontextprotocol/server";
import { keysTools } from "./tools.ts";
import { version } from "./version.ts";

/** The `tools/list` entries, in order, shared by `keys mcp` and the MCP server of the docs site. */
export const toolListings: readonly Tool[] = keysTools.map((tool) => ({
  name: tool.name,
  title: tool.title,
  description: tool.description,
  inputSchema: { ...wireSchema(tool), type: "object" },
  annotations: toolAnnotations(tool),
}));

const toolsByName = indexTools(keysTools);

/**
 * Runs one tool the way `tools/call` does. An unknown name, a schema miss and an executor failure
 * all come back as an error result, never as a throw, so every transport answers with the same text.
 *
 * @param {string} name - The tool's name, such as `keys_address_get`.
 * @param {Readonly<Record<string, unknown>>} args - The arguments the client sent.
 * @returns {Promise<CallToolResult>} The tool's text, or the sanitized error.
 */
export async function callTool(
  name: string,
  args: Readonly<Record<string, unknown>>,
): Promise<CallToolResult> {
  const tool = toolsByName.get(name);
  if (!tool) return errorResult(`Unknown keys tool: ${JSON.stringify(name)}`);

  try {
    return { content: (await invokeTool(tool, args)).content };
  } catch (error) {
    if (error instanceof ToolInputError) return errorResult(...error.lines);
    return errorResult(
      `${tool.name} failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Creates an unconnected MCP server exposing the key and mnemonic tools.
 *
 * @returns {Server} Unconnected MCP server.
 */
export function createMcpServer(): Server {
  return createToolServer({ name: "keys", version }, keysTools);
}
