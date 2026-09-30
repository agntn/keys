import { callTool, toolListings } from "@agntn/keys/mcp";
import {
  defineMcpTool,
  type McpToolDefinition,
  type McpToolDefinitionListItem,
} from "@nuxtjs/mcp-toolkit/server";
import { z } from "zod";

/**
 * One keys tool for the Docus MCP server, served beside `list-pages` and `get-page`. The name,
 * prose, annotations and executor are the ones `keys mcp` lists. The toolkit takes Zod only, so
 * the shared TypeBox schema is read back through its JSON Schema and keeps every limit it declares.
 * The SDK gets the whole object, not its shape: a shape comes back as a plain `z.object()`, which
 * strips a key the tool does not take, so a misspelled option would be dropped without a word.
 *
 * @param {string} name - The tool's name, such as `keys_address_get`.
 * @returns {McpToolDefinitionListItem} The tool definition for `server/mcp/tools/`.
 */
export function keysMcpTool(name: string): McpToolDefinitionListItem {
  const listing = toolListings.find((candidate) => candidate.name === name);
  if (listing === undefined) {
    throw new Error(`Unknown keys tool: ${name}`);
  }
  const schema = z.fromJSONSchema(listing.inputSchema as z.core.JSONSchema.JSONSchema);
  /** The toolkit types a raw shape only, while the SDK it hands the schema to takes an object too. */
  const inputSchema = schema as unknown as NonNullable<McpToolDefinition["inputSchema"]>;
  return defineMcpTool({
    name: listing.name,
    title: listing.title,
    description: listing.description,
    annotations: listing.annotations,
    inputSchema,
    handler: (args: Readonly<Record<string, unknown>>) => callTool(name, args),
  });
}
