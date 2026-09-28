import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";
import { toolListings } from "../src/mcp.ts";

const toolsDir = new URL("../docs/server/mcp/tools/", import.meta.url);

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
});
