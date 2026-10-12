import { toToolkitTools } from "@agntn/tools/toolkit";
import { defineMcpHandler, getMcpTools } from "@nuxtjs/mcp-toolkit/server";
import { serverInfo } from "../../../src/server-info.ts";
import { keysTools } from "../../../src/tools.ts";

const keyTools = toToolkitTools(serverInfo, keysTools);

/** Introduces itself like `keys mcp`. An array in `tools` would evict the Docus page tools. */
export default defineMcpHandler({
  ...serverInfo,
  tools: async (event) => [...(await getMcpTools({ event })), ...keyTools],
});
