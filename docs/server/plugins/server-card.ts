import { serverCardHook } from "@agntn/tools/toolkit";
import { serverInfo } from "../../../src/server-info.ts";
import { keysTools } from "../../../src/tools.ts";

/** Docus alone lists two page tools on the card and not a single key. */
export default defineNitroPlugin((nitroApp) => {
  nitroApp.hooks.hook("agent-discovery:mcp-server-card", serverCardHook(serverInfo, keysTools));
});
