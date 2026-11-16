/** Vercel AI SDK tools over the same definitions MCP, Pi, OMP and the CLI read. */

import { toAiTools, type AiTools } from "@agntn/tools/ai";
import type { Tool } from "ai";
import { keysTools } from "./tools.ts";

/** Every key tool under its MCP name. Those that mint or sign ask first, unless `toolApproval` says otherwise. */
export const keysAiTools: AiTools<typeof keysTools> = /* @__PURE__ */ askBeforeWrites();

/**
 * Builds the map with `needsApproval` on every tool whose effect isn't a read.
 * @returns {AiTools<typeof keysTools>} The AI SDK tools.
 */
function askBeforeWrites(): AiTools<typeof keysTools> {
  const tools: Readonly<Record<string, Tool>> = toAiTools(keysTools);
  return Object.fromEntries(
    keysTools.map(({ name, effect }) => {
      const tool = tools[name];
      return [name, effect === "read" ? tool : { ...tool, needsApproval: true }];
    }),
  ) as AiTools<typeof keysTools>;
}
