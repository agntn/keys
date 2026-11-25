/** Vercel AI SDK tools over the same definitions MCP, Pi, OMP and the CLI read. */

import { toAiTools, type AiTools } from "@agntn/tools/ai";
import { keysTools } from "./tools.ts";

/** Every key tool under its MCP name. Those that mint or sign ask first, unless `toolApproval` says otherwise. */
export const keysAiTools: AiTools<typeof keysTools> = /* @__PURE__ */ toAiTools(keysTools);
