/** Pi extension exposing blockchain key, mnemonic, address, and signing tools. */
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { sanitizeLine } from "@agntn/tools";
import { registerPiTools, type PiRenderers } from "@agntn/tools/pi";
import type * as KeysTools from "../../../dist/tools.d.mts";

const sourceModuleUrl = new URL("../../../src/tools.ts", import.meta.url);
const distributionModuleUrl = new URL("../../../dist/tools.mjs", import.meta.url);

/**
 * Narrows the call arguments Pi hands a renderer, which it types as `unknown`.
 * @param value - The arguments.
 * @returns {value is Readonly<Record<string, unknown>>} Whether they are an object.
 */
function isArguments(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null;
}

/**
 * Registers the key tools from the source in a checkout, from the build in the package.
 * @param pi - Pi extension API.
 */
export default async function keysExtension(pi: ExtensionAPI): Promise<void> {
  const { keysTools, callSummaries } = (await import(
    existsSync(fileURLToPath(sourceModuleUrl)) ? sourceModuleUrl.href : distributionModuleUrl.href
  )) as typeof KeysTools;
  const renderers = Object.fromEntries(
    keysTools.map((tool): [string, PiRenderers] => [
      tool.name,
      {
        renderCall(args) {
          const summary = isArguments(args) ? callSummaries[tool.name]?.(args) : undefined;
          return new Text(sanitizeLine(summary ? `${tool.title}: ${summary}` : tool.title), 0, 0);
        },
      },
    ]),
  );
  registerPiTools(pi, keysTools, { renderers });
}
