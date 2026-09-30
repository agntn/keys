/** OMP extension exposing blockchain key, mnemonic, address, and signing tools. */
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Text, type ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { registerOmpTools, type OmpRenderers } from "@agntn/tools/omp";
import type * as KeysTools from "../../../dist/tools.d.mts";

const sourceModulePath = fileURLToPath(new URL("../../../src/tools.ts", import.meta.url));

/**
 * Both specifiers stay literal: compiled OMP resolves bare imports only where it sees them.
 * @returns {Promise<typeof KeysTools>} The tool definitions.
 */
function loadTools(): Promise<typeof KeysTools> {
  return (
    existsSync(sourceModulePath)
      ? import("../../../src/tools.ts")
      : import("../../../dist/tools.mjs")
  ) as Promise<typeof KeysTools>;
}

/**
 * Registers the key tools; the executors load on the first call.
 * @param pi - OMP extension API.
 */
export default async function keysExtension(pi: ExtensionAPI): Promise<void> {
  const { keysTools, callSummaries } = await loadTools();
  const renderers = Object.fromEntries(
    Object.entries(callSummaries).map(([name, describeCall]): [string, OmpRenderers] => [
      name,
      { describeCall },
    ]),
  );
  registerOmpTools(pi, keysTools, { Text, renderers });
}
