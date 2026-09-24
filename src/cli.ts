#!/usr/bin/env node

import { existsSync } from "node:fs";
import { sep } from "node:path";
import { fileURLToPath } from "node:url";
import { defineCommand, runMain } from "citty";
import type McpCommand from "./commands/mcp.ts";
import { version } from "./version.ts";

/** The same file from `src/cli.ts` and `dist/cli.mjs`; the npm package ships only `dist`. */
const sourceMcpCommand = new URL("../src/commands/mcp.ts", import.meta.url);
const sourceMcpCommandPath = fileURLToPath(sourceMcpCommand);

/**
 * Narrows the module a runtime URL import returned, which TypeScript types as `any`.
 * @param value - The imported module namespace.
 * @returns {value is { default: typeof McpCommand }} Whether it exports a default command.
 */
function isCommandModule(value: unknown): value is { default: typeof McpCommand } {
  return typeof value === "object" && value !== null && "default" in value;
}

/**
 * Whether the source can run. It imports `typebox`, a devDependency the bundle inlines, so a
 * checkout installed with production dependencies only has to keep the bundle.
 * @returns {boolean} Whether `typebox` resolves from this package.
 */
function hasSourceDependencies(): boolean {
  try {
    import.meta.resolve("typebox");
    return true;
  } catch {
    return false;
  }
}

/**
 * Loads the MCP command. A built bin inside a checkout runs the live source, as the Pi and
 * OMP extensions do, so a local server needs a restart after a change instead of `pnpm build`.
 * Node refuses to strip types under `node_modules`, so a git install that ships `src` keeps
 * the bundle too. `KEYS_DIST=1` keeps it everywhere, for tests of the packed output.
 * @returns {Promise<typeof McpCommand>} The citty command that starts the stdio server.
 */
async function loadMcpCommand(): Promise<typeof McpCommand> {
  const fromSource =
    !import.meta.url.endsWith(".ts") &&
    process.env.KEYS_DIST !== "1" &&
    !sourceMcpCommandPath.includes(`${sep}node_modules${sep}`) &&
    existsSync(sourceMcpCommandPath) &&
    hasSourceDependencies();
  if (!fromSource) return (await import("./commands/mcp.ts")).default;
  const module: unknown = await import(sourceMcpCommand.href);
  if (!isCommandModule(module)) {
    throw new TypeError(`${sourceMcpCommandPath} has no default command`);
  }
  return module.default;
}

const main = defineCommand({
  meta: {
    name: "keys",
    version,
    description: "Blockchain key, address, mnemonic, and signing tools",
  },
  subCommands: {
    mcp: loadMcpCommand,
  },
});

await runMain(main);
