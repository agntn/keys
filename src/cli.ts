#!/usr/bin/env node

import { defineCommand, runMain } from "citty";
import { version } from "./version.ts";

const main = defineCommand({
  meta: {
    name: "keys",
    version,
    description: "Blockchain key, address, mnemonic, and signing tools",
  },
  subCommands: {
    mcp: () => import("./commands/mcp.ts").then((module) => module.default),
  },
});

await runMain(main);
