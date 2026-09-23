import { readFileSync } from "node:fs";
import oxfmt from "@agntn/ox/oxfmt";
import oxlint from "@agntn/ox/oxlint";
import { defineConfig } from "vite-plus";

const readonlyParams = oxlint.rules?.["typescript/prefer-readonly-parameter-types"];
if (!Array.isArray(readonlyParams)) {
  throw new TypeError("@agntn/ox no longer configures typescript/prefer-readonly-parameter-types");
}
const [severity, options] = readonlyParams;

const { compilerOptions } = JSON.parse(
  readFileSync(new URL("tsconfig.json", import.meta.url), "utf8"),
) as { compilerOptions: { target?: string; verbatimModuleSyntax?: boolean } };

/**
 * Transform every test with the root tsconfig instead of the nearest one. docs/tsconfig.json only
 * references files Nuxt generates, so the docs helpers under test cannot load without docs/.nuxt.
 * Vite's OxcOptions type omits `tsconfig`, but the oxc plugin hands every key to rolldown unchanged.
 */
const transformOverride: object = {
  tsconfig: {
    compilerOptions: {
      target: compilerOptions.target,
      verbatimModuleSyntax: compilerOptions.verbatimModuleSyntax,
    },
  },
};

export default defineConfig({
  oxc: { ...transformOverride },
  fmt: {
    ...oxfmt,
    ignorePatterns: ["dist", "coverage", "docs"],
  },
  lint: {
    ...oxlint,
    rules: {
      ...oxlint.rules,
      /**
       * TypedArrays have no readonly form in TS lib, and both HDKey classes are
       * foreign mutable classes re-exported in the public API, so all three are
       * allow-listed instead of rewritten.
       */
      "typescript/prefer-readonly-parameter-types": [
        severity,
        {
          ...options,
          allow: [
            ...(options?.allow ?? []),
            { from: "lib", name: "Uint8Array" },
            { from: "package", name: "HDKey", package: "@scure/bip32" },
            { from: "package", name: "HDKey", package: "micro-key-producer" },
          ],
        },
      ],
    },
    /** test-integration is a separate package whose deps root CI never installs. */
    ignorePatterns: ["dist", "coverage", "docs", "test-integration"],
  },
  /**
   * One bundle, all inputs, so the chains share the curve and encoding chunks instead of each
   * embedding its own copy. Chunks keep stable names under `_chunks`, as obuild wrote them.
   */
  pack: {
    entry: {
      index: "src/index.ts",
      cli: "src/cli.ts",
      mcp: "src/mcp.ts",
      "tool-operations": "src/tool-operations.ts",
      "utils/bip32/index": "src/utils/bip32/index.ts",
      "utils/bip39/index": "src/utils/bip39/index.ts",
      "utils/slip10/index": "src/utils/slip10/index.ts",
      "blockchains/*": "src/blockchains/*.ts",
    },
    dts: true,
    format: "esm",
    platform: "node",
    hash: false,
    outputOptions: {
      chunkFileNames: "_chunks/[name].mjs",
      /* JSDoc ships once, in the declarations; the runtime files keep only legal and annotation comments. */
      comments: { jsdoc: false },
    },
    /* typebox stays inline, so the MCP server does not resolve it from node_modules on every start. */
    deps: {
      onlyBundle: [/^typebox(?:\/|$)/u],
      alwaysBundle: [/^typebox(?:\/|$)/u],
    },
    /* The inlined typebox carries no license header of its own, so its MIT notice ships beside it. */
    copy: [{ from: "node_modules/typebox/license", rename: "typebox.LICENSE" }],
    /**
     * Rolldown marks every source module with `//#region <path>` and has no option to turn that off.
     * Inlined typebox alone brings 171 of them, each spelling out its pnpm store path.
     */
    plugins: [
      {
        name: "strip-regions",
        renderChunk: (code: string) => code.replaceAll(/^\/\/#(?:end)?region\b.*(?:\n|$)/gmu, ""),
      },
    ],
  },
});
