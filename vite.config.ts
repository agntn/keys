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
    ignorePatterns: ["dist", "coverage", "docs", "CHANGELOG.md"],
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
});
