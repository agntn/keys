import { readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";

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

export default defineConfig({ oxc: { ...transformOverride } });
