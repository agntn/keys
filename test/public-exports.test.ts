import { describe, expect, it } from "vitest";

const EXPORTS = [
  ["@agntn/keys/bip32", "/dist/utils/bip32/index.mjs"],
  ["@agntn/keys/bip39", "/dist/utils/bip39/index.mjs"],
  ["@agntn/keys/slip10", "/dist/utils/slip10/index.mjs"],
] as const;

describe("Public derivation exports", () => {
  it.each(EXPORTS)("resolves %s", (specifier, path) => {
    expect(import.meta.resolve(specifier).endsWith(path)).toBe(true);
  });
});
