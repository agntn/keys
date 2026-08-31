import oxlint from "@agntn/ox/oxlint";
import { defineConfig } from "oxlint";

const readonlyParams = oxlint.rules?.["typescript/prefer-readonly-parameter-types"];
if (!Array.isArray(readonlyParams)) {
  throw new TypeError("@agntn/ox no longer configures typescript/prefer-readonly-parameter-types");
}
const [severity, options] = readonlyParams;

export default defineConfig({
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
  ignorePatterns: ["dist", "coverage", "docs/.docs", "test-integration"],
});
