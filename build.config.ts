import { defineBuildConfig } from "obuild/config";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: [
        "./src/index.ts",
        "./src/cli.ts",
        "./src/mcp.ts",
        "./src/tool-operations.ts",
        "./src/utils/bip32/index.ts",
        "./src/utils/bip39/index.ts",
        "./src/utils/slip10/index.ts",
        "./src/blockchains/aptos.ts",
        "./src/blockchains/base.ts",
        "./src/blockchains/bitcoin.ts",
        "./src/blockchains/litecoin.ts",
        "./src/blockchains/cardano.ts",
        "./src/blockchains/ethereum.ts",
        "./src/blockchains/solana.ts",
        "./src/blockchains/sui.ts",
        "./src/blockchains/tron.ts",
      ],
      license: false,
    },
  ],
  hooks: {
    /**
     * Keep TypeBox inside the MCP bundle to avoid resolving it during every server startup.
     * @param config - Rolldown configuration mutated before bundling.
     */
    rolldownConfig(config) {
      const externals = Array.isArray(config.external) ? config.external : [];
      config.external = externals.filter(
        (entry) => entry !== "typebox" && !(entry instanceof RegExp && entry.test("typebox/value")),
      );
    },
  },
});
