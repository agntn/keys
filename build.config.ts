import { readdirSync } from "node:fs";
import { defineBuildConfig } from "obuild/config";

/** One input per chain file, so a new chain needs no edit here. */
const blockchainInputs = readdirSync(new URL("src/blockchains/", import.meta.url))
  .filter((file) => file.endsWith(".ts"))
  .map((file) => `./src/blockchains/${file}`);

export default defineBuildConfig({
  entries: [
    {
      /** One bundle, so the chains share the curve and encoding chunks under `_chunks/`. */
      type: "bundle",
      /** The inlined typebox ships minified, which halves its chunk. */
      minifyLibs: ["typebox"],
      input: [
        "./src/index.ts",
        "./src/cli.ts",
        "./src/mcp.ts",
        "./src/tool-operations.ts",
        "./src/utils/bip32/index.ts",
        "./src/utils/bip38/index.ts",
        "./src/utils/bip39/index.ts",
        "./src/utils/bip44/index.ts",
        "./src/utils/electrum/index.ts",
        "./src/utils/secp256k1/index.ts",
        "./src/utils/slip10/index.ts",
        "./src/utils/wif/index.ts",
        ...blockchainInputs,
      ],
    },
  ],
});
