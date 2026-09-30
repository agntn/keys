import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";
import { brainwalletVectors } from "./fixtures.ts";

const guide = readFileSync(
  new URL("../docs/content/1.guide/4.wallets.md", import.meta.url),
  "utf8",
);
const section = guide.split("## Salted brainwallets")[1]?.split("\n## ")[0] ?? "";
const example = section.match(/```js\n([\s\S]*?)```/u)?.[1];

describe("Brainwallet documentation", () => {
  it.each(brainwalletVectors.slice(0, 2))(
    "derives the address the page names with hashed $recipe.hashed",
    ({ recipe, address }) => {
      if (!example) throw new Error("Missing brainwallet example");
      const script = example
        .replaceAll('"@agntn/keys/brainwallet"', '"./src/utils/brainwallet/index.ts"')
        .replaceAll('"@agntn/keys/blockchains/bitcoin"', '"./src/blockchains/bitcoin.ts"')
        .replace('hashed: "hex"', `hashed: ${JSON.stringify(recipe.hashed)}`);
      const derived = execFileSync(
        process.execPath,
        [
          "--import",
          "tsx",
          "--input-type=module",
          "--eval",
          `${script}\nconsole.log(wallet.address);`,
        ],
        { encoding: "utf8", cwd: new URL("../", import.meta.url) },
      ).trim();
      expect(derived).toBe(address);
      expect(section).toContain(`\`${address}\``);
    },
  );
});
