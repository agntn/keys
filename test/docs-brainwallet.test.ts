import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";
import { brainwalletVectors } from "./fixtures.ts";

const guide = readFileSync(
  new URL("../docs/content/1.guide/4.wallets.md", import.meta.url),
  "utf8",
);
const section = guide.split("## Salted brainwallets")[1]?.split("\n## ")[0] ?? "";
const [example, plainExample] = Array.from(
  section.matchAll(/```js\n([\s\S]*?)```/gu),
  (match) => match[1],
);

/* Runs a page snippet against the source and prints the address it ends on. */
function snippetAddress(snippet: string): string {
  const script = snippet
    .replaceAll('"@agntn/keys/brainwallet"', '"./src/utils/brainwallet/index.ts"')
    .replaceAll('"@agntn/keys/blockchains/bitcoin"', '"./src/blockchains/bitcoin.ts"');
  return execFileSync(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "--eval", `${script}\nconsole.log(wallet.address);`],
    { encoding: "utf8", cwd: new URL("../", import.meta.url) },
  ).trim();
}

describe("Brainwallet documentation", () => {
  it.each(brainwalletVectors.slice(0, 2))(
    "derives the address the page names with hashed $recipe.hashed",
    ({ recipe, address }) => {
      if (!example) throw new Error("Missing brainwallet example");
      const snippet = example.replace('hashed: "hex"', `hashed: ${JSON.stringify(recipe.hashed)}`);
      expect(snippetAddress(snippet)).toBe(address);
      expect(section).toContain(`\`${address}\``);
    },
  );

  it("derives the plain SHA-256 address the page names", () => {
    if (!plainExample) throw new Error("Missing plain brainwallet example");
    const address = snippetAddress(plainExample);
    expect(address).toBe("1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T");
    expect(section).toContain(`\`${address}\``);
  });
});
