import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";
import { storeVectors } from "./fixtures.ts";

const guide = readFileSync(new URL("../docs/content/1.guide/2.keys.md", import.meta.url), "utf8");
const section = guide.split("## Keystore files")[1]?.split("\n## ")[0] ?? "";
const example = section.match(/```js\n([\s\S]*?)```/u)?.[1];

describe("Keystore documentation", () => {
  it("opens the geth file the page shows at the address it names", () => {
    if (!example) throw new Error("Missing keystore example");
    const { address } = storeVectors[1];
    const script = example
      .replaceAll('"@agntn/keys/store"', '"./src/utils/store/index.ts"')
      .replaceAll('"@agntn/keys/blockchains/ethereum"', '"./src/blockchains/ethereum.ts"');
    const opened = execFileSync(
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
    expect(opened).toBe(address);
    expect(section).toContain(`\`${address}\``);
  });
});
