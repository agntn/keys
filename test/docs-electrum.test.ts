import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";
import { electrumVectors } from "./fixtures.ts";

const guide = readFileSync(
  new URL("../docs/content/1.guide/4.wallets.md", import.meta.url),
  "utf8",
);
const example = guide
  .split("## Electrum is a different scheme")[1]
  ?.match(/```js\n([\s\S]*?)```/u)?.[1];

describe("Electrum wallet documentation", () => {
  it.each([electrumVectors[0], electrumVectors[2]])("derives the $seedType example", (vector) => {
    if (!example) throw new Error("Missing Electrum example");
    const script = example
      .replaceAll('"@agntn/keys"', '"./src/index.ts"')
      .replaceAll('"@agntn/keys/bip32"', '"./src/utils/bip32/index.ts"')
      .replaceAll('"@agntn/keys/blockchains/bitcoin"', '"./src/blockchains/bitcoin.ts"')
      .replace(/const phrase = .*;/u, `const phrase = ${JSON.stringify(vector.mnemonic)};`)
      .replace(/\.derive\("m\/0'\/0\/0"\)/u, `.derive(${JSON.stringify(vector.path)})`);
    const address = execFileSync(
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
    expect(address).toBe(vector.address);
  });
});
