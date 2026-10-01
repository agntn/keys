import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";
import { electrumOldVectors, electrumVectors } from "./fixtures.ts";

const guide = readFileSync(
  new URL("../docs/content/1.guide/4.wallets.md", import.meta.url),
  "utf8",
);
const section = guide.split("## Electrum is a different scheme")[1];
const example = section?.match(/```js\n([\s\S]*?)```/u)?.[1];
const oldExample = section
  ?.split("### What about seeds from before Electrum 2.0?")[1]
  ?.match(/```js\n([\s\S]*?)```/u)?.[1];

/* Runs a guide snippet against the checkout's sources and prints one expression. */
function run(script: string, expression: string): string {
  return execFileSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--input-type=module",
      "--eval",
      `${script
        .replaceAll('"@agntn/keys"', '"./src/index.ts"')
        .replaceAll('"@agntn/keys/electrum"', '"./src/utils/electrum/index.ts"')
        .replaceAll('"@agntn/keys/bip32"', '"./src/utils/bip32/index.ts"')
        .replaceAll(
          '"@agntn/keys/blockchains/bitcoin"',
          '"./src/blockchains/bitcoin.ts"',
        )}\nconsole.log(${expression});`,
    ],
    { encoding: "utf8", cwd: new URL("../", import.meta.url) },
  ).trim();
}

describe("Electrum wallet documentation", () => {
  it.each([electrumVectors[0], electrumVectors[2]])("derives the $seedType example", (vector) => {
    if (!example) throw new Error("Missing Electrum example");
    const script = example
      .replace(/const phrase = .*;/u, `const phrase = ${JSON.stringify(vector.mnemonic)};`)
      .replace(/\.derive\("m\/0'\/0\/0"\)/u, `.derive(${JSON.stringify(vector.path)})`);
    const address = run(script, "wallet.address");
    expect(address).toBe(vector.address);
  });

  it("derives the old seed example", () => {
    if (!oldExample) throw new Error("Missing old Electrum example");
    const [vector] = electrumOldVectors;
    expect(run(oldExample, "address")).toBe(vector.children[0].address);
  });
});
