import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";
import { CHAINS } from "../docs/app/utils/chains";
import { blockchains } from "../src/_blockchains.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

describe("docs chain lists", () => {
  /** The site lists chains by hand, so a registry entry without them never shows up there. */
  it("give every registered chain a row, a page and its icon", () => {
    expect(CHAINS.map((chain) => chain.driver).sort()).toEqual(Object.keys(blockchains).sort());
    const bundle = read("docs/nuxt.config.ts");
    const sidebar = read("docs/app/composables/useSubNavigation.ts");
    for (const { driver, icon } of CHAINS) {
      expect(read(`docs/content/2.blockchains/${driver}.md`)).toContain(
        `::chain-facts{driver="${driver}"`,
      );
      expect(bundle, driver).toContain(`"${icon.replace(/^i-token-/u, "token:")}"`);
      expect(sidebar, driver).toContain(`"/blockchains/${driver}": "${icon}"`);
    }
  });
});
