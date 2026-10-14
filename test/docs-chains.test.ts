import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";
import { CHAINS } from "../docs/app/utils/chains";
import { deriveAddresses, loadExplorerChains } from "../docs/app/utils/derive";
import { KEY_ONE_HEX, LANDING_IDS } from "../docs/app/utils/landing";
import { blockchains } from "../src/_blockchains.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

describe("docs chain lists", () => {
  /** The site lists chains by hand, so a registry entry without them never shows up there. */
  it("give every registered chain a row, a page and its icon", async () => {
    expect(CHAINS.map((chain) => chain.driver).sort()).toEqual(Object.keys(blockchains).sort());
    const chains = await loadExplorerChains(await import("../src/index.ts"));
    const derived = new Set(deriveAddresses(KEY_ONE_HEX, chains).addresses.map((row) => row.id));
    const bundle = read("docs/nuxt.config.ts");
    const sidebar = read("docs/app/composables/useSubNavigation.ts");
    for (const { driver, icon, row } of CHAINS) {
      expect(derived.has(row), `${driver} explorer row`).toBe(true);
      expect(LANDING_IDS.has(row), `${driver} landing fixture`).toBe(true);
      expect(read(`docs/content/2.blockchains/${driver}.md`)).toContain(
        `::chain-facts{driver="${driver}"`,
      );
      expect(bundle, driver).toContain(`"${icon.replace(/^i-token-/u, "token:")}"`);
      expect(sidebar, driver).toContain(`"/blockchains/${driver}": "${icon}"`);
    }
  });
});
