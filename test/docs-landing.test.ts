import { describe, expect, it } from "vite-plus/test";
import { deriveAddresses, loadExplorerChains } from "../docs/app/utils/derive";
import {
  HD_STATIC,
  KEY_ONE_HEX,
  LANDING_IDS,
  TEST_MNEMONIC,
  landingStaticPipeline,
  landingStaticRows,
  toPipeline,
} from "../docs/app/utils/landing";
import { TOOL_COUNT, spellOut } from "../docs/app/utils/tools";
import { TOOL_NAMES } from "../src/tool-parameters.ts";

describe("landing fixtures", () => {
  it("match what the library derives for private key 1", async () => {
    const chains = await loadExplorerChains(await import("../src/index.ts"));
    const derivation = deriveAddresses(KEY_ONE_HEX, chains);

    expect(derivation.addresses.filter((row) => LANDING_IDS.has(row.id))).toEqual(
      landingStaticRows,
    );
    expect(toPipeline(derivation)).toEqual(landingStaticPipeline);
    expect(chains.ethereum.deriveHDWallet(TEST_MNEMONIC, HD_STATIC.path).address).toBe(
      HD_STATIC.address,
    );
  });
});

describe("tool count", () => {
  it("comes from TOOL_NAMES", () => {
    expect(TOOL_COUNT).toBe(TOOL_NAMES.length);
  });

  it.each([
    [0, "Zero"],
    [7, "Seven"],
    [19, "Nineteen"],
    [20, "Twenty"],
    [21, "Twenty-one"],
    [99, "Ninety-nine"],
  ])("spells %i as %s", (value, words) => {
    expect(spellOut(value)).toBe(words);
  });

  it.each([-1, 100, 1.5])("refuses %s", (value) => {
    expect(() => spellOut(value)).toThrow(RangeError);
  });
});
