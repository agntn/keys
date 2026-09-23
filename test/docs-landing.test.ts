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
