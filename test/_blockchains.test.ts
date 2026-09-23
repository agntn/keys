import { describe, expect, it } from "vitest";
import { blockchains, lazy } from "../src/_blockchains.ts";

describe("lazy blockchain loader", () => {
  it("names the chain when its module has no class", async () => {
    const load = lazy("broken", async () => ({}));
    await expect(load()()).rejects.toThrow("The broken module loaded without a blockchain class");
  });

  it("keeps loading chains after an import fails", async () => {
    const missing = lazy("missing", () => Promise.reject(new Error("module not found")));
    await expect(missing()()).rejects.toThrow("module not found");
    await expect(blockchains.bitcoin()()).resolves.toMatchObject({ name: "bitcoin" });
  });
});
