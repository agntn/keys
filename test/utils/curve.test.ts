import { describe, expect, it } from "vite-plus/test";
import * as curves from "@agntn/curves";
import * as curve from "../../src/utils/curve/index.ts";

describe("Curve subpath", () => {
  it("hands out the functions and limits of @agntn/curves themselves", () => {
    expect(Object.keys(curve).length).toBe(14);
    for (const [name, value] of Object.entries(curve)) {
      expect(curves).toHaveProperty(name, value);
    }
  });
});
