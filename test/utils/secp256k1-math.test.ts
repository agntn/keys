import { describe, expect, it } from "vite-plus/test";
import * as curves from "@agntn/curves/secp256k1";
import * as secp256k1 from "../../src/utils/secp256k1/index.ts";

const MATH = [
  "addPoints",
  "subtractPoints",
  "negatePoint",
  "multiplyPoint",
  "multiplyGenerator",
  "addScalars",
  "subtractScalars",
  "multiplyScalars",
  "invertScalar",
  "liftX",
  "isOnCurve",
] as const;

describe("secp256k1 math", () => {
  it("comes from @agntn/curves/secp256k1, not a copy", () => {
    for (const name of MATH) expect(secp256k1[name]).toBe(curves[name]);
  });
});
