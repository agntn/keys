import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";

describe("landing OG image", () => {
  /** The OG file is named after this description, and Nitro skips a prerender path holding `..`. */
  it("keeps the SEO description a plain line without a trailing period", () => {
    const page = readFileSync(new URL("../docs/content/index.md", import.meta.url), "utf8");
    const description = /^ {2}description: (.*)$/mu.exec(page)?.[1] ?? "";
    expect(description).toMatch(/^[^\s"'>|]/u);
    expect(description).not.toMatch(/ #|\.\s*$/u);
  });
});
