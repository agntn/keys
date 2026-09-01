import pkg from "../package.json" with { type: "json" };

/** Current package version reported during MCP initialization. */
export const version: string = pkg.version;
