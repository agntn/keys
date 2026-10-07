import { serverInfo } from "../../../src/server-info.ts";

/** Introduces itself like `keys mcp`, with the Docus page tools beside the key ones. */
export default defineMcpHandler({ ...serverInfo });
