import type { McpServerInfo } from "@agntn/tools/mcp";
import { version } from "./version.ts";

/** How both MCP servers introduce themselves, so a connector card says more than a name. */
export const serverInfo = {
  name: "keys",
  version,
  description:
    "Mnemonics, WIFs, xpubs and signatures from Bitcoin to the XRP Ledger, even the puzzle mnemonic your wallet app calls invalid. Made for puzzles and experiments, so keep real money far away. Nothing you send gets kept.",
  icons: [
    { src: "https://keys.agntn.dev/favicon.svg", mimeType: "image/svg+xml", sizes: ["any"] },
    { src: "https://keys.agntn.dev/icon-512.png", mimeType: "image/png", sizes: ["512x512"] },
  ],
} satisfies McpServerInfo;
