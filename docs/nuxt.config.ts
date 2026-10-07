import { resolve } from "node:path";
import { keysTheme } from "./shiki-theme";

/** Bundled from the checkout's sources: a deploy needs neither dist/ nor the root node_modules. */
const librarySource = resolve(import.meta.dirname, "../src");

/** Runtime deps under src/index.ts and src/mcp.ts, installed here so they resolve from docs/node_modules. */
const libraryDependencies = [
  "@agntn/ciphers",
  "@agntn/curves",
  "@agntn/encodings",
  "@agntn/hashes",
  "@agntn/tools",
  "@modelcontextprotocol/server",
  "@noble/curves",
  "@scure/bip32",
  "@scure/bip39",
  "micro-key-producer",
];

/** Every subpath src/ imports, dynamic ones too, so dev bundles them up front, not on demand. */
const libraryEntries = [
  "@agntn/curves/secp256k1",
  "@agntn/encodings/base32",
  "@agntn/encodings/base64",
  "@agntn/encodings/base58",
  "@agntn/encodings/bech32",
  "@agntn/hashes",
  "@noble/curves/ed25519.js",
  "@noble/curves/secp256k1.js",
  "@noble/curves/utils.js",
  "@scure/bip32",
  "@scure/bip39",
  "@scure/bip39/wordlists/czech.js",
  "@scure/bip39/wordlists/english.js",
  "@scure/bip39/wordlists/french.js",
  "@scure/bip39/wordlists/italian.js",
  "@scure/bip39/wordlists/japanese.js",
  "@scure/bip39/wordlists/korean.js",
  "@scure/bip39/wordlists/portuguese.js",
  "@scure/bip39/wordlists/simplified-chinese.js",
  "@scure/bip39/wordlists/spanish.js",
  "@scure/bip39/wordlists/traditional-chinese.js",
  "micro-key-producer/slip10.js",
];

export default defineNuxtConfig({
  extends: ["docus"],
  /** The repo root is its own pnpm workspace; Nuxt must not treat it as this site's. */
  workspaceDir: import.meta.dirname,
  alias: {
    "@agntn/keys/mcp": resolve(librarySource, "mcp.ts"),
    "@agntn/keys": resolve(librarySource, "index.ts"),
  },
  vite: {
    resolve: {
      /** Bare imports in ../src resolve upwards from the importer and skip docs/node_modules. */
      dedupe: libraryDependencies,
    },
    optimizeDeps: {
      include: libraryEntries,
    },
    server: {
      /** Dev serves the library from outside the workspace, which Vite refuses without this. */
      fs: { allow: [librarySource] },
    },
  },
  devtools: { enabled: false },
  telemetry: false,
  site: {
    url: "https://keys.agntn.dev",
    name: "@agntn/keys",
  },
  llms: {
    domain: "https://keys.agntn.dev",
    title: "@agntn/keys",
    description:
      "Keys to addresses to signatures on a whole pile of chains from a mnemonic or from nothing at all",
    sections: [
      {
        title: "MCP Server",
        description: "The tools of `keys mcp` and the page tools of this site over Streamable HTTP.",
        links: [
          {
            title: "MCP endpoint",
            href: "https://keys.agntn.dev/mcp",
            description:
              "Add it to any MCP client as an HTTP server, for example `claude mcp add --transport http keys https://keys.agntn.dev/mcp`.",
          },
        ],
      },
      {
        title: "Explorer",
        links: [
          {
            title: "Keyspace",
            href: "https://keys.agntn.dev/keyspace",
            description:
              "Walk secp256k1 private keys in the browser and derive addresses for every chain in the package",
          },
        ],
      },
    ],
  },
  icon: {
    clientBundle: {
      icons: [
        "lucide:arrow-down",
        "lucide:arrow-left",
        "lucide:arrow-right",
        "lucide:arrow-up",
        "lucide:arrow-up-right",
        "lucide:book-open",
        "lucide:boxes",
        "lucide:check",
        "lucide:check-circle",
        "lucide:chevron-down",
        "lucide:chevron-left",
        "lucide:chevron-right",
        "lucide:chevrons-up-down",
        "lucide:circle-help",
        "lucide:circle-plus",
        "lucide:copy",
        "lucide:cpu",
        "lucide:dices",
        "lucide:expand",
        "lucide:key",
        "lucide:key-round",
        "lucide:link",
        "lucide:loader-circle",
        "lucide:map-pin",
        "lucide:plus",
        "lucide:shield-alert",
        "lucide:wallet",
        "simple-icons:github",
        "simple-icons:npm",
        "token:ada",
        "token:apt",
        "token:atom",
        "token:base",
        "token:bch",
        "token:bsv",
        "token:btc",
        "token:btg",
        "token:dash",
        "token:dcr",
        "token:dot",
        "token:doge",
        "token:eth",
        "token:ltc",
        "token:sol",
        "token:sui",
        "token:trx",
        "token:xec",
        "token:xlm",
        "token:near",
        "token:xrp",
        "token:zec",
        "vscode-icons:file-type-js",
        "vscode-icons:file-type-json",
        "vscode-icons:file-type-shell",
        "vscode-icons:file-type-typescript",
      ],
    },
  },
  colorMode: {
    preference: "dark",
  },
  app: {
    head: {
      link: [
        { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" },
        { rel: "apple-touch-icon", sizes: "180x180", href: "/apple-touch-icon.png" },
        { rel: "manifest", href: "/site.webmanifest" },
      ],
      meta: [
        { name: "theme-color", media: "(prefers-color-scheme: dark)", content: "#0b0d10" },
        { name: "theme-color", media: "(prefers-color-scheme: light)", content: "#eef1f4" },
        { name: "apple-mobile-web-app-title", content: "keys" },
        { property: "og:locale", content: "en_US" },
        { name: "author", content: "oritwoen" },
      ],
    },
  },
  ogImage: {
    defaults: {
      alt: "@agntn/keys. Keys to addresses to signatures on a whole pile of chains",
    },
  },
  nitro: {
    preset: "cloudflare_module",
    /**
     * One MCP SDK in the worker. The toolkit builds its server from one copy and `agents` checks it
     * with `instanceof` against another. pnpm splits them by the `zod` peer each one resolves.
     */
    alias: {
      "@modelcontextprotocol/sdk": resolve(
        import.meta.dirname,
        "node_modules/@modelcontextprotocol/sdk/dist/esm",
      ),
    },
    compatibilityDate: "2026-09-03",
    /** The library writes bigint literals, which have no es2019 form. The worker runs them as they are. */
    esbuild: { options: { target: "es2022" } },
    prerender: {
      crawlLinks: true,
      routes: ["/", "/keyspace", "/sitemap.xml", "/robots.txt", "/llms.txt", "/llms-full.txt"],
    },
    cloudflare: {
      deployConfig: true,
      nodeCompat: true,
    },
  },
  compatibilityDate: "2026-09-03",
  /** Fonts live in public/fonts and app/assets/fonts.css, where nuxt-og-image reads them from. */
  css: ["~/assets/fonts.css"],
  fonts: {
    families: [
      { name: "Figtree", provider: "local", weights: [400, 500] },
      { name: "Fira Code", provider: "local", weights: [400, 500] },
    ],
  },
  content: {
    database: {
      type: "d1",
      bindingName: "DB",
    },
    build: {
      markdown: {
        highlight: {
          // One theme of CSS variables for both modes; app.css gives the variables their light and dark values.
          theme: {
            default: keysTheme,
            light: keysTheme,
            dark: keysTheme,
          },
        },
      },
    },
  },
});
