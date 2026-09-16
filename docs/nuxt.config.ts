import { resolve } from "node:path";

/** Bundled from the checkout's sources: a deploy needs neither dist/ nor the root node_modules. */
const librarySource = resolve(import.meta.dirname, "../src");

/** Runtime deps under src/index.ts, installed here so they resolve from docs/node_modules. */
const libraryDependencies = [
  "@noble/curves",
  "@noble/hashes",
  "@scure/base",
  "@scure/bip32",
  "@scure/bip39",
  "micro-key-producer",
];

export default defineNuxtConfig({
  extends: ["docus"],
  /** The repo root is its own pnpm workspace; Nuxt must not treat it as this site's. */
  workspaceDir: import.meta.dirname,
  alias: {
    "@agntn/keys": resolve(librarySource, "index.ts"),
  },
  vite: {
    resolve: {
      /** Bare imports in ../src resolve upwards from the importer and skip docs/node_modules. */
      dedupe: libraryDependencies,
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
  },
  icon: {
    clientBundle: {
      icons: [
        "lucide:arrow-right",
        "lucide:arrow-up-right",
        "lucide:book-open",
        "lucide:boxes",
        "lucide:check",
        "lucide:chevron-left",
        "lucide:chevron-right",
        "lucide:circle-plus",
        "lucide:copy",
        "lucide:cpu",
        "lucide:dices",
        "lucide:hexagon",
        "lucide:key",
        "lucide:layers",
        "lucide:loader-circle",
        "lucide:map-pin",
        "lucide:plus",
        "lucide:shield-alert",
        "lucide:ticket",
        "lucide:wallet",
        "lucide:zap",
        "simple-icons:bitcoin",
        "simple-icons:cardano",
        "simple-icons:coinbase",
        "simple-icons:ethereum",
        "simple-icons:github",
        "simple-icons:litecoin",
        "simple-icons:npm",
        "simple-icons:solana",
        "simple-icons:sui",
        "vscode-icons:file-type-js",
        "vscode-icons:file-type-typescript",
        "vscode-icons:file-type-json",
        "vscode-icons:file-type-shell",
      ],
    },
  },
  colorMode: {
    preference: "dark",
  },
  /** Docus ships an MCP endpoint that wants the Cloudflare Agents SDK on Workers. Not used. */
  mcp: {
    enabled: false,
  },
  nitro: {
    preset: "cloudflare_module",
    compatibilityDate: "2026-09-03",
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
  fonts: {
    families: [
      { name: "Space Grotesk", weights: [400, 500, 600] },
      { name: "Space Mono", weights: [400, 700] },
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
          theme: {
            default: "github-light",
            light: "github-light",
            dark: "poimandres",
          },
        },
      },
    },
  },
});
