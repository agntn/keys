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

/** Every subpath src/ imports, dynamic ones too, so dev bundles them up front, not on demand. */
const libraryEntries = [
  "@noble/curves/ed25519.js",
  "@noble/curves/secp256k1.js",
  "@noble/curves/utils.js",
  "@noble/hashes/blake1.js",
  "@noble/hashes/blake2.js",
  "@noble/hashes/legacy.js",
  "@noble/hashes/sha2.js",
  "@noble/hashes/hmac.js",
  "@noble/hashes/pbkdf2.js",
  "@noble/hashes/sha3.js",
  "@noble/hashes/utils.js",
  "@scure/base",
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
      "Keys to addresses to signatures on twelve chains from a mnemonic or from nothing at all",
    sections: [
      {
        title: "Explorer",
        links: [
          {
            title: "Keyspace",
            href: "https://keys.agntn.dev/keyspace",
            description: "Walk secp256k1 private keys in the browser and derive addresses for twelve chains",
          },
        ],
      },
    ],
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
        "lucide:key",
        "lucide:loader-circle",
        "lucide:map-pin",
        "lucide:plus",
        "lucide:shield-alert",
        "lucide:wallet",
        "simple-icons:github",
        "simple-icons:npm",
        "token:ada",
        "token:apt",
        "token:base",
        "token:bch",
        "token:btc",
        "token:dcr",
        "token:eth",
        "token:ltc",
        "token:sol",
        "token:sui",
        "token:trx",
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
      alt: "@agntn/keys. Keys to addresses to signatures on twelve chains",
    },
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
  /** Fonts live in public/fonts and app/assets/fonts.css, where nuxt-og-image reads them from. */
  css: ["~/assets/fonts.css"],
  fonts: {
    families: [
      { name: "Space Grotesk", provider: "local", weights: [400, 500, 600] },
      { name: "Space Mono", provider: "local", weights: [400, 700] },
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
