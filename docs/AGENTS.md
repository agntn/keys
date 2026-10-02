# docs/

Docus site for `@agntn/keys`. Markdown lives in `content/`. The browser explorer is a Vue component in the Nuxt app, not a `playground/` script. The one route of its own that answers at request time is `/mcp`, the Docus MCP server with every tool of `keys mcp` beside its own `list-pages` and `get-page`.

The site uses the agntn instrument design system, the one `agntn/puzzles/docs` introduced. For panel geometry, typography, motion and the component that owns each part, read [DESIGN.md](DESIGN.md).

## Layout

```
docs/
├── nuxt.config.ts                 # extends: ['docus'], cloudflare_module preset, @agntn/keys aliased to ../src
├── app/app.config.ts              # title, github, theme
├── app/app.css                    # tokens, the shared `console-*`, `hero-*` and `roster` grammar, `keys-*` classes, `.key-bytes`
├── app/components/                # Docus overrides: header (logo, areas, section tabs, mobile menu), sidebar, toc, page header links, surround cards, footer; KeysCallout and RosterSort
├── app/components/OgImage/        # Docs and Landing Takumi templates, theme colours as literals
├── app/assets/fonts.css           # @font-face for the Figtree and Fira Code TTFs in public/fonts, shared by the site and the OG images
├── app/components/content/        # MDC components (`::landing-home`, `::chain-facts`, `::chain-list`), the landing instruments, KeyspaceExplorer, Console* and Prose* overrides
├── app/composables/               # useLandingKey (live key walk), useSubNavigation (sections, tabs, icons), useCopied, useRosterFlip
├── app/utils/                     # chains (display list), parse-key (range, stepping), derive (rows per chain), format, tokens (`tok-*`), roster (UTable classes)
├── content/index.md               # landing
├── content/1.guide/               # getting started
├── content/2.blockchains/         # one page per chain
├── public/                        # favicon.svg and the files cut from it, site.webmanifest, fonts/
├── shiki-theme.ts                 # code block theme, every colour a `--shiki-token-*` variable from app.css
├── server/routes/sitemap.xml.ts   # Docus sitemap plus the Vue pages
├── server/mcp/index.ts            # the Docus MCP handler at /mcp, named and versioned like `keys mcp`
├── server/mcp/tools/              # one file per key tool, each `keysMcpTool("<name>")`
├── server/utils/keys-mcp.ts       # a tool from `@agntn/keys/mcp`: its entry in `toolListings` and `callTool`, the TypeBox schema read into Zod
└── app/pages/keyspace.vue         # explorer, own route outside the docs layout
```

`playground/` at the repo root stays Node/tsx demos.

## Commands

```bash
pnpm install          # from docs/, nothing to build in the repo root first
pnpm dev              # http://localhost:3000
pnpm build            # Cloudflare Workers output in .output/, every route prerendered
pnpm deploy           # build, then wrangler deploy to keys.agntn.dev
pnpm generate         # static output only, no worker
```

Deployment: Workers Builds with root directory `docs`. It installs `docs/` and nothing else, which is enough because the library is bundled from `../src` (next paragraph). The build image takes Node.js from `.node-version` at the repo root and never reads `engines`, so without that file the site builds on the image's default Node.js instead of 26. Nitro preset `cloudflare_module`. Nuxt Content needs a D1 binding named `DB`; `wrangler.jsonc` carries the binding and the `NUXT_SITE_URL` var, Nitro merges it into the generated `.output/server/wrangler.json`. The database is `agntn-keys`, created once with `wrangler d1 create agntn-keys`; its id sits in `wrangler.jsonc`. Workers Builds installs with pnpm 11, whose `minimumReleaseAge` refuses a version younger than a day, so `pnpm-workspace.yaml` here and at the root lists `@agntn/*` under `minimumReleaseAgeExclude`. A name in its place covers only that package, and the deploy fails for a day after every other `@agntn` release.

`@agntn/keys` is an alias in `nuxt.config.ts` for `../src/index.ts`. Vite bundles the checkout's sources for the browser and Nitro gets the same alias for the prerender, so `dist/` and the root `node_modules` are never touched. The subgraph under `src/index.ts` imports from npm: `@agntn/encodings`, `@agntn/hashes`, `@noble/curves`, `@scure/base`, `@scure/bip32`, `@scure/bip39` and `micro-key-producer`. Each one is a dependency of `docs/package.json`, pinned to the root's version, and listed in `vite.resolve.dedupe` in `nuxt.config.ts`, because Vite resolves a bare import from the importer's directory upwards and `../src` never reaches `docs/node_modules`. The exact subpaths `src/` imports, dynamic imports included, sit in `vite.optimizeDeps.include`; without that list dev discovers them when a lazy chain module loads, optimizes again and reloads the page under the explorer. A new npm import under `src/` that `index.ts` can reach needs all three entries or the deploy or the dev server breaks. The CLI entry stays out of the alias. `@agntn/keys/mcp` has its own, see [MCP](#mcp).

Three resolution traps, all because the repo root is its own pnpm workspace:

- `pnpm-workspace.yaml` sets `shamefullyHoist: true`. Without it `docs/node_modules` holds only direct dependencies, Node walks up to the root `node_modules`, and the server bundle can end up with a second copy of Vue.
- `nuxt.config.ts` pins `workspaceDir` to `docs/` and disables devtools and telemetry, which would otherwise resolve from the root.
- `vite.server.fs.allow` in `nuxt.config.ts` adds `../src`. Vite serves only directories on that list, and with `workspaceDir` pinned to `docs/` the library sits outside it, so `pnpm dev` couldn't load it otherwise.

## MCP

`@agntn/keys/mcp` is a second alias, for `../src/mcp.ts`. A file in `server/mcp/tools/` names one tool and nothing else: `keysMcpTool()` takes the name, prose and annotations from `toolListings` and runs `callTool()` from there, so a tool changed in `src/` changes here without an edit. A new tool in `src/tools.ts` needs one more file here, and `test/docs-mcp.test.ts` fails until it has one. `@nuxtjs/mcp-toolkit` wants Zod, so its schema is `z.fromJSONSchema()` over the TypeBox one, passed as the whole object so an unknown key is refused instead of stripped. A schema error reads in Zod's words. Every other answer is the text `keys mcp` gives.

On the `cloudflare_module` preset the toolkit hands its server to `createMcpHandler` from `agents`, which tells an SDK v1 server apart with `instanceof`. pnpm installs one copy of `@modelcontextprotocol/sdk` per `zod` peer it resolves, so the toolkit and `agents` can each get their own and every request fails with "createMcpHandler received an unsupported server". `nitro.alias` points every import of the SDK at the copy in `docs/node_modules`. Keep it until both resolve the same one. `@agntn/ciphers`, `@agntn/tools` and `@modelcontextprotocol/server` are dependencies here for `src/mcp.ts`, pinned to the root's versions and deduped like the others; `@modelcontextprotocol/sdk` stays for the toolkit and `agents`. They run on the worker only, so they stay out of `optimizeDeps`. The library writes bigint literals, so `nitro.esbuild` targets es2022.

`/mcp` is the one place where key material reaches the server, because an agent sends it there on purpose. The worker must not log or keep it: no `evlog` module, no `observability` block in `wrangler.jsonc`, no `console` call with tool arguments. The page at `content/1.guide/1.index.md#remote-mcp` says so to users.

## Tests

`test/docs-parse-key.test.ts` and `test/docs-landing.test.ts` in the repo root cover `app/utils/`, and `test/docs-mcp.test.ts` checks that `server/mcp/tools/` holds one file per tool `keys mcp` lists. All three run with the root suite, no docs install needed. The root `vite.config.ts` transforms them with the root tsconfig, because `docs/tsconfig.json` only references files Nuxt generates. `derive.ts` takes the library module as an argument and imports its types from `../src` by path, so a root test passes `src/index.ts` and never needs the `@agntn/keys` alias; `test/public-exports.test.ts` keeps that name for the built package. Keep pure helpers in `app/utils/` so they stay testable from the root; anything that touches `ref` or `onMounted` belongs in `app/composables/`.

The landing renders before the library loads, so `app/utils/landing.ts` records private key 1 on every row, the Bitcoin pipeline and the first HD sample as fixtures. `test/docs-landing.test.ts` derives the same values from `src/` and fails when they drift, so a fixture edit without a library change is a lie the test catches.

## SEO

- `seo.schema` in `app/app.config.ts` emits the landing JSON-LD: `WebSite`, the agntn `Organization` as publisher, and a free `SoftwareApplication` with `sameAs` on GitHub and npm. Docs pages get `Article` plus `BreadcrumbList` from Docus on their own.
- `app/pages/keyspace.vue` sits outside `content/`, so it calls `useSeo` and `defineOgImage("Docs", props, { alt })` itself, `server/routes/sitemap.xml.ts` appends it to the Docus sitemap and `llms.sections` in `nuxt.config.ts` lists it for `llms.txt`. A new page under `app/pages/` needs all three or crawlers and agents never see it.
- Docus links `/favicon.ico` without shipping one. `public/favicon.svg` is the source, the PNGs and the `.ico` are cut from it with ImageMagick (`magick -background none favicon.svg -resize 512x512 icon-512.png`, `-define icon:auto-resize=48,32,16 favicon.ico`), `app.head` in `nuxt.config.ts` links them with the manifest, theme colours, `og:locale` and `author`.
- Audit on `.output/public/*.html` with grep for `<meta`, `<link rel="canonical"` and `"@type"`, not by impression.

## OG images

- `app/components/OgImage/Docs.takumi.vue` and `Landing.takumi.vue` override the Docus templates of the same name and are rendered by Takumi at build time. Takumi has no CSS variables, so the theme colours from `app.css` are repeated there as literals.
- nuxt-og-image doesn't see the faces `@nuxt/fonts` generates, but it parses `@font-face` rules from the files in `css`. That's why `app/assets/fonts.css` declares the four TTFs in `public/fonts` (Figtree and Fira Code, 400 and 500) and `fonts.families` uses the `local` provider. Site and OG images share the files. Without them Takumi falls back to Inter, which is what `agntn/puzzles` ships today.
- Docus encodes title and description in the OG file name and a comma is a separator there, so the template gets descriptions without commas. Frontmatter descriptions use periods and `and` instead, and stay under 160 characters.
- The landing OG file is named from the SEO description and Nitro refuses a prerender path containing `..`, so a description ending in a period is silently skipped and the landing ships with a dead `og:image`. Keep the description in `content/index.md` without a trailing period and check `grep c_Landing` in the build log has no `(skipped)`.

## Constraints

- The explorer derives in the browser only. `/mcp` is the one server route that accepts private keys or mnemonics; do not add another.
- Do not log, persist, or send key material.
- secp256k1 keyspace is `1 .. n-1`. ed25519 rows reuse the same 32 bytes as a secret; label that.
- Keep Node demos in `playground/`.
- Icons: `token` (Web3 Icons, monochrome) for chains by ticker (`i-token-btc`), Lucide for the interface, `simple-icons` for GitHub and npm, `vscode-icons` for file types in code block headers. A chain icon that only exists in colour is not a reason to mix sets.
- Chains are listed by hand: rows and `loadExplorerChains` in `app/utils/derive.ts`, fixtures in `app/utils/landing.ts`, the display list in `app/utils/chains.ts` (name, curve, icon, blurb and the fixture row, read by the landing instruments, `ChainList` and `ChainFacts`), the secp256k1 list in `LandingToolCall.vue`, sidebar icons in `useSubNavigation.ts`, the icon bundle in `nuxt.config.ts`. A new chain in `src/_blockchains.ts` needs all of them plus a page under `content/2.blockchains/` with its `::chain-facts`.
