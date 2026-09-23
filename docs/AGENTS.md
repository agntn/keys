# docs/

Docus site for `@agntn/keys`. Markdown lives in `content/`. The browser explorer is a Vue component in the Nuxt app, not a `playground/` script.

## Layout

```
docs/
├── nuxt.config.ts                 # extends: ['docus'], cloudflare_module preset, @agntn/keys aliased to ../src
├── app/app.config.ts              # title, github, theme
├── app/app.css                    # theme tokens (light + .dark), shared `keys-*` classes
├── app/components/                # Docus overrides: AppHeaderLogo, AppHeaderCTA (nav), AppFooterLeft, DocsAsideLeftBody
├── app/components/OgImage/        # Docs and Landing Takumi templates, theme colours as literals
├── app/assets/fonts.css           # @font-face for the TTFs in public/fonts, shared by the site and the OG images
├── app/components/content/        # MDC components (`::landing-home`, `::keyspace-explorer`, `::chain-facts`)
├── app/composables/               # useLandingKey (live key walk), useSubNavigation (sidebar icons)
├── app/utils/                     # parse-key (range, stepping), derive (rows per chain), format
├── content/index.md               # landing
├── content/1.guide/               # getting started
├── content/2.blockchains/         # one page per chain
├── public/                        # favicon.svg and the files cut from it, site.webmanifest, fonts/
├── server/routes/sitemap.xml.ts   # Docus sitemap plus the Vue pages
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

Deployment: Workers Builds with root directory `docs`. It installs `docs/` and nothing else, which is enough because the library is bundled from `../src` (next paragraph). Nitro preset `cloudflare_module`. Nuxt Content needs a D1 binding named `DB`; `wrangler.jsonc` carries the binding and the `NUXT_SITE_URL` var, Nitro merges it into the generated `.output/server/wrangler.json`. The database is `agntn-keys`, created once with `wrangler d1 create agntn-keys`; its id sits in `wrangler.jsonc`.

`@agntn/keys` is an alias in `nuxt.config.ts` for `../src/index.ts`. Vite bundles the checkout's sources for the browser and Nitro gets the same alias for the prerender, so `dist/` and the root `node_modules` are never touched. The subgraph under `src/index.ts` imports from npm: `@noble/curves`, `@noble/hashes`, `@scure/base`, `@scure/bip32`, `@scure/bip39` and `micro-key-producer`. Each one is a dependency of `docs/package.json`, pinned to the root's version, and listed in `vite.resolve.dedupe` in `nuxt.config.ts`, because Vite resolves a bare import from the importer's directory upwards and `../src` never reaches `docs/node_modules`. The exact subpaths `src/` imports, dynamic imports included, sit in `vite.optimizeDeps.include`; without that list dev discovers them when a lazy chain module loads, optimizes again and reloads the page under the explorer. A new npm import under `src/` that `index.ts` can reach needs all three entries or the deploy or the dev server breaks. The CLI, MCP and tool entries stay out of the alias.

Three resolution traps, all because the repo root is its own pnpm workspace:

- `pnpm-workspace.yaml` sets `shamefullyHoist: true`. Without it `docs/node_modules` holds only direct dependencies, Node walks up to the root `node_modules`, and the server bundle can end up with a second copy of Vue.
- `nuxt.config.ts` pins `workspaceDir` to `docs/` and disables devtools and telemetry, which would otherwise resolve from the root.
- `vite.server.fs.allow` in `nuxt.config.ts` adds `../src`. Vite serves only directories on that list, and with `workspaceDir` pinned to `docs/` the library sits outside it, so `pnpm dev` couldn't load it otherwise.

## Tests

`test/docs-parse-key.test.ts` and `test/docs-landing.test.ts` in the repo root cover `app/utils/` and run with the root suite, no docs install needed. The root `vite.config.ts` transforms them with the root tsconfig, because `docs/tsconfig.json` only references files Nuxt generates. `derive.ts` takes the library module as an argument and imports its types from `../src` by path, so a root test passes `src/index.ts` and never needs the `@agntn/keys` alias; `test/public-exports.test.ts` keeps that name for the built package. Keep pure helpers in `app/utils/` so they stay testable from the root; anything that touches `ref` or `onMounted` belongs in `app/composables/`.

The landing renders before the library loads, so `app/utils/landing.ts` records private key 1 on every row, the Bitcoin pipeline and the first HD sample as fixtures. `test/docs-landing.test.ts` derives the same values from `src/` and fails when they drift, so a fixture edit without a library change is a lie the test catches.

## SEO

- `seo.schema` in `app/app.config.ts` emits the landing JSON-LD: `WebSite`, the agntn `Organization` as publisher, and a free `SoftwareApplication` with `sameAs` on GitHub and npm. Docs pages get `Article` plus `BreadcrumbList` from Docus on their own.
- `app/pages/keyspace.vue` sits outside `content/`, so it calls `useSeo` and `defineOgImage("Docs", props, { alt })` itself, `server/routes/sitemap.xml.ts` appends it to the Docus sitemap and `llms.sections` in `nuxt.config.ts` lists it for `llms.txt`. A new page under `app/pages/` needs all three or crawlers and agents never see it.
- Docus links `/favicon.ico` without shipping one. `public/favicon.svg` is the source, the PNGs and the `.ico` are cut from it with ImageMagick (`magick -background none favicon.svg -resize 512x512 icon-512.png`, `-define icon:auto-resize=48,32,16 favicon.ico`), `app.head` in `nuxt.config.ts` links them with the manifest, theme colours, `og:locale` and `author`.
- Audit on `.output/public/*.html` with grep for `<meta`, `<link rel="canonical"` and `"@type"`, not by impression.

## OG images

- `app/components/OgImage/Docs.takumi.vue` and `Landing.takumi.vue` override the Docus templates of the same name and are rendered by Takumi at build time. Takumi has no CSS variables, so the theme colours from `app.css` are repeated there as literals.
- nuxt-og-image doesn't see the faces `@nuxt/fonts` generates, but it parses `@font-face` rules from the files in `css`. That's why `app/assets/fonts.css` declares the five TTFs in `public/fonts` and `fonts.families` uses the `local` provider. Site and OG images share the files.
- Docus encodes title and description in the OG file name and a comma is a separator there, so the template gets descriptions without commas. Frontmatter descriptions use periods and `and` instead, and stay under 160 characters.
- The landing OG file is named from the SEO description and Nitro refuses a prerender path containing `..`, so a description ending in a period is silently skipped and the landing ships with a dead `og:image`. Keep the description in `content/index.md` without a trailing period and check `grep c_Landing` in the build log has no `(skipped)`.

## Constraints

- Derivation runs in the browser only. Do not add a server route that accepts private keys or mnemonics.
- Do not log, persist, or send key material.
- secp256k1 keyspace is `1 .. n-1`. ed25519 rows reuse the same 32 bytes as a secret; label that.
- Keep Node demos in `playground/`.
- Icons: `token` (Web3 Icons, monochrome) for chains by ticker (`i-token-btc`), Lucide for the interface, `simple-icons` for GitHub and npm, `vscode-icons` for file types in code block headers. A chain icon that only exists in colour is not a reason to mix sets.
- Chains are listed by hand: rows and `loadExplorerChains` in `app/utils/derive.ts`, fixtures in `app/utils/landing.ts`, the grid in `LandingHome.vue`, `LandingToolCall.vue`, `LandingRotatingCode.vue`, sidebar icons in `useSubNavigation.ts`, the icon bundle in `nuxt.config.ts`. A new chain in `src/_blockchains.ts` needs all of them plus a page under `content/2.blockchains/`.
