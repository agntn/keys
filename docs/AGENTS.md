# docs/

Docus site for `@agntn/keys`. Markdown lives in `content/`. The browser explorer is a Vue component in the Nuxt app, not a `playground/` script.

## Layout

```
docs/
├── nuxt.config.ts                 # extends: ['docus'], cloudflare_module preset, @agntn/keys aliased to ../src
├── app/app.config.ts              # title, github, theme
├── app/app.css                    # theme tokens (light + .dark), shared `keys-*` classes
├── app/components/                # Docus overrides: AppHeaderLogo, AppHeaderCTA (nav), AppFooterLeft, DocsAsideLeftBody
├── app/components/content/        # MDC components (`::landing-home`, `::keyspace-explorer`, `::chain-facts`)
├── app/composables/               # useLandingKey (live key walk), useSubNavigation (sidebar icons)
├── app/utils/                     # parse-key (range, stepping), derive (rows per chain), format
├── content/index.md               # landing
├── content/1.guide/               # getting started
├── content/2.blockchains/         # one page per chain
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

`@agntn/keys` is an alias in `nuxt.config.ts` for `../src/index.ts`. Vite bundles the checkout's sources for the browser and Nitro gets the same alias for the prerender, so `dist/` and the root `node_modules` are never touched. The subgraph under `src/index.ts` imports from npm: `@noble/curves`, `@noble/hashes`, `@scure/base`, `@scure/bip32`, `@scure/bip39` and `micro-key-producer`. Each one is a dependency of `docs/package.json`, pinned to the root's version, and listed in `vite.resolve.dedupe` in `nuxt.config.ts`, because Vite resolves a bare import from the importer's directory upwards and `../src` never reaches `docs/node_modules`. A new npm import under `src/` that `index.ts` can reach needs both entries or the deploy breaks. The CLI, MCP and tool entries stay out of the alias.

Three resolution traps, all because the repo root is its own pnpm workspace:

- `pnpm-workspace.yaml` sets `shamefullyHoist: true`. Without it `docs/node_modules` holds only direct dependencies, Node walks up to the root `node_modules`, and the server bundle can end up with a second copy of Vue.
- `nuxt.config.ts` pins `workspaceDir` to `docs/` and disables devtools and telemetry, which would otherwise resolve from the root.
- `vite.server.fs.allow` in `nuxt.config.ts` adds `../src`. Vite serves only directories on that list, and with `workspaceDir` pinned to `docs/` the library sits outside it, so `pnpm dev` couldn't load it otherwise.

## Tests

`test/docs-parse-key.test.ts` in the repo root covers `app/utils/parse-key.ts` and runs with the root suite, no docs install needed. The root `vitest.config.ts` transforms it with the root tsconfig, because `docs/tsconfig.json` only references files Nuxt generates. Keep pure helpers in `app/utils/` so they stay testable from the root.

## Constraints

- Derivation runs in the browser only. Do not add a server route that accepts private keys or mnemonics.
- Do not log, persist, or send key material.
- secp256k1 keyspace is `1 .. n-1`. ed25519 rows reuse the same 32 bytes as a secret; label that.
- Keep Node demos in `playground/`.
