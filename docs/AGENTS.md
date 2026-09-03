# docs/

Docus site for `@agntn/keys`. Markdown lives in `content/`. The browser explorer is a Vue component in the Nuxt app, not a `playground/` script.

## Layout

```
docs/
├── nuxt.config.ts                 # extends: ['docus']
├── app/app.config.ts              # title, github, theme
├── app/app.css                    # theme tokens (light + .dark), shared `keys-*` classes
├── app/components/                # Docus overrides: AppHeaderLogo, AppHeaderCTA (nav), AppFooterLeft
├── app/components/content/        # MDC components (`::landing-home`, `::keyspace-explorer`)
├── app/utils/                     # parse/derive helpers
├── content/index.md               # landing
├── content/1.guide/               # getting started
├── content/2.blockchains/         # one page per chain
└── app/pages/keyspace.vue         # explorer, own route outside the docs layout
```

`playground/` at the repo root stays Node/tsx demos.

## Commands

```bash
pnpm install          # from docs/, after pnpm build in the repo root
pnpm dev              # http://localhost:3000
pnpm build            # Nitro output in .output/
pnpm generate         # static output in .output/public
```

The explorer imports `@agntn/keys` from `file:..`. Build the parent package first.

## Constraints

- Derivation runs in the browser only. Do not add a server route that accepts private keys or mnemonics.
- Do not log, persist, or send key material.
- secp256k1 keyspace is `1 .. n-1`. ed25519 rows reuse the same 32 bytes as a secret; label that.
- Keep Node demos in `playground/`.
