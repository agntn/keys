# Contributing

## Setup

Run `pnpm install` at the root. One install is enough now. It also fills `docs/node_modules`, where `test/docs-mcp.test.ts` loads Zod and the toolkit. `pnpm test` runs lint, the type checks, the build, the extension checks, the suite with coverage and the MCP eval.

The lint scripts build first, because the Pi and OMP extensions take their tool types from `dist/tools.d.mts`. So `build`, `lint`, `fmt`, `test`, `test:mcp` and packing all rewrite `dist/`. Serving `keys mcp` or an extension from your checkout? Run them in a separate worktree, or the live server gets a new bundle under its feet.

## Adding a chain

1. `src/blockchains/<name>.ts` exports a class extending `AbstractBlockchain` (or the family base in `src/utils/`), by name and as the default export. It implements `name`, `curve`, `bip44`, `getKeyPublic`, `getAddress`, `validateAddress`, `signMessage` and `verifyMessage`.
2. More than one address format means overriding `defaultAddressType`. One format still takes `type` and hands it to `refuseAddressType`, so a wallet never claims a type it didn't write.
3. Register it in `src/_blockchains.ts` with `lazy()`.
4. Add `test/blockchains/<name>.test.ts`, with vectors from outside this package.
5. The site lists chains by hand. That means a row in `CHAINS` in `docs/app/utils/chains.ts`, rows in `docs/app/utils/derive.ts` and a fixture in `docs/app/utils/landing.ts`. Then its icon in the `nuxt.config.ts` bundle and in `useSubNavigation.ts`, and `docs/content/2.blockchains/<name>.md` with `::chain-facts`. `test/docs-chains.test.ts` points at whatever you forgot.

## Crypto and code

- A primitive an `@agntn/*` package covers comes from it: every hash from `@agntn/hashes`, point math from `@agntn/curves`, encodings from `@agntn/encodings`. Signing, ed25519 and HD stay on @noble/@scure until a sibling takes them over. A missing primitive is an issue on the sibling, not a new @noble dependency, and an audit is no argument for one.
- Never Node `crypto`, not even for randomness. Keys come from the curve's `utils.randomSecretKey()`.
- secp256k1 chains sign through `evmSignMessage` or their own preamble, ed25519 chains extend `AbstractEd25519Blockchain`, which signs the raw message, and wrap or hash it before `super` when their wallets do. Don't mix them.
- `src/` uses `Uint8Array.fromHex`, `.toHex()` and `concatBytes` from `src/utils/bytes.ts`. Tests and the playground use `hex` from `@agntn/encodings/hex`, because the type-aware lint types them without the `esnext` lib.
- No `as any`, `@ts-ignore` or `@ts-expect-error` in `src/`. Tests may use `@ts-expect-error` for input that's wrong on purpose.
- `src/index.ts` only re-exports. Public loading goes through `blockchains.chain(options)()`; a direct constructor is for subclassing and explicit imports.
- BIP39 stays strict by default through `@scure/bip39`. Localized word lists load only when asked for, and lookups normalize to NFKD first. Every numeric lookup says whether it counts from 0 or 1.

## Agent tools

- One `defineTool` per tool in `src/tools.ts`, with its executor in the domain module under `src/tool-operations/` that `index.ts` re-exports. Shared argument readers live in `arguments.ts` and the chain and network ones in `blockchain.ts`. Look there before you write another `requiredString`. `keys mcp`, the docs `/mcp`, Pi and OMP all serve that list, so a fix never lands on one surface only.
- Schemas in `src/tool-schemas.ts` take `Type` from `@agntn/tools`, never a bare `typebox` import, which OMP rewrites to its own facade. Every root is a plain object without `oneOf`, and a `pattern` stays portable across JSON Schema consumers. Unicode property escapes belong in the executor.
- Executors compose public library capabilities and keep their own checks for callers that skip the schema. A blank optional name reads as omitted, while passphrases keep blank and whitespace values.
- Secret input never lands in an error or in structured details.
- A tool maps to a real library capability. The names and parameters are still experimental, so nobody should build on them as a stable contract yet.

## Tests

- Tests import from `vite-plus/test` and share vectors through `test/fixtures.ts`.
- Real modules, no module mocks. The one exception is `test/docs-mcp.test.ts`, because the toolkit's server entry won't load outside Nitro.
- No wallet SDKs, not even for a manual check. Freeze what ethers, web3.js or a chain SDK produces as a vector in `fixtures.ts`, with the library and its version in the JSDoc.
- Public, disposable keys only. Nothing here should ever hold a real fund, and nothing's audited.
- The built bin runs its usage paths under `test/record-loads.mjs`: `--help`, `-h` and an unknown command must not load the server stack.
- Pi and OMP dev dependencies are pinned to exact versions.

## Docs site

`pnpm docs` serves it on port 3000.

- `pnpm --dir docs typecheck` runs vue-tsc over the app, `.vue` files too. `pnpm test:types` calls it. Docus ships raw TypeScript that fails this config, so the script skips its errors and fails on yours.
- A page under `docs/app/pages/` calls `useSeo` and `defineOgImage` itself, goes into `PAGES` in `server/api/__sitemap__/pages.ts` and gets listed in `llms.sections` in `nuxt.config.ts`. Skip one and crawlers or agents never see it.
- A frontmatter `description` stays under 160 characters. Commas and a closing period are fine. The OG card keeps them, and its file is named by a hash, not by your sentence.
- Icons: `token` for chains by ticker, Lucide for the interface, `simple-icons` for GitHub and npm, `vscode-icons` for file types. A chain icon that only comes in colour doesn't justify a second set.
- `public/favicon.svg` is the source. The PNGs and the `.ico` are cut from it with ImageMagick, and both MCP servers show `favicon.svg` and `icon-512.png`.
- A new npm import that `src/index.ts` reaches goes into `libraryDependencies` and `libraryEntries` in `docs/nuxt.config.ts`, not `docs/package.json`. Miss either list and the dev server breaks. The site's own imports still need to be in `docs/package.json`, and `test/docs-dependencies.test.ts` checks them.
- Pure helpers go in `app/utils/` so the root suite can test them. Anything touching `ref` or `onMounted` goes in `app/composables/`.
- The explorer derives in the browser. `/mcp` is the only server route that takes key material, and that's not an invitation to add another.
