# packages/pi agent interface

## Scope

Pi coding agent extension only. Registers the tool definitions of `../../src/tools.ts`, one per name in `TOOL_NAMES` (`../../src/tool-parameters.ts`). **Do not** add blockchain logic, crypto, or chain implementations here. Those live in `../../src/`. This package is a thin tool surface over shared executors.

## Layout

- `extensions/keys.ts`: the extension. One `export default async function(pi: ExtensionAPI)` handing every definition to `registerPiTools` from `@agntn/tools/pi`.
- `../omp/extensions/keys.ts`: the OMP extension, the same list through `registerOmpTools`. A tool change goes to `src/tools.ts`, not here.

## Key facts

- **Tool resolution:** the extension loads `src/tools.ts` in a checkout and `dist/tools.mjs` in the built package, and the executors load on the first call. Run `pnpm build` before relying on the dist path.
- **Type checking:** `pnpm test:ext` (`tsc -p ../../tsconfig.extensions.json --noEmit`). Wired into `pnpm test` after `pnpm build` (the extensions tsconfig maps `@agntn/keys` → `dist/index.d.mts`, so dist must exist first).
- **Tool params:** schemas live in `../../src/tool-schemas.ts`, built with `Type` from `@agntn/tools`. Keep every root a plain object, without `oneOf`.
- **Concrete class contract:** every lazy-loaded class extends `AbstractBlockchain`, so `validateAddress`, `signMessage`, and `verifyMessage` are required and called directly.
- **Lazy double-call:** `blockchains.chain({ network })()` — first call passes constructor options, second imports and constructs the concrete class. See `../../src/_blockchains.ts`.
- **Host loader:** Pi imports extensions through jiti with `moduleCache: false`, so overlapping imports of modules with a shared graph hand one importer a half-built namespace. The lazy registry loads chain modules one at a time for that reason; keep new shared imports serial too. The mocked `ExtensionAPI` cannot see this, so the "Pi host loader" test in `../../test/pi-extension.test.ts` goes through jiti.

## Constraints

- No new abstraction layers (KISS/YAGNI). Add a tool only when it maps to a real library capability.
- Pin Pi and OMP dev deps to exact versions (no `latest`), like the rest of the repo.
- Experimental surface: tool names/params may change. Don't treat them as a stable contract yet.
- Tool schema regexes must stay portable across JSON Schema consumers. Keep features specific to JavaScript, such as Unicode property escapes, in executor validation rather than in `pattern` fields.
- Security: tools can accept or emit plaintext private keys, mnemonics, entropy, and signatures in the transcript. Never connect them to keys that control real funds. Use only public or disposable material.
