# packages/pi — agent interface

## Scope

Pi coding-agent extension only. Wraps the `ubichain` library as 6 agent tools. **Do not** add blockchain logic, crypto, or chain implementations here — those live in `../../src/`. This package is a thin tool surface over the public library API.

## Layout

- `extensions/ubichain.ts` — the extension. One `export default function(pi: ExtensionAPI)` registering 6 tools via `pi.registerTool`.

## Key facts

- **Library resolution:** `loadLib()` imports built `ubichain` from `dist/`; falls back to `../../../src/index.ts` in dev before a build. Run `pnpm build` before relying on the dist path.
- **Type-check:** `pnpm test:ext` (`tsc -p ../../tsconfig.extensions.json --noEmit`). Wired into `pnpm test` after `pnpm build` (the extensions tsconfig maps `ubichain` → `dist/index.d.mts`, so dist must exist first).
- **Tool params:** declared with `typebox` `Type.*`, not zod. Match the existing style.
- **Concrete class contract:** every lazy-loaded class extends `AbstractBlockchain`, so `validateAddress`, `signMessage`, and `verifyMessage` are required and called directly.
- **Lazy double-call:** `blockchains.chain({ network })()` — first call passes constructor options, second imports and constructs the concrete class. See `../../src/_blockchains.ts`.

## Constraints

- No new abstraction layers (KISS/YAGNI). Add a tool only when it maps to a real library capability.
- Pin Pi/typebox dev deps to exact versions (no `latest`) — consistent with the rest of the repo.
- Experimental surface: tool names/params may change. Don't treat them as a stable contract yet.
- Security: tools emit plaintext private keys/signatures into the transcript. Never wire this to real-funds keys; burner-only.
