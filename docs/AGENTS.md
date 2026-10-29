# docs/

Cloudflare Workers Builds deploys this site to keys.agntn.dev with `docs` as the root directory. Its `pnpm install` walks up to the root lockfile and fills the whole workspace, so a bare import in `../src` resolves from the root, but `dist/` never exists there. Node.js comes from the root `.node-version`, never from `engines`.

The build trigger only watches `docs/*`, `src/*`, `CHANGELOG.md` and `.node-version`. A bump that touches nothing but the catalog in the root `pnpm-workspace.yaml` and `pnpm-lock.yaml` leaves the live site on the old versions until the next commit in one of those paths.

Resources on the Cloudflare account, bound by id in `wrangler.jsonc`:

- D1 `agntn-keys` as `DB` for Nuxt Content
- No KV, R2 or secrets: the library runs from the bundle, in the browser and in the worker

`/mcp` is the one place where key material reaches the server, because an agent sends it there on purpose. The worker must not log or keep it: tool arguments stay out of every log line, observability included. `content/1.guide/1.index.md#remote-mcp` promises users exactly that.
