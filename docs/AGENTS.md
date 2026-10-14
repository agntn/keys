# docs/

Cloudflare Workers Builds deploys this site to keys.agntn.dev. It installs `docs/` alone, so the root `node_modules` and `dist/` never exist there, and it takes Node.js from the root `.node-version`, never from `engines`.

Resources on the Cloudflare account, bound by id in `wrangler.jsonc`:

- D1 `agntn-keys` as `DB` for Nuxt Content
- No KV, R2 or secrets: the library runs from the bundle, in the browser and in the worker

`/mcp` is the one place where key material reaches the server, because an agent sends it there on purpose. The worker must not log or keep it: tool arguments stay out of every log line, observability included. `content/1.guide/1.index.md#remote-mcp` promises users exactly that.
