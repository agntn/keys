# Tests

## Scope

Vitest coverage for the public library, MCP server, and Pi extension. The tree mirrors `src/` where practical.

## Conventions

- Put shared cryptographic vectors in `fixtures.ts`.
- Exercise exported behavior through real modules, without module mocks. The one stub is `defineMcpTool` in `docs-mcp.test.ts`: the toolkit returns its input, but its entry won't load outside Nitro.
- Use independent specification vectors, round trips, or mechanical invariants for crypto checks.
- Keep wallet SDKs out of the tests, manual checks included. Freeze what ethers, web3.js or a chain SDK produces as vectors in `fixtures.ts`, with the library and version in the JSDoc.
- Keep puzzle fixtures public and disposable. Never add live wallet secrets.
- Exercise MCP protocol behavior in memory and every advertised tool through the stdio CLI.
- Run the built bin's usage paths under `record-loads.mjs`; `--help`, `-h` and an unknown command must not load the server stack.
- Run the focused test first, then `pnpm test` before delivery.
