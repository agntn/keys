# Source surface

## Scope

Core package source plus the MCP and CLI entry points. Blockchain implementations and cryptographic primitives remain in their existing subdirectories.

## MCP layout

- `tool-operations.ts`: executors independent of a particular host, with boundary validation shared with Pi.
- `tool-schemas.ts`: TypeBox parameter schemas shared by MCP and Pi. Limits and portable patterns live in `tool-parameters.ts`.
- `mcp.ts`: MCP annotations, dispatch, and error conversion. It exports `toolListings` and `callTool()`, which `createMcpServer()` and the docs server at `/mcp` both use.
- `cli.ts`: executable entry point with a lazy `mcp` subcommand. Built into `dist/cli.mjs`, it takes that subcommand from `src/` in a checkout (see the MCP transport note in the root `AGENTS.md`).
- `commands/mcp.ts`: stdio transport bootstrap. stdout is reserved for JSON-RPC. The server and the SDK are imported inside `run()`, because citty resolves the subcommand for `--help` and for an unknown command too.

## Constraints

- Keep cryptographic behavior in the library classes and utilities. Tool executors only compose public capabilities.
- Secret inputs must not be copied into errors or structured details.
- Every surface validates input, while `tool-operations.ts` remains the final boundary when a host skips schemas.
- OMP skips schemas and fills every property, so a blank optional name (network, address type) counts as omitted there. Passphrases keep blank and whitespace values, and the BIP39 language still rejects `""`.
- Published ESM uses `.mjs` and declarations use `.d.mts`.
