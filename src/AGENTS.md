# Source surface

## Scope

Core package source plus the MCP and CLI entry points. Blockchain implementations and cryptographic primitives remain in their existing subdirectories.

## MCP layout

- `tools.ts`: one `defineTool` per tool from `@agntn/tools`, the list MCP, Pi and OMP serve. It imports the executors on the first call.
- `tool-operations.ts`: executors independent of a particular host, with their own boundary checks.
- `tool-schemas.ts`: TypeBox parameter schemas, built with `Type` from `@agntn/tools`. Limits and portable patterns live in `tool-parameters.ts`.
- `mcp.ts`: `createMcpServer()` through `@agntn/tools/mcp`, plus `toolListings` and `callTool()` for the docs server at `/mcp`, which answer like `keys mcp`.
- `cli.ts`: the `keys` bin, `runCli` from `@agntn/tools/cli` over `keysTools` with `mcp: true`. Every tool is a command and its flags come from the schema, so nothing here repeats an argument. A `cli` hint on `defineTool` changes how a tool reads on the line. Built into `dist/cli.mjs`, a bare `keys mcp` serves `src/mcp.ts` in a checkout (see the MCP transport note in the root `AGENTS.md`). stdout of `mcp` is reserved for JSON-RPC.

## Constraints

- Keep cryptographic behavior in the library classes and utilities. Tool executors only compose public capabilities.
- Secret inputs must not be copied into errors or structured details.
- `@agntn/tools` validates input on every surface, while `tool-operations.ts` keeps its own checks for any caller that skips the schema.
- The executors read a blank optional name (network, address type) as omitted; OMP drops one the schema refuses before the call. Passphrases keep blank and whitespace values, and the BIP39 language still rejects `""`.
- Published ESM uses `.mjs` and declarations use `.d.mts`.
