# Source surface

## Scope

Core package source plus the MCP and CLI entry points. Blockchain implementations and cryptographic primitives remain in their existing subdirectories.

## MCP layout

- `tool-operations.ts`: executors independent of a particular host, with boundary validation shared with Pi.
- `mcp.ts`: TypeBox schemas, MCP annotations, dispatch, and error conversion.
- `cli.ts`: executable entry point with a lazy `mcp` subcommand.
- `commands/mcp.ts`: stdio transport bootstrap. stdout is reserved for JSON-RPC.

## Constraints

- Keep cryptographic behavior in the library classes and utilities. Tool executors only compose public capabilities.
- Secret inputs must not be copied into errors or structured details.
- Every surface validates input, while `tool-operations.ts` remains the final boundary when a host skips schemas.
- Published ESM uses `.mjs` and declarations use `.d.mts`.
