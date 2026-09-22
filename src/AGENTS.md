# Source surface

## Scope

Core package source plus the MCP and CLI entry points. Blockchain implementations and cryptographic primitives remain in their existing subdirectories.

## MCP layout

- `tool-operations.ts`: executors independent of a particular host, with boundary validation shared with Pi.
- `tool-schemas.ts`: TypeBox parameter schemas shared by MCP and Pi. Limits and portable patterns live in `tool-parameters.ts`.
- `mcp.ts`: MCP annotations, dispatch, and error conversion. Only MCP adds `BIP44_PATH_MODE_SCHEMA` to the shared BIP44 fields; Pi providers require a plain object root.
- `cli.ts`: executable entry point with a lazy `mcp` subcommand.
- `commands/mcp.ts`: stdio transport bootstrap. stdout is reserved for JSON-RPC. The server and the SDK are imported inside `run()`, because citty resolves the subcommand for `--help` and for an unknown command too.

## Constraints

- Keep cryptographic behavior in the library classes and utilities. Tool executors only compose public capabilities.
- Secret inputs must not be copied into errors or structured details.
- Every surface validates input, while `tool-operations.ts` remains the final boundary when a host skips schemas.
- Published ESM uses `.mjs` and declarations use `.d.mts`.
