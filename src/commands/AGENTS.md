# CLI commands

## Scope

Thin citty command adapters. Commands may select transport and logging behavior, but domain logic belongs in `../tool-operations.ts`.

## MCP invariant

The stdio command reserves stdout for JSON-RPC frames. Keep diagnostics on stderr and connect the server from `../mcp.ts` without redefining tools.
