# Tests

## Scope

Vitest coverage for the public library and Pi extension. The tree mirrors `src/` where practical.

## Conventions

- Put shared cryptographic vectors in `fixtures.ts`.
- Exercise exported behavior through real modules, without module mocks.
- Use independent specification vectors, round trips, or mechanical invariants for crypto checks.
- Keep puzzle fixtures public and disposable. Never add live wallet secrets.
- Run the focused test first, then `pnpm test` before delivery.
