# Integration compatibility test

## Scope

This directory is a standalone pnpm workspace for manual compatibility checks against external wallet libraries. Its manifest, lockfile, and `pnpm-workspace.yaml` are independent from the repository root.

## Conventions

- Keep checks focused on interoperability with the public `@agntn/keys` API; blockchain implementation belongs in `../src/`.
- Type-check with `pnpm exec tsc --noEmit` and execute TypeScript with `pnpm exec tsx solana-test.ts`.
- Use generated test keys only. Output includes plaintext private keys and must remain local.
- A passing Solana check requires matching public keys, addresses, signatures, and successful verification in both directions.
