# @agntn/keys knowledge base

## OVERVIEW

TypeScript library providing a unified interface for key generation, address derivation, wallet creation, and message signing across 8 blockchains (Bitcoin, Ethereum, Base, Solana, Aptos, Cardano, SUI, TRON). Built entirely on the @noble/@scure audited crypto ecosystem.

## STRUCTURE

```
keys/
├── src/
│   ├── index.ts            # Public API surface (re-exports only)
│   ├── blockchain.ts        # AbstractBlockchain base + useBlockchain() identity helper
│   ├── types.ts             # All shared types (Blockchain, Keys, Wallet, etc.)
│   ├── _blockchains.ts      # Lazy-loading registry with double-call pattern
│   ├── blockchains/         # One concrete class per chain (see blockchains/AGENTS.md)
│   └── utils/               # Shared crypto utilities (see utils/AGENTS.md)
├── test/                    # Mirrors src/ structure exactly
│   ├── fixtures.ts          # Shared test vectors (secp256k1, ed25519, bip39, addresses)
│   ├── blockchains/         # One test file per chain
│   └── utils/               # One test file per utility
├── test-integration/        # Separate package - compatibility with ethers and @solana/web3.js
├── playground/              # Runnable demo scripts (bip32, bip39, bip44, slip10, signing)
└── docs/                    # Docus-based documentation site
```

## WHERE TO LOOK

| Task               | Location                                                                          | Notes                                                      |
| ------------------ | --------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Add new blockchain | `src/blockchains/` + `src/_blockchains.ts`                                        | Extend the appropriate base class, register in lazy loader |
| Add address format | `src/utils/address.ts`                                                            | Shared across chains (legacy, segwit, hex, base58)         |
| Add EVM chain      | `src/utils/evm.ts` → `AbstractEVMBlockchain`                                      | Minimal subclass with `name` and `bip44`                   |
| Fix signing        | `src/utils/signing.ts` (generic) or `evm.ts`/`ed25519-chains.ts` (chain-specific) | EVM uses preamble hash, ed25519 signs raw                  |
| Change public API  | `src/index.ts`                                                                    | Re-exports only, never add logic here                      |
| Add BIP/derivation | `src/utils/bip32/`, `bip39/`, `bip44/`, `slip10/`                                 | Subdirs with index.ts                                      |
| Write tests        | `test/` mirroring `src/` path                                                     | Use fixtures from `test/fixtures.ts`                       |
| Integration test   | `test-integration/`                                                               | Separate pnpm package, manual execution                    |
| Run demos          | `playground/*.ts`                                                                 | Execute via `pnpm playground <file>`                       |

## CONVENTIONS

- **All crypto from @noble/@scure** - never import raw crypto from Node or other libs
- **Class pattern** - every blockchain exports a named concrete class and the same class as its default export
- **Abstract bases** - all chains extend `AbstractBlockchain`; Ethereum and Base extend `AbstractEVMBlockchain`
- **Lazy double-call** - `blockchains.chain(options)()` passes constructor options, then imports and constructs the class
- **Curve-split signing** - secp256k1 chains use `evmSignMessage` (Ethereum preamble + keccak256), ed25519 chains use `ed25519SignMessage` (raw, no prehash)
- **Test mirrors src** - `src/blockchains/bitcoin.ts` -> `test/blockchains/bitcoin.test.ts`
- **Shared fixtures** - test vectors live in `test/fixtures.ts`, not duplicated per test file
- **ESM only** - `"type": "module"` in package.json, `.mjs` output
- **oxlint and oxfmt** - `oxlint.config.ts` and `oxfmt.config.ts` spread the shared `@agntn/ox` policy (type-aware via `oxlint-tsgolint`); keep only repository-local additions (ignore patterns, the readonly-parameter allow-list) here
- **obuild** - entry points are explicit in `build.config.ts`; keep package `exports` aligned with emitted `.mjs`/`.d.mts` files

## ANTI-PATTERNS

- **No type assertions in src/** - zero `as any`, `@ts-ignore`, `@ts-expect-error` in source code (`@ts-expect-error` exists in tests only, for intentional invalid input testing)
- **No non-noble crypto** - never use Node `crypto` module for hashing/signing (only `webcrypto.getRandomValues` for key generation)
- **No logic in index.ts** - only re-exports
- **Don't bypass the lazy registry by accident** - use `blockchains.chain(options)()` for routine public loading; direct constructors are for explicit per-chain imports and subclassing
- **Don't mix signing utils** - secp256k1 chains must use `evmSignMessage`, ed25519 chains must use `ed25519SignMessage` or chain-specific variant

## COMMANDS

```bash
pnpm dev              # vitest watch mode
pnpm test             # lint + type check + vitest with coverage
pnpm test:types       # tsc --noEmit --skipLibCheck
pnpm build            # obuild via build.config.ts
pnpm lint             # oxlint + oxfmt check
pnpm lint:fix         # oxlint + oxfmt fixes
pnpm playground <f>   # run any TS file via tsx
```

## NOTES

- **CI runs**: lint -> type check -> build -> vitest with coverage (Node 22, pnpm). Autofix workflow commits lint fixes on PRs.
- **Package exports** only expose `"."` and `"./blockchains/*"` - utils are internal, not part of public API.
- **utils/ has mixed structure** - plain `.ts` files (address, encoding, crypto-hash, secp256k1, ed25519, ed25519-chains, evm, signing) and subdirectories with `index.ts` (bip32/, bip39/, bip44/, slip10/).
- **`__cardano/notes.md`** - research notes for Cardano implementation, not code. The actual implementation is `cardano.ts`.
- **Signing verification tests** - both verification tests in `test/utils/signing.test.ts` are enabled; they derive the secp256k1 public key from the fixture private key because `secp256k1TestVectors.publicKeyCompressed` does not pair with `privateKey` (kept only for address-derivation tests, which are self-consistent).
- **`createVersionedHash` is deprecated** in `address.ts` - use `addSchemeByte` instead.
