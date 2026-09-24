# @agntn/keys knowledge base

## OVERVIEW

TypeScript library providing a unified interface for key generation, address derivation, wallet creation, and message signing across 15 blockchains (Bitcoin, Bitcoin Cash, Bitcoin Gold, Bitcoin SV, Litecoin, Decred, Dogecoin, Ethereum, Base, Solana, Stellar, Aptos, Cardano, SUI, TRON). Built entirely on the @noble/@scure audited crypto ecosystem.

## STRUCTURE

```
keys/
├── src/
│   ├── index.ts             # Public API surface (re-exports only)
│   ├── blockchain.ts        # AbstractBlockchain base + useBlockchain() identity helper
│   ├── types.ts             # All shared types (Blockchain, Keys, Wallet, etc.)
│   ├── _blockchains.ts      # Lazy-loading registry with double-call pattern
│   ├── tool-operations.ts   # Shared MCP, Pi and OMP executors
│   ├── mcp.ts               # MCP schemas, dispatch, and server factory
│   ├── cli.ts               # keys executable with lazy mcp subcommand
│   ├── commands/            # CLI transport adapters
│   ├── blockchains/         # One concrete class per chain (see blockchains/AGENTS.md)
│   └── utils/               # Shared crypto utilities (see utils/AGENTS.md)
├── test/                    # Mirrors src/ structure exactly
│   ├── fixtures.ts          # Shared test vectors (secp256k1, ed25519, bip39, addresses)
│   ├── blockchains/         # One test file per chain
│   └── utils/               # One test file per utility
├── test-integration/        # Separate package - compatibility with ethers and @solana/web3.js
├── playground/              # Node demo scripts (bip32, bip39, bip44, slip10, signing)
└── docs/                    # Docus site: markdown guide plus browser keyspace explorer
```

## WHERE TO LOOK

| Task               | Location                                                                          | Notes                                                                               |
| ------------------ | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Add new blockchain | `src/blockchains/` + `src/_blockchains.ts`                                        | Extend the appropriate base class, register in lazy loader                          |
| Add address format | `src/utils/address.ts`                                                            | Shared across chains (legacy, segwit, hex, base58)                                  |
| Add Bitcoin family | `src/utils/bitcoin.ts` → `AbstractBitcoinBlockchain`                              | Reuse transparent address and HD behavior; keep chain signing rules explicit        |
| Bitcoin keys only  | `src/utils/bitcoin.ts` → `AbstractBitcoinMessageBlockchain`                       | Keys and Core message signing without address formats, as BCH, BSV and Dogecoin use |
| Add EVM chain      | `src/utils/evm.ts` → `AbstractEVMBlockchain`                                      | Minimal subclass with `name` and `bip44`                                            |
| Fix signing        | `src/utils/signing.ts` (generic) or `evm.ts`/`ed25519-chains.ts` (chain-specific) | EVM uses preamble hash, ed25519 signs raw                                           |
| Change public API  | `src/index.ts`                                                                    | Re-exports only, never add logic here                                               |
| Change agent tools | `src/tool-operations.ts`, `src/mcp.ts`, `packages/{pi,omp}/extensions/keys.ts`    | Executors are shared; schemas stay aligned                                          |
| Add BIP/derivation | `src/utils/bip32/`, `bip39/`, `bip44/`, `slip10/`                                 | Subdirs with index.ts                                                               |
| Mnemonic to wallet | `src/blockchain.ts` → `deriveHDWallet` + `src/utils/hd.ts`                        | Bitcoin family infers the address type; Sui overrides it, Cardano throws (CIP-1852) |
| Write tests        | `test/` mirroring `src/` path                                                     | Use fixtures from `test/fixtures.ts`                                                |
| Integration test   | `test-integration/`                                                               | Separate pnpm package, manual execution                                             |
| Run demos          | `playground/*.ts`                                                                 | Execute via `pnpm playground <file>`                                                |
| Docs / keyspace UI | `docs/`                                                                           | Docus: `content/` markdown, explorer in `app/components/`                           |

## CONVENTIONS

- **All crypto from @noble/@scure** - never import raw crypto from Node or other libs
- **Class pattern** - every blockchain exports a named concrete class and the same class as its default export
- **Abstract bases** - all chains extend `AbstractBlockchain`; Ethereum and Base extend `AbstractEVMBlockchain`
- **Lazy double-call** - `blockchains.chain(options)()` passes constructor options, then imports and constructs the class
- **Curve-split signing** - secp256k1 chains use `evmSignMessage` (Ethereum preamble + keccak256), ed25519 chains use `ed25519SignMessage` (raw, no prehash)
- **Paths per chain** - `getDerivationPath` on the base class is BIP44; Solana, Stellar and Aptos override it with their SLIP-10 shape, every level hardened (Stellar stops at the account, Solana at the change branch), Sui hardens the ed25519 path and walks BIP32 `m/54'/784'/account'/change/index` on secp256k1, Cardano writes CIP-1852 with a plain role and index. `keys_bip44_path` generates through it, so Cardano takes roles up to 5 where BIP44 chains stop at 1
- **Test mirrors src** - `src/blockchains/bitcoin.ts` -> `test/blockchains/bitcoin.test.ts`
- **Test imports** - test files import from `vite-plus/test`, not `vitest`
- **Shared fixtures** - test vectors live in `test/fixtures.ts`, not duplicated per test file
- **ESM only** - `"type": "module"` in package.json, `.mjs` output
- **Vite+** - `vite.config.ts` is the one config for `vp lint`, `vp fmt`, `vp test` and `vp pack`. The `lint` and `fmt` blocks spread the shared `@agntn/ox` policy (type-aware); keep only repository-local additions (ignore patterns, the readonly-parameter allow-list) there
- **`vp pack`** - entry points are explicit in the `pack` block; keep package `exports` aligned with emitted `.mjs`/`.d.mts` files

## ANTI-PATTERNS

- **No type assertions in src/** - zero `as any`, `@ts-ignore`, `@ts-expect-error` in source code (`@ts-expect-error` exists in tests only, for intentional invalid input testing)
- **No non-noble crypto** - never import Node `crypto`, not even for randomness. Keys come from the curve's `utils.randomSecretKey()`
- **No syntax Node cannot strip** - `src/` runs under plain Node type stripping, so no `enum`, `namespace` or parameter properties (`erasableSyntaxOnly` enforces it), and relative imports end in `.ts`
- **No logic in index.ts** - only re-exports
- **Don't bypass the lazy registry by accident** - use `blockchains.chain(options)()` for routine public loading; direct constructors are for explicit per-chain imports and subclassing
- **Don't mix signing utils** - secp256k1 chains must use `evmSignMessage`, ed25519 chains must use `ed25519SignMessage` or chain-specific variant

## COMMANDS

```bash
pnpm dev              # vp test in watch mode
pnpm test             # lint + type check + vp test with coverage
pnpm test:types       # tsc --noEmit --skipLibCheck
pnpm build            # vp pack via vite.config.ts
pnpm lint             # vp lint + vp fmt --check
pnpm lint:fix         # vp lint --fix + vp fmt
pnpm playground <f>   # run any TS file via tsx
pnpm docs             # Docus + keyspace explorer on :3000
pnpm test:mcp         # build and exercise all 19 MCP tools over stdio
```

## NOTES

- **CI runs**: lint -> type check -> build -> vp test with coverage (Node 24, pnpm through `setup-vp`). Autofix workflow commits lint fixes on PRs.
- **Package exports** expose `"."`, `"./mcp"`, `"./blockchains/*"`, and the HD derivation subpaths `"./bip32"`, `"./bip39"`, and `"./slip10"`; other utils remain internal.
- **OMP extension** - `packages/omp/extensions/keys.ts` is a full copy of the Pi file, with both dynamic imports of the executors kept literal. OMP does not expand globs in the manifest, so `omp.extensions` names the file. `test/omp-extension.test.ts` keeps the two registrations identical.
- **MCP transport** runs through `keys mcp`. Inside a checkout, `dist/cli.mjs` loads the MCP command from `src/`, like the Pi and OMP extensions, so a local server only needs a restart after a change. The npm package ships only `dist` and runs the bundle. A copy under `node_modules` keeps the bundle too, because Node does not strip types there, and so does a checkout without dev dependencies, whose source cannot import `typebox`. `KEYS_DIST=1` forces the bundle in a checkout, as `test/cli.test.ts` and `test/eval-mcp.mjs` do. Changes to `src/cli.ts` itself still need `pnpm build`. stdout is reserved for JSON-RPC, and `createMcpServer()` remains importable for hosts with their own transport.
- **utils/ has mixed structure** - plain `.ts` files (address, encoding, crypto-hash, secp256k1, ed25519, ed25519-chains, evm, signing) and subdirectories with `index.ts` (bip32/, bip39/, bip44/, slip10/).
- **`__cardano/notes.md`** - research notes for Cardano implementation, not code. The actual implementation is `cardano.ts`.
- **Shared secp256k1 fixture** - `secp256k1TestVectors.publicKeyCompressed` is the key of `privateKey`, shared by the signing round trips and the address tests. The Bitcoin address generators decode the SEC1 point before hashing, so an invented key fails them.
- **`createVersionedHash` is deprecated** in `address.ts` - use `addSchemeByte` instead.
