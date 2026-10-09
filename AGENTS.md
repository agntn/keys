# @agntn/keys knowledge base

## OVERVIEW

TypeScript library providing a unified interface for key generation, address derivation, wallet creation, and message signing across Bitcoin, Bitcoin Cash, Bitcoin Gold, Bitcoin SV, Litecoin, Dash, Decred, Dogecoin, Zcash, eCash, Ethereum, Base, Solana, Stellar, Aptos, Cardano, SUI, TRON, the XRP Ledger, NEAR, Cosmos SDK chains, Polkadot and Monero. Signing curves and HD derivation come from @noble/@scure, point math on secp256k1 and custom curves from @agntn/curves, every hash from @agntn/hashes, base encodings from @agntn/encodings, AES from @agntn/ciphers. Nothing in the package is audited or meant for production, real funds or sensitive data.

## STRUCTURE

```
keys/
├── src/
│   ├── index.ts             # Public API surface (re-exports only)
│   ├── blockchain.ts        # AbstractBlockchain base + useBlockchain() identity helper
│   ├── types.ts             # All shared types (Blockchain, Keys, Wallet, etc.)
│   ├── _blockchains.ts      # Lazy-loading registry with double-call pattern
│   ├── tools.ts             # One @agntn/tools definition per tool, served to MCP, Pi and OMP
│   ├── tool-operations.ts   # Executors behind the definitions, loaded on the first call
│   ├── mcp.ts               # MCP server factory, toolListings and callTool for docs/server/mcp
│   ├── server-info.ts       # name, version, pitch and icons both MCP servers introduce themselves with
│   ├── cli.ts               # keys executable: runCli over the tools, mcp from source in a checkout
│   ├── blockchains/         # One concrete class per chain (see blockchains/AGENTS.md)
│   └── utils/               # Shared crypto utilities (see utils/AGENTS.md)
├── test/                    # Mirrors src/ structure exactly
│   ├── fixtures.ts          # Shared test vectors (secp256k1, ed25519, bip39, addresses)
│   ├── blockchains/         # One test file per chain
│   └── utils/               # One test file per utility
├── playground/              # Node demo scripts (bip32, bip39, bip44, slip10, signing)
└── docs/                    # Docus site: markdown guide plus browser keyspace explorer
```

## WHERE TO LOOK

| Task                | Location                                                                          | Notes                                                                                                                                   |
| ------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Add new blockchain  | `src/blockchains/` + `src/_blockchains.ts`                                        | Extend the appropriate base class, register in lazy loader                                                                              |
| Add address format  | `src/utils/address.ts`                                                            | Shared across chains (legacy, segwit, hex, base58)                                                                                      |
| Add Bitcoin family  | `src/utils/bitcoin.ts` → `AbstractBitcoinBlockchain`                              | Reuse transparent address and HD behavior; keep chain signing rules explicit                                                            |
| Bitcoin keys only   | `src/utils/bitcoin.ts` → `AbstractBitcoinMessageBlockchain`                       | Keys and Core message signing without address formats, as Zcash uses                                                                    |
| Base58 P2PKH only   | `src/utils/bitcoin.ts` → `AbstractBitcoinP2PKHBlockchain`                         | One byte versions per network, P2SH optional, as BSV, Dash and Dogecoin use                                                             |
| CashAddr P2PKH      | `src/utils/bitcoin.ts` → `AbstractCashAddrBlockchain`                             | A prefix per network and the hash lengths each type pays to, as BCH and eCash use                                                       |
| Add EVM chain       | `src/utils/evm.ts` → `AbstractEVMBlockchain`                                      | Minimal subclass with `name` and `bip44`                                                                                                |
| Fix signing         | `src/utils/signing.ts` (generic) or `evm.ts`/`ed25519-chains.ts` (chain-specific) | EVM uses preamble hash, ed25519 signs raw                                                                                               |
| Core signature      | `src/utils/secp256k1/compact-signature.ts`                                        | Base64 of a header byte, then `r` and `s`, for the Bitcoin family and Decred; `recoverMessageSigner` reads it                           |
| BIP322 signature    | `src/utils/bip322/`                                                               | `verify` and `sign`; unrunnable scripts are inconclusive                                                                                |
| Transaction sighash | `src/utils/transaction/`                                                          | Legacy, BIP143 and BIP341 sighash with every hash type; `extractSignatures` gives r, s and z of an input                                |
| Script address      | `src/utils/script/`                                                               | `multisig` and `address` for P2SH, P2WSH and P2SH-P2WSH; `keys_script_address_get` gives all three                                      |
| Output descriptor   | `src/utils/descriptor/`                                                           | `parse` and `checksum` for `pkh`, `wpkh`, `sh`, `wsh` and `tr`, checked against BIP 380 to 387 and Core                                 |
| Reused nonce        | `src/utils/secp256k1/nonce.ts` → `recoverReusedNonce`                             | ECDSA and BIP340; `keys_secp256k1_nonce_recover` answers with the public key only                                                       |
| EVM signer          | `src/utils/eip712.ts` + `recoverSecp256k1Signer` in `signing.ts`                  | `hashTypedData`; `recoverMessageSigner`/`recoverDigestSigner` on EVM and TRON                                                           |
| Change public API   | `src/index.ts`                                                                    | Re-exports only, never add logic here                                                                                                   |
| Change agent tools  | `src/tools.ts`, `src/tool-schemas.ts`, `src/tool-operations.ts`                   | One definition per tool; a new tool also gets its file in `docs/server/mcp/tools/`                                                      |
| Keystore files      | `src/utils/store/`                                                                | Web3 Secret Storage v3: scrypt/PBKDF2, AES-128-CTR from `@agntn/ciphers/aes`                                                            |
| Add BIP/derivation  | `src/utils/bip32/`, `bip39/`, `bip44/`, `slip10/`                                 | Subdirs with index.ts                                                                                                                   |
| Mnemonic to wallet  | `src/blockchain.ts` → `deriveHDWallet` + `src/utils/hd.ts`                        | Bitcoin family infers the address type; Sui overrides it, Cardano and Monero throw, Polkadot walks Substrate junctions                  |
| XRPL family seed    | `src/blockchains/xrpl.ts` → `deriveSeedWallet`                                    | `s...`/`sEd...` to account 0 as rippled derives it; `keys_wallet_derive` takes one as `privateKey`                                      |
| Monero seed words   | `src/blockchains/monero.ts` → `deriveSeedWallet` + `src/utils/monero-seed.ts`     | 25 English words to the spend key, view key and standard address; `keys_wallet_derive` takes them as `privateKey`                       |
| Scan wallet paths   | `src/utils/hd-scan.ts` → `scanSchemes`                                            | Named schemes per chain as data; `keys_hd_wallet_scan` walks them                                                                       |
| Xpub to address     | `src/utils/extended-key.ts` → `deriveXpubWallet` on the base class                | SLIP-0132 prefixes pick the type on the Bitcoin family; normal levels only, no xprv                                                     |
| Xpub + child key    | `src/utils/bip32/parent.ts` → `recoverParent`                                     | Parent xprv from a normal child; the private prefix pairs with the xpub's                                                               |
| Curve math          | `@agntn/curves`                                                                   | `src/utils/secp256k1/index.ts` and `src/utils/curve/` only re-export it; a fix or a new operation goes there, and so do the agent tools |
| Scattered words     | `src/utils/bip39/order.ts` → `orderWords`                                         | Checksum filter over the orders of loose words; `keys_bip39_words_order` caps it                                                        |
| Mistyped words      | `src/utils/bip39/repair.ts` → `repairWords`                                       | Typo and OCR fixes for words off the list; `keys_bip39_words_repair` caps them                                                          |
| Write tests         | `test/` mirroring `src/` path                                                     | Use fixtures from `test/fixtures.ts`                                                                                                    |
| Run demos           | `playground/*.ts`                                                                 | Execute via `pnpm playground <file>`                                                                                                    |
| Docs / keyspace UI  | `docs/`                                                                           | Docus: `content/` markdown, explorer in `app/components/`                                                                               |

## CONVENTIONS

- **Crypto from @agntn first** - a primitive an `@agntn/*` package covers comes from it (every hash from `@agntn/hashes`, point math from `@agntn/curves`); signing, ed25519 and HD stay on @noble/@scure until one does. A missing primitive is an issue on the sibling package, not a new @noble dependency, and an audit is no argument for one. Never import raw crypto from Node or other libs
- **Hex and bytes** - `Uint8Array.fromHex`, `.toHex()` and `concatBytes` from `src/utils/bytes.ts` in `src/`; tests and playground use `hex` from `@agntn/encodings/hex`, because the type-aware lint types them without the `esnext` lib of `tsconfig.json`
- **Class pattern** - every blockchain exports a named concrete class and the same class as its default export
- **Abstract bases** - all chains extend `AbstractBlockchain`; Ethereum and Base extend `AbstractEVMBlockchain`
- **Lazy double-call** - `blockchains.chain(options)()` passes constructor options, then imports and constructs the class
- **Curve-split signing** - secp256k1 chains use `evmSignMessage` (Ethereum preamble + keccak256), ed25519 chains use `ed25519SignMessage` (raw, no prehash)
- **Paths per chain** - `getDerivationPath` on the base class is BIP44; Solana, Stellar, Aptos and NEAR override it with their SLIP-10 shape, every level hardened (Stellar and NEAR stop at the account, Solana at the change branch), Sui hardens the ed25519 path and walks BIP32 `m/54'/784'/account'/change/index` on secp256k1, Cardano writes CIP-1852 with a plain role and index, XRPL keeps BIP44 and refuses ed25519, Polkadot throws because Substrate wallets walk named `//hard` junctions instead, Monero throws because its wallets restore from their 25-word seed. `keys_bip44_generate` goes through it, so Cardano takes roles up to 5 where BIP44 chains stop at 1
- **Test mirrors src** - `src/blockchains/bitcoin.ts` -> `test/blockchains/bitcoin.test.ts`
- **Test imports** - test files import from `vite-plus/test`, not `vitest`
- **Shared fixtures** - test vectors live in `test/fixtures.ts`, not duplicated per test file
- **ESM only** - `"type": "module"` in package.json, `.mjs` output
- **Vite+** - `vite.config.ts` is the one config for `vp lint`, `vp fmt` and `vp test`. The `lint` and `fmt` blocks spread the shared `@agntn/ox` policy (type-aware); keep only repository-local additions (ignore patterns, the readonly-parameter allow-list) there
- **obuild** - `build.config.ts` bundles every entry at once; chain files come from reading `src/blockchains/`, the other entries are listed by hand. Keep package `exports` aligned with emitted `.mjs`/`.d.mts` files

## ANTI-PATTERNS

- **No type assertions in src/** - zero `as any`, `@ts-ignore`, `@ts-expect-error` in source code (`@ts-expect-error` exists in tests only, for intentional invalid input testing)
- **No Node crypto** - never import Node `crypto`, not even for randomness. Keys come from the curve's `utils.randomSecretKey()`
- **No syntax Node cannot strip** - `src/` runs under plain Node type stripping, so no `enum`, `namespace` or parameter properties (`erasableSyntaxOnly` enforces it), and relative imports end in `.ts`
- **No logic in index.ts** - only re-exports
- **Don't bypass the lazy registry by accident** - use `blockchains.chain(options)()` for routine public loading; direct constructors are for explicit per-chain imports and subclassing
- **Don't mix signing utils** - secp256k1 chains must use `evmSignMessage`, ed25519 chains must use `ed25519SignMessage` or chain-specific variant

## COMMANDS

```bash
pnpm install && pnpm --dir docs install  # both: test/docs-mcp.test.ts loads Zod and the toolkit from docs/
pnpm dev              # vp test in watch mode
pnpm test             # lint + types + build + test:ext + vp test with coverage + MCP eval
pnpm test:types       # tsc --noEmit --skipLibCheck, then the type tests
pnpm test:ext         # type check the Pi and OMP extensions
pnpm build            # obuild via build.config.ts
pnpm lint             # obuild, then vp lint + vp fmt --check
pnpm lint:fix         # obuild, then vp lint --fix + vp fmt
pnpm fmt              # same as lint:fix
pnpm playground <f>   # run any TS file via tsx
pnpm docs             # Docus + keyspace explorer on :3000
pnpm test:mcp         # build and exercise every MCP tool over stdio
```

`build`, `lint`, `lint:fix`, `fmt`, `test` and `test:mcp` all rewrite `dist/`, and so does packing or publishing through `prepack`. The lint scripts build first because the Pi and OMP extensions take their tool types from `dist/tools.d.mts`, and without that file the type-aware lint reads every executor call there as `error` typed. A checkout whose `dist/` serves the `keys` bin or the extensions gets a new bundle under them, so run these in a separate worktree while that server is live.

## NOTES

- **CI runs**: lint -> type check -> build -> vp test with coverage (Node 26, pnpm through `setup-vp`, which installs the root and `docs/`). Autofix workflow commits lint fixes on PRs.
- **Package exports** expose `"."`, `"./mcp"`, `"./blockchains/*"`, and the HD derivation subpaths `"./bip32"`, `"./bip39"`, `"./bip44"` and `"./slip10"`, plus `"./bip38"` for encrypted keys, `"./bip322"` for BIP322 message signatures, `"./store"` for Web3 Secret Storage keystores, `"./brainwallet"` for salted and plain brainwallet keys, `"./electrum"` for Electrum seeds, `"./secp256k1"` for SEC1 public key conversion and point and scalar math, `"./curve"` for arithmetic on a curve the caller defines, `"./script"` for multisig and script addresses, `"./descriptor"` for output descriptors, `"./transaction"` for the signatures and sighash of a transaction input and `"./wif"` for wallet import format; other utils remain internal.
- **Agent tools** - `src/tools.ts` declares each tool once with `defineTool` from `@agntn/tools`, and `createMcpServer`, `registerPiTools`, `registerOmpTools` and `runCli` in `src/cli.ts` serve the same list, validating every call against the schema before the executor runs. Schemas take `Type` from `@agntn/tools`, never a bare `typebox` import, which OMP rewrites to its omptype facade. OMP gets the JSON Schema through `pi.typebox.Type.Unsafe` and drops a blank optional string the schema refuses before the call. The executors load on the first call, so registering the tools or starting `keys mcp` loads no chain. `callSummaries` in the same file gives the Pi and OMP status lines their summary.
- **Shipped extensions** - `files` lists both extensions, and they load `dist/tools.mjs` from the package, `src/tools.ts` in a checkout. `test/public-exports.test.ts` runs a tool from each extension with only the shipped files.
- **OMP extension** - `packages/omp/extensions/keys.ts` keeps both dynamic imports of the tools literal and takes `Text` from the OMP package root. OMP does not expand globs in the manifest, so `omp.extensions` names the file. `test/omp-extension.test.ts` holds its registrations to the definitions Pi gets.
- **MCP transport** runs through `keys mcp`. Inside a checkout, a bare `keys mcp` from `dist/cli.mjs` imports `createMcpServer` from `src/mcp.ts`, like the Pi and OMP extensions, so a local server only needs a restart after a change. Everywhere else `runCli` serves it with `mcp: serverInfo`, the same tools under the same name, pitch and icons. The npm package has no `src` and runs the bundle. A copy under `node_modules` keeps the bundle too, because Node does not strip types there. The source needs production dependencies only. `KEYS_DIST=1` forces the bundle in a checkout, as `test/cli.test.ts` and `test/eval-mcp.mjs` do. Changes to `src/cli.ts` itself still need `pnpm build`. stdout is reserved for JSON-RPC, and `createMcpServer()` remains importable for hosts with their own transport. `toolListings` and `callTool()` from the same module feed the remote server at `keys.agntn.dev/mcp` (see `docs/AGENTS.md`). Both servers introduce themselves with `serverInfo` from `src/server-info.ts`: name, version, a one-line pitch and the site's icons, so a connector card shows more than a name (#263). That takes `@agntn/tools` 0.2.2: 0.2.0 dropped the pitch and icons on the stdio side, and `runCli` only learned to pass them in agntn/tools#66.
- **utils/ has mixed structure** - plain `.ts` files (address, encoding, crypto-hash, ed25519, ed25519-chains, evm, signing) and subdirectories with `index.ts` (bip32/, bip38/, bip322/, bip39/, bip44/, curve/, descriptor/, electrum/, script/, secp256k1/, slip10/, store/, transaction/, wif/).
- **`__cardano/notes.md`** - research notes for Cardano implementation, not code. The actual implementation is `cardano.ts`.
- **Shared secp256k1 fixture** - `secp256k1TestVectors.publicKeyCompressed` is the key of `privateKey`, shared by the signing round trips and the address tests. The Bitcoin address generators decode the SEC1 point before hashing, so an invented key fails them.
- **Not audited** - the README and the first guide page open with a `Not audited` caution. It names no dependency, so it stays true when @noble/@scure give way to `@agntn/*`.
- **`createVersionedHash` is deprecated** in `address.ts` - use `addSchemeByte` instead.
