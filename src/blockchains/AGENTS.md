# BLOCKCHAINS

## OVERVIEW

Lazy-loaded class modules. Each file exports a named concrete class and the same class as its default export.

## CHAIN FAMILIES

| Family               | Chains                 | Signing                                           | Key Derivation                      |
| -------------------- | ---------------------- | ------------------------------------------------- | ----------------------------------- |
| **EVM**              | ethereum, base         | `evmSignMessage` (preamble + keccak256)           | secp256k1 via `utils/secp256k1`     |
| **Bitcoin family**   | bitcoin, litecoin      | chain-specific message preamble                   | secp256k1 via `utils/secp256k1`     |
| **secp256k1 custom** | tron                   | `evmSignMessage` (same signing, custom addresses) | secp256k1 via `utils/secp256k1`     |
| **ed25519**          | solana, aptos, cardano | `ed25519SignMessage` (raw, no prehash)            | ed25519 via `utils/ed25519`         |
| **dual-curve**       | sui                    | both (selected via `options.scheme`)              | ed25519 default, secp256k1 optional |

## ADDING A NEW CHAIN

1. Create `src/blockchains/<name>.ts` with `class Name extends AbstractBlockchain`
2. Implement `name`, `curve`, `bip44`, `getKeyPublic`, `getAddress`, `validateAddress`, `signMessage`, and `verifyMessage`
3. Export the class by name and as the default export
4. Register it in `src/_blockchains.ts`: `<name>: lazy(() => import("./blockchains/<name>.ts"))`
5. Create `test/blockchains/<name>.test.ts` using fixtures from `test/fixtures.ts`
6. For EVM chains, extend `AbstractEVMBlockchain` and provide only `name` and `bip44`

## PATTERNS

- **Bitcoin base class** - `AbstractBitcoinBlockchain` in `utils/bitcoin.ts` shares address generation and HD purpose inference. Litecoin signs its Core digest with noble prehash disabled and accepts both P2SH prefix generations.
- **EVM base class** - `Ethereum` and `Base` extend `AbstractEVMBlockchain`, which owns their shared key, address, validation, and signing behavior
- **Network params** - Bitcoin, Litecoin, and Cardano keep separate address parameters for each network in `NETWORK_PARAMS`; TRON uses `0x41` and `T` on mainnet, Shasta, and Nile
- **BIP44 coin type** - every chain sets `bip44` from `BIP44` enum or SLIP-0044 number
- **SUI dual-curve** - `getKeyPublic` and `signMessage` check `options.scheme` to pick ed25519 or secp256k1
- **HD wallets** - `deriveHDWallet` on the base class walks BIP32 or SLIP-10 by curve; Bitcoin and Litecoin infer the address type from the path purpose, Sui takes the curve from the scheme, Cardano throws because CIP-1852 derives differently

## COMPLEXITY

- **Bitcoin** - five address formats (legacy, p2sh, segwit, p2wsh, taproot) plus testnet variants
- **Cardano** - custom address encoding with three address types and centralized network parameters
- **SUI** - dual-curve support with scheme-based dispatch
- **TRON** - custom Keccak and Base58Check encoding
- **Solana and Aptos** - straightforward single-curve subclasses
- **Ethereum and Base** - minimal `AbstractEVMBlockchain` subclasses
