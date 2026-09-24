# BLOCKCHAINS

## OVERVIEW

Lazy-loaded class modules. Each file exports a named concrete class and the same class as its default export.

## CHAIN FAMILIES

| Family               | Chains                         | Signing                                           | Key Derivation                      |
| -------------------- | ------------------------------ | ------------------------------------------------- | ----------------------------------- |
| **EVM**              | ethereum, base                 | `evmSignMessage` (preamble + keccak256)           | secp256k1 via `utils/secp256k1`     |
| **Bitcoin family**   | bitcoin, litecoin, bitcoingold | chain-specific message preamble                   | secp256k1 via `utils/secp256k1`     |
| **CashAddr**         | bitcoincash                    | Bitcoin's preamble, same digest and signature     | secp256k1 via `utils/secp256k1`     |
| **P2PKH only**       | bitcoinsv, dash, dogecoin      | Bitcoin's digest; Dash and Dogecoin own preambles | secp256k1 via `utils/secp256k1`     |
| **secp256k1 custom** | tron                           | `hashWithPreamble` (TIP-191 preamble + keccak256) | secp256k1 via `utils/secp256k1`     |
| **ed25519**          | solana, aptos, cardano         | `ed25519SignMessage` (raw, no prehash)            | ed25519 via `utils/ed25519`         |
| **ed25519 custom**   | stellar                        | SEP-53 digest (prefix + SHA-256), signed raw      | ed25519 via `utils/ed25519`         |
| **dual-curve**       | sui                            | `PersonalMessage` digest on either curve (scheme) | ed25519 default, secp256k1 optional |

Decred uses `AbstractBlockchain` directly: ECDSA P2PKH with BLAKE-256, not Bitcoin address hashing or EVM signing. Its HD method throws because standard BIP32 does not preserve Decred's legacy derivation.

## ADDING A NEW CHAIN

1. Create `src/blockchains/<name>.ts` with `class Name extends AbstractBlockchain`
2. Implement `name`, `curve`, `bip44`, `getKeyPublic`, `getAddress`, `validateAddress`, `signMessage`, and `verifyMessage`
3. Export the class by name and as the default export
4. Register it in `src/_blockchains.ts`: `<name>: lazy("<name>", () => import("./blockchains/<name>.ts"))`
5. Create `test/blockchains/<name>.test.ts` using fixtures from `test/fixtures.ts`
6. For EVM chains, extend `AbstractEVMBlockchain` and provide only `name` and `bip44`

## PATTERNS

- **Bitcoin base class** - `AbstractBitcoinBlockchain` in `utils/bitcoin.ts` shares address generation and HD purpose inference on top of the keys and Core message signing in `AbstractBitcoinMessageBlockchain`. Litecoin keeps only its network table, its preamble and a validation that accepts both P2SH prefix generations.
- **Bitcoin Cash** - `BitcoinCash` extends `AbstractBitcoinMessageBlockchain`, the keys and signing half of the Bitcoin base, and writes P2PKH as CashAddr through `utils/cashaddr.ts`. `legacy` is its only address type; validation follows Bitcoin Cash Node and refuses base58
- **Bitcoin Gold** - `BitcoinGold` extends `AbstractBitcoinBlockchain` with its own preamble, `G`/`A` version bytes and `btg` bech32. Its Taproot deployment timed out before any release could signal it, so `getAddress` refuses `taproot` and validation refuses witness v1 and later, which would be spendable by anyone there
- **Bitcoin SV** - `BitcoinSV` extends the same half and writes Bitcoin's base58 P2PKH. `legacy` is its only address type; validation refuses P2SH, which the node rejects as an output since Genesis (`bad-txns-vout-p2sh`)
- **Dogecoin** - `Dogecoin` extends the same half with its own preamble and `D`/`9`/`A` version bytes. `legacy` is its only address type, because the chain has no SegWit and the shared `p2sh` type wraps P2WPKH, which anyone could spend there; validation still accepts P2SH, the multisig destination
- **Dash** - `Dash` extends the same half with the `DarkCoin` preamble and `X`/`7` version bytes. Like Dogecoin it writes `legacy` only, because it has no SegWit, and validation accepts P2SH
- **EVM base class** - `Ethereum` and `Base` extend `AbstractEVMBlockchain`, which owns their shared key, address, validation, and signing behavior
- **Network params** - Bitcoin Cash keeps its CashAddr prefixes in `NETWORK_PREFIXES`, Bitcoin SV its P2PKH version bytes in `NETWORK_VERSIONS`; Bitcoin, Litecoin, Bitcoin Gold, Dash, Dogecoin, and Cardano keep separate address parameters for each network in `NETWORK_PARAMS`; TRON uses `0x41` and `T` on mainnet, Shasta, and Nile
- **BIP44 coin type** - every chain sets `bip44` from `BIP44` enum or SLIP-0044 number
- **SUI dual-curve** - `getKeyPublic` and `signMessage` check `options.scheme` to pick ed25519 or secp256k1; both sign the `signPersonalMessage` digest, secp256k1 over its sha256 like the SDK
- **HD wallets** - `deriveHDWallet` on the base class walks BIP32 or SLIP-10 by curve; Bitcoin, Litecoin and Bitcoin Gold infer the address type from the path purpose, Sui takes the curve from the scheme, Cardano throws because CIP-1852 derives differently
- **Derivation paths** - `getDerivationPath` is BIP44 on the base class; Solana, Stellar and Aptos override it with the hardened SLIP-10 shape their wallets use, cut at each chain's depth; Sui hardens only the ed25519 path and walks BIP32 `m/54'/784'/account'/change/index` on secp256k1; Cardano writes CIP-1852, `m/1852'/1815'/account'/role/index` with the role and index plain

## COMPLEXITY

- **Bitcoin Cash** - CashAddr polymod over a 40-bit residue on BigInt, prefix optional on input
- **Bitcoin** - five address formats (legacy, p2sh, segwit, p2wsh, taproot) plus testnet variants
- **Cardano** - custom address encoding with three address types and centralized network parameters
- **SUI** - dual-curve support with scheme-based dispatch
- **TRON** - custom Keccak and Base58Check encoding
- **Solana and Aptos** - straightforward single-curve subclasses
- **Stellar** - StrKey base32 with a CRC16-XModem checksum; `M` and `C` StrKeys validate, only `G` is produced
- **Ethereum and Base** - minimal `AbstractEVMBlockchain` subclasses
