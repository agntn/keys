# BLOCKCHAINS

## OVERVIEW

Lazy-loaded class modules. Each file exports a named concrete class and the same class as its default export.

## CHAIN FAMILIES

| Family               | Chains                           | Signing                                                                    | Key Derivation                      |
| -------------------- | -------------------------------- | -------------------------------------------------------------------------- | ----------------------------------- |
| **EVM**              | ethereum, base                   | `evmSignMessage` (preamble + keccak256)                                    | secp256k1 via `utils/secp256k1`     |
| **Bitcoin family**   | bitcoin, litecoin, bitcoingold   | chain-specific message preamble                                            | secp256k1 via `utils/secp256k1`     |
| **CashAddr**         | bitcoincash, ecash               | Bitcoin's digest; Bitcoin Cash keeps Bitcoin's preamble, eCash has its own | secp256k1 via `utils/secp256k1`     |
| **P2PKH only**       | bitcoinsv, dash, dogecoin, zcash | Bitcoin's digest; Dash, Dogecoin and Zcash own preambles                   | secp256k1 via `utils/secp256k1`     |
| **secp256k1 custom** | tron                             | `hashWithPreamble` (TIP-191 preamble + keccak256)                          | secp256k1 via `utils/secp256k1`     |
| **ed25519**          | solana, aptos, cardano           | `ed25519SignMessage` (raw, no prehash)                                     | ed25519 via `utils/ed25519`         |
| **ed25519 custom**   | stellar                          | SEP-53 digest (prefix + SHA-256), signed raw                               | ed25519 via `utils/ed25519`         |
| **dual-curve**       | sui                              | `PersonalMessage` digest on either curve (scheme)                          | ed25519 default, secp256k1 optional |

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
- **CashAddr P2PKH** - `AbstractCashAddrBlockchain` in `utils/bitcoin.ts` sits on the keys and signing half of the Bitcoin base and writes P2PKH as CashAddr through `utils/cashaddr.ts`. It owns the mainnet and testnet check, `legacy` only `getAddress` and a validation that refuses base58. A subclass passes its label and a `CASHADDR_PARAMS` table: the prefix of each network and the hash lengths its node pays to, by type
- **Bitcoin Cash** - `BitcoinCash` extends the CashAddr base under `bitcoincash` and `bchtest`. Validation follows Bitcoin Cash Node, CashTokens types and 32 byte script hashes included
- **eCash** - `ECash` extends the CashAddr base under `ecash` and `ectest` with Bitcoin ABC's `eCash` preamble. Validation follows Bitcoin ABC, which pays to 20 byte hashes under types 0 and 1 only, so the CashTokens types are refused. `bip44` is SLIP-0044's 899; Cashtab's 1899 and the older 145 paths go through `deriveHDWallet` as given
- **Bitcoin Gold** - `BitcoinGold` extends `AbstractBitcoinBlockchain` with its own preamble, `G`/`A` version bytes and `btg` bech32. Its Taproot deployment timed out before any release could signal it, so `getAddress` refuses `taproot` and validation refuses witness v1 and later, which would be spendable by anyone there
- **Base58 P2PKH** - `AbstractBitcoinP2PKHBlockchain` in `utils/bitcoin.ts` sits on the same half and owns the mainnet and testnet check, `legacy` only `getAddress` and base58 validation. A subclass passes its label for error messages and a `NETWORK_PARAMS` table of one byte versions; a network without `bytesVersionP2SH` refuses P2SH
- **Bitcoin SV** - `BitcoinSV` extends the base58 P2PKH base and writes Bitcoin's base58 P2PKH. `legacy` is its only address type; validation refuses P2SH, which the node rejects as an output since Genesis (`bad-txns-vout-p2sh`)
- **Dogecoin** - `Dogecoin` extends the base58 P2PKH base with its own preamble and `D`/`9`/`A` version bytes. `legacy` is its only address type, because the chain has no SegWit and the shared `p2sh` type wraps P2WPKH, which anyone could spend there; validation still accepts P2SH, the multisig destination
- **Dash** - `Dash` extends the base58 P2PKH base with the `DarkCoin` preamble and `X`/`7` version bytes. Like Dogecoin it writes `legacy` only, because it has no SegWit, and validation accepts P2SH
- **Zcash** - `Zcash` extends the same half with the `Zcash` preamble and writes transparent `t1` P2PKH only. Its version bytes are two bytes wide, so it builds and checks base58 itself instead of the one byte helpers in `utils/address.ts`. Validation also accepts P2SH (`t3`) and ZIP-320 TEX (`tex1`, bech32m over the P2PKH hash); Sapling and unified addresses are shielded and return false
- **EVM base class** - `Ethereum` and `Base` extend `AbstractEVMBlockchain`, which owns their shared key, address, validation, and signing behavior
- **Network params** - Bitcoin Cash and eCash keep their CashAddr prefixes in `CASHADDR_PARAMS`; Bitcoin, Litecoin, Bitcoin Gold, Bitcoin SV, Dash, Dogecoin, Zcash, and Cardano keep separate address parameters for each network in `NETWORK_PARAMS`; TRON uses `0x41` and `T` on mainnet, Shasta, and Nile
- **BIP44 coin type** - every chain sets `bip44` from `BIP44` enum or SLIP-0044 number
- **SUI dual-curve** - `getKeyPublic` and `signMessage` check `options.scheme` to pick ed25519 or secp256k1; both sign the `signPersonalMessage` digest, secp256k1 over its sha256 like the SDK
- **HD wallets** - `deriveHDWallet` on the base class walks BIP32 or SLIP-10 by curve; Bitcoin, Litecoin and Bitcoin Gold infer the address type from the path purpose, Sui takes the curve from the scheme, Cardano throws because CIP-1852 derives differently
- **Derivation paths** - `getDerivationPath` is BIP44 on the base class; Solana, Stellar and Aptos override it with the hardened SLIP-10 shape their wallets use, cut at each chain's depth; Sui hardens only the ed25519 path and walks BIP32 `m/54'/784'/account'/change/index` on secp256k1; Cardano writes CIP-1852, `m/1852'/1815'/account'/role/index` with the role and index plain

## COMPLEXITY

- **Bitcoin Cash and eCash** - CashAddr polymod over a 40-bit residue on BigInt, prefix optional on input
- **Bitcoin** - five address formats (legacy, p2sh, segwit, p2wsh, taproot) plus testnet variants
- **Cardano** - custom address encoding with three address types and centralized network parameters
- **SUI** - dual-curve support with scheme-based dispatch
- **TRON** - custom Keccak and Base58Check encoding
- **Solana and Aptos** - straightforward single-curve subclasses
- **Stellar** - StrKey base32 with a CRC16-XModem checksum; `M` and `C` StrKeys validate, only `G` is produced
- **Ethereum and Base** - minimal `AbstractEVMBlockchain` subclasses
