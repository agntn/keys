# UTILS

## OVERVIEW

Shared cryptographic primitives and encoding utilities. BIP32, BIP39, and SLIP-10 are public package subpaths; other utilities are internal.

## STRUCTURE

**Plain files** (imported directly by blockchains):

| File                | Lines | Used By                          | Purpose                                                                            |
| ------------------- | ----- | -------------------------------- | ---------------------------------------------------------------------------------- |
| `address.ts`        | 312   | bitcoin, sui, aptos, tron        | hash160, legacy/P2SH/SegWit address gen + validation, hex address validation       |
| `evm.ts`            | ~220  | EVM classes and secp256k1 chains | EVM address generation, EIP-55 checksum, preamble signing, `AbstractEVMBlockchain` |
| `signing.ts`        | ~100  | evm.ts, ed25519-chains.ts        | Generic sign/verify dispatching by curve type                                      |
| `ed25519-chains.ts` | ~50   | solana, aptos, cardano, sui      | Shared raw Ed25519 signing and verification                                        |
| `secp256k1.ts`      | ~100  | bitcoin, tron, sui, evm.ts       | Public key generation (compressed/uncompressed)                                    |
| `ed25519.ts`        | ~50   | solana, aptos, cardano, sui      | Ed25519 public key generation                                                      |
| `encoding.ts`       | ~60   | address.ts, tron                 | Base58Check encode/decode/validate                                                 |
| `crypto-hash.ts`    | ~70   | (internal)                       | Hash function wrappers                                                             |

**Subdirectories** (each has `index.ts`):

| Dir       | Purpose                       | Exports                                                                               |
| --------- | ----------------------------- | ------------------------------------------------------------------------------------- |
| `bip32/`  | HD key derivation (secp256k1) | `getMasterKeyFromSeed`, `deriveHDKey`, `HARDENED_OFFSET`                              |
| `bip39/`  | Mnemonic phrases              | `generateMnemonic`, `mnemonicToSeed`, `validateMnemonic`, `getMnemonicWordCandidates` |
| `bip44/`  | Derivation paths              | `BIP44` enum, `getBIP44Path`, `parseBIP44Path`, `getBlockchainPath`                   |
| `slip10/` | ED25519 HD derivation         | `getMasterKeyFromSeed`, `deriveHDKey`                                                 |

## DEPENDENCY FLOW

```
blockchains/*.ts
  ├── secp256k1 chains → secp256k1.ts + evm.ts (signing) + address.ts
  └── ed25519 chains   → ed25519.ts + ed25519-chains.ts (signing)

evm.ts
  ├── secp256k1.ts (key gen)
  ├── signing.ts (generic sign dispatch)
  └── @noble/curves, @noble/hashes (keccak, secp256k1 Point)

signing.ts
  └── @noble/curves (secp256k1.sign, ed25519.sign)

address.ts
  ├── encoding.ts (base58check)
  └── @noble/hashes (sha256, ripemd160), @scure/base (bech32, bech32m)

bip44/ → bip32/ (imports HARDENED_OFFSET, formatIndex)
```

## HOTSPOTS

- **`address.ts`** (312 lines) - most complex file. Handles legacy P2PKH, P2SH, SegWit v0 (bech32), SegWit v1/Taproot (bech32m), P2WSH, and hex address validation. Touch carefully.
- **`evm.ts`** (~220 lines) - EVM address generation, EIP-55 checksum, preamble signing, and the `AbstractEVMBlockchain` base used by Ethereum and Base.
- **`createVersionedHash`** in address.ts is **deprecated** - use `addSchemeByte` instead.
