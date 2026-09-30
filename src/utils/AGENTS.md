# UTILS

## OVERVIEW

Shared cryptographic primitives and encoding utilities. BIP32, BIP38, BIP39, BIP44, Electrum, secp256k1, SLIP-10 and WIF are public package subpaths; other utilities are internal. Every hash comes from `@agntn/hashes`, hex goes through the native `Uint8Array.fromHex` and `toHex`.

## STRUCTURE

**Plain files** (imported directly by blockchains):

| File                | Lines | Used By                                                                              | Purpose                                                                                                                                  |
| ------------------- | ----- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `address.ts`        | 312   | bitcoin, sui, aptos, tron, zcash                                                     | hash160, legacy/P2SH/SegWit address gen + validation, hex address validation                                                             |
| `bitcoin.ts`        |       | bitcoin, litecoin, bitcoingold, bitcoincash, ecash, bitcoinsv, dash, dogecoin, zcash | Keys and message serialization for all nine; base58 P2PKH for three, CashAddr for two, full addresses and HD purpose inference for three |
| `cashaddr.ts`       |       | bitcoin.ts, for bitcoincash and ecash                                                | CashAddr encode and decode with the version byte rules Bitcoin Cash Node and Bitcoin ABC share                                           |
| `evm.ts`            | ~220  | EVM classes and secp256k1 chains                                                     | EVM address generation, EIP-55 checksum, preamble signing, `AbstractEVMBlockchain`                                                       |
| `signing.ts`        | ~100  | evm.ts, ed25519-chains.ts                                                            | Generic sign/verify dispatching by curve type                                                                                            |
| `ed25519-chains.ts` | ~50   | solana, aptos, cardano                                                               | Shared raw Ed25519 signing and verification                                                                                              |
| `ed25519.ts`        | ~50   | the ed25519 chains and sui                                                           | Ed25519 public key generation                                                                                                            |
| `encoding.ts`       | ~60   | address.ts, tron, zcash                                                              | Base58Check encode/decode/validate                                                                                                       |
| `crypto-hash.ts`    | ~70   | (internal)                                                                           | Hash function wrappers                                                                                                                   |
| `bytes.ts`          | ~15   | signing, wif, decred, stellar, sui, zcash                                            | `concatBytes`, the one byte helper without a native equivalent                                                                           |
| `hd.ts`             | ~100  | blockchain.ts, tool-operations.ts                                                    | Mnemonic to private key at a path: BIP32 for secp256k1, SLIP-10 for ed25519; names the BIP39 check a rejected phrase fails               |
| `extended-key.ts`   | ~110  | blockchain.ts, bitcoin.ts, litecoin                                                  | SLIP-0132 prefixes; an xpub down normal levels to a child public key, refusing xprv and hardened levels                                  |

**Subdirectories** (each has `index.ts`):

| Dir          | Purpose                       | Exports                                                                                                                                       |
| ------------ | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `bip32/`     | HD key derivation (secp256k1) | `getMasterKeyFromSeed`, `deriveHDKey`, `HARDENED_OFFSET`                                                                                      |
| `bip38/`     | Encrypted key headers         | `inspect`: mode, flags, address hash, owner entropy, lot and sequence without the passphrase; no decryption                                   |
| `bip39/`     | Mnemonic phrases              | `generateMnemonic`, `mnemonicToSeed`, `validateMnemonic`, `getMnemonicWordCandidates`, `lookupWords`, `lookupIndices`                         |
| `bip44/`     | Derivation paths              | `BIP44` coin types, `BIP44Change`, `getPath`, `parse`; `getBIP32Path` and `getHardenedPath` for the chain shapes stay internal in `paths.ts`  |
| `electrum/`  | Electrum seeds                | `inspect` names the seed version, `deriveSeed` gives the seed of a standard or SegWit phrase; normalization and the legacy list stay internal |
| `secp256k1/` | SEC1 public keys              | `convertPublicKey` between compressed and uncompressed; key generation and signing for the secp256k1 chains stay internal in `keys.ts`        |
| `slip10/`    | ED25519 HD derivation         | `getMasterKeyFromSeed`, `deriveHDKey`                                                                                                         |
| `wif/`       | Wallet import format          | `encode` and `decode` for Bitcoin, Litecoin, Dash, Decred and Dogecoin, checked against an explicit chain and network                         |

## DEPENDENCY FLOW

```
blockchains/*.ts
  ├── secp256k1 chains → secp256k1/keys.ts + evm.ts (signing) + address.ts
  └── ed25519 chains   → ed25519.ts + ed25519-chains.ts (signing)

evm.ts
  ├── secp256k1/keys.ts (key gen)
  ├── signing.ts (generic sign dispatch)
  └── @noble/curves (secp256k1 Point), @agntn/hashes (keccak256)

signing.ts
  └── @noble/curves (secp256k1.sign, ed25519.sign)

address.ts
  ├── encoding.ts (base58check)
  └── @agntn/hashes (sha256, ripemd160), @scure/base (bech32, bech32m)

bip44/ → bip32/ (imports HARDENED_OFFSET, formatIndex)
```

## HOTSPOTS

- **`address.ts`** (312 lines) - most complex file. Handles legacy P2PKH, P2SH, SegWit v0 (bech32), SegWit v1/Taproot (bech32m), P2WSH, and hex address validation. Touch carefully.
- **`evm.ts`** (~220 lines) - EVM address generation, EIP-55 checksum, preamble signing, and the `AbstractEVMBlockchain` base used by Ethereum and Base.
- **`createVersionedHash`** in address.ts is **deprecated** - use `addSchemeByte` instead.
