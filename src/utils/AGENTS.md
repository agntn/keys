# UTILS

## OVERVIEW

Shared cryptographic primitives and encoding utilities. BIP32, BIP38, BIP39, BIP44, brainwallet, Electrum, secp256k1, SLIP-10, store and WIF are public package subpaths; other utilities are internal. Every hash comes from `@agntn/hashes`, hex goes through the native `Uint8Array.fromHex` and `toHex`.

## STRUCTURE

**Plain files** (imported directly by blockchains):

| File                 | Lines | Used By                                                                              | Purpose                                                                                                                                  |
| -------------------- | ----- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `address.ts`         | 324   | bitcoin, sui, aptos, tron, zcash                                                     | hash160, legacy/P2SH/SegWit address gen + validation, hex address validation                                                             |
| `bitcoin.ts`         |       | bitcoin, litecoin, bitcoingold, bitcoincash, ecash, bitcoinsv, dash, dogecoin, zcash | Keys and message serialization for all nine; base58 P2PKH for three, CashAddr for two, full addresses and HD purpose inference for three |
| `cashaddr.ts`        |       | bitcoin.ts, for bitcoincash and ecash                                                | CashAddr encode and decode with the version byte rules Bitcoin Cash Node and Bitcoin ABC share                                           |
| `evm.ts`             | ~220  | EVM classes and secp256k1 chains                                                     | EVM address generation, EIP-55 checksum, preamble signing, `AbstractEVMBlockchain`                                                       |
| `evm-address.ts`     | ~70   | evm.ts, store/                                                                       | EVM address from a public key, EIP-55 checksum and validation, without the chain classes                                                 |
| `signing.ts`         | ~100  | evm.ts, ed25519-chains.ts, tron                                                      | Generic sign/verify dispatching by curve type; `recoverSecp256k1Signer` reads the key behind r, s and v                                  |
| `eip712.ts`          | ~350  | index.ts, tool-operations.ts                                                         | `hashTypedData`: the `eth_signTypedData_v4` digest, `EIP712Domain` inferred from the domain when `types` leaves it out                   |
| `ed25519-chains.ts`  | ~50   | solana, aptos, cardano                                                               | Shared raw Ed25519 signing and verification                                                                                              |
| `ed25519.ts`         | ~50   | the ed25519 chains and sui                                                           | Ed25519 public key generation                                                                                                            |
| `encoding.ts`        | ~60   | address.ts, tron, zcash                                                              | Base58Check encode/decode/validate                                                                                                       |
| `crypto-hash.ts`     | ~70   | (internal)                                                                           | Hash function wrappers                                                                                                                   |
| `bytes.ts`           | ~15   | signing, wif, decred, stellar, sui, zcash                                            | `concatBytes`, the one byte helper without a native equivalent                                                                           |
| `hd.ts`              | ~100  | blockchain.ts, tool-operations.ts                                                    | Mnemonic to private key at a path: BIP32 for secp256k1, SLIP-10 for ed25519; names the BIP39 check a rejected phrase fails               |
| `hd-scan.ts`         |       | tool-operations.ts                                                                   | Named wallet path schemes per chain and the walk over them, each parent node derived once                                                |
| `entropy-profile.ts` |       | tool-operations.ts                                                                   | BIP39 entropy read as text, a byte pattern and an MD5, SHA-1 or SHA-256 of a known or given text                                         |
| `extended-key.ts`    | ~130  | blockchain.ts, bitcoin.ts, litecoin, bip32/parent.ts                                 | SLIP-0132 prefixes; an xpub down normal levels to a child public key, refusing xprv and hardened levels                                  |

**Subdirectories** (each has `index.ts`):

| Dir            | Purpose                       | Exports                                                                                                                                       |
| -------------- | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `bip32/`       | HD key derivation (secp256k1) | `getMasterKeyFromSeed`, `deriveHDKey`, `HARDENED_OFFSET`; `recoverParent` takes an xpub and a normal child key back to the parent xprv        |
| `bip38/`       | Encrypted keys                | `inspect` reads the header without the passphrase; `decrypt` opens both modes, `BIP38PassphraseError` when the address hash misses            |
| `bip39/`       | Mnemonic phrases              | `generateMnemonic`, `mnemonicToSeed`, `validateMnemonic`, `getMnemonicWordCandidates`, `lookupWords`, `lookupIndices`                         |
| `bip44/`       | Derivation paths              | `BIP44` coin types, `BIP44Change`, `getPath`, `parse`; `getBIP32Path` and `getHardenedPath` for the chain shapes stay internal in `paths.ts`  |
| `brainwallet/` | Brainwallet keys              | `derive`: scrypt or PBKDF2, then SHA-256 of the output bytes or their hex; plain SHA-256 or keccak256; WarpWallet                             |
| `electrum/`    | Electrum seeds                | `inspect` names the version, `deriveSeed` seeds standard and SegWit, `deriveOld*` walk an old one; the normalizer and word list stay internal |
| `secp256k1/`   | SEC1 public keys              | `convertPublicKey` between compressed and uncompressed; key generation, signing, Core's base64 signatures and key errors stay internal        |
| `slip10/`      | ED25519 HD derivation         | `getMasterKeyFromSeed`, `deriveHDKey`                                                                                                         |
| `store/`       | Keystore files                | `decrypt`, `encrypt` and `inspect` for Web3 Secret Storage v3 keystores; `KeystorePasswordError` for a wrong password                         |
| `wif/`         | Wallet import format          | `encode` and `decode` for Bitcoin, Litecoin, Dash, Decred and Dogecoin, checked against an explicit chain and network                         |

## DEPENDENCY FLOW

```
blockchains/*.ts
  ├── secp256k1 chains → secp256k1/keys.ts + secp256k1/decode.ts + evm.ts (signing) + address.ts
  └── ed25519 chains   → ed25519.ts + ed25519-chains.ts (signing)

evm.ts
  ├── secp256k1/keys.ts (key gen)
  ├── signing.ts (generic sign dispatch)
  └── @noble/curves (secp256k1 Point), @agntn/hashes (keccak256)

signing.ts
  └── @noble/curves (secp256k1.sign, ed25519.sign)

address.ts
  ├── encoding.ts (base58check)
  └── @agntn/hashes (sha256, ripemd160), @agntn/encodings (segwit)

bip44/ → bip32/ (imports HARDENED_OFFSET, formatIndex)
```

## HOTSPOTS

- **`address.ts`** (324 lines) - most complex file. Handles legacy P2PKH, P2SH, SegWit v0 (bech32), SegWit v1/Taproot (bech32m), P2WSH, and hex address validation. Touch carefully.
- **`evm.ts`** (~220 lines) - EVM address generation, EIP-55 checksum, preamble signing, and the `AbstractEVMBlockchain` base used by Ethereum and Base.
- **`createVersionedHash`** in address.ts is **deprecated** - use `addSchemeByte` instead.
