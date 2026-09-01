# @agntn/keys

[![npm version](https://img.shields.io/npm/v/%40agntn%2Fkeys?style=flat&colorA=130f40&colorB=474787)](https://npmjs.com/package/@agntn/keys)
[![npm downloads](https://img.shields.io/npm/dm/%40agntn%2Fkeys?style=flat&colorA=130f40&colorB=474787)](https://npm.chart.dev/@agntn/keys)
[![license](https://img.shields.io/github/license/agntn/keys?style=flat&colorA=130f40&colorB=474787)](https://github.com/agntn/keys/blob/main/LICENSE.md)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/agntn/keys)

Typed key generation, address derivation, and message signing across eight blockchains and two curves.

> [!WARNING]
> **@agntn/keys is experimental.** The package name, public API, provider model, and tool surfaces may change before the first stable release. Pin exact versions if you build on it now.

## Features

- 🔑 **Key generation** - cryptographically secure private keys via Web Crypto API
- 📫 **Address generation** - all major formats per chain (legacy, segwit, taproot, base58, hex)
- ✅ **Address validation** - verify validity and checksums for every supported format
- 💼 **Wallet construction** - generate a new wallet or derive one from an existing private key
- ✍️ **Message signing** - sign and verify with secp256k1 or ed25519
- 🛤️ **BIP44 paths** - derivation path utilities for all supported chains
- 🔌 **Lazy loading** - blockchain implementations load on demand for smaller bundles
- 📐 **Fully typed** - TypeScript definitions for every interface

## Install

```bash
pnpm add @agntn/keys
```

## Usage

Concrete blockchain classes are lazy-loaded. The double-call pattern `blockchains.chain(options)()` first passes config, then imports and constructs the class.

### Generate a wallet

```ts
import { useBlockchain, blockchains } from "@agntn/keys";

const ethereum = await blockchains.ethereum()();
const chain = useBlockchain(ethereum);

const wallet = chain.generateWallet();
console.log(wallet.keys.private); // hex private key
console.log(wallet.keys.public); // hex public key
console.log(wallet.address); // 0x... checksum address
```

### Bitcoin address types

```ts
import { useBlockchain, blockchains } from "@agntn/keys";

const btc = useBlockchain(await blockchains.bitcoin()());

const privateKey = btc.generateKeyPrivate();
const publicKey = btc.getKeyPublic(privateKey);

btc.getAddress(publicKey); // legacy (1...)
btc.getAddress(publicKey, "segwit"); // native segwit (bc1q...)
btc.getAddress(publicKey, "taproot"); // taproot (bc1p...)
btc.getAddress(publicKey, "p2sh"); // pay-to-script-hash (3...)
btc.getAddress(publicKey, "p2wsh"); // witness script hash

// testnet
const testnet = useBlockchain(await blockchains.bitcoin({ network: "testnet" })());
testnet.getAddress(publicKey, "segwit"); // tb1q...
```

### Sign and verify messages

```ts
import { useBlockchain, blockchains } from "@agntn/keys";

const chain = useBlockchain(await blockchains.solana()());

const { keys } = chain.generateKeys();
const signature = chain.signMessage("hello", keys.private);
const valid = chain.verifyMessage("hello", signature, keys.public); // true
```

### EVM chains share addresses

```ts
import { useBlockchain, blockchains } from "@agntn/keys";

const eth = useBlockchain(await blockchains.ethereum()());
const base = useBlockchain(await blockchains.base()());

const privateKey = eth.generateKeyPrivate();
const pubKey = eth.getKeyPublic(privateKey);

eth.getAddress(pubKey) === base.getAddress(pubKey); // true
```

### Derive HD keys

```ts
import { mnemonicToSeed } from "@agntn/keys/bip39";
import { getMasterKeyFromSeed, deriveHDKey } from "@agntn/keys/bip32";

const seed = mnemonicToSeed(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const master = getMasterKeyFromSeed(seed);
const account = deriveHDKey(master, "m/84'/0'/0'/0/0");
```

Use `@agntn/keys/slip10` instead of `@agntn/keys/bip32` for ed25519 derivation.

## Supported Blockchains

| Chain        | Curve              | Address Formats                      | Testnet |
| ------------ | ------------------ | ------------------------------------ | ------- |
| **Bitcoin**  | secp256k1          | legacy, p2sh, segwit, p2wsh, taproot | ✅      |
| **Ethereum** | secp256k1          | EIP-55 checksum                      | -       |
| **Base**     | secp256k1          | EVM-compatible                       | -       |
| **Solana**   | ed25519            | base58                               | -       |
| **Aptos**    | ed25519            | 0x-prefixed hex                      | -       |
| **Cardano**  | ed25519            | payment, stake, enterprise           | ✅      |
| **SUI**      | ed25519, secp256k1 | 0x-prefixed hex (blake2b)            | -       |
| **TRON**     | secp256k1          | base58check                          | ✅      |

All chains support key generation, address derivation, address validation, and message signing.

## Security

Built on audited cryptographic packages from [@paulmillr](https://github.com/paulmillr):

- [@noble/curves](https://github.com/paulmillr/noble-curves) - elliptic curve implementations (secp256k1, ed25519)
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) - SHA-256, Keccak, BLAKE2b, SHA3
- [@scure/base](https://github.com/paulmillr/scure-base) - base58, bech32, hex encoding
- [@scure/bip32](https://github.com/paulmillr/scure-bip32) - HD wallet key derivation
- [micro-key-producer](https://github.com/paulmillr/micro-key-producer) - SLIP-0010 for ed25519

> [!CAUTION]
> **Never use this with real funds or with any wallet that has ever been used.** Generated and signed material is handled as plaintext; treat every key it touches as burned the moment it is produced. Generate fresh throwaway keys for testing only and assume anything passing through `@agntn/keys` is compromised. Keys that control real funds belong on a hardware wallet, never in a process, log, or agent transcript.

## License

[MIT](./LICENSE.md)
