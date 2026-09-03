---
title: Bitcoin
icon: i-simple-icons-bitcoin
description: secp256k1 with legacy, p2sh, segwit, p2wsh, and taproot addresses, on mainnet and testnet.
---

::chain-facts{driver="bitcoin" curve="secp256k1" formats="legacy, p2sh, segwit, p2wsh, taproot" coin="0"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const bitcoinChain = useBlockchain(await blockchains.bitcoin()());
const testnetChain = useBlockchain(await blockchains.bitcoin({ network: "testnet" })());
```

Or import the class directly from `@agntn/keys/blockchains/bitcoin` and call `new Bitcoin()`.

## Five formats

| Type | Mainnet | Testnet | Encoding |
| --- | --- | --- | --- |
| `legacy` (default) | `1...` | `m...` or `n...` | base58check, version `0x00` / `0x6f` |
| `p2sh` | `3...` | `2...` | base58check, version `0x05` / `0xc4` |
| `segwit` | `bc1q...` | `tb1q...` | bech32, witness v0, P2WPKH |
| `p2wsh` | `bc1q...` | `tb1q...` | bech32, witness v0, script hash |
| `taproot` | `bc1p...` | `tb1p...` | bech32m, witness v1 |

```js
const publicKey = bitcoinChain.getKeyPublic(privateKey);

bitcoinChain.getAddress(publicKey); // 1...
bitcoinChain.getAddress(publicKey, "p2sh"); // 3...
bitcoinChain.getAddress(publicKey, "segwit"); // bc1q...
bitcoinChain.getAddress(publicKey, "taproot"); // bc1p...

bitcoinChain.generateWallet({}, "segwit"); // whole wallet, segwit address
```

Legacy and p2sh both start from `RIPEMD160(SHA256(pubkey))`. p2sh wraps that hash in a `0 <20 bytes>` redeem script and hashes again. Segwit puts the same 20 bytes behind witness version 0. Taproot is the real thing: the x only key gets tweaked with `TapTweak` per BIP341, so the address matches what Bitcoin Core derives for a key path spend, not a shortcut that only looks right.

## Validation

```js
bitcoinChain.validateAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"); // true
bitcoinChain.validateAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"); // true
bitcoinChain.validateAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"); // true
bitcoinChain.validateAddress("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"); // true
```

The prefix picks the decoder, then the checksum has to hold. A mainnet driver rejects testnet addresses and the other way round, which is what you want and occasionally what surprises you in a test.

## Mnemonics

`deriveHDWallet` reads the BIP43 purpose when you do not pass an address type:

```js
bitcoinChain.deriveHDWallet(mnemonic, "m/84'/0'/0'/0/0").address; // bc1q..., segwit from purpose 84
bitcoinChain.deriveHDWallet(mnemonic, "m/86'/0'/0'/0/0").address; // bc1p..., taproot from purpose 86
bitcoinChain.deriveHDWallet(mnemonic, "m/44'/0'/0'/0/0", {}, "segwit"); // explicit type wins
```

Purpose 44 is legacy, 49 is p2sh, 84 segwit, 86 taproot. Anything else with no explicit type falls back to legacy.

## Signing

`signMessage` hashes with the `"\x18Bitcoin Signed Message:\n"` preamble, the same one Bitcoin Core uses, and signs with secp256k1. The result is a hex signature that `verifyMessage` checks against the public key. It is not the base64 recoverable format `bitcoin-cli signmessage` prints, so do not paste one into the other.

## Where it lives

`src/blockchains/bitcoin.ts` holds the network table and the type dispatch. The hashing and encoding helpers sit in `src/utils/address.ts` and `src/utils/encoding.ts`, shared with TRON and the custom chain example.
