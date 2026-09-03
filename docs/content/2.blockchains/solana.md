---
title: Solana
icon: i-simple-icons-solana
description: ed25519. The address is the public key itself in base58, nothing hashed.
---

::chain-facts{driver="solana" curve="ed25519" formats="base58" coin="501"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const solanaChain = useBlockchain(await blockchains.solana()());
```

## The address

```js
const publicKey = solanaChain.getKeyPublic(privateKey); // 32 bytes, 64 hex chars
solanaChain.getAddress(publicKey); // base58 of the same 32 bytes
```

No hash, no version byte, no checksum. The address is the public key with a friendlier encoding. It makes Solana the easiest chain in the package and the one where `validateAddress` can say the least: any 32 bytes that decode from base58 pass, including a program address that no private key controls.

## Validation

```js
solanaChain.validateAddress("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"); // true
```

Decodes as base58 and is exactly 32 bytes. That is the whole check.

## Mnemonics

Solana derives with SLIP-10, which only has hardened children. Every segment of the path needs the tick:

```js
solanaChain.deriveHDWallet(mnemonic, "m/44'/501'/0'/0'").address;
```

A path with an unhardened segment throws before derivation. Phantom and Solflare use exactly this shape, so the first account matches what those wallets show.

## Signing

`signMessage` is a plain ed25519 signature over the message bytes, hex encoded, and `verifyMessage` checks it against the public key. That is the format `nacl.sign.detached` produces, minus the base58 wrapper some wallets add on top.
