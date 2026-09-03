---
title: TRON
icon: i-lucide-zap
description: secp256k1 with Ethereum's 20 byte hash wrapped in base58check, so every address starts with T.
---

::chain-facts{driver="tron" curve="secp256k1" formats="base58check" coin="195"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const tronChain = useBlockchain(await blockchains.tron()());
```

## The address

Keccak-256 of the public key, last 20 bytes, exactly like Ethereum. Then a version byte `0x41` in front and base58check around it, which is why every TRON address starts with `T`.

```js
const publicKey = tronChain.getKeyPublic(privateKey);
tronChain.getAddress(publicKey); // TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW
```

Strip the base58check and swap `0x41` for `0x`, and you have the Ethereum address of the same key. That is a nice trick for debugging and a bad idea for anything else.

## Testnet

```js
const shasta = useBlockchain(await blockchains.tron({ network: "testnet" })());
```

TRON testnets use the same `0x41` prefix as mainnet, so testnet addresses also start with `T`. The driver accepts the option for symmetry with the other chains, but there is no way to tell a Shasta address from a mainnet one by looking at it. Do not rely on the string.

## Validation

```js
tronChain.validateAddress("TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW"); // true
tronChain.validateAddress("1JCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW"); // false, wrong prefix
```

Base58check decode, version byte `0x41`, 21 bytes total. The checksum catches typos, the prefix catches pasted Bitcoin addresses.

## Signing

`signMessage` reuses the EVM signing code, so the message gets the `"\x19Ethereum Signed Message:\n"` preamble before Keccak-256 and secp256k1. That is not the `"\x19TRON Signed Message:\n"` preamble TronLink uses for its own signing, so a signature from here will not verify in a TRON wallet and the other way round. `verifyMessage` in this package checks what `signMessage` here produces.
