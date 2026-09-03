---
title: Aptos
icon: i-lucide-hexagon
description: ed25519 with addresses from SHA3-256 over the public key and a scheme byte.
---

::chain-facts{driver="aptos" curve="ed25519" formats="0x hex" coin="637"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const aptosChain = useBlockchain(await blockchains.aptos()());
```

## The address

Public key, then one scheme byte `0x00` for a single ed25519 signer, then SHA3-256. The 32 byte digest with `0x` in front is the address.

```js
const publicKey = aptosChain.getKeyPublic(privateKey);
aptosChain.getAddress(publicKey); // 0x7e08ac7940568c91564ddc6f5f3bf91b15a9334194ab7855daeac51c5cc74936
```

The scheme byte is the part people forget when they reimplement this by hand. Hash the bare key and you get a valid looking address that belongs to nobody.

## Validation

```js
aptosChain.validateAddress("0x7e08ac7940568c91564ddc6f5f3bf91b15a9334194ab7855daeac51c5cc74936"); // true
aptosChain.validateAddress("0x1"); // true, special address
aptosChain.validateAddress("7e08ac7940568c91564ddc6f5f3bf91b15a9334194ab7855daeac51c5cc74936"); // false, no 0x
```

`0x` plus 64 hex characters, case does not matter. The single digit forms like `0x1` are the framework addresses and validate as well. There is no checksum, so a wrong character produces a different valid address instead of an error. Copy carefully.

## Mnemonics

SLIP-10, hardened segments only:

```js
aptosChain.deriveHDWallet(mnemonic, "m/44'/637'/0'/0'/0'").address;
```

That is the path Petra uses for the first account.

## Signing

Plain ed25519 over the message bytes, hex out. `verifyMessage` checks it against the public key.
