---
title: Solana
icon: i-token-sol
description: ed25519. The address is the public key itself in base58 with nothing hashed.
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

No hash, no version byte, no checksum. The address is the public key with a friendlier encoding, that's it. It makes Solana the easiest chain in the package and the one where `validateAddress` can say the least: any 32 bytes that decode from base58 pass, including a program address that no private key controls.

## Validation

```js
solanaChain.validateAddress("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"); // true
```

Decodes as base58 and is exactly 32 bytes. That is the whole check.

## Mnemonics

Solana derives with SLIP-10, which only has hardened children. Every segment of the path needs the tick:

```js
solanaChain.deriveHDWallet(mnemonic, { path: "m/44'/501'/0'/0'" }).address;
```

A path with an unhardened segment throws before derivation, there isn't a soft child to give you. Phantom and Solflare use exactly this shape, so the first account matches what those wallets show. `solanaChain.getDerivationPath({ account: 1 })` gives the next one, `m/44'/501'/1'/0'`.

## Keypair files

Got the `id.json` the Solana CLI writes, or a secret exported from Phantom or Solflare? Pass it straight to `deriveSeedWallet`. No slicing bytes by hand first.

```js
solanaChain.deriveSeedWallet("2Ana1pUpv2ZbMVkwF5FXapYeBEjdxDatLn7nvJkhgTSdZd8hbDHTd21as7EAsg7ypityqfsw2pMQKJcVDVcAEsd").address;
// 9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj, and the id.json array of the same 64 bytes gives the same
```

The seed in this public test vector just counts from 1 to 32. The other half is the public key, so the file carries its own answer key. Halves that don't match throw instead of handing you some other address.

You get `keys.private` as the 32-byte seed in hex, the key every other Solana method here takes. `keys_wallet_derive` reads both forms as `privateKey` too.

## Signing

`signMessage` is a plain ed25519 signature over the message bytes, hex encoded, and `verifyMessage` checks it against the public key. That is the format `nacl.sign.detached` produces, minus the base58 wrapper some wallets add on top.
