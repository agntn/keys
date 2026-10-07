---
title: Polkadot
icon: i-token-dot
description: ed25519 keys and BIP39 words to Polkadot, Kusama and Substrate SS58 addresses. Hard junctions derive the way subkey and polkadot.js do.
seo:
  title: Polkadot and Kusama SS58 addresses from keys and BIP39 words
---

::chain-facts{driver="polkadot" curve="ed25519" formats="SS58 under any network prefix" coin="354"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const polkadot = useBlockchain(await blockchains.polkadot()());
const kusama = useBlockchain(await blockchains.polkadot({ ss58Prefix: 2 })());
const westend = useBlockchain(await blockchains.polkadot({ network: "testnet" })());
```

One class for every Substrate chain. The chain shows up as a number in front of the key. 0 is Polkadot, 2 is Kusama, 42 is the generic Substrate format. `network: "testnet"` picks 42, which is what Westend and Paseo use.

::warning{title="ed25519 only, for now"}
Most wallets create sr25519 accounts. This driver writes ed25519 ones. Same words, other curve, other address. So if Polkadot.js shows something else for your phrase, nothing's broken. sr25519 comes once `@agntn/curves` has Ristretto255 to stand on.
::

## What's in an address?

The prefix, the public key itself and two checksum bytes, in base58. No hash of the key at all. The account is the key.

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = polkadot.getKeyPublic(privateKey);

polkadot.getAddress(publicKey); // 12jacCzszzdckmb7pYNSGxy61nUwP9nrNefP92AFpKP62N46
kusama.getAddress(publicKey); // EJu8C5gmaP54tQ3dc8V2mVwJkmXVX3tkXmeNPSrk2a4akcB
westend.getAddress(publicKey); // 5DoHTsjp9DN9KEabruKS8p8wAAVHgrEiJ9vtyjAuGEMZqpWt
```

Three addresses, one key. The only blake2b in there is the checksum, and it hashes the string `SS58PRE` in front of everything. Yes, really.

Prefixes up to 63 take one byte, the rest up to 16383 take two. 46 and 47 are reserved, so they throw when you load the chain. `validateAddress` wants the checksum and this instance's prefix:

```js
polkadot.validateAddress("12jacCzszzdckmb7pYNSGxy61nUwP9nrNefP92AFpKP62N46"); // true
polkadot.validateAddress("EJu8C5gmaP54tQ3dc8V2mVwJkmXVX3tkXmeNPSrk2a4akcB"); // false
```

A Kusama account on Polkadot is `false`, good checksum or not. Only 32-byte accounts pass. Old account indices and 33-byte ECDSA ones don't come from a key here, so they don't validate either.

## Mnemonics

Not BIP32, and not even the BIP39 seed. Substrate runs PBKDF2 over the phrase's entropy, keeps 32 bytes and calls it the mini secret. That's the root key. Below it you walk junctions.

```js
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

polkadot.deriveHDWallet(mnemonic, "m").address;
// 14HKDhPM8fr6JB9yk9TGZTsBUdk8WJq1AiMbi1YAzUarv1Jp
polkadot.deriveHDWallet(mnemonic, "//polkadot//0").address;
// 14a9YHn5Mast138yujPzW3NKQw83fZS2gN2QQPmsZAf5NC8U
```

`m` or an empty path is the root. `//name` is a hard junction, and a number like `//0` counts as a number. The `///password` of a Substrate URI goes in `passphrase`, not in the path.

What throws? A soft junction like `/0`, since ed25519 can't walk one. And two junctions the reference tools read differently. `//0x00` is hex to polkadot.js and a name to subkey. A number past 64 bits is a 256-bit number to one and a name to the other. Two implementations, two keys. We'd rather throw than guess which one your wallet used.

Here's a fun one. The checksum never gets into the entropy. Twelve times `abandon` fails the checksum, but with `allowInvalidChecksum` it lands on the exact account above, with a warning.

There's no BIP44 path to build, so `getDerivationPath()` throws. `keys_hd_wallet_scan` won't walk Polkadot either. Wallets name their own junctions, so there's no list to walk.

## Signing

`signMessage` wraps the message in `<Bytes>` and `</Bytes>` first. That's what the polkadot.js extension does in `signRaw`, so your signature matches the one it hands out. You get 64 bytes of ed25519 in hex.

```js
const signature = polkadot.signMessage("Hello, Polkadot!", privateKey);
polkadot.verifyMessage("Hello, Polkadot!", signature, publicKey); // true
```

`verifyMessage` takes a signature over the raw message too, like polkadot.js `signatureVerify`. Got one from a script that never wrapped anything? It still checks out.

## Agents

On `chain: "polkadot"` the `prefix` argument is the SS58 number as text, `"2"` for Kusama. `keys_hd_wallet_derive` takes junctions or `m` as its path, and `passphrase` is the URI password.

## Where it lives

`src/blockchains/polkadot.ts`, with SS58 in `src/utils/ss58.ts` and junctions in `src/utils/substrate.ts`. ed25519 comes from `@noble/curves`, blake2b and PBKDF2 from `@agntn/hashes`, base58 from `@agntn/encodings`.
