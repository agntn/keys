---
title: Decred
icon: i-token-dcr
description: secp256k1 with BLAKE-256 in every hash. Addresses start with Ds. No mnemonic derivation and that's on purpose.
---

::chain-facts{driver="decred" curve="secp256k1" formats="legacy ECDSA P2PKH" coin="42"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const decredChain = useBlockchain(await blockchains.decred()());
const testnet = useBlockchain(await blockchains.decred({ network: "testnet" })());
```

Mainnet and testnet3 only, anything else throws in the constructor.

## The address

Decred looks like Bitcoin from a distance and swaps the hash the moment you get close. `RIPEMD160(BLAKE256(pubkey))`, a two byte prefix in front, then base58check with a double BLAKE-256 checksum instead of double SHA-256.

| Network | Prefix | Starts with |
| --- | --- | --- |
| mainnet | `07 3f` | `Ds` |
| testnet | `0f 21` | `Ts` |

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = decredChain.getKeyPublic(privateKey);

decredChain.getAddress(publicKey); // DsmcYVbP1Nmag2H4AS17UTvmWXmGeA7nLDx
testnet.getAddress(publicKey); // TsmfmUitQApgnNxQypdGd2x36djCCpDpERU
```

That's the only format. Ask for `"segwit"` or anything else and `getAddress` throws a `RangeError` instead of quietly handing you a legacy address. Schnorr and Ed25519 keys, which dcrd also knows, aren't implemented.

## Validation

```js
decredChain.validateAddress("DsmcYVbP1Nmag2H4AS17UTvmWXmGeA7nLDx"); // true
decredChain.validateAddress("TsmfmUitQApgnNxQypdGd2x36djCCpDpERU"); // false, testnet on a mainnet driver
```

Base58 decode with the BLAKE-256 checksum, 22 bytes of payload, and both prefix bytes have to match the driver's network. A Bitcoin address fails at the checksum before the prefix even gets a look.

## Mnemonics

`deriveHDWallet` throws. dcrd's HD derivation strips leading zero bytes from keys where BIP32 keeps them, so a plain BIP32 walk lands on the wrong key for some paths and looks perfectly fine doing it. A driver that's silently wrong is worse than one that refuses, so it refuses. `deriveWallet` with a private key works as usual, and so does WIF:

```js
import { encodeWIF, decodeWIF } from "@agntn/keys";

encodeWIF(privateKey, { chain: "decred" }); // PmQdGRXNZdAgEqwDZMLAF2XSQRLFeSFKi4HLPbdW3kC66HegjYtxq
decodeWIF(wif, { chain: "decred" }).privateKey;
```

Decred WIF has its own layout: two prefix bytes, a scheme byte that's `0x00` for ECDSA, the key, and a single BLAKE-256 checksum. Only the compressed form exists, `compressed: false` throws.

## Signing

`"Decred Signed Message:\n"` with compact size lengths in front of the preamble and the message, one round of BLAKE-256, then secp256k1. 64 bytes of `r||s` in hex, verified with `verifyMessage` on the same driver.

## Where it lives

`src/blockchains/decred.ts`, all of it. It extends `AbstractBlockchain` directly, not the Bitcoin base, because nothing except the curve is shared.
