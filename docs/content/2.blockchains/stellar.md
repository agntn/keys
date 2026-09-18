---
title: Stellar
icon: i-token-xlm
description: ed25519 with the public key wrapped as a G StrKey, and message signing the way SEP-53 says.
---

::chain-facts{driver="stellar" curve="ed25519" formats="StrKey" coin="148"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const stellarChain = useBlockchain(await blockchains.stellar()());
```

Pubnet and testnet share the address format, so `{ network: "testnet" }` is accepted and changes nothing.

## The address

The public key with a version byte in front and a CRC16-XModem checksum behind, base32 without padding. Version `0x30` is what puts the `G` at the start.

```js
const publicKey = stellarChain.getKeyPublic(privateKey); // 32 bytes, 64 hex chars
stellarChain.getAddress(publicKey); // GBGLLK7WVV47X5NLXTFPZQTJ3BONEZI62S4ILNMGT4SBV3PQUW5CTECA
```

The secret seed StrKey that starts with `S` is the same encoding over the private key. This package doesn't produce it, the private key stays hex like on every other chain.

## Validation

```js
stellarChain.validateAddress("GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"); // true
stellarChain.validateAddress("SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMN"); // false, secret seed
```

Three kinds of StrKey pass: an account (`G`), a muxed account (`M`, the account plus a 64-bit id), and a contract (`C`). Each one has to be the exact length for its kind, uppercase, with the version byte and the checksum in place. A secret seed is a valid StrKey and not an address, so it fails, on purpose.

## Mnemonics

SEP-0005 puts accounts at `m/44'/148'/x'`, three hardened levels, SLIP-10 underneath:

```js
stellarChain.deriveHDWallet(mnemonic, "m/44'/148'/0'").address; // GDRXE2BQ... for the SEP-0005 test phrase
```

That is the path SEP-0005 wallets, Freighter among them, walk for the first account. The SEP's own test vectors are in the test suite.

## Signing

`signMessage` signs what the Stellar SDK's `Keypair.signMessage` signs under SEP-53: SHA-256 over `"Stellar Signed Message:\n"` and the message bytes, then plain ed25519 over that digest. The same key gives the same 64 bytes here and there, and `verifyMessage` on either side accepts them.

```js
const signature = stellarChain.signMessage("hello", privateKey);
stellarChain.verifyMessage("hello", signature, publicKey); // true

import { Keypair } from "@stellar/stellar-sdk";
Keypair.fromPublicKey(address).verifyMessage("hello", hexToBytes(signature)); // true
```

A signature over the raw bytes, without the prefix, is what `Keypair.sign` produces for transaction hashes. It is not a message signature, and `verifyMessage` rejects it.
