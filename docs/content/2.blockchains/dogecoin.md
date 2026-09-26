---
title: Dogecoin
icon: i-token-doge
description: Bitcoin's P2PKH recipe behind a D, its own message preamble, and one address type, because the chain never got SegWit.
---

::chain-facts{driver="dogecoin" curve="secp256k1" formats="legacy P2PKH" coin="3"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const dogeChain = useBlockchain(await blockchains.dogecoin()());
const testnet = useBlockchain(await blockchains.dogecoin({ network: "testnet" })());
```

Mainnet and testnet only, anything else throws in the constructor. Regtest in Dogecoin Core borrows Bitcoin's testnet bytes, so it's left out.

## The address

Dogecoin grew out of Litecoin's code, which grew out of Bitcoin's, and the address never moved far from home. `RIPEMD160(SHA256(pubkey))`, a version byte in front, base58check. The version bytes come from Dogecoin Core v1.14.9 `chainparams.cpp`.

| Network | P2PKH | P2SH |
| --- | --- | --- |
| mainnet | `0x1e`, starts with `D` | `0x16`, starts with `9` or `A` |
| testnet | `0x71`, starts with `n` | `0xc4`, starts with `2` |

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = dogeChain.getKeyPublic(privateKey);

dogeChain.getAddress(publicKey); // DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE
testnet.getAddress(publicKey); // nesRpRaAbTDmZHwmzBkLd2AtF7Z9L9z5S2
```

`legacy` is the only type it writes. Dogecoin never activated SegWit, so there's no bech32, and the library's `p2sh` type is P2SH wrapping a P2WPKH program. On a chain without SegWit that script is spendable by anyone who sees it. So `"p2sh"`, `"segwit"` and the rest throw a `RangeError` instead of handing you that address.

## Validation

```js
dogeChain.validateAddress("DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE"); // true
dogeChain.validateAddress("A7HRQk3GFCW2QasvdZxXuYj8kkQK5QrYLs"); // true, P2SH
dogeChain.validateAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"); // false, Bitcoin's version byte
```

P2PKH and P2SH under the driver's own version bytes. P2SH passes because multisig wallets really pay to it, the library just never writes one. A testnet address fails on mainnet and the other way round. The vectors in the tests come from the node's own `key_tests.cpp` and `base58_keys_valid.json`.

## Mnemonics

BIP32 on `m/44'/3'/account'/change/index`, coin type 3 from SLIP-0044.

```js
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

dogeChain.deriveHDWallet(mnemonic, "m/44'/3'/0'/0/0").address;
// DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC, the same address Ledger Live derives
```

The purpose level doesn't pick a format, there's only one. `m/84'` still gives you a `D` address, and an explicit `"p2sh"` still throws.

## WIF

```js
import { decodeWIF } from "@agntn/keys";

decodeWIF("QP5rQxpaP8HHPEdCEqxTjiHGWRvsyPvzZJeJ9BCxpfT13FN9VesQ", { chain: "dogecoin" });
// { privateKey: '0e01…370a', chain: 'dogecoin', network: 'mainnet', compressed: true }
```

Version `0x9e` on mainnet, so compressed keys start with `Q` and uncompressed ones with `6`. That's the string `dumpprivkey` gives you. Testnet is `0xf1`, not Bitcoin's, so unlike Litecoin and Dash a Dogecoin testnet key doesn't pass as a Bitcoin one.

## Signing

Dogecoin Core signs under `"\x19Dogecoin Signed Message:\n"`, then does what Bitcoin does: compact size lengths, double SHA-256, secp256k1. So a Bitcoin signature doesn't verify here, and the other way round. The Dogecoin vectors in bitcoinjs-message match byte for byte once you drop their header byte. `{ recovered: true }` throws, same as on Bitcoin.

## Where it lives

`src/blockchains/dogecoin.ts` has the version bytes, the preamble and the address rules. It extends `AbstractBitcoinMessageBlockchain` in `src/utils/bitcoin.ts`, the part of the Bitcoin base with keys and signed messages and none of the address formats.
