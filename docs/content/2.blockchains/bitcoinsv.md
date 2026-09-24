---
title: Bitcoin SV
icon: i-token-bsv
description: Bitcoin's key, Bitcoin's hash, Bitcoin's base58. One address type, Bitcoin's message preamble, and no P2SH since Genesis.
---

::chain-facts{driver="bitcoinsv" curve="secp256k1" formats="legacy P2PKH" coin="236"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const bsvChain = useBlockchain(await blockchains.bitcoinsv()());
const testnet = useBlockchain(await blockchains.bitcoinsv({ network: "testnet" })());
```

Mainnet and testnet only, anything else throws in the constructor. Testnet, STN and regtest share the same version bytes in the node, so one testnet driver covers them.

## The address

Nothing new here, and that's the point. Bitcoin SV kept Bitcoin's P2PKH recipe as is: `RIPEMD160(SHA256(pubkey))`, a version byte in front, base58check.

| Network | Version | Starts with |
| --- | --- | --- |
| mainnet | `0x00` | `1` |
| testnet | `0x6f` | `m` or `n` |

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = bsvChain.getKeyPublic(privateKey);

bsvChain.getAddress(publicKey); // 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
testnet.getAddress(publicKey); // mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r
```

Same key, same string as Bitcoin's legacy address. So a `1` address alone doesn't tell you which chain it lives on. Only a balance lookup does.

`legacy` is the only type. Ask for `"p2sh"`, `"segwit"` or anything else and `getAddress` throws a `RangeError`. There's no segwit on this chain, and Bitcoin's `p2sh` type wraps a segwit program anyway.

## Validation

```js
bsvChain.validateAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"); // true
bsvChain.validateAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"); // false, P2SH
bsvChain.validateAddress("bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h"); // false
```

Base58check under the driver's own version byte, and nothing else. A testnet address fails on mainnet and the other way round.

The `3` refusal is deliberate. The node still decodes a P2SH address, but since Genesis it rejects any transaction paying to one with `bad-txns-vout-p2sh`. An address you can't send to isn't one worth calling valid. Bech32 and CashAddr fail too, the chain never had them.

## Mnemonics

BIP32 on `m/44'/236'/account'/change/index`, coin type 236 from SLIP-0044. That's what Yours Wallet and the BSV Blockchain py-sdk derive.

```js
const mnemonic =
  "chief december immune nominee forest scheme slight tornado cupboard post summer program";

bsvChain.deriveHDWallet(mnemonic, "m/44'/236'/0'/0/0").address;
// 127kSo2jNBnSoZeQniZ86WpUQjPvMhSVdA, the key py-sdk's own tests expect
```

ElectrumSV is the odd one out. It kept Bitcoin's coin type 0, so a seed from it wants `m/44'/0'/0'/0/0`. Pass that path yourself and you get the same address Bitcoin gives. The purpose level doesn't pick a format either way, there's only one.

WIF is Bitcoin's too, prefix `0x80`. `encodeWIF(privateKey, { chain: "bitcoin" })` gives the string a Bitcoin SV wallet imports.

## Signing

The node kept `"\x18Bitcoin Signed Message:\n"`, so the digest is Bitcoin's: compact size lengths, double SHA-256, secp256k1. A Bitcoin SV signature is the same 64 bytes of `r||s` hex that Bitcoin gives for that key and message. The `BSM` vectors in the BSV Blockchain ts-sdk match byte for byte once you drop their header byte. Like Bitcoin, `{ recovered: true }` throws, because the recoverable form is base64 with that header byte in front.

## Where it lives

`src/blockchains/bitcoinsv.ts` has the version bytes and the address rules. It extends `AbstractBitcoinMessageBlockchain` in `src/utils/bitcoin.ts`, the part of the Bitcoin base with keys and signed messages and none of the address formats.
