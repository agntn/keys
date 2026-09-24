---
title: Zcash
icon: i-token-zec
description: Transparent Zcash only. Bitcoin's P2PKH behind two version bytes, a t1 address, and nothing shielded.
---

::chain-facts{driver="zcash" curve="secp256k1" formats="transparent P2PKH" coin="133"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const zcashChain = useBlockchain(await blockchains.zcash()());
const testnet = useBlockchain(await blockchains.zcash({ network: "testnet" })());
```

Mainnet and testnet only, anything else throws in the constructor. Regtest in zcashd uses the testnet base58 bytes, so a testnet driver reads its `tm` and `t2` addresses. Not its TEX addresses though, those get a `texregtest` prefix of their own.

## Transparent, not shielded

Zcash has two worlds. The shielded one (Sapling `zs1`, Orchard inside unified `u1` addresses) runs on Jubjub and Pallas keys with ZIP-32 derivation, and none of that is secp256k1. The transparent one is basically Bitcoin from 2016. This driver does the transparent one and nothing else.

So `validateAddress` answers false for a perfectly good `zs1` or `u1` address. False here means "not transparent", not "not Zcash". Keep that in mind before you tell anyone their shielded address is broken.

## The address

`RIPEMD160(SHA256(pubkey))`, two version bytes in front, base58check. The two bytes are the whole difference from Bitcoin, and the reason every address starts with `t`. The bytes come from zcashd v6.20.0 `chainparams.cpp`.

| Network | P2PKH | P2SH |
| --- | --- | --- |
| mainnet | `1c b8`, starts with `t1` | `1c bd`, starts with `t3` |
| testnet | `1d 25`, starts with `tm` | `1c ba`, starts with `t2` |

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = zcashChain.getKeyPublic(privateKey);

zcashChain.getAddress(publicKey); // t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs
testnet.getAddress(publicKey); // tmLPctKo9j49rtCSKpwEBpLBeykiTGomGQs
```

`legacy` is the only type it writes. Zcash never had SegWit, and the library's `p2sh` type is P2SH wrapping a P2WPKH program, which anyone can spend on a chain without SegWit. So `"p2sh"`, `"segwit"` and the rest throw a `RangeError`.

## Validation

```js
zcashChain.validateAddress("t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs"); // true
zcashChain.validateAddress("t3VDyGHn9mbyCf448m2cHTu5uXvsJpKHbiZ"); // true, P2SH
zcashChain.validateAddress("tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte"); // true, TEX
zcashChain.validateAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"); // false, Bitcoin's version byte
```

P2PKH and P2SH under the driver's own version bytes, plus TEX. A TEX address from ZIP-320 is the same 20 byte P2PKH hash in bech32m under `tex`, and it tells the sending wallet to pay from transparent funds only. ZIP-320 exists because Binance wanted exactly that for deposits, so it passes. The library never writes one, same as P2SH. A testnet address fails on mainnet and the other way round.

The vectors in the tests come from zcashd's own `key_tests.cpp` and `base58_keys_valid.json`, the TEX pair from ZIP-320, and the shielded addresses that have to fail from librustzcash.

## Mnemonics

BIP32 on `m/44'/133'/account'/change/index`, coin type 133 from SLIP-0044.

```js
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

zcashChain.deriveHDWallet(mnemonic, "m/44'/133'/0'/0/0").address;
// t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F, the same address Ledger Live derives
```

The purpose level doesn't pick a format, there's only one. `m/84'` still gives you a `t1` address, and an explicit `"p2sh"` still throws.

One trap on testnet. zcashd walks coin type 1 there, but `getDerivationPath` writes 133 on every network, like every other driver in the library. For a testnet wallet that has to match zcashd, pass `m/44'/1'/0'/0/0` yourself.

WIF works without a Zcash entry. Zcash kept Bitcoin's `0x80` and `0xef`, so `decodeWIF(wif, { chain: "bitcoin" })` reads a key exported from zcashd.

## Signing

zcashd signs under `"\x16Zcash Signed Message:\n"`, then does what Bitcoin does: compact size lengths, double SHA-256, secp256k1. Only the preamble differs, and that's enough for a Bitcoin signature to fail here. The tests take the signature from Zallet's `verifymessage` test, recover its key, get Zallet's `t1` address back and verify it. `{ recovered: true }` throws, same as on Bitcoin.

## Where it lives

`src/blockchains/zcash.ts` has the version bytes, the preamble and the address rules. It extends `AbstractBitcoinMessageBlockchain` in `src/utils/bitcoin.ts`, the part of the Bitcoin base with keys and signed messages and none of the address formats. The base58 helpers in `src/utils/address.ts` take one version byte, so the driver puts its two bytes on the hash itself.
