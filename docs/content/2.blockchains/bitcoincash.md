---
title: Bitcoin Cash
icon: i-token-bch
description: Bitcoin's key and hash written as CashAddr. One address type and Bitcoin's message preamble. Base58 stays out on purpose.
---

::chain-facts{driver="bitcoincash" curve="secp256k1" formats="legacy P2PKH in CashAddr" coin="145"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const bchChain = useBlockchain(await blockchains.bitcoincash()());
const testnet = useBlockchain(await blockchains.bitcoincash({ network: "testnet" })());
```

Mainnet and testnet only, anything else throws in the constructor. Testnet3, testnet4, scalenet and chipnet all use the same `bchtest` prefix, so one testnet driver covers them.

## The address

The hash is Bitcoin's, `RIPEMD160(SHA256(pubkey))`, byte for byte. Only the writing changes. A version byte goes in front, the whole thing is regrouped into 5-bit digits, and CashAddr adds a 40-bit checksum taken over the prefix too.

| Network | Prefix | Starts with |
| --- | --- | --- |
| mainnet | `bitcoincash` | `bitcoincash:q` |
| testnet | `bchtest` | `bchtest:q` |

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = bchChain.getKeyPublic(privateKey);

bchChain.getAddress(publicKey); // bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h
testnet.getAddress(publicKey); // bchtest:qp63uahgrxged4z5jswyt5dn5v3lzsem6cq85x00dt
```

That's `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` on Bitcoin, same key, same hash. The prefix is always written out, because that's the form wallets and explorers print.

`legacy` is the only type and it means pay to pubkey hash. It doesn't mean base58: the base58 form of that hash is a Bitcoin address, so the driver never produces it. Ask for `"p2sh"`, `"segwit"` or anything else and `getAddress` throws a `RangeError`. Bitcoin's `p2sh` type wraps a segwit program, and there's no segwit on Bitcoin Cash, so a quiet fallback here could only lose money.

## Validation

```js
bchChain.validateAddress("bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h"); // true
bchChain.validateAddress("qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h"); // true, prefix left off
bchChain.validateAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"); // false, base58
```

It reads CashAddr the way Bitcoin Cash Node does. The prefix is optional. Upper or lower case works, a mix of both doesn't. The checksum is always computed under the driver's own prefix, so a testnet or eCash address fails like a typo would. Past the checksum, the version byte has to agree with the hash length, and the type and length have to be ones the node pays to: pubkey hashes over 20 bytes, script hashes over 20 or 32, plus the token-aware twins CashTokens added (`z...` and `r...`).

Base58 is refused even though the node still takes it. Its bytes say Bitcoin, and agntn/chains draws the same line.

## Mnemonics

BIP32 on `m/44'/145'/account'/change/index`. The purpose level doesn't pick a format here the way it does on Bitcoin, since there's only one.

```js
const mnemonic = "all all all all all all all all all all all all";

bchChain.deriveHDWallet(mnemonic, "m/44'/145'/0'/0/0").address;
// bitcoincash:qr08q88p9etk89wgv05nwlrkm4l0urz4cyl36hh9sv, what a Trezor shows for that seed
```

WIF is Bitcoin's too, prefix `0x80`. `encodeWIF(privateKey, { chain: "bitcoin" })` gives the string a Bitcoin Cash wallet imports.

## Signing

Bitcoin Cash Node kept Bitcoin's `"\x18Bitcoin Signed Message:\n"`, so the digest is identical: compact size lengths, double SHA-256, secp256k1. A Bitcoin Cash signature and a Bitcoin signature over the same key and message are the same 64 bytes of `r||s` hex. Like Bitcoin, `{ recovered: true }` throws, because the node's recoverable form is base64 with a header byte.

## Where it lives

`src/blockchains/bitcoincash.ts` has the prefixes and the address rules. It extends `AbstractCashAddrBlockchain` in `src/utils/bitcoin.ts`: CashAddr P2PKH under one prefix per network, on top of the keys and signed messages of the Bitcoin base. The CashAddr codec is in `src/utils/cashaddr.ts`.
