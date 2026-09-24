---
title: Dash
icon: i-token-dash
description: Bitcoin's P2PKH recipe behind an X. One address type and a message preamble that still says DarkCoin.
---

::chain-facts{driver="dash" curve="secp256k1" formats="legacy P2PKH" coin="5"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const dashChain = useBlockchain(await blockchains.dash()());
const testnet = useBlockchain(await blockchains.dash({ network: "testnet" })());
```

Mainnet and testnet only, anything else throws in the constructor. Devnets and regtest in Dash Core use the testnet bytes, so a testnet driver already reads their addresses.

## The address

Dash has X11 for mining and masternodes on top, but none of that reaches the address. `RIPEMD160(SHA256(pubkey))`, a version byte in front, base58check. The version bytes come from Dash Core v23.1.8 `chainparams.cpp`.

| Network | P2PKH | P2SH |
| --- | --- | --- |
| mainnet | `0x4c`, starts with `X` | `0x10`, starts with `7` |
| testnet | `0x8c`, starts with `y` | `0x13`, starts with `8` or `9` |

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = dashChain.getKeyPublic(privateKey);

dashChain.getAddress(publicKey); // XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE
testnet.getAddress(publicKey); // yWziQMcwmKjRdzi7eWjwiQX8EjWcd6dSg6
```

`legacy` is the only type it writes. Dash never took SegWit, so there's no bech32 to write. The library's `p2sh` type is P2SH wrapping a P2WPKH program, and on a chain without SegWit anyone who sees that script can spend from it. So `"p2sh"`, `"segwit"` and the rest throw a `RangeError` instead.

## Validation

```js
dashChain.validateAddress("XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE"); // true
dashChain.validateAddress("7XShCrc5u9rZZv7j18WqbUMZMxp8k1Hq4z"); // true, P2SH
dashChain.validateAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"); // false, Bitcoin's version byte
```

P2PKH and P2SH under the driver's own version bytes. P2SH passes because multisig wallets pay to it, the library just never writes one. A testnet address fails on mainnet and the other way round. The vectors in the tests come from the node's own `key_tests.cpp` and `key_io_valid.json`.

## Mnemonics

BIP32 on `m/44'/5'/account'/change/index`, coin type 5 from SLIP-0044.

```js
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

dashChain.deriveHDWallet(mnemonic, "m/44'/5'/0'/0/0").address;
// XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5, the same address Ledger Live derives
```

The purpose level doesn't pick a format, there's only one. `m/84'` still gives you an `X` address, and an explicit `"p2sh"` still throws.

WIF isn't here yet. Dash's prefix is `0xcc`, and `encodeWIF` and `decodeWIF` speak only Bitcoin, Litecoin and Decred, so a key from a Dash wallet export goes in as hex.

## Signing

Dash was DarkCoin until 2015, and the message preamble never got the rename. Dash Core signs under `"\x19DarkCoin Signed Message:\n"` to this day, then does what Bitcoin does: compact size lengths, double SHA-256, secp256k1. So a Bitcoin signature doesn't verify here, and the other way round. The `message_sign` case in Dash Core's `util_tests.cpp` matches byte for byte once you drop its header byte. `{ recovered: true }` throws, same as on Bitcoin.

## Where it lives

`src/blockchains/dash.ts` has the version bytes, the preamble and the address rules. It extends `AbstractBitcoinMessageBlockchain` in `src/utils/bitcoin.ts`, the part of the Bitcoin base with keys and signed messages and none of the address formats.
