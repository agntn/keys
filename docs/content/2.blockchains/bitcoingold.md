---
title: Bitcoin Gold
icon: i-token-btg
description: Bitcoin's driver with Bitcoin Gold's prefixes and preamble. Four address formats on mainnet and testnet and no taproot at all.
---

::chain-facts{driver="bitcoingold" curve="secp256k1" formats="legacy, p2sh, segwit, p2wsh" coin="156"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const btgChain = useBlockchain(await blockchains.bitcoingold()());
const testnet = useBlockchain(await blockchains.bitcoingold({ network: "testnet" })());
```

Mainnet and testnet only, anything else throws in the constructor. Testnet, signet and regtest share one set of version bytes in the node, and they're Bitcoin's testnet bytes.

## Four formats, not five

Bitcoin Gold forked off Bitcoin in 2017, after SegWit was already live, so it kept SegWit. The prefixes are its own.

| Type | Mainnet | Testnet | Encoding |
| --- | --- | --- | --- |
| `legacy` (default) | `G...` | `m...` or `n...` | base58check, version `0x26` / `0x6f` |
| `p2sh` | `A...` | `2...` | base58check, version `0x17` / `0xc4` |
| `segwit` | `btg1q...` | `tbtg1q...` | bech32, witness v0, P2WPKH |
| `p2wsh` | `btg1q...` | `tbtg1q...` | bech32, witness v0, script hash |

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = btgChain.getKeyPublic(privateKey);

btgChain.getAddress(publicKey); // GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5
btgChain.getAddress(publicKey, "p2sh"); // AZ1BpW94ubqHRzsqdfoFCMgVyN1H4CnSEp
btgChain.getAddress(publicKey, "segwit"); // btg1qw508d6qejxtdg4y5r3zarvary0c5xw7k6w057a
```

Look at the segwit one next to Bitcoin's `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`. Same hash in the middle, different prefix and checksum. The testnet legacy address is byte for byte Bitcoin's testnet address, so an `m` address alone doesn't say which chain it's on.

## Why there's no taproot

The node has the Taproot deployment copied from Bitcoin Core, signaling window included: April to August 2021. But no Bitcoin Gold release came out in that window. v0.17.3 came out in 2020, v0.21.3 in December 2024, long after the window closed. Nobody could signal, so the deployment failed and never activated.

So the driver refuses it everywhere. `getAddress(publicKey, "taproot")` throws a `RangeError`, and `deriveHDWallet` on an `m/86'` path throws the same way. `validateAddress` returns `false` for `btg1p...` and every later witness version, even though the node decodes them fine. Without Taproot rules a witness v1 output is spendable by anyone. Calling that address valid would just set a trap.

## Validation

```js
btgChain.validateAddress("GUHcigT74ggLsmbxHFTLfn2ZUNJUWiXaMG"); // true
btgChain.validateAddress("btg1q5cuatynjmk4szh40mmunszfzh7zrc5xmn8padv"); // true
btgChain.validateAddress("btg1p5rgvqejqh9dh37t9g94dd9cm8vtqns7dndgj423egwggsggcdzms7pg7wc"); // false, witness v1
btgChain.validateAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"); // false, Bitcoin's version byte
```

The first three come straight from the node's `key_io_valid.json`. A testnet address fails on mainnet and the other way round.

## Mnemonics

BIP32 on coin type 156 from SLIP-0044, the one Trezor uses too. The purpose level picks the format, the same as on Bitcoin.

```js
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

btgChain.deriveHDWallet(mnemonic, "m/44'/156'/0'/0/0").address; // GeTZ7bjfXtGsyEcerSSFJNUSZwLfjtCJX9
btgChain.deriveHDWallet(mnemonic, "m/49'/156'/0'/0/0").address; // AL8uaqKrP4n61pb2BrQXpMC3VcUdjmpAwn
btgChain.deriveHDWallet(mnemonic, "m/84'/156'/0'/0/0").address; // btg1qkwnu2phwvard2spr2n0a9d84x590ahywl3yacu
```

WIF is Bitcoin's, prefix `0x80` on mainnet and `0xef` on testnet. `encodeWIF(privateKey, { chain: "bitcoin" })` gives a string a Bitcoin Gold wallet imports.

## Signing

The node signs with `"\x1dBitcoin Gold Signed Message:\n"`, so a Bitcoin signature doesn't verify here and the other way round. The rest is Core's recipe: compact size lengths, double SHA-256, secp256k1. What comes back is 64 bytes of `r||s` hex. The node's own `rpc_signmessage.py` vector matches byte for byte once you drop the header byte from its base64. `{ recovered: true }` throws, like on Bitcoin.

The replay protection Bitcoin Gold added at the fork, `SIGHASH_FORKID`, is about transactions. Signed messages never had it, and this library doesn't sign transactions anyway.

## Where it lives

`src/blockchains/bitcoingold.ts` has the network table, the preamble and the taproot refusal. Everything else comes from `AbstractBitcoinBlockchain` in `src/utils/bitcoin.ts`, shared with Bitcoin and Litecoin.
