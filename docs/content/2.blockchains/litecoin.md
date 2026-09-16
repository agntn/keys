---
title: Litecoin
icon: i-token-ltc
description: Bitcoin's driver with Litecoin's prefixes. Five address formats on mainnet and testnet and its own signed message preamble.
---

::chain-facts{driver="litecoin" curve="secp256k1" formats="legacy, p2sh, segwit, p2wsh, taproot" coin="2"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const litecoinChain = useBlockchain(await blockchains.litecoin()());
const testnetChain = useBlockchain(await blockchains.litecoin({ network: "testnet" })());
```

Anything other than `mainnet` and `testnet` throws in the constructor. There's no signet or regtest table.

## Same five formats, different prefixes

| Type | Mainnet | Testnet | Encoding |
| --- | --- | --- | --- |
| `legacy` (default) | `L...` | `m...` or `n...` | base58check, version `0x30` / `0x6f` |
| `p2sh` | `M...` | `Q...` | base58check, version `0x32` / `0x3a` |
| `segwit` | `ltc1q...` | `tltc1q...` | bech32, witness v0, P2WPKH |
| `p2wsh` | `ltc1q...` | `tltc1q...` | bech32, witness v0, script hash |
| `taproot` | `ltc1p...` | `tltc1p...` | bech32m, witness v1 |

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = litecoinChain.getKeyPublic(privateKey);

litecoinChain.getAddress(publicKey); // LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ
litecoinChain.getAddress(publicKey, "p2sh"); // MR8UQSBr5ULwWheBHznrHk2jxyxkHQu8vB
litecoinChain.getAddress(publicKey, "segwit"); // ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9
litecoinChain.getAddress(publicKey, "taproot"); // ltc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sszjagvq
```

The hashing is Bitcoin's, `RIPEMD160(SHA256(pubkey))`, the same taproot tweak too. Only the version bytes and the bech32 prefix change, which is why the segwit address above is `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` on Bitcoin with a different tail: same 20 bytes, different human readable part, different checksum.

Testnet legacy addresses start with `m` or `n`, exactly like Bitcoin testnet, and the WIF prefix is shared as well. A Litecoin testnet key and a Bitcoin testnet key are the same string. Not a bug, that's how Litecoin Core did it.

MWEB isn't supported, neither addresses nor anything else.

## Validation

```js
litecoinChain.validateAddress("LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ"); // true
litecoinChain.validateAddress("MR8UQSBr5ULwWheBHznrHk2jxyxkHQu8vB"); // true
litecoinChain.validateAddress("ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9"); // true
litecoinChain.validateAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"); // false, wrong network
```

One extra: the old P2SH prefix, `3...` on mainnet and `2...` on testnet, still validates. Old wallets still produce it, so rejecting it would only break real users. `getAddress` never emits it, you always get `M`.

## Mnemonics

`deriveHDWallet` reads the purpose the way Bitcoin does, with coin type 2:

```js
litecoinChain.deriveHDWallet(mnemonic, "m/84'/2'/0'/0/0").address; // ltc1q..., segwit from purpose 84
litecoinChain.deriveHDWallet(mnemonic, "m/44'/2'/0'/0/0").address; // L..., legacy from purpose 44
```

## WIF

```js
import { encodeWIF } from "@agntn/keys";

encodeWIF(privateKey, { chain: "litecoin" }); // T33ydQRKp4FCW5LCLLUB7deioUMoveiwekdwUwyfRDeGZm76aUjV
```

Version `0xb0` on mainnet, so compressed keys start with `T` and uncompressed ones with `6`. Testnet is `0xef`, the Bitcoin one.

## Signing

Same construction as Bitcoin with `"\x19Litecoin Signed Message:\n"` in front: double SHA-256, secp256k1, 64 bytes of `r||s` in hex. A Bitcoin signature over the same key and message is a different string because the preamble differs, so verify with the chain that signed.

## Where it lives

`src/blockchains/litecoin.ts` is the network table, the preamble and the validation extra. Everything else comes from `AbstractBitcoinBlockchain` in `src/utils/bitcoin.ts`, shared with Bitcoin.
