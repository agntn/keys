---
title: Bitcoin
icon: i-token-btc
description: secp256k1 with five address formats from legacy to taproot on mainnet and testnet.
---

::chain-facts{driver="bitcoin" curve="secp256k1" formats="legacy, p2sh, segwit, p2wsh, taproot" coin="0"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const bitcoinChain = useBlockchain(await blockchains.bitcoin()());
const testnetChain = useBlockchain(await blockchains.bitcoin({ network: "testnet" })());
```

Or import the class directly from `@agntn/keys/blockchains/bitcoin` and call `new Bitcoin()`.

Mainnet and testnet only, anything else throws in the constructor. Signet uses the testnet prefixes, so a testnet driver writes its addresses. Regtest keeps the testnet base58 bytes but writes segwit under `bcrt`, and there is no table for that.

## Five formats

| Type | Mainnet | Testnet | Encoding |
| --- | --- | --- | --- |
| `legacy` (default) | `1...` | `m...` or `n...` | base58check, version `0x00` / `0x6f` |
| `p2sh` | `3...` | `2...` | base58check, version `0x05` / `0xc4` |
| `segwit` | `bc1q...` | `tb1q...` | bech32, witness v0, P2WPKH |
| `p2wsh` | `bc1q...` | `tb1q...` | bech32, witness v0, script hash |
| `taproot` | `bc1p...` | `tb1p...` | bech32m, witness v1 |

```js
const publicKey = bitcoinChain.getKeyPublic(privateKey);

bitcoinChain.getAddress(publicKey); // 1...
bitcoinChain.getAddress(publicKey, "p2sh"); // 3...
bitcoinChain.getAddress(publicKey, "segwit"); // bc1q...
bitcoinChain.getAddress(publicKey, "taproot"); // bc1p...

bitcoinChain.generateWallet({}, "segwit"); // whole wallet, segwit address
```

Legacy and p2sh both start from `RIPEMD160(SHA256(pubkey))`. p2sh wraps that hash in a `0 <20 bytes>` redeem script and hashes again. Segwit puts the same 20 bytes behind witness version 0. Taproot is the real thing: the x only key gets tweaked with `TapTweak` per BIP341, so the address matches what Bitcoin Core derives for a key path spend, not a shortcut that only looks right.

## Validation

```js
bitcoinChain.validateAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"); // true
bitcoinChain.validateAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"); // true
bitcoinChain.validateAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"); // true
bitcoinChain.validateAddress("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"); // true
```

The prefix picks the decoder, then the checksum has to hold. A mainnet driver rejects testnet addresses and the other way round, which is what you want and occasionally what surprises you in a test.

## Mnemonics

`deriveHDWallet` reads the BIP43 purpose when you don't pass an address type:

```js
bitcoinChain.deriveHDWallet(mnemonic, "m/84'/0'/0'/0/0").address; // bc1q..., segwit from purpose 84
bitcoinChain.deriveHDWallet(mnemonic, "m/86'/0'/0'/0/0").address; // bc1p..., taproot from purpose 86
bitcoinChain.deriveHDWallet(mnemonic, "m/44'/0'/0'/0/0", {}, "segwit"); // explicit type wins
```

Purpose 44 is legacy, 49 is p2sh, 84 segwit, 86 taproot. Anything else with no explicit type falls back to legacy. A puzzle phrase with a broken checksum goes through with `{ allowInvalidChecksum: true }`, the [wallets guide](/guide/wallets#puzzle-mnemonics) has the details.

## WIF

```js
import { encode, decode } from "@agntn/keys/wif";

encode(privateKey, { chain: "bitcoin" }); // K... or L..., compressed
encode(privateKey, { chain: "bitcoin", compressed: false }); // 5...
encode(privateKey, { chain: "bitcoin", network: "testnet" }); // c...

decode("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", { chain: "bitcoin" }).compressed; // true
```

Version `0x80` on mainnet, `0xef` on testnet, a trailing `0x01` when the public key is compressed. `decode` checks the prefix against the chain and network you name, so a testnet WIF on a mainnet call throws instead of handing you a key for the wrong network.

## Signing

`signMessage` hashes with the `"\x18Bitcoin Signed Message:\n"` preamble, the one Bitcoin Core uses, and signs with secp256k1. By default you get 64 bytes of `r||s` hex. `verifyMessage` checks it against the public key.

`bitcoin-cli signmessage` prints something else. Base64, with a header byte in front of `r||s` that says how to get the key back. Ask for that one with `recovered`:

```js
const signature = bitcoinChain.signMessage("hello", privateKey, { recovered: true });
// base64, byte for byte what signmessagewithprivkey prints for the same key
bitcoinChain.verifyMessage("hello", signature, publicKey); // true

const signer = bitcoinChain.recoverMessageSigner("hello", signature);
// { publicKey: "02...", addressType: "legacy" }
bitcoinChain.getAddress(signer.publicKey, signer.addressType); // 1...
```

Got a signature and an address, but no key? That's what `recoverMessageSigner` is for. The header sets the key's encoding and, under BIP137, its address type. 27 to 34 is P2PKH, 35 to 38 P2SH-P2WPKH, 39 to 42 P2WPKH. Electrum ignores that and signs SegWit under a P2PKH header, so `keys_message_recover` matches a compressed key from such a header against all three. One catch. Any well formed signature recovers some key for any message. Wrong message, different key, no error. The address match is the real check.

## Proving a bc1 address with BIP322

`signmessage` stops at P2PKH. So how does the owner of a `bc1q` or `bc1p` address prove it? BIP322. The wallet signs a fake transaction that spends from the address. The witness of that spend is the signature. `@agntn/keys/bip322` checks it:

```js
import { sign, verify } from "@agntn/keys/bip322";

verify("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", "Hello World", "smpAkcwRAIg...");
// { state: "valid", format: "simple", addressType: "segwit", publicKey: "02c7f1...", lockTime: 0, sequence: 0 }

sign("Hello World", privateKey, "taproot"); // "smp..."
```

Three answers, not two. `valid`, `invalid`, or `inconclusive` when only a script interpreter could tell. P2WPKH, Taproot key path, P2SH-P2WPKH and P2PKH get the full check. Multisig, P2WSH and Taproot script paths get their hashes checked. A script that doesn't match the address is `invalid`. One that matches still needs running, so `inconclusive`, reason included. Same for proof of funds. Never `valid` on a guess.

The prefix names the format. `smp` is just the witness, `ful` the whole signed transaction. No prefix? It reads as simple, the way signers wrote it before the BIP was final. A P2PKH address also takes the old `signmessage` base64. `sign` writes `smp` for segwit and taproot, `ful` for p2sh and legacy. MCP and Pi call them `keys_bip322_verify` and `keys_bip322_sign`.

## Recovering a key from a reused nonce

ECDSA has one rule. Every signature gets a fresh nonce. Reuse it once and the key is gone. Two signatures with the same `r` over different digests, a bit of algebra, done. Sounds rare? Transaction `9ec4bc49...` from 2012 signs both of its inputs with one `r`.

The algebra is the easy part. The real work is `z`, the sighash each signature signs. `@agntn/keys/transaction` reads it out of the raw transaction:

```js
import { recoverReusedNonce } from "@agntn/keys/secp256k1";
import { extractSignatures } from "@agntn/keys/transaction";

const p2pkh = "76a91470792fb74a5df745bac07df6fe020f871cbb293b88ac";
const spent = [{ script: p2pkh, value: 130000 }, { script: p2pkh, value: 20000 }];
const [first] = extractSignatures(rawTx, 0, spent);
const [second] = extractSignatures(rawTx, 1, spent);
// both: { type: "ecdsa", r: "d47ce4c0...", s, z, hashType: 1, publicKey: "04dbd0c6..." }

recoverReusedNonce(first, second); // { privateKey, nonce, publicKey: "03dbd0c6..." }
```

`spent` is what each input spends. Grab the script and the value from any explorer. Legacy, SegWit v0 and Taproot key path all work, with every hash type. That 2012 transaction even has DER from before BIP66, and it reads fine. Taproot wants every spent output, unless it signs with `ANYONECANPAY`. Script paths and `OP_CODESEPARATOR` get refused, not guessed.

Schnorr leaks the same way. Pass `type: "schnorr"` and the x-only key. The key comes back only after both signatures verify under it, so no lucky false positives. Agents get `keys_transaction_signatures_extract` and `keys_secp256k1_nonce_recover`. The second one names the public key and keeps the private one to itself.

## Where it lives

`src/blockchains/bitcoin.ts` holds the network table and the preamble. The five formats, validation and purpose inference sit in `AbstractBitcoinBlockchain` in `src/utils/bitcoin.ts`, shared with Litecoin and Bitcoin Gold. Keys and message hashing come from `AbstractBitcoinMessageBlockchain` under it, which Bitcoin Cash, Bitcoin SV, Dash, Dogecoin, Zcash and eCash share too; Bitcoin SV, Dash and Dogecoin reach it through `AbstractBitcoinP2PKHBlockchain`, Bitcoin Cash and eCash through `AbstractCashAddrBlockchain`. The hashing and encoding helpers below that are `src/utils/address.ts` and `src/utils/encoding.ts`, shared with TRON and the custom chain example.
