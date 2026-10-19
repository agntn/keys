---
title: Polkadot
icon: i-token-dot
description: sr25519 and ed25519 keys to Polkadot and Kusama SS58 addresses. BIP39 words walk hard and soft junctions the way subkey and polkadot.js do.
seo:
  title: Polkadot and Kusama SS58 addresses from keys and BIP39 words
---

::chain-facts{driver="polkadot" curve="sr25519, ed25519" formats="SS58 under any network prefix" coin="354"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const polkadot = useBlockchain(await blockchains.polkadot()());
const kusama = useBlockchain(await blockchains.polkadot({ ss58Prefix: 2 })());
const westend = useBlockchain(await blockchains.polkadot({ network: "testnet" })());
```

One class for every Substrate chain. The chain shows up as a number in front of the key. 0 is Polkadot, 2 is Kusama, 42 is the generic Substrate format. `network: "testnet"` picks 42, which is what Westend and Paseo use.

## sr25519 or ed25519?

Same words, two curves, two addresses. Wallets start new accounts on sr25519, Schnorr signatures over Ristretto255. So that's the default here too, and polkadot.js lands on the same address for the same key.

ed25519 is one option away. `addressType` or `scheme` picks it, the same way Sui and the XRP Ledger pick their curve:

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";

polkadot.deriveWallet(privateKey).address;
// 12KMynug1KE977ArE9vEXrGAf8qsCejt5BvG9HS3yKNq1Lbk
polkadot.deriveWallet(privateKey, { addressType: "ed25519" }).address;
// 12jacCzszzdckmb7pYNSGxy61nUwP9nrNefP92AFpKP62N46
```

Both are SS58 and both validate. Which one is yours? The one your wallet shows. Anything this driver wrote before it learned sr25519 sits on ed25519.

## What's in an address?

The prefix, the public key itself and two checksum bytes, in base58. No hash of the key at all. The account is the key, whichever curve made it.

```js
const publicKey = polkadot.getKeyPublic(privateKey);

polkadot.getAddress(publicKey); // 12KMynug1KE977ArE9vEXrGAf8qsCejt5BvG9HS3yKNq1Lbk
kusama.getAddress(publicKey); // DtgVmzUmtybRDyn3DgHHeo1x78TK1zvT52XNeieu2Zoa1de
westend.getAddress(publicKey); // 5DP4qTec9XxffaALGWsEPhS1oWrDWMBjzhBmyzShREMJpymt
```

Three addresses, one key. The only blake2b in there is the checksum, and it hashes the string `SS58PRE` in front of everything. Yes, really.

Prefixes up to 63 take one byte, the rest up to 16383 take two. 46 and 47 are reserved, so they throw when you load the chain. `validateAddress` wants the checksum and this instance's prefix:

```js
polkadot.validateAddress("12KMynug1KE977ArE9vEXrGAf8qsCejt5BvG9HS3yKNq1Lbk"); // true
polkadot.validateAddress("DtgVmzUmtybRDyn3DgHHeo1x78TK1zvT52XNeieu2Zoa1de"); // false
```

A Kusama account on Polkadot is `false`, good checksum or not. Only 32-byte accounts pass. Old account indices and 33-byte ECDSA ones don't come from a key here, so they don't validate either.

## Mnemonics

Not BIP32, and not even the BIP39 seed. Substrate runs PBKDF2 over the phrase's entropy, keeps 32 bytes and calls it the mini secret. That's the root key. Below it you walk junctions.

```js
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

polkadot.deriveHDWallet(mnemonic, { path: "m" }).address;
// 13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo
polkadot.deriveHDWallet(mnemonic, { path: "//polkadot//0" }).address;
// 13N3YF2JiKJsHjoEkAesZgiSGa19RgDrzvzx7pJvhR9UAiCH
polkadot.deriveHDWallet(mnemonic, { path: "//polkadot/0" }).address;
// 15QQjX54qES39Qp8cGuNrmNQn6sPH9Zon2kc91PK49gyWiZN
```

`m` or an empty path is the root. `//name` is a hard junction, `/name` a soft one, and a number like `//0` counts as a number. The `///password` of a Substrate URI goes in `passphrase`, not in the path.

### Why soft junctions?

They're the sr25519 party trick. A soft child's public key follows from its parent's public key alone, no secret needed. ed25519 can't do that, so a soft junction throws there and only `//hard` ones walk.

### What's the private key?

At the root it's the 32-byte mini secret, what subkey calls the secret seed. Below it you get 64 bytes, the key and then the nonce schnorrkel signs with. Both go straight back into `deriveWallet` and `signMessage`.

polkadot.js rolls a fresh nonce on every soft step, so that second half never repeats there. Here it's pinned, and the same path gives the same secret twice. The key half and the address match polkadot.js either way.

### What throws?

- A soft junction on ed25519.
- `//0x00`, which is hex to polkadot.js and a name to subkey.
- A number past 64 bits, a 256-bit number to one and a name to the other.

Two implementations, two keys. We'd rather throw than guess which one your wallet used.

Here's a fun one. The checksum never gets into the entropy. Twelve times `abandon` fails the checksum, but with `allowInvalidChecksum` it lands on the exact account above, with a warning.

There's no BIP44 path to build, so `getDerivationPath()` throws. `keys_hd_wallet_scan` won't walk Polkadot either. Wallets name their own junctions, so there's no list to walk.

## Signing

`signMessage` wraps the message in `<Bytes>` and `</Bytes>` first. That's what the polkadot.js extension does in `signRaw`, so polkadot.js verifies what you get back. 64 bytes in hex, on either curve.

```js
const signature = polkadot.signMessage("Hello, Polkadot!", { privateKey });
polkadot.verifyMessage("Hello, Polkadot!", { signature, publicKey }); // true
```

Sign the same message twice on sr25519 and you get two different signatures. That's the random nonce, not a bug. Both verify, so compare verdicts, not bytes. ed25519 with `scheme: "ed25519"` stays deterministic.

`verifyMessage` takes a signature over the raw message too, like polkadot.js `signatureVerify`. Got one from a script that never wrapped anything? It still checks out. Without a `scheme` it tries sr25519 and ed25519, so either kind of account passes.

## Agents

On `chain: "polkadot"` the `prefix` argument is the SS58 number as text, `"2"` for Kusama. `keys_hd_wallet_derive` takes junctions or `m` as its path, and `passphrase` is the URI password.

`addressType` picks the curve on `keys_wallet_generate`, `keys_wallet_derive`, `keys_hd_wallet_derive` and `keys_message_sign`, sr25519 when you leave it out. The 128 hex characters a derived account hands back go right into `privateKey` again.

## Where it lives

`src/blockchains/polkadot.ts`, with SS58 in `src/utils/ss58.ts`, junctions in `src/utils/substrate.ts` and the sr25519 key forms in `src/utils/sr25519.ts`. sr25519 comes from `@agntn/curves`, ed25519 from `@noble/curves`, blake2b and PBKDF2 from `@agntn/hashes`, base58 from `@agntn/encodings`.
