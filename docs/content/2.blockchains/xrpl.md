---
title: XRP Ledger
icon: i-token-xrp
description: Family seeds and BIP39 words to classic r addresses. secp256k1 by default and ed25519 when the seed says so.
seo:
  title: XRP Ledger addresses from family seeds and BIP39 words
---

::chain-facts{driver="xrpl" curve="secp256k1, ed25519" formats="classic r address (base58)" coin="144"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const xrpChain = useBlockchain(await blockchains.xrpl()());
xrpChain.curve; // ['secp256k1', 'ed25519']
```

Mainnet, testnet and devnet write the same addresses. The `network` option changes nothing here.

## Where does an `r` address come from?

From Bitcoin, mostly. The account ID is `RIPEMD160(SHA256(publicKey))`, the hash160 every Bitcoin `1` address starts from. Then it goes through Base58Check under version byte `0`, but in XRPL's own alphabet. Same 58 characters, different order, and that order puts `r` where Bitcoin has `1`.

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = xrpChain.getKeyPublic(privateKey);

xrpChain.getAddress(publicKey); // rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH
```

Bitcoin writes the same key as `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`. Squint. 21 of the 34 characters line up. 35 of the 58 letters sit exactly where Bitcoin keeps them.

## Two curves, one argument

Like [Sui](/blockchains/sui), the address type is the signature scheme. Unlike Sui, secp256k1 is the default. rippled proposes it when nobody asks, and it's the only curve BIP39 words reach.

| Scheme | Public key | Address hashes |
| --- | --- | --- |
| `secp256k1` (default) | 33 bytes, compressed | the key as is |
| `ed25519` | 33 bytes, `ED` then the 32 the curve gives | the key with its `ED` byte |

That `ED` byte is XRPL's, not ours. xrpl.js prints it as `publicKey` too. Same wallet, same hex on both sides.

```js
const wallet = xrpChain.generateWallet(); // secp256k1
const walletEd = xrpChain.generateWallet({}, "ed25519");
walletEd.keys.public; // 'ed...'
```

`getAddress` reads the curve from the key when you leave the type out. Pass an `ED` key as `secp256k1` and it throws and tells you to ask for `ed25519`. Writing an address for a key that can't sign for it would be worse.

## Family seeds

This is the secret XRPL wallets actually hand out. `s` plus 28 characters means secp256k1, `sEd` plus 28 means ed25519. Inside sit 16 bytes of entropy. `deriveSeedWallet` turns them into account 0 the way rippled does.

```js
xrpChain.deriveSeedWallet("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").address;
// rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh

xrpChain.deriveSeedWallet("sEdSJHdnVumf99WfaHTnU8DaQkx5Q4n").address;
// rGMTQpyhaDwWTqmw4dcYHj5NPJhtWNhtRW
```

The first one is the genesis account. Its seed is the first 16 bytes of SHA-512 over the word `masterpassphrase`. Probably the most public secret on the whole ledger. Fine for a docs page.

secp256k1 takes two steps. A root key comes out of SHA-512Half over the seed and a counter. A second scalar comes from the root's public key, and the two add up mod n. ed25519? One SHA-512Half and done. Both match xrpl.js byte for byte.

The seed's version picks the curve, and an address type overrides it, as `deriveKeypair` allows:

```js
xrpChain.deriveSeedWallet("sp6JdwovBCsiwnMhXuvZGZtPUoGVj", {}, "ed25519").address;
// rGMTQpyhaDwWTqmw4dcYHj5NPJhtWNhtRW, the sEd seed above has the same 16 bytes
```

A mistyped character fails the checksum and throws. It won't hand you some other wallet that happens to decode.

## Validation

```js
xrpChain.validateAddress("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"); // true
xrpChain.validateAddress("XVjUbnJUzL9Vb5zXMPdoFURPqGtaRzBkr5DuJfResXEzcKh"); // false
```

Classic addresses only: `r`, XRPL base58, version `0`, 20 bytes and a checksum that holds. X-addresses pack a destination tag in with the account, so they come back `false` here.

## Mnemonics

BIP32 on secp256k1 at `m/44'/144'/account'/change/index`. `Wallet.fromMnemonic` in xrpl.js takes `m/44'/144'/0'/0/0` when you don't pass a path.

```js
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

xrpChain.deriveHDWallet(mnemonic, "m/44'/144'/0'/0/0").address;
// rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3
```

ed25519 throws. xrpl.js never derives an ed25519 key from BIP39 words, so there's no wallet to match. Want ed25519? Use an `sEd` seed.

Phrase should reach an address, but you don't know where? `keys_hd_wallet_scan` walks `bip44` over accounts and indices.

## Signing

`signMessage` signs like `sign` in ripple-keypairs. secp256k1 signs the SHA-512Half of the message and writes DER, ed25519 signs the message itself.

```js
const signature = xrpChain.signMessage("Hello, XRPL!", privateKey);
// '3044...', DER, the bytes ripple-keypairs gives for this key
xrpChain.verifyMessage("Hello, XRPL!", signature, publicKey); // true
```

Yes, DER. Every other secp256k1 driver here hands back 64 bytes of `r||s`. But ripple-keypairs only reads DER, and a signature it can't read isn't much of a signature. `verifyMessage` reads the curve from the key, `ED` or 32 bytes means ed25519. `{ recovered: true }` throws, XRPL never recovers a key from a `v`.

## Where it lives

`src/blockchains/xrpl.ts` has the seed decoding, the rippled key steps and the signing. The scheme handling is `AbstractDualCurveBlockchain` in `src/utils/dual-curve.ts`, which it shares with Sui. Base58 comes from `@agntn/encodings`, SHA-512 and hash160 from `@agntn/hashes`.
