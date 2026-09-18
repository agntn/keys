---
title: Sui
icon: i-token-sui
description: ed25519 or secp256k1 on one chain. Blake2b over a flag byte and the public key.
---

::chain-facts{driver="sui" curve="ed25519, secp256k1" formats="0x hex (Blake2b)" coin="784"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const suiChain = useBlockchain(await blockchains.sui()());
suiChain.curve; // ['ed25519', 'secp256k1']
```

## Two curves, one argument

Sui accepts several signature schemes and tags each key with a flag byte. The driver supports two of them:

| Scheme | Flag | Public key |
| --- | --- | --- |
| `ed25519` (default) | `0x00` | 32 bytes |
| `secp256k1` | `0x01` | 33 bytes, compressed |

secp256r1 (`0x02`) and multisig (`0x03`) aren't implemented.

The address is `Blake2b-256(flag + publicKey)` with `0x` in front. Because the flag is part of the hash, the same private key gives two unrelated addresses depending on the scheme.

```js
// ed25519, the default
const wallet = suiChain.generateWallet();

// secp256k1: the address type doubles as the scheme
const walletSecp = suiChain.generateWallet({}, "secp256k1");
```

Passing `"secp256k1"` as the address type sets the scheme for the key as well, so `generateWallet`, `deriveWallet`, and `deriveHDWallet` all stay consistent with one argument. When you go step by step you have to say it twice:

```js
const secpKey = suiChain.getKeyPublic(privateKey, { scheme: "secp256k1" });
const secpAddress = suiChain.getAddress(secpKey, "secp256k1");
```

Forget the second one and you hash a secp256k1 key with the ed25519 flag. The result validates, looks fine, and no key can ever spend from it. This is the single easiest way to lose funds with this package, which is why the wallet methods take the scheme once.

## Validation

```js
suiChain.validateAddress("0x7e08ac7940568c91564ddc6f5f3bf91b15a9334194ab7855daeac51c5cc74936"); // true
suiChain.validateAddress("7e08ac7940568c91564ddc6f5f3bf91b15a9334194ab7855daeac51c5cc74936"); // false
```

`0x` and 64 hex characters, any case. No checksum, same caveat as Aptos.

## Mnemonics

ed25519 goes through SLIP-10 and needs every segment hardened, `m/44'/784'/0'/0'/0'`. secp256k1 goes through BIP32 and takes the usual `m/54'/784'/0'/0/0` shape. Pass the scheme as the address type and the driver picks the right derivation:

```js
suiChain.deriveHDWallet(mnemonic, "m/44'/784'/0'/0'/0'").address; // ed25519
suiChain.deriveHDWallet(mnemonic, "m/54'/784'/0'/0/0", {}, "secp256k1").address;
```

## Signing

`signMessage` signs what the Sui SDK's `signPersonalMessage` signs: the message as a BCS byte vector behind the `PersonalMessage` intent (`0x03 0x00 0x00`), hashed with Blake2b-256. ed25519 signs that digest as is, secp256k1 signs its SHA-256 the way `Secp256k1Keypair` does, so the same key gives the same bytes here and there. The scheme comes from the options, ed25519 by default.

```js
const signature = suiChain.signMessage("hello", privateKey);
suiChain.verifyMessage("hello", signature, publicKey); // true

const secpSignature = suiChain.signMessage("hello", privateKey, { scheme: "secp256k1" });
suiChain.verifyMessage("hello", secpSignature, secpKey, { scheme: "secp256k1" }); // true
```

What comes back is the 64 signature bytes in hex, `r||s` without a recovery byte on secp256k1, no flag and no public key. Sui tooling wants the serialized form, `flag || signature || publicKey` in base64, so build that before you hand it to `verifyPersonalMessageSignature`:

```js
import { toBase64 } from "@mysten/sui/utils";
import { verifyPersonalMessageSignature } from "@mysten/sui/verify";
import { hexToBytes } from "@noble/hashes/utils.js";

const flag = 0x00; // 0x01 for secp256k1
const serialized = toBase64(
  Uint8Array.from([flag, ...hexToBytes(signature), ...hexToBytes(publicKey)]),
);
await verifyPersonalMessageSignature(new TextEncoder().encode("hello"), serialized, { address });
```
