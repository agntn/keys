---
title: Sui
icon: i-simple-icons-sui
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

secp256r1 (`0x02`) and multisig (`0x03`) are not implemented.

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

ed25519 or secp256k1 depending on the scheme in the options, hex out. The signature does not carry the flag byte, so keep track of which scheme signed if you hand it to Sui tooling.
