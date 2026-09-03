---
title: Ethereum
icon: i-simple-icons-ethereum
description: secp256k1 with EIP-55 checksummed addresses and personal_sign message signatures.
---

::chain-facts{driver="ethereum" curve="secp256k1" formats="EIP-55 hex" coin="60"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const ethereumChain = useBlockchain(await blockchains.ethereum()());
```

## The address

Uncompressed public key without the `04`, Keccak-256, last 20 bytes, `0x`, then the EIP-55 case checksum.

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = ethereumChain.getKeyPublic(privateKey);

ethereumChain.getAddress(publicKey); // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
```

Yes, that is the address of private key `1`. It shows up in a lot of test suites.

## Validation

```js
ethereumChain.validateAddress("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"); // true
ethereumChain.validateAddress("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"); // true, no checksum to check
ethereumChain.validateAddress("0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf"); // false, bad checksum
```

Lowercase and uppercase pass, mixed case has to match. A rejected mixed case address is almost always a copy and paste that lost a character somewhere, so treat `false` as "look at it again", not as "this address does not exist".

## Signing

`signMessage` prepends `"\x19Ethereum Signed Message:\n" + length`, hashes with Keccak-256, and signs with secp256k1. That is `personal_sign`, so the signature verifies in MetaMask, ethers, viem, and anything else that follows EIP-191.

```js
const signature = ethereumChain.signMessage("hello", privateKey);
ethereumChain.verifyMessage("hello", signature, publicKey); // true
```

## One driver, every EVM chain

Ethereum is `AbstractEVMBlockchain` with a name and coin type 60. Base is the same class with a different name. The [EVM guide](/guide/evm) explains why one private key gives one address on every EVM chain and how to add another one in two lines.
