---
title: Cardano
icon: i-simple-icons-cardano
description: ed25519 with bech32 base, enterprise, and stake addresses. Mnemonic derivation is refused on purpose.
---

::chain-facts{driver="cardano" curve="ed25519" formats="bech32 base, enterprise, stake" coin="1815"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const cardanoChain = useBlockchain(await blockchains.cardano()());
const preprod = useBlockchain(await blockchains.cardano({ network: "testnet" })());
```

## Three address types

Cardano hashes the public key with Blake2b-224 and puts a header byte in front: the address type in the high nibble, the network id in the low one. Then bech32.

| Type | Mainnet | Testnet | Payload |
| --- | --- | --- | --- |
| base (default, also `payment`) | `addr1...` | `addr_test1...` | payment hash + stake hash, 57 bytes |
| `enterprise` | `addr1...` | `addr_test1...` | payment hash only, 29 bytes |
| `stake` | `stake1...` | `stake_test1...` | stake hash, 29 bytes |

```js
const publicKey = cardanoChain.getKeyPublic(privateKey);

cardanoChain.getAddress(publicKey); // base
cardanoChain.getAddress(publicKey, "enterprise");
cardanoChain.getAddress(publicKey, "stake");
```

One honest caveat about the base address. A real base address carries two different hashes, the payment key and the stake key, and a wallet derives them from two paths. This driver has one key, so it uses the same hash for both halves. The address is valid and spendable with that key, but its stake half points at the payment key, which is not how a full wallet lays things out. Use `enterprise` when you want an address with no staking story at all.

Testnet is a constructor option, not an address type. Preprod and preview both use network id 0, so one driver covers them.

## Validation

```js
cardanoChain.validateAddress(
  "addr1q9kytfmxk3vdze7s5prpnrjl6j3qldqssvn7mkcpnpvd2p0ltsyswunewxmf58504d9tkqelz2vf02w0msgtvcuzdmsdhq0z4",
); // true
```

bech32 decode, then the header byte has to match the driver's network, and the length has to match the type: 57 bytes for base, 29 for enterprise and stake. A mainnet driver rejects `addr_test` addresses.

## Mnemonics

`deriveHDWallet` throws. Cardano wallets follow CIP-1852, which starts from the BIP39 entropy and runs it through a different key derivation than BIP32 or SLIP-10. Faking it from the BIP39 seed would produce addresses that Daedalus, Lace, and Eternl have never heard of, and a library that quietly does that is worse than one that refuses. So it refuses.

## Signing

Plain ed25519 over the message bytes, hex out. Not the CIP-8 envelope that dapps use for wallet login.
