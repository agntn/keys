---
title: eCash
icon: i-token-xec
description: Bitcoin Cash's CashAddr under the ecash prefix and Bitcoin ABC's own message preamble. One address type and none of the CashTokens types.
---

::chain-facts{driver="ecash" curve="secp256k1" formats="legacy P2PKH in CashAddr" coin="899"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const xecChain = useBlockchain(await blockchains.ecash()());
const testnet = useBlockchain(await blockchains.ecash({ network: "testnet" })());
```

Mainnet and testnet only, anything else throws in the constructor. Regtest has its own `ecregtest` prefix, and there's no driver for it.

## The address

eCash split off Bitcoin Cash in 2020 and kept the address format. The hash is Bitcoin's, `RIPEMD160(SHA256(pubkey))`, the version byte and the 40-bit checksum are CashAddr's. What changes is the prefix, and since the checksum is taken over the prefix, the rest of the string changes with it.

| Network | Prefix | Starts with |
| --- | --- | --- |
| mainnet | `ecash` | `ecash:q` |
| testnet | `ectest` | `ectest:q` |

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = xecChain.getKeyPublic(privateKey);

xecChain.getAddress(publicKey); // ecash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cacy2kzvq
testnet.getAddress(publicKey); // ectest:qp63uahgrxged4z5jswyt5dn5v3lzsem6cmn623003
```

Put that next to `bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h`. The payload is the same up to the last eight characters, the checksum. Same key, same hash, and Bitcoin shows it as `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`.

`legacy` is the only type and it means pay to pubkey hash, written as CashAddr. Ask for `"p2sh"`, `"segwit"` or anything else and `getAddress` throws a `RangeError`, for the same reason as on [Bitcoin Cash](/blockchains/bitcoincash): Bitcoin's `p2sh` type wraps a segwit program, and there's no segwit here.

## Validation

```js
xecChain.validateAddress("ecash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cacy2kzvq"); // true
xecChain.validateAddress("qp63uahgrxged4z5jswyt5dn5v3lzsem6cacy2kzvq"); // true, prefix left off
xecChain.validateAddress("bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h"); // false
```

It decodes CashAddr the same way the Bitcoin Cash driver does: optional prefix, one case over the whole string, checksum under the driver's own prefix. The difference is what counts as payable. Bitcoin ABC turns two things into a destination, a 20 byte key hash under type 0 and a 20 byte script hash under type 1, and nothing else. The token types and the 32 byte script hashes that CashTokens brought to Bitcoin Cash came after the split, so a `z...` or `r...` payload under `ecash:` checksums fine and still comes back `false`.

Base58 is refused too. Its bytes say Bitcoin.

## Mnemonics

BIP32 on `m/44'/899'/account'/change/index`, the coin type SLIP-0044 gives XEC and the one Electrum ABC and Trezor use. Not every wallet agrees. Cashtab walks `m/44'/1899'/0'/0/0`, and wallets made before the split walk Bitcoin Cash's `m/44'/145'`. `deriveHDWallet` takes whatever path you give it, so pass the one your wallet used.

```js
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

xecChain.deriveHDWallet(mnemonic, "m/44'/899'/0'/0/0").address;
// ecash:qpluxjhhlxfjwsymf9nmctvsdrwzwygadsh2pq0ang
xecChain.deriveHDWallet(mnemonic, "m/44'/145'/0'/0/0").address;
// ecash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnqdxfumtxd, what bip_utils gives on that path
```

WIF is Bitcoin's, prefix `0x80`. `encodeWIF(privateKey, { chain: "bitcoin" })` gives the string an eCash wallet imports.

## Signing

This is where eCash and Bitcoin Cash part ways. Bitcoin ABC signs under `"\x16eCash Signed Message:\n"`, not Bitcoin's preamble. The digest is built the usual way, compact size lengths and double SHA-256, but with a different preamble the hash is different. A Bitcoin Cash signature doesn't verify here and the other way around.

The signature is 64 bytes of `r||s` hex. A signature from ecash-lib verifies, but don't expect the same bytes from the same key, because ecash-lib picks a different nonce. `{ recovered: true }` throws, like on Bitcoin, since the node's recoverable form is base64 with a header byte.

## Where it lives

`src/blockchains/ecash.ts` has the prefixes, the hash lengths Bitcoin ABC pays to and the preamble. Everything else comes from `AbstractCashAddrBlockchain` in `src/utils/bitcoin.ts`, which it shares with Bitcoin Cash. The CashAddr codec is in `src/utils/cashaddr.ts`.
