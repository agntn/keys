# @agntn/keys: Pi extension

Pi coding agent extension exposing the [`@agntn/keys`](../../README.md) library as agent tools for key generation, brainwallets, WIF conversion, BIP38 inspection and decryption, keystore files, BIP39 generation, entropy encoding, inspection and recovery, address derivation, validation, signing, and BIP44 paths across Bitcoin, Bitcoin Cash, Bitcoin Gold, Bitcoin SV, Litecoin, Dash, Decred, Dogecoin, Zcash, eCash, Ethereum, Base, Solana, Stellar, Aptos, TRON, SUI, Cardano, the XRP Ledger, NEAR, Cosmos SDK chains and Polkadot.

> [!WARNING]
> **This extension is experimental.** The package name, public API, provider model, CLI flags, and tool surfaces may change before the first stable release. Pin exact versions if you build on it now.

## Tools

| Tool                                  | Purpose                                                                 |
| ------------------------------------- | ----------------------------------------------------------------------- |
| `keys_electrum_wallet_derive`         | Derive a Bitcoin address from an Electrum phrase and path or index      |
| `keys_brainwallet_derive`             | Derive a Bitcoin or Ethereum address from a brainwallet recipe          |
| `keys_bip39_seed_derive`              | Derive seed hex from a valid mnemonic and optional passphrase           |
| `keys_secp256k1_public_key_convert`   | Convert secp256k1 public keys between SEC1 encodings                    |
| `keys_secp256k1_nonce_recover`        | Find the key behind two signatures that share a nonce, public half only |
| `keys_wif_encode`                     | Export a disposable private key as native BTC, LTC or DCR WIF           |
| `keys_wif_decode`                     | Read native WIF into a hex key, network and compression flag            |
| `keys_bip38_inspect`                  | Read a BIP38 key's header and check an address, no passphrase           |
| `keys_bip38_decrypt`                  | Open a BIP38 key with its passphrase, WIF only with `revealKey`         |
| `keys_store_decrypt`                  | Open a v3 keystore with its password, address only, never the key       |
| `keys_wallet_generate`                | Generate private key + public key + address for a chain                 |
| `keys_wallet_derive`                  | Derive public key + address from an existing private key                |
| `keys_hd_wallet_derive`               | Derive public key + address from a mnemonic or entropy and path         |
| `keys_hd_wallet_scan`                 | Find which common wallet path takes a mnemonic to an address            |
| `keys_xpub_wallet_derive`             | Derive public key + address from an xpub, ypub or zpub and a path       |
| `keys_bip32_parent_recover`           | Recover a parent from its xpub and one leaked normal child key          |
| `keys_bip39_generate`                 | Generate a disposable English BIP39 mnemonic                            |
| `keys_bip39_inspect`                  | Validate a BIP39 mnemonic and read what its entropy looks like          |
| `keys_bip39_entropy_encode`           | Encode hexadecimal entropy as an English BIP39 mnemonic                 |
| `keys_bip39_indices_lookup`           | Map numeric positions to words in an official BIP39 list                |
| `keys_bip39_words_lookup`             | Report 0- and 1-based indices, expanding prefixes of 3+ letters         |
| `keys_bip39_word_recover`             | List words allowed by the checksum for one missing position             |
| `keys_bip39_words_order`              | List orders of scattered words whose checksum passes                    |
| `keys_bip39_words_repair`             | Fix mistyped words and list the phrases whose checksum passes           |
| `keys_address_get`                    | Derive an address from a public key                                     |
| `keys_address_validate`               | Check if an address is valid for a chain                                |
| `keys_script_address_get`             | P2SH, P2WSH and P2SH-P2WSH addresses of a script or a multisig          |
| `keys_descriptor_derive`              | Addresses and checksum of a Bitcoin output descriptor                   |
| `keys_message_sign`                   | Sign a message with a private key (secp256k1/ed25519)                   |
| `keys_message_verify`                 | Verify a signature against message + public key                         |
| `keys_message_recover`                | Recover key + address from signmessage, personal_sign or EIP-712        |
| `keys_bip322_sign`                    | Sign a BIP322 proof for a legacy, P2SH, SegWit or Taproot address       |
| `keys_bip322_verify`                  | Check a BIP322 proof: valid, invalid or inconclusive with a reason      |
| `keys_transaction_signatures_extract` | Read r, s, sighash z and signer of each signature on an input           |
| `keys_bip44_parse`                    | Parse a BIP44 path into its levels                                      |
| `keys_bip44_generate`                 | Generate the derivation path a chain's wallets use                      |

## BIP39 seed

`keys_bip39_seed_derive` takes `mnemonic`, optional `passphrase` and optional `language` (English by default). It returns a 64-byte seed as hex, not a master private key. All 10 official lists are supported, with checksum validation required. Mnemonic whitespace is collapsed, passphrase whitespace is preserved, and NFKD applies to both. Each text input is capped at 4096 characters. Inputs and the returned seed enter the transcript, so use only public or disposable material.

## Electrum wallets

`keys_electrum_wallet_derive` is separate from BIP39. Supply the complete Electrum phrase and exact BIP32 `path`, with an optional `passphrase` and Bitcoin `network`. Standard seeds produce P2PKH addresses, SegWit seeds P2WPKH. An old seed from before Electrum 2.0 has no path: pass `change` (0 or 1) and `index` instead, both 0 by default. It gives uncompressed P2PKH addresses and also returns the master public key. The result includes `scheme: "electrum"` and `seedType`, but no seed or private key. 2FA and unrecognized versions are rejected. Both phrase and passphrase use Electrum normalization. Inputs are saved in the transcript, so never submit real wallet secrets.

## Salted brainwallets

`keys_brainwallet_derive` wants the whole recipe, no defaults to guess: `passphrase`, `salt` with its `saltEncoding`, `kdf` with its costs (`N`, `r`, `p` for scrypt, `iterations` and `digest` for PBKDF2), `hashed` for what SHA-256 reads after the KDF, and `compressed`. brainwallet.io is scrypt with `N` 262144, `r` 8, `p` 1, `hashed: "hex"` and `compressed: false`. A plain brainwallet skips the salt: `kdf: "sha256"` (brainwallet.org) or `"keccak256"`, with `iterations` for extra rounds. `kdf: "warpwallet"` takes just the salt and runs WarpWallet's fixed costs, so no `N`, `iterations` or `hashed`. `chain: "ethereum"` gives an Ethereum address and drops `compressed`. The answer is the public key and the address, plus a match against an optional `target`. The private key never leaves, but the passphrase sits in the transcript.

`keys_xpub_wallet_derive` takes a `chain`, an `extendedKey` and normal levels below it, such as `m/0/0`. On Bitcoin, Bitcoin Gold and Litecoin the SLIP-0132 prefix picks the address type, and `addressType` overrides it for a BIP84 or BIP49 account exported as `xpub`. Hardened levels and extended private keys are rejected. The key reveals every address of its account and is saved in the transcript.

`keys_wallet_generate`, `keys_wallet_derive`, `keys_hd_wallet_derive`, `keys_xpub_wallet_derive` and `keys_address_get` print an `Address type:` line on chains with more than one format: Bitcoin, Bitcoin Gold, Litecoin, Sui and Cardano. It's the type you passed, the one the path purpose or key prefix picked, or the chain's default, so nobody has to guess it from the first characters of the address.

`keys_wallet_derive` takes an optional `compressed`, `true` by default. Old wallets and brainwallets wrote the uncompressed key, and on the Bitcoin family that's another legacy address from the same private key, so pass `compressed: false` for them. Ethereum, Base and TRON hash the uncompressed key anyway and refuse `true`. Sui on secp256k1 refuses `false`, and the ed25519 chains take no flag at all.

## Puzzle checksum override

`keys_hd_wallet_derive` rejects invalid checksums by default. For public puzzle candidates, set `allowInvalidChecksum: true` explicitly. The tool derives from the supplied words without repairing them and includes a warning in both text and details when the checksum is invalid. Words from the selected list and BIP39 word counts are still required. The list comes from optional `language`, English by default, as in the other BIP39 tools. Whitespace collapsing, NFKD normalization and chain/path restrictions are unchanged.

Got the entropy instead of the words? Pass `entropy` as hex, 16 to 32 bytes, in place of `mnemonic`. The tool spells it with the `language` list and derives from those words, so a puzzle that goes hash, entropy, wallet takes one call, not a detour through `keys_bip39_entropy_encode`. One of the two, never both.

`keys_bip39_inspect` reports `wordCountValid`, `wordlistValid` and `checksumValid`. The checksum verdict is `null` when word count or dictionary membership prevents checking it. A bad checksum alone is not proof that a puzzle answer is wrong. A valid phrase also gets its entropy read as text, as a pattern (all zeros, a repeated byte or block, a handful of distinct bytes, a date in the hex digits or as a Unix timestamp) and as the MD5, SHA-1 or SHA-256 of a short built-in word list, cut to the entropy length. Got candidate answers? Pass them as `preimages` and they're hashed too, byte for byte, so `"Red Blue"` and `"red blue"` are two guesses. `keys_bip39_word_recover` remains a checksum filter, so it is unsuitable when the target may use an invalid checksum. See the [Movie Enigma example](../../README.md#puzzle-phrases-with-an-invalid-checksum).

## Install

`pi install npm:@agntn/keys` for Pi, `omp install @agntn/keys` for OMP. Read the security note below first, it isn't boilerplate.

Installed from npm, the extension loads the tool definitions from `dist/tools.mjs`; in a checkout it uses `src/tools.ts`. MCP, Pi and OMP serve the same definitions through `@agntn/tools`, so they run the same checks and give the same answers.

## Requirements in a checkout

- A built library (`pnpm build`) for production resolution of the `@agntn/keys` import.
- Dev deps `@earendil-works/pi-coding-agent`, `@earendil-works/pi-tui`.

Both WIF tools require a chain and default to mainnet. Encoding defaults to compressed keys; decoding preserves the encoded flag. Bitcoin, Litecoin and Dash testnet WIFs overlap, so decoding checks the requested context rather than identifying ownership. Decred supports compressed ECDSA keys only.

`keys_bip39_generate` accepts `{ "words": 24 }` for 24 words, or `{}` for the default 12. The other supported lengths are 15, 18 and 21 words. It generates fresh cryptographic randomness rather than asking the model for entropy.

## Security note

`keys_wallet_generate` returns a plaintext private key, while `keys_wallet_derive` and `keys_message_sign` accept one. `keys_bip39_generate` returns a plaintext mnemonic. Other BIP39 tools accept words or complete and partial phrases, and may return equivalent entropy, indices, or words allowed by the checksum. WIF tools convert between two equivalent secret representations, neither encrypted. Tool arguments and output land in the agent transcript.

> [!CAUTION]
> **Never use this with real funds or with any wallet that has ever been used.** Treat every key it touches as burned the moment it appears in tool output. Generate fresh throwaway keys for testing only; assume anything passing through this extension is compromised and discard it. Keys that control real funds belong on a hardware wallet, never in an agent transcript.
