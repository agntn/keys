# @agntn/keys: Pi extension

Pi coding agent extension exposing the [`@agntn/keys`](../../README.md) library as agent tools for key generation, WIF conversion, BIP38 inspection, BIP39 generation, entropy encoding, inspection and recovery, address derivation, validation, signing, and BIP44 paths across 18 blockchains (Bitcoin, Bitcoin Cash, Bitcoin Gold, Bitcoin SV, Litecoin, Dash, Decred, Dogecoin, Zcash, eCash, Ethereum, Base, Solana, Stellar, Aptos, TRON, SUI, Cardano).

> [!WARNING]
> **This extension is experimental.** The package name, public API, provider model, CLI flags, and tool surfaces may change before the first stable release. Pin exact versions if you build on it now.

## Tools

| Tool                                | Purpose                                                            |
| ----------------------------------- | ------------------------------------------------------------------ |
| `keys_electrum_wallet_derive`       | Derive a Bitcoin address from an explicit Electrum phrase and path |
| `keys_bip39_seed_derive`            | Derive seed hex from a valid mnemonic and optional passphrase      |
| `keys_secp256k1_public_key_convert` | Convert secp256k1 public keys between SEC1 encodings               |
| `keys_wif_encode`                   | Export a disposable private key as native BTC, LTC or DCR WIF      |
| `keys_wif_decode`                   | Read native WIF into a hex key, network and compression flag       |
| `keys_bip38_inspect`                | Read a BIP38 key's header and check an address, no passphrase      |
| `keys_wallet_generate`              | Generate private key + public key + address for a chain            |
| `keys_wallet_derive`                | Derive public key + address from an existing private key           |
| `keys_hd_wallet_derive`             | Derive public key + address from a mnemonic and path               |
| `keys_xpub_wallet_derive`           | Derive public key + address from an xpub, ypub or zpub and a path  |
| `keys_bip39_generate`               | Generate a disposable English BIP39 mnemonic                       |
| `keys_bip39_inspect`                | Validate a BIP39 mnemonic and recover its entropy                  |
| `keys_bip39_entropy_encode`         | Encode hexadecimal entropy as an English BIP39 mnemonic            |
| `keys_bip39_indices_lookup`         | Map numeric positions to words in an official BIP39 list           |
| `keys_bip39_words_lookup`           | Search an official word list and report 0- and 1-based indices     |
| `keys_bip39_word_recover`           | List words allowed by the checksum for one missing position        |
| `keys_address_get`                  | Derive an address from a public key                                |
| `keys_address_validate`             | Check if an address is valid for a chain                           |
| `keys_message_sign`                 | Sign a message with a private key (secp256k1/ed25519)              |
| `keys_message_verify`               | Verify a signature against message + public key                    |
| `keys_bip44_path`                   | Generate or parse a BIP44 derivation path                          |

## BIP39 seed

`keys_bip39_seed_derive` takes `mnemonic`, optional `passphrase` and optional `language` (English by default). It returns a 64-byte seed as hex, not a master private key. All 10 official lists are supported, with checksum validation required. Mnemonic whitespace is collapsed, passphrase whitespace is preserved, and NFKD applies to both. Each text input is capped at 4096 characters. Inputs and the returned seed enter the transcript, so use only public or disposable material.

## Electrum wallets

`keys_electrum_wallet_derive` is separate from BIP39. Supply the complete Electrum phrase and exact BIP32 `path`, with an optional `passphrase` and Bitcoin `network`. Standard seeds produce P2PKH addresses, SegWit seeds P2WPKH. The result includes `scheme: "electrum"` and `seedType`, but no seed or private key. Legacy, 2FA and unrecognized versions are rejected. Both phrase and passphrase use Electrum normalization. Inputs are saved in the transcript, so never submit real wallet secrets.

`keys_xpub_wallet_derive` takes a `chain`, an `extendedKey` and normal levels below it, such as `m/0/0`. On Bitcoin, Bitcoin Gold and Litecoin the SLIP-0132 prefix picks the address type, and `addressType` overrides it for a BIP84 or BIP49 account exported as `xpub`. Hardened levels and extended private keys are rejected. The key reveals every address of its account and is saved in the transcript.

`keys_wallet_generate`, `keys_wallet_derive`, `keys_hd_wallet_derive`, `keys_xpub_wallet_derive` and `keys_address_get` print an `Address type:` line on chains with more than one format: Bitcoin, Bitcoin Gold, Litecoin, Sui and Cardano. It's the type you passed, the one the path purpose or key prefix picked, or the chain's default, so nobody has to guess it from the first characters of the address.

## Puzzle checksum override

`keys_hd_wallet_derive` rejects invalid checksums by default. For public puzzle candidates, set `allowInvalidChecksum: true` explicitly. The tool derives from the supplied words without repairing them and includes a warning in both text and details when the checksum is invalid. English dictionary membership and BIP39 word counts are still required. Whitespace collapsing, NFKD normalization and chain/path restrictions are unchanged.

`keys_bip39_inspect` reports `wordCountValid`, `wordlistValid` and `checksumValid`. The checksum verdict is `null` when word count or dictionary membership prevents checking it. A bad checksum alone is not proof that a puzzle answer is wrong. `keys_bip39_word_recover` remains a checksum filter, so it is unsuitable when the target may use an invalid checksum. See the [Movie Enigma example](../../README.md#puzzle-phrases-with-an-invalid-checksum).

## Install

`pi install npm:@agntn/keys` for Pi, `omp install @agntn/keys` for OMP. Read the security note below first, it isn't boilerplate.

Installed from npm, the extension loads the shared executors from `dist/tool-operations.mjs`; in a checkout it uses `src/tool-operations.ts`. MCP and Pi therefore run the same boundary checks and produce the same answers.

## Requirements in a checkout

- A built library (`pnpm build`) for production resolution of the `@agntn/keys` import.
- Dev deps `@earendil-works/pi-coding-agent`, `@earendil-works/pi-tui`, `typebox`.

Both WIF tools require a chain and default to mainnet. Encoding defaults to compressed keys; decoding preserves the encoded flag. Bitcoin, Litecoin and Dash testnet WIFs overlap, so decoding checks the requested context rather than identifying ownership. Decred supports compressed ECDSA keys only.

`keys_bip39_generate` accepts `{ "words": 24 }` for 24 words, or `{}` for the default 12. The other supported lengths are 15, 18 and 21 words. It generates fresh cryptographic randomness rather than asking the model for entropy.

## Security note

`keys_wallet_generate` returns a plaintext private key, while `keys_wallet_derive` and `keys_message_sign` accept one. `keys_bip39_generate` returns a plaintext mnemonic. Other BIP39 tools accept words or complete and partial phrases, and may return equivalent entropy, indices, or words allowed by the checksum. WIF tools convert between two equivalent secret representations, neither encrypted. Tool arguments and output land in the agent transcript.

> [!CAUTION]
> **Never use this with real funds or with any wallet that has ever been used.** Treat every key it touches as burned the moment it appears in tool output. Generate fresh throwaway keys for testing only; assume anything passing through this extension is compromised and discard it. Keys that control real funds belong on a hardware wallet, never in an agent transcript.
