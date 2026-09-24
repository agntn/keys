# @agntn/keys: Pi extension

Pi coding agent extension exposing the [`@agntn/keys`](../../README.md) library as 19 agent tools for key generation, WIF conversion, BIP39 generation, entropy encoding, inspection and recovery, address derivation, validation, signing, and BIP44 paths across 17 blockchains (Bitcoin, Bitcoin Cash, Bitcoin Gold, Bitcoin SV, Litecoin, Dash, Decred, Dogecoin, Zcash, Ethereum, Base, Solana, Stellar, Aptos, TRON, SUI, Cardano).

> [!WARNING]
> **This extension is experimental.** The package name, public API, provider model, CLI flags, and tool surfaces may change before the first stable release. Pin exact versions if you build on it now.

## Tools

| Tool                          | Purpose                                                            |
| ----------------------------- | ------------------------------------------------------------------ |
| `keys_derive_electrum_wallet` | Derive a Bitcoin address from an explicit Electrum phrase and path |
| `keys_derive_bip39_seed`      | Derive seed hex from a valid mnemonic and optional passphrase      |
| `keys_convert_public_key`     | Convert secp256k1 public keys between SEC1 encodings               |
| `keys_encode_wif`             | Export a disposable private key as native BTC, LTC or DCR WIF      |
| `keys_decode_wif`             | Read native WIF into a hex key, network and compression flag       |
| `keys_generate_wallet`        | Generate private key + public key + address for a chain            |
| `keys_derive_wallet`          | Derive public key + address from an existing private key           |
| `keys_derive_hd_wallet`       | Derive public key + address from a mnemonic and path               |
| `keys_generate_mnemonic`      | Generate a disposable English BIP39 mnemonic                       |
| `keys_inspect_mnemonic`       | Validate a BIP39 mnemonic and recover its entropy                  |
| `keys_encode_bip39_entropy`   | Encode hexadecimal entropy as an English BIP39 mnemonic            |
| `keys_lookup_bip39_indices`   | Map numeric positions to words in an official BIP39 list           |
| `keys_lookup_bip39_words`     | Search an official word list and report 0- and 1-based indices     |
| `keys_recover_mnemonic_word`  | List words allowed by the checksum for one missing position        |
| `keys_get_address`            | Derive an address from a public key                                |
| `keys_validate_address`       | Check if an address is valid for a chain                           |
| `keys_sign_message`           | Sign a message with a private key (secp256k1/ed25519)              |
| `keys_verify_message`         | Verify a signature against message + public key                    |
| `keys_bip44_path`             | Generate or parse a BIP44 derivation path                          |

## BIP39 seed

`keys_derive_bip39_seed` takes `mnemonic`, optional `passphrase` and optional `language` (English by default). It returns a 64-byte seed as hex, not a master private key. All 10 official lists are supported, with checksum validation required. Mnemonic whitespace is collapsed, passphrase whitespace is preserved, and NFKD applies to both. Each text input is capped at 4096 characters. Inputs and the returned seed enter the transcript, so use only public or disposable material.

## Electrum wallets

`keys_derive_electrum_wallet` is separate from BIP39. Supply the complete Electrum phrase and exact BIP32 `path`, with an optional `passphrase` and Bitcoin `network`. Standard seeds produce P2PKH addresses, SegWit seeds P2WPKH. The result includes `scheme: "electrum"` and `seedType`, but no seed or private key. Legacy, 2FA and unrecognized versions are rejected. Both phrase and passphrase use Electrum normalization. Inputs are saved in the transcript, so never submit real wallet secrets.

## Puzzle checksum override

`keys_derive_hd_wallet` rejects invalid checksums by default. For public puzzle candidates, set `allowInvalidChecksum: true` explicitly. The tool derives from the supplied words without repairing them and includes a warning in both text and details when the checksum is invalid. English dictionary membership and BIP39 word counts are still required. Whitespace collapsing, NFKD normalization and chain/path restrictions are unchanged.

`keys_inspect_mnemonic` reports `wordCountValid`, `wordlistValid` and `checksumValid`. The checksum verdict is `null` when word count or dictionary membership prevents checking it. A bad checksum alone is not proof that a puzzle answer is wrong. `keys_recover_mnemonic_word` remains a checksum filter, so it is unsuitable when the target may use an invalid checksum. See the [Movie Enigma example](../../README.md#puzzle-phrases-with-an-invalid-checksum).

## Repository status

The extension stays in this repository. It is not registered or included in the npm package. Its handling of plaintext private keys must be redesigned before distribution.

The extension loads the shared executors from `dist/tool-operations.mjs`; in a checkout it uses `src/tool-operations.ts`. MCP and Pi therefore run the same boundary checks and produce the same answers.

## Requirements

- A built library (`pnpm build`) for production resolution of the `@agntn/keys` import.
- Dev deps `@earendil-works/pi-coding-agent`, `@earendil-works/pi-tui`, `typebox`.

Both WIF tools require a chain and default to mainnet. Encoding defaults to compressed keys; decoding preserves the encoded flag. Bitcoin and Litecoin testnet WIFs overlap, so decoding checks the requested context rather than identifying ownership. Decred supports compressed ECDSA keys only.

`keys_generate_mnemonic` accepts `{ "words": 24 }` for 24 words, or `{}` for the default 12. The other supported lengths are 15, 18 and 21 words. It generates fresh cryptographic randomness rather than asking the model for entropy.

## Security note

`keys_generate_wallet` returns a plaintext private key, while `keys_derive_wallet` and `keys_sign_message` accept one. `keys_generate_mnemonic` returns a plaintext mnemonic. Other BIP39 tools accept words or complete and partial phrases, and may return equivalent entropy, indices, or words allowed by the checksum. WIF tools convert between two equivalent secret representations, neither encrypted. Tool arguments and output land in the agent transcript.

> [!CAUTION]
> **Never use this with real funds or with any wallet that has ever been used.** Treat every key it touches as burned the moment it appears in tool output. Generate fresh throwaway keys for testing only; assume anything passing through this extension is compromised and discard it. Keys that control real funds belong on a hardware wallet, never in an agent transcript.
