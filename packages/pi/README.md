# @agntn/keys: Pi extension

Pi coding agent extension exposing the [`@agntn/keys`](../../README.md) library as 15 agent tools for key generation, WIF conversion, BIP39 entropy encoding, inspection and recovery, address derivation, validation, signing, and BIP44 paths across 10 blockchains (Bitcoin, Litecoin, Decred, Ethereum, Base, Solana, Aptos, TRON, SUI, Cardano).

> [!WARNING]
> **This extension is experimental.** The package name, public API, provider model, CLI flags, and tool surfaces may change before the first stable release. Pin exact versions if you build on it now.

## Tools

| Tool                         | Purpose                                                        |
| ---------------------------- | -------------------------------------------------------------- |
| `keys_encode_wif`            | Export a disposable private key as native BTC, LTC or DCR WIF  |
| `keys_decode_wif`            | Read native WIF into a hex key, network and compression flag   |
| `keys_generate_wallet`       | Generate private key + public key + address for a chain        |
| `keys_derive_wallet`         | Derive public key + address from an existing private key       |
| `keys_derive_hd_wallet`      | Derive public key + address from a mnemonic and path           |
| `keys_inspect_mnemonic`      | Validate a BIP39 mnemonic and recover its entropy              |
| `keys_encode_bip39_entropy`  | Encode hexadecimal entropy as an English BIP39 mnemonic        |
| `keys_lookup_bip39_indices`  | Map numeric positions to words in an official BIP39 list       |
| `keys_lookup_bip39_words`    | Search an official word list and report 0- and 1-based indices |
| `keys_recover_mnemonic_word` | List words allowed by the checksum for one missing position    |
| `keys_get_address`           | Derive an address from a public key                            |
| `keys_validate_address`      | Check if an address is valid for a chain                       |
| `keys_sign_message`          | Sign a message with a private key (secp256k1/ed25519)          |
| `keys_verify_message`        | Verify a signature against message + public key                |
| `keys_bip44_path`            | Generate or parse a BIP44 derivation path                      |

## Repository status

The extension stays in this repository. It is not registered or included in the npm package. Its handling of plaintext private keys must be redesigned before distribution.

The extension loads the shared executors from `dist/tool-operations.mjs`; in a checkout it uses `src/tool-operations.ts`. MCP and Pi therefore run the same boundary checks and produce the same answers.

## Requirements

- A built library (`pnpm build`) for production resolution of the `@agntn/keys` import.
- Dev deps `@earendil-works/pi-coding-agent`, `@earendil-works/pi-tui`, `typebox`.

Both WIF tools require a chain and default to mainnet. Encoding defaults to compressed keys; decoding preserves the encoded flag. Bitcoin and Litecoin testnet WIFs overlap, so decoding checks the requested context rather than identifying ownership. Decred supports compressed ECDSA keys only.

## Security note

`keys_generate_wallet` returns a plaintext private key, while `keys_derive_wallet` and `keys_sign_message` accept one. The BIP39 tools accept words or complete and partial phrases, and may return equivalent entropy, indices, or words allowed by the checksum. WIF tools convert between two equivalent secret representations, neither encrypted. Tool arguments and output land in the agent transcript.

> [!CAUTION]
> **Never use this with real funds or with any wallet that has ever been used.** Treat every key it touches as burned the moment it appears in tool output. Generate fresh throwaway keys for testing only; assume anything passing through this extension is compromised and discard it. Keys that control real funds belong on a hardware wallet, never in an agent transcript.
