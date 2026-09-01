# @agntn/keys: Pi extension

Pi coding agent extension exposing the [`@agntn/keys`](../../README.md) library as 10 agent tools for key generation, BIP39 inspection and recovery, address derivation, validation, signing, and BIP44 paths across 8 blockchains (Bitcoin, Ethereum, Base, Solana, Aptos, TRON, SUI, Cardano).

> [!WARNING]
> **This extension is experimental.** The package name, public API, provider model, CLI flags, and tool surfaces may change before the first stable release. Pin exact versions if you build on it now.

## Tools

| Tool                         | Purpose                                                        |
| ---------------------------- | -------------------------------------------------------------- |
| `keys_generate_wallet`       | Generate private key + public key + address for a chain        |
| `keys_derive_wallet`         | Derive public key + address from an existing private key       |
| `keys_inspect_mnemonic`      | Validate a BIP39 mnemonic and recover its entropy              |
| `keys_lookup_bip39_words`    | Search an official word list and report 0- and 1-based indices |
| `keys_recover_mnemonic_word` | List words allowed by the checksum for one missing position    |
| `keys_get_address`           | Derive an address from a public key                            |
| `keys_validate_address`      | Check if an address is valid for a chain                       |
| `keys_sign_message`          | Sign a message with a private key (secp256k1/ed25519)          |
| `keys_verify_message`        | Verify a signature against message + public key                |
| `keys_bip44_path`            | Generate or parse a BIP44 derivation path                      |

## Repository status

The extension stays in this repository. It is not registered or included in the npm package. Its handling of plaintext private keys must be redesigned before distribution.

The source imports the built library from `dist/` (`@agntn/keys`); in development before a build it falls back to `src/index.ts`.

## Requirements

- A built library (`pnpm build`) for production resolution of the `@agntn/keys` import.
- Dev deps `@earendil-works/pi-coding-agent`, `@earendil-works/pi-tui`, `typebox`.

## Security note

`keys_generate_wallet` returns a plaintext private key, while `keys_derive_wallet` and `keys_sign_message` accept one. The BIP39 tools accept words or complete and partial phrases, and may return equivalent entropy, indices, or words allowed by the checksum. Tool arguments and output land in the agent transcript.

> [!CAUTION]
> **Never use this with real funds or with any wallet that has ever been used.** Treat every key it touches as burned the moment it appears in tool output. Generate fresh throwaway keys for testing only; assume anything passing through this extension is compromised and discard it. Keys that control real funds belong on a hardware wallet, never in an agent transcript.
