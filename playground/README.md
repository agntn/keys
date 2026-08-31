# @agntn/keys Playground

This folder contains example code and experiments demonstrating the usage of @agntn/keys library features. It's perfect for understanding how to integrate the library into your own projects or to explore new features before they're fully documented.

## Contents

- `lazy-class-demo.ts` - Lazy-loads and constructs concrete blockchain classes
- `signing-demo.ts` - Signs and verifies messages with EVM and Ed25519 classes
- `bip44-demo.ts` - Uses concrete classes to compare BIP44 paths across all supported chains
- `bip32-demo.ts` - Demonstrates BIP32 hierarchical deterministic key derivation
- `bip39-demo.ts` - Generates mnemonics and derives multi-chain seed material
- `slip10-demo.ts` - Demonstrates hardened Ed25519 derivation with SLIP-0010

## Running Examples

Run any example through the project script:

```bash
pnpm playground playground/lazy-class-demo.ts
```

## Notes

- Examples in this folder are for demonstration purposes only and may not include all security best practices
- For production use, refer to the main library documentation and tests
- Feel free to modify and experiment with these examples to better understand the library's capabilities
