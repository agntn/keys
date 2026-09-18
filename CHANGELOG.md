# Changelog

## v0.3.1

[compare changes](https://github.com/agntn/keys/compare/v0.3.0...v0.3.1)

### 🚀 Enhancements

- **stellar:** StrKey addresses, SEP-53 signing ([#68](https://github.com/agntn/keys/pull/68))

### 🩹 Fixes

- **tron:** Sign messages with the TRON preamble ([#66](https://github.com/agntn/keys/pull/66))
- **sui:** Sign what signPersonalMessage signs ([#67](https://github.com/agntn/keys/pull/67))
- **bip44:** Paths ed25519 chains can derive ([#69](https://github.com/agntn/keys/pull/69))

### 🏡 Chore

- Apply automated updates ([e47c015](https://github.com/agntn/keys/commit/e47c015))
- Add `renovate.json` ([5b55d5f](https://github.com/agntn/keys/commit/5b55d5f))

### ✅ Tests

- Ethers and web3.js vectors move to fixtures ([#75](https://github.com/agntn/keys/pull/75))

### ❤️ Contributors

- Ori ([@oritwoen](https://github.com/oritwoen))
- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))

## v0.3.0

[compare changes](https://github.com/agntn/keys/compare/v0.2.0...v0.3.0)

### 🚀 Enhancements

- **deps:** Upgrade to @noble v2 and vitest 4 ([9c5266c](https://github.com/agntn/keys/commit/9c5266c))
- Pi extension for ubichain ([#18](https://github.com/agntn/keys/pull/18))
- **wallets:** Support existing private keys ([#32](https://github.com/agntn/keys/pull/32))
- **hd:** Expose BIP32, BIP39, and SLIP-10 ([#33](https://github.com/agntn/keys/pull/33))
- **pi:** Derive wallets from private keys ([#34](https://github.com/agntn/keys/pull/34))
- **pi:** Add BIP39 mnemonic inspection ([#35](https://github.com/agntn/keys/pull/35))
- **pi:** Narrow one missing BIP39 word ([#38](https://github.com/agntn/keys/pull/38))
- **pi:** Look up BIP39 word indices ([#39](https://github.com/agntn/keys/pull/39))
- **bip39:** Search all official word lists ([#41](https://github.com/agntn/keys/pull/41))
- **bip39:** Map indices to words ([#42](https://github.com/agntn/keys/pull/42))
- **pi:** Turn puzzle entropy into BIP39 words ([#43](https://github.com/agntn/keys/pull/43))
- **hd:** One call from mnemonic to wallet ([#44](https://github.com/agntn/keys/pull/44))
- **mcp:** Expose key tools over stdio ([#45](https://github.com/agntn/keys/pull/45))
- Support Litecoin across the library and tools ([#54](https://github.com/agntn/keys/pull/54))
- **decred:** ECDSA wallets with native address checksums ([#55](https://github.com/agntn/keys/pull/55))
- Support WIF for Bitcoin, Litecoin and Decred ([#56](https://github.com/agntn/keys/pull/56))
- Add mnemonic generation to MCP and Pi ([#57](https://github.com/agntn/keys/pull/57))
- **bip39:** Let mnemonic tools select a language ([#58](https://github.com/agntn/keys/pull/58))
- **hd:** Allow invalid checksums for puzzle wallets ([#59](https://github.com/agntn/keys/pull/59))
- Convert public keys without a private key ([#60](https://github.com/agntn/keys/pull/60))
- **tools:** Add BIP39 seed derivation ([#61](https://github.com/agntn/keys/pull/61))
- **docs:** Docus site with a keyspace explorer ([#51](https://github.com/agntn/keys/pull/51))

### 🩹 Fixes

- **tests:** Use same key for address comparison ([5724748](https://github.com/agntn/keys/commit/5724748))
- CODEOWNERS ([e1f9f56](https://github.com/agntn/keys/commit/e1f9f56))
- **bitcoin:** Use Bitcoin message preamble instead of Ethereum's ([#17](https://github.com/agntn/keys/pull/17))
- **evm:** Correct hashWithPreamble for Uint8Array input ([#16](https://github.com/agntn/keys/pull/16))
- **address:** Correct P2SH redeem script buffer size ([#15](https://github.com/agntn/keys/pull/15))
- **addresses:** Align generated addresses with chain references ([d99c964](https://github.com/agntn/keys/commit/d99c964))
- Generate valid secp256k1 private keys ([#20](https://github.com/agntn/keys/pull/20))
- Type SLIP-10 HD keys ([#21](https://github.com/agntn/keys/pull/21))
- Handle malformed verification keys ([#22](https://github.com/agntn/keys/pull/22))
- **bip44:** Path parser accepted garbage levels ([#26](https://github.com/agntn/keys/pull/26))
- **bip44:** Reject invalid generator inputs ([#27](https://github.com/agntn/keys/pull/27))
- **aptos:** Recognize canonical short addresses ([#28](https://github.com/agntn/keys/pull/28))
- **bitcoin:** Accept uppercase Bech32 ([#29](https://github.com/agntn/keys/pull/29))
- **addresses:** Reject invalid public keys ([#30](https://github.com/agntn/keys/pull/30))
- **pi:** Load packaged keys extension ([#31](https://github.com/agntn/keys/pull/31))
- **tron:** Generate valid testnet addresses ([#46](https://github.com/agntn/keys/pull/46))
- **tools:** Reject unsupported wallet options ([#47](https://github.com/agntn/keys/pull/47))
- Reject ambiguous BIP44 tool inputs ([#48](https://github.com/agntn/keys/pull/48))
- **solana:** Keep generated addresses valid ([#49](https://github.com/agntn/keys/pull/49))
- **pi:** Unblock keys tools on Grok ([#50](https://github.com/agntn/keys/pull/50))
- **bitcoin:** Keep address formats consistent across HD paths ([#53](https://github.com/agntn/keys/pull/53))
- **hd:** Keep hardened indices in range ([#62](https://github.com/agntn/keys/pull/62))
- Secp256k1 signatures match Core and ethers ([#63](https://github.com/agntn/keys/pull/63))
- Ed25519 keys from noble, not node:crypto ([#65](https://github.com/agntn/keys/pull/65))

### 💅 Refactors

- **evm:** Extract preamble hashing into helper ([8be0864](https://github.com/agntn/keys/commit/8be0864))
- **blockchains:** DRY lazy factories ([#3](https://github.com/agntn/keys/pull/3))
- Clean up verify error handling ([#5](https://github.com/agntn/keys/pull/5))
- ⚠️ Use abstract blockchain classes ([#19](https://github.com/agntn/keys/pull/19))

### 📖 Documentation

- README with real output, fewer words ([#64](https://github.com/agntn/keys/pull/64))

### 📦 Build

- Migrate to obuild and typescript 6 ([862dc62](https://github.com/agntn/keys/commit/862dc62))

### 🏡 Chore

- Update README.md ([5c3fe82](https://github.com/agntn/keys/commit/5c3fe82))
- Add CODEOWNERS ([1d38cf6](https://github.com/agntn/keys/commit/1d38cf6))
- Add AGENTS.md ([2ec601d](https://github.com/agntn/keys/commit/2ec601d))
- Rewrite readme, add agents.md, migrate to oxlint + oxfmt ([#12](https://github.com/agntn/keys/pull/12))
- Update dependencies ([a5c7767](https://github.com/agntn/keys/commit/a5c7767))
- Rename package to @agntn/keys ([75a4d26](https://github.com/agntn/keys/commit/75a4d26))
- Refresh dependencies and pnpm ([#23](https://github.com/agntn/keys/pull/23))
- Adopt @agntn/ox lint config ([#25](https://github.com/agntn/keys/pull/25))

### 🤖 CI

- Publish keys from version tags ([#52](https://github.com/agntn/keys/pull/52))

#### ⚠️ Breaking Changes

- ⚠️ Use abstract blockchain classes ([#19](https://github.com/agntn/keys/pull/19))

### ❤️ Contributors

- Ori ([@oritwoen](https://github.com/oritwoen))
- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))
- Oritwoen ([@oritwoen](https://github.com/oritwoen))
- Dominik Opyd <dominik.opyd@gmail.com>

## Unreleased

### Changed

- Adopted the `@agntn/keys` package and `agntn/keys` repository identity.
- Kept the experimental Pi extension out of the package until its handling of plaintext private keys is redesigned.

## v0.2.0

[compare changes](https://github.com/agntn/keys/compare/v0.1.5...v0.2.0)

### 🚀 Enhancements

- Add tests for BIP44 path generation, parsing, and blockchain integration ([5dd7aae](https://github.com/agntn/keys/commit/5dd7aae))
- **tests:** Add integration tests for Solana and Ethereum signing compatibility ([54fa891](https://github.com/agntn/keys/commit/54fa891))
- ⚠️ Implement lazy loading ([bd5b6e2](https://github.com/agntn/keys/commit/bd5b6e2))

#### ⚠️ Breaking Changes

- ⚠️ Implement lazy loading ([bd5b6e2](https://github.com/agntn/keys/commit/bd5b6e2))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.1.5

[compare changes](https://github.com/agntn/keys/compare/v0.1.4...v0.1.5)

### 🚀 Enhancements

- Add BIP39 support ([4372a7f](https://github.com/agntn/keys/commit/4372a7f))
- Add BIP44 support with derivation paths and blockchain integration ([893685c](https://github.com/agntn/keys/commit/893685c))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.1.4

[compare changes](https://github.com/agntn/keys/compare/v0.1.3...v0.1.4)

### 🚀 Enhancements

- Add BIP32 support ([d28aabb](https://github.com/agntn/keys/commit/d28aabb))
- Implement SLIP-0010 support with new utilities and demo ([0aab41b](https://github.com/agntn/keys/commit/0aab41b))

### 🩹 Fixes

- Update BIP32 hardened offset constant format and clean up demo code ([e2e3599](https://github.com/agntn/keys/commit/e2e3599))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.1.3

[compare changes](https://github.com/agntn/keys/compare/v0.1.2...v0.1.3)

### 🚀 Enhancements

- Add support for P2WSH addresses and update SegWit address generation in Bitcoin implementation ([f7811e3](https://github.com/agntn/keys/commit/f7811e3))
- Add network option & testnets to blockchain implementations ([7f0a450](https://github.com/agntn/keys/commit/7f0a450))
- Enhance blockchain interface with implementation types and address formats ([eda307a](https://github.com/agntn/keys/commit/eda307a))

### 🩹 Fixes

- Update repository URL format in package.json to include git protocol ([ee7a5d1](https://github.com/agntn/keys/commit/ee7a5d1))

### 💅 Refactors

- Update TypeScript configuration for module handling and resolution ([fc0030c](https://github.com/agntn/keys/commit/fc0030c))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.1.2

[compare changes](https://github.com/agntn/keys/compare/v0.1.1...v0.1.2)

### 🩹 Fixes

- Correct main and module fields in package.json for proper module resolution ([11d0df8](https://github.com/agntn/keys/commit/11d0df8))

### 💅 Refactors

- Enhance blockchain interface and validation methods for improved type safety ([f646ec7](https://github.com/agntn/keys/commit/f646ec7))
- Simplify address prefix handling and improve variable naming in Cardano implementation ([eebd052](https://github.com/agntn/keys/commit/eebd052))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.1.1

[compare changes](https://github.com/agntn/keys/compare/v0.1.0...v0.1.1)

### 🚀 Enhancements

- Implement Cardano blockchain support with address generation and validation ([7a1d7dc](https://github.com/agntn/keys/commit/7a1d7dc))

### 🩹 Fixes

- Update eslint-utils to version 4.6.0 and reorganize dependencies in pnpm-lock.yaml ([bf6c4eb](https://github.com/agntn/keys/commit/bf6c4eb))

### 🏡 Chore

- Add missing newline in scripts section of package.json ([8267842](https://github.com/agntn/keys/commit/8267842))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.1.0

[compare changes](https://github.com/agntn/keys/compare/v0.0.9...v0.0.10)

### 🚀 Enhancements

- Add CI and autofix workflows for automated testing and linting ([1b48f16](https://github.com/agntn/keys/commit/1b48f16))

### 🩹 Fixes

- Add missing types entry in package.json for TypeScript support ([94ed2d6](https://github.com/agntn/keys/commit/94ed2d6))

### 💅 Refactors

- Update key generation options to use KeyOptions type and optimize address checksum calculation ([ab77d28](https://github.com/agntn/keys/commit/ab77d28))
- Update blockchain interface and response types for clarity and consistency ([60fef35](https://github.com/agntn/keys/commit/60fef35))
- Streamline address handling and validation across Aptos, Sui, and Tron implementations ([2cc742f](https://github.com/agntn/keys/commit/2cc742f))
- Enhance Bitcoin address support with SegWit v0 and v1 (Taproot) implementations ([4020b49](https://github.com/agntn/keys/commit/4020b49))
- Simplify error handling and improve code readability across blockchain implementations ([28a2979](https://github.com/agntn/keys/commit/28a2979))

### 🏡 Chore

- Update license year and enhance README with security dependencies and contributing guidelines ([5d757de](https://github.com/agntn/keys/commit/5d757de))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.0.9

[compare changes](https://github.com/agntn/keys/compare/v0.0.8...v0.0.9)

### 🚀 Enhancements

- Add SegWit (bech32) address support and validation to Bitcoin implementation ([b0363ac](https://github.com/agntn/keys/commit/b0363ac))

### 💅 Refactors

- Rename KeyPair to Keys and update related documentation and tests ([1397ce4](https://github.com/agntn/keys/commit/1397ce4))

### 📖 Documentation

- Init ([4980c1e](https://github.com/agntn/keys/commit/4980c1e))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.0.8

[compare changes](https://github.com/agntn/keys/compare/v0.0.7...v0.0.8)

### 🚀 Enhancements

- Add key pair and wallet generation functions to blockchain interface ([4a51497](https://github.com/agntn/keys/commit/4a51497))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.0.7

[compare changes](https://github.com/agntn/keys/compare/v0.0.6...v0.0.7)

### 🚀 Enhancements

- Implement Base blockchain with address generation and validation ([33c1627](https://github.com/agntn/keys/commit/33c1627))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.0.6

[compare changes](https://github.com/agntn/keys/compare/v0.0.5...v0.0.6)

### 🚀 Enhancements

- Add curve property to blockchain interfaces and implementations ([c6d63d2](https://github.com/agntn/keys/commit/c6d63d2))
- Add Ethereum blockchain support with address generation and validation ([b6010eb](https://github.com/agntn/keys/commit/b6010eb))

### 💅 Refactors

- Rename key generation and address functions for consistency ([8c33dd4](https://github.com/agntn/keys/commit/8c33dd4))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.0.5

[compare changes](https://github.com/agntn/keys/compare/v0.0.4...v0.0.5)

### 🚀 Enhancements

- Add SUI blockchain support with address generation and validation ([bad2b57](https://github.com/agntn/keys/commit/bad2b57))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.0.4

[compare changes](https://github.com/agntn/keys/compare/v0.0.3...v0.0.4)

### 🚀 Enhancements

- Add TRON blockchain functionality with address generation and validation ([6f52038](https://github.com/agntn/keys/commit/6f52038))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.0.3

[compare changes](https://github.com/agntn/keys/compare/v0.0.2...v0.0.3)

### 🚀 Enhancements

- Implement Aptos blockchain functionality with address generation and validation ([5db315a](https://github.com/agntn/keys/commit/5db315a))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.0.2

[compare changes](https://github.com/agntn/keys/compare/v0.0.1...v0.0.2)

### 🚀 Enhancements

- Add solana blockchain functionality with key and address generation ([99e817e](https://github.com/agntn/keys/commit/99e817e))

### 💅 Refactors

- Restructure repository metadata in package.json ([1a86bcb](https://github.com/agntn/keys/commit/1a86bcb))

### 🏡 Chore

- Add MIT License file ([5637ed0](https://github.com/agntn/keys/commit/5637ed0))

### ✅ Tests

- Add coverage ([a97c58e](https://github.com/agntn/keys/commit/a97c58e))

### ❤️ Contributors

- Dominik Opyd <dominik.opyd@gmail.com>

## v0.0.1
