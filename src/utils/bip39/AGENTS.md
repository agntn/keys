# BIP39 utilities

## Scope

Public BIP39 helpers exported through `@agntn/keys/bip39`.

## Conventions

- Keep the existing English defaults source compatible.
- Load localized word lists from `@scure/bip39` only when requested.
- Apply Unicode NFKD normalization before localized word lookup.
- Keep numeric lookup explicit about whether positions start at 0 or 1.
- Keep the official language keys in `languages.ts`; agent schemas import that list instead of copying it.
- Cover every language loader and any normalization rule in `test/utils/bip39.test.ts`.
