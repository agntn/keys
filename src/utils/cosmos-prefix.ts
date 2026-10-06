/** A BIP-173 bech32 prefix: up to 83 printable ASCII characters, lowercase as encoders write it. */
export const COSMOS_PREFIX_PATTERN = "^[\\x21-\\x40\\x5B-\\x7E]{1,83}$";
