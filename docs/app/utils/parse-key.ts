/** secp256k1 group order n. Valid private keys are 1 through n - 1. */
export const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export type ParsedKey = {
  readonly hex: string;
  readonly decimal: bigint;
};

export type ParseError = {
  readonly error: string;
};

/**
 * Parses a hex private key, with or without a 0x prefix, and pads it on the left to 32 bytes.
 */
export function parseHexKey(raw: string): ParsedKey | ParseError {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return { error: "Enter a hex private key." };
  }
  const hex = trimmed.replace(/^0x/iu, "");
  if (!/^[0-9a-fA-F]+$/u.test(hex)) {
    return { error: "Hex must contain only 0-9 and a-f." };
  }
  if (hex.length > 64) {
    return { error: "Hex private key is longer than 32 bytes." };
  }
  return parseDecimalKey(BigInt(`0x${hex}`).toString());
}

/** Parses a decimal private key in the secp256k1 range. */
export function parseDecimalKey(raw: string): ParsedKey | ParseError {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return { error: "Enter a decimal private key." };
  }
  if (!/^[0-9]+$/u.test(trimmed)) {
    return { error: "Decimal must contain only digits." };
  }
  const decimal = BigInt(trimmed);
  if (decimal < 1n) {
    return { error: "Private key must be at least 1." };
  }
  if (decimal >= SECP256K1_ORDER) {
    return { error: "Private key must be less than the secp256k1 group order n." };
  }
  return {
    hex: decimal.toString(16).padStart(64, "0"),
    decimal,
  };
}

/** Walks one step through the secp256k1 keyspace and wraps at the ends. */
export function stepKey(decimal: bigint, delta: bigint): ParsedKey {
  const last = SECP256K1_ORDER - 1n;
  let next = decimal + delta;
  if (next < 1n) {
    next = last;
  }
  if (next >= SECP256K1_ORDER) {
    next = 1n;
  }
  return {
    hex: next.toString(16).padStart(64, "0"),
    decimal: next,
  };
}

export function isParsedKey(value: ParsedKey | ParseError): value is ParsedKey {
  return "hex" in value;
}
