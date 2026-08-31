import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { encodeBase58Check, validateBase58Check } from "./encoding.ts";
import { bech32, bech32m } from "@scure/base";

/**
 * Create RIPEMD160(SHA256(input)) hash - commonly used in Bitcoin-like blockchains
 * @param data - Input bytes
 * @returns {Uint8Array} Hash160 result
 */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function bytesToNumberBE(bytes: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(bytes)}`);
}

function taggedHash(tag: string, data: Uint8Array): Uint8Array {
  const tagHash = sha256(new TextEncoder().encode(tag));
  const input = new Uint8Array(tagHash.length * 2 + data.length);
  input.set(tagHash);
  input.set(tagHash, tagHash.length);
  input.set(data, tagHash.length * 2);
  return sha256(input);
}

function xOnlyFromPublicKey(keyPublicBytes: Uint8Array): Uint8Array {
  const point = secp256k1.Point.fromBytes(keyPublicBytes);
  return point.toBytes(true).slice(1);
}

function generateTaprootProgram(keyPublicBytes: Uint8Array): Uint8Array {
  const internalKey = xOnlyFromPublicKey(keyPublicBytes);
  const internalPoint = secp256k1.Point.fromHex(bytesToHex(new Uint8Array([0x02, ...internalKey])));
  const tweak = bytesToNumberBE(taggedHash("TapTweak", internalKey));

  if (tweak >= secp256k1.Point.Fn.ORDER) {
    throw new Error("Invalid Taproot tweak");
  }

  const outputPoint = internalPoint.add(secp256k1.Point.BASE.multiply(tweak));
  if (outputPoint.is0()) {
    throw new Error("Invalid Taproot output point");
  }

  return outputPoint.toBytes(true).slice(1);
}

/**
 * Base Bitcoin address options that use version bytes (legacy P2PKH and P2SH)
 */
export type OptionsAddressVersioned = {
  readonly bytesVersion: number;
};

// Use the unified type for both legacy and P2SH addresses
export type OptionsAddressLegacy = OptionsAddressVersioned;
export type OptionsAddressP2SH = OptionsAddressVersioned;

// SegWit (bech32) address options
export type OptionsAddressSegWit = {
  readonly hrp: string; // Human readable part (prefix)
  readonly witnessVersion: number; // Usually 0 for standard P2WPKH, 1 for Taproot
};

/**
 * Options for validating hex addresses
 */
export interface OptionsAddressHex {
  readonly prefix?: string; // Prefix for address (e.g. '0x')
  readonly length?: number; // Expected length without prefix
  readonly caseSensitive?: boolean; // Whether hex is case sensitive
}

/**
 * Create a versioned hash with a version byte
 * @param hash - The hash to version
 * @param bytesVersion - The version byte to use
 * @returns {Uint8Array} Versioned hash with version byte prepended
 * @deprecated Use addSchemeByte instead
 */
export function createVersionedHash(hash: Uint8Array, bytesVersion: number): Uint8Array {
  return addSchemeByte(hash, bytesVersion, true);
}

/**
 * Generate Legacy (P2PKH) address for Bitcoin-like blockchains
 * @param keyPublic - The public key as a hex string
 * @param options - Options for address generation with version byte
 * @returns {string} Legacy address
 */
export function generateAddressLegacy(keyPublic: string, options: OptionsAddressLegacy): string {
  // Convert public key to bytes
  const bytesKeyPublic = hexToBytes(keyPublic);

  // Hash the public key with hash160 (RIPEMD160(SHA256(pubkey)))
  const hashPubKey = hash160(bytesKeyPublic);

  // Create versioned hash
  const hashVersioned = createVersionedHash(hashPubKey, options.bytesVersion);

  // Encode with Base58Check
  return encodeBase58Check(hashVersioned);
}

/**
 * Validate a Bitcoin-like Legacy (P2PKH) address
 * @param address - The address to validate
 * @param options - Options for address validation with version byte
 * @returns {boolean} Whether the address is valid
 */
export function validateAddressLegacy(address: string, options: OptionsAddressLegacy): boolean {
  // Get expected prefix for this version
  const expectedPrefix = options.bytesVersion === 0x00 ? "1" : undefined;

  // Use common validation function
  return validateBase58Check(address, options.bytesVersion, expectedPrefix);
}

/**
 * Generate P2SH address for Bitcoin-like blockchains
 * @param keyPublic - The public key as a hex string
 * @param options - Options for address generation with version byte
 * @returns {string} P2SH address
 */
export function generateAddressP2SH(keyPublic: string, options: OptionsAddressP2SH): string {
  // Convert public key to bytes
  const bytesKeyPublic = hexToBytes(keyPublic);

  // Hash the public key with hash160 (RIPEMD160(SHA256(pubkey)))
  const hashPubKey = hash160(bytesKeyPublic);

  // Create redeem script (simplification, real P2SH would be more complex)
  const redeemScript = new Uint8Array(hashPubKey.length + 2);
  redeemScript[0] = 0x00; // OP_0
  redeemScript[1] = 0x14; // 20 bytes length
  redeemScript.set(hashPubKey, 2);

  // Hash the redeem script
  const hashRedeemScript = hash160(redeemScript);

  // Create versioned hash
  const hashVersioned = createVersionedHash(hashRedeemScript, options.bytesVersion);

  // Encode with Base58Check
  return encodeBase58Check(hashVersioned);
}

/**
 * Validate a P2SH address
 * @param address - The address to validate
 * @param options - Options for address validation with version byte
 * @returns {boolean} Whether the address is valid
 */
export function validateAddressP2SH(address: string, options: OptionsAddressP2SH): boolean {
  // Get expected prefix for this version
  const expectedPrefix = options.bytesVersion === 0x05 ? "3" : undefined;

  // Use common validation function
  return validateBase58Check(address, options.bytesVersion, expectedPrefix);
}

/**
 * Generate SegWit (bech32 or bech32m) address for Bitcoin-like blockchains
 * @param keyPublic - The public key as a hex string
 * @param options - Options for SegWit address generation
 * @param type - Optional type of SegWit address ('p2wpkh' or 'p2wsh')
 * @returns {string} SegWit address (bech32 or bech32m format, depending on witness version)
 */
export function generateAddressSegWit(
  keyPublic: string,
  options: OptionsAddressSegWit,
  type: "p2wpkh" | "p2wsh" = "p2wpkh",
): string {
  // Convert public key to bytes
  const bytesKeyPublic = hexToBytes(keyPublic);

  let programBytes: Uint8Array;

  if (options.witnessVersion === 1) {
    programBytes = generateTaprootProgram(bytesKeyPublic);
  } else if (type === "p2wsh") {
    // For P2WSH, we hash the script (in this case, a simple pubkey script)
    const script = new Uint8Array(bytesKeyPublic.length + 2);
    script[0] = 0x21; // Length of pubkey (33 bytes)
    script.set(bytesKeyPublic, 1);
    script[script.length - 1] = 0xac; // OP_CHECKSIG

    programBytes = sha256(script);
  } else {
    // For P2WPKH, use hash160
    programBytes = hash160(bytesKeyPublic);
  }

  // Convert program bytes to 5-bit words
  const words =
    options.witnessVersion === 0 ? bech32.toWords(programBytes) : bech32m.toWords(programBytes);

  // Add witness version to the beginning of the words array
  const wordsWithVersion = [options.witnessVersion, ...words];

  // Encode with appropriate encoder (bech32 for v0, bech32m for v1+)
  return options.witnessVersion === 0
    ? bech32.encode(options.hrp, wordsWithVersion)
    : bech32m.encode(options.hrp, wordsWithVersion);
}

/**
 * Result of an unsafe bech32/bech32m decode, as consumed by validation helpers
 */
type DecodedBech = void | {
  readonly prefix: string;
  readonly words: readonly number[];
};

/**
 * Check that a SegWit address decoded with the expected human readable part,
 * falling back to the other bech32 variant when the primary decode failed
 * @param address - The address being validated
 * @param decoded - Result of decoding the address with the primary decoder
 * @param options - Options for SegWit address validation
 * @returns {boolean} Whether validation may continue
 */
function hasValidSegWitPrefix(
  address: string,
  decoded: DecodedBech,
  options: OptionsAddressSegWit,
): boolean {
  if (decoded && decoded.prefix === options.hrp) {
    return true;
  }

  const fallback = options.witnessVersion === 0 ? bech32m : bech32;
  const decoded2 = fallback.decodeUnsafe(address);
  if (!decoded2 || decoded2.prefix !== options.hrp) {
    return false;
  }
  return true;
}

/**
 * Check the witness program length: 20 (P2WPKH) or 32 (P2WSH) bytes for v0,
 * 32 bytes (x-only pubkey) for v1 Taproot, unrestricted for future versions
 * @param data - The decoded witness program bytes
 * @param witnessVersion - The witness version the program was decoded for
 * @returns {boolean} Whether the program length is valid
 */
function hasValidWitnessProgramLength(data: Uint8Array, witnessVersion: number): boolean {
  if (witnessVersion === 0) {
    return data.length === 20 || data.length === 32;
  }
  if (witnessVersion === 1) {
    return data.length === 32;
  }

  return true;
}

/**
 * Validate a Bitcoin-like SegWit (bech32 or bech32m) address
 * @param address - The address to validate
 * @param options - Options for SegWit address validation
 * @returns {boolean} Whether the address is valid
 */
export function validateAddressSegWit(address: string, options: OptionsAddressSegWit): boolean {
  try {
    // Decode based on witness version (bech32 for v0, bech32m for v1+)
    const decoder = options.witnessVersion === 0 ? bech32 : bech32m;
    const decoded = decoder.decodeUnsafe(address);

    if (!hasValidSegWitPrefix(address, decoded, options)) {
      return false;
    }

    // If we get here, we've successfully decoded, now verify the witness version
    const words = decoded ? decoded.words : [];
    if (words.length === 0 || words[0] !== options.witnessVersion) {
      return false;
    }

    // Check length (depends on witness version)
    const data = decoder.fromWordsUnsafe(words.slice(1));
    if (!data) return false;

    return hasValidWitnessProgramLength(data, options.witnessVersion);
  } catch {
    // If decoding fails, the address is invalid
    return false;
  }
}

/**
 * Validate a hex address with common format like 0x-prefixed addresses
 * Used by Ethereum, Sui, Aptos and others
 *
 * @param address - Address to validate
 * @param options - Validation options
 * @returns {boolean} Whether the address is valid
 */
export function validateAddressHex(address: string, options: OptionsAddressHex = {}): boolean {
  // Set defaults
  const prefix = options.prefix || "0x";
  const expectedLength = options.length ?? 40;
  const caseSensitive = options.caseSensitive ?? false;

  // Check prefix
  if (!address.startsWith(prefix)) {
    return false;
  }

  // Remove prefix and check length
  const addressWithoutPrefix = address.slice(prefix.length);
  if (addressWithoutPrefix.length !== expectedLength) {
    return false;
  }

  // Create regex pattern based on case sensitivity
  const pattern = caseSensitive
    ? new RegExp(`^[0-9a-f]{${expectedLength}}$`)
    : new RegExp(`^[0-9a-fA-F]{${expectedLength}}$`);

  // Check if it's valid hex
  return pattern.test(addressWithoutPrefix);
}

/**
 * Create a standard prefixed hash address
 * Used by Ethereum, Sui, Aptos and others
 *
 * @param hash - Hash bytes to use as address
 * @param prefix - Prefix to add (default: '0x')
 * @returns {string} Prefixed hex address
 */
export function createPrefixedAddress(hash: Uint8Array, prefix: string = "0x"): string {
  return prefix + bytesToHex(hash);
}

/**
 * Helper function to create a byte array with scheme/flag byte and data
 * Used by many blockchains like Sui, Aptos
 *
 * @param data - The main data bytes
 * @param schemeByte - The scheme or flag byte to prepend/append
 * @param prepend - Whether to prepend (true) or append (false) the scheme byte
 * @returns {Uint8Array} Combined byte array
 */
export function addSchemeByte(
  data: Uint8Array,
  schemeByte: number,
  prepend: boolean = true,
): Uint8Array {
  // Create new array with extra byte
  const result = new Uint8Array(data.length + 1);

  if (prepend) {
    // Scheme byte at the beginning
    result[0] = schemeByte;
    result.set(data, 1);
  } else {
    // Scheme byte at the end
    result.set(data);
    result[data.length] = schemeByte;
  }

  return result;
}
