import { bytesToHex } from "@noble/hashes/utils.js";
import { getMasterKeyFromSeed as getBIP32MasterKey } from "./bip32/index.ts";
import { inspectBIP39Mnemonic, mnemonicToSeed } from "./bip39/index.ts";
import { getMasterKeyFromSeed as getSLIP10MasterKey } from "./slip10/index.ts";
import type { Curve } from "../types.ts";

/**
 * Collapses whitespace so a phrase pasted with line breaks still validates.
 * @param mnemonic - Raw mnemonic text
 * @returns {string} Words joined by single spaces
 */
export function normalizeMnemonic(mnemonic: string): string {
  return mnemonic.trim().split(/\s+/u).join(" ");
}

/**
 * Walks an English BIP39 mnemonic down a path: BIP32 for secp256k1, SLIP-10 for ed25519.
 * @param mnemonic - English BIP39 words, never repaired to satisfy a checksum
 * @param path - Derivation path such as `m/84'/0'/0'/0/0`
 * @param curve - Curve of the key the chain expects
 * @param passphrase - BIP39 passphrase, empty by default
 * @param allowInvalidChecksum - Accept only checksum failures when explicitly true
 * @returns {{ privateKey: string; checksumValid: boolean }} Derived key and actual checksum verdict
 */
export function deriveMnemonicKey(
  mnemonic: string,
  path: string,
  curve: Curve,
  passphrase = "",
  allowInvalidChecksum = false,
): { readonly privateKey: string; readonly checksumValid: boolean } {
  if (typeof allowInvalidChecksum !== "boolean") {
    throw new TypeError("allowInvalidChecksum must be a boolean");
  }
  const normalizedMnemonic = normalizeMnemonic(mnemonic);
  const inspection = inspectBIP39Mnemonic(normalizedMnemonic);
  if (inspection.checksumValid === null || (!inspection.valid && !allowInvalidChecksum)) {
    throw new Error("Invalid BIP39 mnemonic");
  }

  const seed = mnemonicToSeed(normalizedMnemonic, passphrase);
  const privateKey =
    curve === "ed25519"
      ? getSLIP10MasterKey(seed).derive(path).privateKey
      : getBIP32MasterKey(seed).derive(path).privateKey;
  if (!privateKey) {
    throw new Error(`No private key at ${path}`);
  }
  return { privateKey: bytesToHex(privateKey), checksumValid: inspection.valid };
}
