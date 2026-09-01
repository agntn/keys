import { bytesToHex } from "@noble/hashes/utils.js";
import { getMasterKeyFromSeed as getBIP32MasterKey } from "./bip32/index.ts";
import { mnemonicToSeed, validateMnemonic } from "./bip39/index.ts";
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
 * @param mnemonic - English BIP39 mnemonic with a valid checksum
 * @param path - Derivation path such as `m/84'/0'/0'/0/0`
 * @param curve - Curve of the key the chain expects
 * @param passphrase - BIP39 passphrase, empty by default
 * @returns {string} Private key at the path as hex
 */
export function deriveKeyPrivateFromMnemonic(
  mnemonic: string,
  path: string,
  curve: Curve,
  passphrase = "",
): string {
  const normalizedMnemonic = normalizeMnemonic(mnemonic);
  if (!validateMnemonic(normalizedMnemonic)) {
    throw new Error("Invalid BIP39 mnemonic");
  }

  const seed = mnemonicToSeed(normalizedMnemonic, passphrase);
  if (curve === "ed25519") {
    return bytesToHex(getSLIP10MasterKey(seed).derive(path).privateKey);
  }

  const keyPrivate = getBIP32MasterKey(seed).derive(path).privateKey;
  if (!keyPrivate) {
    throw new Error(`No private key at ${path}`);
  }
  return bytesToHex(keyPrivate);
}
