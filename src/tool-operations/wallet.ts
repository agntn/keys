import { blockchains } from "../_blockchains.ts";
import type { AbstractBlockchain } from "../blockchain.ts";
import { FAMILY_SEED_SCHEMA_PATTERN, MAX_WALLET_SECRET_LENGTH } from "../tool-parameters.ts";
import type { KeyOptions, Wallet } from "../types.ts";
import {
  MONERO_SEED,
  hexArgument,
  PRIVATE_KEY_HEX,
  requiredString,
  type SubaddressArguments,
  type SubaddressIndices,
  subaddressIndices,
} from "./arguments.ts";
import { type ChainArguments, getBlockchain, addressTypeLines } from "./blockchain.ts";
import { type ToolResult, content } from "./results.ts";

/** Generated wallet material. */
export interface GeneratedWalletDetails {
  chain: string;
  network: string;
  curve: string;
  bip44: number;
  privateKey: string;
  publicKey: string;
  address: string;
}

/** Public wallet material derived from a secret input. */
export interface DerivedWalletDetails {
  chain: string;
  network: string;
  publicKey: string;
  addressType?: string;
  /** The public key form the caller asked for; absent when it was left to the default. */
  compressed?: boolean;
  address: string;
  /** Account of a Monero subaddress, present when the caller picked one. */
  account?: number;
  /** Index of a Monero subaddress within its account, present when the caller picked one. */
  addressIndex?: number;
  path?: string;
  warnings?: readonly string[];
}

const FAMILY_SEED = new RegExp(FAMILY_SEED_SCHEMA_PATTERN, "u");

function formatCurve(curve: string | readonly string[]): string {
  return typeof curve === "string" ? curve : curve.join(", ");
}

/**
 * Generate a disposable wallet for one supported blockchain.
 * @param chainValue - Blockchain name.
 * @param options - Network, address type, and the prefix on cosmos or polkadot.
 * @returns {Promise<ToolResult<GeneratedWalletDetails | undefined>>} Generated key and address material.
 */
export async function generateWallet(
  chainValue: unknown,
  options: Omit<ChainArguments, "coinType"> = {},
): Promise<ToolResult<GeneratedWalletDetails | undefined>> {
  const { network, addressType: type, prefix } = options;
  const { blockchain, addressType } = await getBlockchain(chainValue, {
    network,
    addressType: type,
    prefix,
  });
  const wallet = blockchain.generateWallet({ addressType });
  const details = {
    chain: blockchain.name,
    network: blockchain.network,
    curve: formatCurve(blockchain.curve),
    bip44: blockchain.coinType,
    privateKey: wallet.keys.private,
    publicKey: wallet.keys.public,
    address: wallet.address,
  };
  return {
    content: content(
      [
        `Chain: ${details.chain} (${details.network})`,
        `Curve: ${details.curve}`,
        `BIP44: ${details.bip44}`,
        ...addressTypeLines(wallet.addressType),
        `Private key: ${details.privateKey}`,
        `Public key: ${details.publicKey}`,
        `Address: ${details.address}`,
      ].join("\n"),
    ),
    details: undefined,
  };
}

/**
 * Reads the public key form, which the chain then checks against its address.
 * @param value - Raw argument
 * @returns {boolean | undefined} The form to derive, undefined when omitted
 */
function walletCompressed(value: unknown): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw new TypeError("compressed must be a boolean");
  return value;
}

/** A secret as the caller passed it, with the key options and address type to derive it with. */
interface SecretWalletRequest {
  readonly secret: string;
  readonly options: KeyOptions;
  readonly addressType: string | undefined;
}

/**
 * Derives a wallet from an XRPL family seed, Monero seed words or a private key in hex.
 * @param blockchain - The chain to derive on
 * @param request - The secret, key options and the address type the caller asked for
 * @returns {Wallet} The wallet
 */
function secretWallet(
  blockchain: Readonly<AbstractBlockchain>,
  request: SecretWalletRequest,
): Wallet {
  const { secret, options, addressType } = request;
  if (FAMILY_SEED.test(secret) || MONERO_SEED.test(secret)) {
    return blockchain.deriveSeedWallet(secret, { ...options, addressType });
  }
  const keyPrivate = hexArgument(secret, {
    name: "Private key",
    pattern: PRIVATE_KEY_HEX,
    shape: "64 hex characters, a family seed (s...) on xrpl or the seed words on monero,",
  });
  return blockchain.deriveWallet(keyPrivate, { ...options, addressType });
}

/**
 * Swaps a Monero wallet's address for the one at an account and index; the view key stays inside.
 * @param spendKey - The private spend key its seed or key gave
 * @param subaddress - Account and index of the address, and the network of the wallet
 * @returns {Promise<Wallet>} The wallet at that address, its public key the pair the address holds
 */
async function moneroSubaddressWallet(
  spendKey: string,
  subaddress: SubaddressIndices & { readonly network: string },
): Promise<Wallet> {
  const { network, ...indices } = subaddress;
  const monero = await blockchains.monero({ network })();
  const wallet = monero.deriveWallet(spendKey);
  if (indices.account === 0 && indices.index === 0) return wallet;
  const pair = monero.getSubaddressKeyPublic(wallet.keys.public, {
    ...indices,
    viewKey: monero.getViewKey(spendKey),
  });
  return {
    keys: { private: spendKey, public: pair },
    address: monero.getAddress(pair, "subaddress"),
    addressType: "subaddress",
  };
}

/** Wallet tool arguments besides the chain, raw until the executor checks them. */
export interface WalletArguments extends Omit<ChainArguments, "coinType">, SubaddressArguments {
  /** Private key as hex, a family seed on xrpl or the seed words on monero. */
  readonly privateKey?: unknown;
  /** secp256k1 public key form, compressed by default. */
  readonly compressed?: unknown;
}

/**
 * Derive public wallet material from a private key without echoing the secret.
 * @param chainValue - Blockchain name.
 * @param options - The key, with the chain's network, address type, prefix and Monero subaddress.
 * @returns {Promise<ToolResult<DerivedWalletDetails>>} Derived public wallet material.
 */
export async function deriveWallet(
  chainValue: unknown,
  options: WalletArguments,
): Promise<ToolResult<DerivedWalletDetails>> {
  const { blockchain, addressType } = await getBlockchain(chainValue, {
    network: options.network,
    addressType: options.addressType,
    prefix: options.prefix,
  });
  const compressed = walletCompressed(options.compressed);
  const keyOptions = compressed === undefined ? {} : { compressed };
  const subaddress = subaddressIndices(blockchain.name, options);
  const secret = requiredString(options.privateKey, "Private key");
  if (secret.length > MAX_WALLET_SECRET_LENGTH) {
    throw new RangeError(`Private key must not exceed ${MAX_WALLET_SECRET_LENGTH} characters`);
  }
  if (MONERO_SEED.test(secret) && blockchain.name !== "monero") {
    throw new TypeError(
      `Seed words go to keys_hd_wallet_derive as a BIP39 mnemonic; ${blockchain.name} takes a private key here`,
    );
  }
  const derived = secretWallet(blockchain, { secret, options: keyOptions, addressType });
  const wallet =
    subaddress === undefined
      ? derived
      : await moneroSubaddressWallet(derived.keys.private, {
          network: blockchain.network,
          ...subaddress,
        });
  const details = {
    chain: blockchain.name,
    network: blockchain.network,
    ...(wallet.addressType === undefined ? {} : { addressType: wallet.addressType }),
    ...(compressed === undefined ? {} : { compressed }),
    publicKey: wallet.keys.public,
    address: wallet.address,
    ...(subaddress === undefined
      ? {}
      : { account: subaddress.account, addressIndex: subaddress.index }),
  };
  return {
    content: content(
      [
        ...addressTypeLines(details.addressType),
        `Public key: ${details.publicKey}`,
        `Address: ${details.address}`,
      ].join("\n"),
    ),
    details,
  };
}
