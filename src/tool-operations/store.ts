import {
  MAX_SCRYPT_BLOCKS,
  MAX_KEYSTORE_LENGTH,
  MAX_KEYSTORE_PASSWORD_LENGTH,
} from "../tool-parameters.ts";
import {
  type KeystoreKDF,
  inspect as inspectStore,
  decrypt as decryptStoreKey,
  KeystorePasswordError,
} from "../utils/store/index.ts";
import { costArgument, requiredString } from "./arguments.ts";
import { getBlockchain } from "./blockchain.ts";
import { type ToolResult, content } from "./results.ts";

/** Keystore parameters, and the public wallet when the password opens it. */
export interface DecryptedStoreDetails {
  version: 3;
  id?: string;
  kdf: KeystoreKDF & { dklen: number };
  /** The address the file stores, EIP-55, when it stores one. */
  storedAddress?: string;
  /** Whether the password gives the stored MAC. */
  unlocked: boolean;
  chain?: "ethereum";
  publicKey?: string;
  address?: string;
}

/**
 * Refuses keystore costs above the ceilings the KDF tools set, before the KDF runs.
 * @param kdf - KDF, costs and derived key length the file names
 */
function checkStoreCost(kdf: Readonly<KeystoreKDF & { dklen: number }>): void {
  costArgument(kdf.dklen, "keyLength");
  if (kdf.kdf === "pbkdf2") {
    costArgument(kdf.c, "iterations");
    return;
  }
  costArgument(kdf.n, "N", 2);
  costArgument(kdf.r, "r");
  costArgument(kdf.p, "p");
  if (kdf.n * kdf.r > MAX_SCRYPT_BLOCKS) {
    throw new RangeError(`N * r must not exceed ${MAX_SCRYPT_BLOCKS}`);
  }
}

/**
 * Reads a keystore's parameters under the cost ceilings, as text lines and details.
 * @param keystore - Keystore JSON text
 * @returns {{ header: string[]; base: Omit<DecryptedStoreDetails, "unlocked"> }} What the file shows
 */
function storeSummary(keystore: string): {
  header: string[];
  base: Omit<DecryptedStoreDetails, "unlocked">;
} {
  const file = inspectStore(keystore);
  const kdf: KeystoreKDF & { dklen: number } =
    file.kdf === "scrypt"
      ? { kdf: "scrypt", n: file.n, r: file.r, p: file.p, dklen: file.dklen }
      : { kdf: "pbkdf2", c: file.c, dklen: file.dklen };
  checkStoreCost(kdf);
  const costs =
    kdf.kdf === "scrypt" ? `n ${kdf.n}, r ${kdf.r}, p ${kdf.p}` : `c ${kdf.c}, hmac-sha256`;
  const stored = file.address === undefined ? {} : { storedAddress: file.address };
  return {
    header: [
      `Keystore: version 3, ${kdf.kdf} (${costs}), aes-128-ctr`,
      ...(file.address === undefined ? [] : [`Stored address: ${file.address}`]),
    ],
    base: { version: 3, ...(file.id === undefined ? {} : { id: file.id }), kdf, ...stored },
  };
}

/**
 * Opens a version 3 keystore and gives its public Ethereum wallet, never its private key. A wrong
 * password is a result, not an error.
 * @param keystoreValue - Keystore JSON text
 * @param passwordValue - Password
 * @returns {Promise<ToolResult<DecryptedStoreDetails>>} Parameters, verdict, public key and address
 */
export async function decryptStore(
  keystoreValue: unknown,
  passwordValue: unknown,
): Promise<ToolResult<DecryptedStoreDetails>> {
  const keystore = requiredString(keystoreValue, "Keystore");
  if (keystore.length > MAX_KEYSTORE_LENGTH) {
    throw new RangeError(`Keystore must not exceed ${MAX_KEYSTORE_LENGTH} characters`);
  }
  const password = requiredString(passwordValue, "Password");
  if (Array.from(password).length > MAX_KEYSTORE_PASSWORD_LENGTH) {
    throw new RangeError(`Password must not exceed ${MAX_KEYSTORE_PASSWORD_LENGTH} characters`);
  }
  const { header, base } = storeSummary(keystore);
  let privateKey: Uint8Array;
  try {
    privateKey = decryptStoreKey(keystore, password);
  } catch (error) {
    if (!(error instanceof KeystorePasswordError)) throw error;
    return {
      content: content([...header, "Password: wrong, the MAC does not match"].join("\n")),
      details: { ...base, unlocked: false },
    };
  }
  const { blockchain } = await getBlockchain("ethereum");
  const wallet = blockchain.deriveWallet(privateKey.toHex());
  const details: DecryptedStoreDetails = {
    ...base,
    unlocked: true,
    chain: "ethereum",
    publicKey: wallet.keys.public,
    address: wallet.address,
  };
  return {
    content: content(
      [
        ...header,
        "Password: correct",
        `Public key: ${wallet.keys.public}`,
        `Address: ${wallet.address}`,
      ].join("\n"),
    ),
    details,
  };
}
