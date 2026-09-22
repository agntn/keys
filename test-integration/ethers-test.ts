import {
  HDNodeWallet,
  Signature,
  SigningKey,
  Wallet,
  hashMessage,
  pbkdf2,
  toUtf8Bytes,
  verifyMessage,
} from "ethers";
import * as keys from "../src";
/**
 * Direct class imports: this package has no `"type": "module"`, so tsx compiles it
 * as CommonJS where the lazy registry's top-level await is unavailable.
 */
import { Bitcoin } from "../src/blockchains/bitcoin";
import { Ethereum } from "../src/blockchains/ethereum";
import { Litecoin } from "../src/blockchains/litecoin";
import {
  bip39TestVectors,
  ethereumTestVectors,
  invalidChecksumPuzzle,
  litecoinTestVectors,
} from "../test/fixtures";

let mismatches = 0;

function check(label: string, actual: string, expected: string): void {
  const ok = actual === expected;
  if (!ok) mismatches++;
  console.log(`${ok ? "ok  " : "FAIL"} ${label}`);
  if (!ok) console.log(`     ethers  ${expected}\n     keys    ${actual}`);
}

async function main(): Promise<void> {
  const ethereum = keys.useBlockchain(new Ethereum());
  const { privateKey } = ethereumTestVectors;
  const signingKey = new SigningKey(`0x${privateKey}`);
  const wallet = new Wallet(`0x${privateKey}`);

  console.log("===== Ethereum keys and address =====");
  check(
    "compressed public key",
    ethereum.getKeyPublic(privateKey),
    signingKey.compressedPublicKey.slice(2),
  );
  check(
    "fixture public key",
    ethereumTestVectors.publicKey,
    signingKey.compressedPublicKey.slice(2),
  );
  check(
    "uncompressed public key",
    ethereum.getKeyPublic(privateKey, { compressed: false }),
    signingKey.publicKey.slice(2),
  );
  check("address", ethereum.getAddress(ethereumTestVectors.publicKey), wallet.address);
  check("fixture address", ethereumTestVectors.address, wallet.address);

  console.log("\n===== Ethereum signMessage =====");
  for (const [message, digest, signatureWithV] of ethereumTestVectors.messages) {
    const label = JSON.stringify(message.length > 24 ? `${message.slice(0, 21)}...` : message);
    const ethersSignature = Signature.from(await wallet.signMessage(message));
    check(`${label} digest`, digest, hashMessage(message).slice(2));
    check(`${label} fixture signature`, signatureWithV, ethersSignature.serialized.slice(2));
    check(
      `${label} keys signature`,
      ethereum.signMessage(message, privateKey),
      ethersSignature.r.slice(2) + ethersSignature.s.slice(2),
    );
    const recovered = ethereum.signMessage(message, privateKey, { recovered: true });
    check(`${label} keys signature with v`, recovered, ethersSignature.serialized.slice(2));
    check(
      `${label} ethers recovers the signer`,
      verifyMessage(message, `0x${recovered}`),
      wallet.address,
    );
  }

  console.log("\n===== Litecoin BIP32 with the TREZOR passphrase =====");
  const litecoin = keys.useBlockchain(new Litecoin());
  for (const [purpose, , fixturePrivateKey, fixturePublicKey] of litecoinTestVectors.hd) {
    const path = `m/${purpose}'/2'/0'/1/2`;
    const node = HDNodeWallet.fromPhrase(bip39TestVectors.mnemonic, "TREZOR", path);
    const derived = litecoin.deriveHDWallet(bip39TestVectors.mnemonic, path, {
      passphrase: "TREZOR",
    });
    check(`${path} private key`, derived.keys.private, node.privateKey.slice(2));
    check(`${path} fixture private key`, fixturePrivateKey, node.privateKey.slice(2));
    check(`${path} public key`, derived.keys.public, node.publicKey.slice(2));
    check(`${path} fixture public key`, fixturePublicKey, node.publicKey.slice(2));
  }

  console.log("\n===== Bitcoin BIP32 over an invalid checksum with a passphrase =====");
  const { mnemonic, withPassphrase } = invalidChecksumPuzzle;
  const seed = pbkdf2(
    toUtf8Bytes(mnemonic.normalize("NFKD")),
    toUtf8Bytes(`mnemonic${withPassphrase.passphrase}`.normalize("NFKD")),
    2048,
    64,
    "sha512",
  );
  const node = HDNodeWallet.fromSeed(seed).derivePath(withPassphrase.path);
  const bitcoin = keys.useBlockchain(new Bitcoin());
  const derived = bitcoin.deriveHDWallet(mnemonic, withPassphrase.path, {
    passphrase: withPassphrase.passphrase,
    allowInvalidChecksum: true,
  });
  check(`${withPassphrase.path} public key`, derived.keys.public, node.publicKey.slice(2));
  check(
    `${withPassphrase.path} fixture public key`,
    withPassphrase.publicKey,
    node.publicKey.slice(2),
  );

  console.log(mismatches === 0 ? "\nAll ethers checks match." : `\n${mismatches} mismatches.`);
  process.exitCode = mismatches === 0 ? 0 : 1;
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
