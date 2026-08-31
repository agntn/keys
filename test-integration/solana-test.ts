import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import * as keys from "../src";

// Function to convert hex to byte array
function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// Function to convert byte array to hex
function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

void (async () => {
  const solanaKeypair = Keypair.generate();
  const solanaPrivateKeyHex = bytesToHex(solanaKeypair.secretKey.slice(0, 32));
  const solanaPublicKeyHex = bytesToHex(solanaKeypair.publicKey.toBytes());
  const solanaPublicKeyBase58 = solanaKeypair.publicKey.toBase58();

  console.log("===== Solana Web3.js Keys =====");
  console.log("Private Key (hex):", solanaPrivateKeyHex);
  console.log("Public Key (hex):", solanaPublicKeyHex);
  console.log("Public Key (base58):", solanaPublicKeyBase58);

  const solanaBlockchain = keys.useBlockchain(await keys.blockchains.solana()());
  const keysPublicKey = solanaBlockchain.getKeyPublic(solanaPrivateKeyHex);
  const keysAddress = solanaBlockchain.getAddress(keysPublicKey);

  console.log("\n===== @agntn/keys Keys =====");
  console.log("Private Key (hex):", solanaPrivateKeyHex);
  console.log("Public Key (hex):", keysPublicKey);
  console.log("Address (base58):", keysAddress);

  const message = "Test message for Solana signature";
  const messageBytes = new TextEncoder().encode(message);
  const solanaSignature = nacl.sign.detached(messageBytes, solanaKeypair.secretKey);

  console.log("\n===== Signatures =====");
  console.log("Solana/tweetnacl Signature (hex):", bytesToHex(solanaSignature));

  const keysSignature = solanaBlockchain.signMessage(message, solanaPrivateKeyHex);
  console.log("@agntn/keys Signature (hex):", keysSignature);

  const solanaVerified = nacl.sign.detached.verify(
    messageBytes,
    solanaSignature,
    solanaKeypair.publicKey.toBytes(),
  );

  const keysVerified = solanaBlockchain.verifyMessage(message, keysSignature, keysPublicKey);

  console.log("\n===== Verification =====");
  console.log("Solana/tweetnacl verification:", solanaVerified);
  console.log("@agntn/keys verification:", keysVerified);

  console.log("\n===== Cross Verification =====");
  const solanaSignatureVerifiedByKeys = solanaBlockchain.verifyMessage(
    message,
    bytesToHex(solanaSignature),
    solanaPublicKeyHex,
  );
  const keysSignatureVerifiedByNacl = nacl.sign.detached.verify(
    messageBytes,
    hexToBytes(keysSignature),
    solanaKeypair.publicKey.toBytes(),
  );
  console.log("Solana/tweetnacl signature verified by keys:", solanaSignatureVerifiedByKeys);
  console.log("@agntn/keys signature verified by tweetnacl:", keysSignatureVerifiedByNacl);
})();
