import { hex } from "@agntn/encodings/hex";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { describe, expect, it } from "vite-plus/test";
import { extractSignatures } from "../../src/utils/transaction/index.ts";
import { pushOf, scriptPushes } from "../../src/utils/transaction/script.ts";
import { legacySighash, taprootSighash } from "../../src/utils/transaction/sighash.ts";
import {
  decodeTransaction,
  serializeTransaction,
} from "../../src/utils/transaction/transaction.ts";
import { secp256k1TestVectors, transactionVectors } from "../fixtures.ts";

const { legacy, p2wpkh, p2shP2wpkh, p2shP2wsh, taproot, reusedNonce2012 } = transactionVectors;

/* Spent outputs of the BIP341 vector with values as bigints, the shape the sighash takes. */
const taprootSpent = taproot.spent.map((output) => ({
  value: BigInt(output.value),
  script: hex.decode(output.script),
}));

describe("legacy sighash", () => {
  it.each(Object.entries(legacy))("matches Bitcoin Core's sighash.json: %s", (_name, row) => {
    const transaction = decodeTransaction(hex.decode(row.transaction));
    const digest = legacySighash(transaction, row.index, hex.decode(row.script), row.hashType);
    expect(hex.encode(Uint8Array.from(digest).reverse())).toBe(row.sighash);
  });

  it("signs one for SIGHASH_SINGLE past the last output, as Core does", () => {
    const transaction = decodeTransaction(hex.decode(p2wpkh.transaction));
    const digest = legacySighash(
      { ...transaction, outputs: transaction.outputs.slice(0, 1) },
      1,
      new Uint8Array(0),
      3,
    );
    expect(hex.encode(digest)).toBe(`01${"00".repeat(31)}`);
  });
});

describe("taproot sighash", () => {
  it.each(taproot.inputs)("matches BIP341 key path input $index", (input) => {
    const transaction = decodeTransaction(hex.decode(taproot.unsigned));
    const digest = taprootSighash(transaction, input.index, taprootSpent, input.hashType);
    expect(hex.encode(digest)).toBe(input.sighash);
  });

  it("refuses a hash type BIP341 does not define and SIGHASH_SINGLE without its output", () => {
    const transaction = decodeTransaction(hex.decode(taproot.unsigned));
    expect(() => taprootSighash(transaction, 0, taprootSpent, 0x04)).toThrow(/no hash type 0x4/u);
    const short = { ...transaction, outputs: [] };
    expect(() => taprootSighash(short, 0, taprootSpent, 0x03)).toThrow(/needs an output 0/u);
  });
});

describe("pushOf", () => {
  it("pushes directly up to 75 bytes, then with the shortest OP_PUSHDATA", () => {
    const heads = [75, 76, 255, 256].map((length) =>
      hex.encode(pushOf(new Uint8Array(length)).subarray(0, 3)),
    );
    expect(heads).toEqual(["4b0000", "4c4c00", "4cff00", "4d0001"]);
  });
});

describe("extractSignatures", () => {
  it("reads a P2PK input by legacy rules and a P2WPKH input by BIP143", () => {
    const [p2pk] = extractSignatures(p2wpkh.transaction, 0, p2wpkh.spent);
    expect(p2pk).toMatchObject({ type: "ecdsa", hashType: 1, publicKey: p2wpkh.p2pkPublicKey });
    const [witness] = extractSignatures(p2wpkh.transaction, 1, p2wpkh.spent);
    expect(witness).toEqual({
      type: "ecdsa",
      r: "3609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a",
      s: "573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee",
      z: p2wpkh.sighash,
      hashType: 1,
      publicKey: p2wpkh.publicKey,
    });
  });

  it("reads P2WPKH nested in P2SH from the one output it spends", () => {
    const [signature] = extractSignatures(p2shP2wpkh.transaction, 0, p2shP2wpkh.spent);
    expect(signature?.z).toBe(p2shP2wpkh.sighash);
    expect(signature?.publicKey).toBe(p2shP2wpkh.publicKey);
  });

  it("reads all six hash types of the BIP143 6-of-6 and names each signer", () => {
    const signatures = extractSignatures(p2shP2wsh.transaction, 0, p2shP2wsh.spent);
    expect(signatures.map(({ hashType, z, publicKey }) => [hashType, z, publicKey])).toEqual(
      p2shP2wsh.signatures,
    );
  });

  it.each(taproot.inputs)("reads the Taproot key path of BIP341 input $index", (input) => {
    const [signature] = extractSignatures(taproot.signed, input.index, taproot.spent);
    const outputKey = taproot.spent[input.index]?.script.slice(4);
    expect(signature).toMatchObject({
      type: "schnorr",
      hashType: input.hashType,
      z: input.sighash,
    });
    expect(signature?.publicKey).toBe(outputKey);
  });

  it("takes the one spent output of an ANYONECANPAY Taproot input", () => {
    const input = taproot.inputs.find((each) => each.hashType === 0x83);
    const spent = taproot.spent.filter((_output, index) => index === input?.index);
    const [signature] = extractSignatures(taproot.signed, input?.index ?? 0, spent);
    expect(signature?.z).toBe(input?.sighash);
  });

  it("reads loose DER from 2012 and finds the shared r on both inputs", () => {
    const { transaction, spent, r, publicKey } = reusedNonce2012;
    const signatures = [0, 1].flatMap((index) => extractSignatures(transaction, index, spent));
    expect(signatures.map((signature) => [signature.r, signature.publicKey])).toEqual([
      [r, publicKey],
      [r, publicKey],
    ]);
    expect(signatures[0]?.z).not.toBe(signatures[1]?.z);
  });

  it("reads long form DER lengths, as Core's lax parser does before BIP66", () => {
    const { transaction, spent } = reusedNonce2012;
    const decoded = decodeTransaction(hex.decode(transaction));
    const [original] = extractSignatures(transaction, 0, spent);
    const [, publicKey] = scriptPushes(decoded.inputs[0]?.scriptSig ?? new Uint8Array(0));
    const der = `3081470281 20${original?.r}028200 20${original?.s}01`.replaceAll(" ", "");
    const scriptSig = hex.decode(`4b${der}41${hex.encode(publicKey ?? new Uint8Array(0))}`);
    const inputs = decoded.inputs.map((input, index) =>
      index === 0 ? { ...input, scriptSig } : input,
    );
    const stretched = hex.encode(serializeTransaction({ ...decoded, inputs }, false));
    expect(extractSignatures(stretched, 0, spent)).toEqual([original]);
  });

  it("drops a signature over 75 bytes from the script code under OP_PUSHDATA1", () => {
    const { privateKey, publicKeyCompressed } = secp256k1TestVectors;
    const decoded = decodeTransaction(hex.decode(reusedNonce2012.transaction));
    const tail = hex.decode(`7521${publicKeyCompressed}ac`);
    const digest = legacySighash(decoded, 0, tail, 1);
    const compact = hex.encode(
      secp256k1.sign(digest, hex.decode(privateKey), { prehash: false, format: "compact" }),
    );
    const der = `30820048028200 20${compact.slice(0, 64)}028200 20${compact.slice(64)}01`;
    const push = `4c4d${der.replaceAll(" ", "")}`;
    const inputs = decoded.inputs.map((input, index) =>
      index === 0 ? { ...input, scriptSig: hex.decode(push) } : input,
    );
    const transaction = hex.encode(serializeTransaction({ ...decoded, inputs }, false));
    const spent = [{ script: `${push}${hex.encode(tail)}`, value: 130000 }];
    const [signature] = extractSignatures(transaction, 0, spent);
    expect(signature?.z).toBe(hex.encode(digest));
    expect(signature?.publicKey).toBe(publicKeyCompressed);
  });

  it("answers an unsigned input with no signatures", () => {
    for (const input of taproot.inputs) {
      expect(extractSignatures(taproot.unsigned, input.index, taproot.spent)).toEqual([]);
    }
    const signed = decodeTransaction(hex.decode(p2shP2wsh.transaction));
    const inputs = signed.inputs.map((input) => ({
      ...input,
      scriptSig: new Uint8Array(0),
      witness: [],
    }));
    const unsigned = hex.encode(serializeTransaction({ ...signed, inputs }, true));
    expect(extractSignatures(unsigned, 0, p2shP2wsh.spent)).toEqual([]);
    const native = [{ script: `0020${"00".repeat(32)}`, value: 1 }];
    expect(extractSignatures(unsigned, 0, native)).toEqual([]);
  });

  it("refuses what it cannot read instead of guessing a sighash", () => {
    const { transaction, spent } = reusedNonce2012;
    expect(() => extractSignatures("0x00", 0, spent)).toThrow(TypeError);
    expect(() => extractSignatures("00", 0, spent)).toThrow(/^Transaction /u);
    expect(() => extractSignatures(transaction, 2, spent)).toThrow(/0 to 1/u);
    expect(() => extractSignatures(transaction, 0, [...spent, ...spent])).toThrow(
      /one spent output/u,
    );
    expect(() => extractSignatures(transaction, 0, [{ script: "zz", value: 0 }])).toThrow(
      TypeError,
    );
    expect(() => extractSignatures(transaction, 0, [{ script: "", value: -1 }])).toThrow(
      /satoshis/u,
    );
    expect(() =>
      extractSignatures(transaction, 0, [
        { script: "ab76a91470792fb74a5df745bac07df6fe020f871cbb293b88ac", value: 0 },
      ]),
    ).toThrow(/OP_CODESEPARATOR/u);
    const input = taproot.inputs.find((each) => each.hashType === 0x01);
    expect(() =>
      extractSignatures(taproot.signed, input?.index ?? 0, taproot.spent.slice(0, 1)),
    ).toThrow(/every input/u);
    const wrongProgram = [{ script: `0020${"00".repeat(32)}`, value: 987654321 }];
    expect(() => extractSignatures(p2shP2wsh.transaction, 0, wrongProgram)).toThrow(
      /P2WSH program/u,
    );
  });
});
