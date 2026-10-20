import { describe, expect, it } from "vite-plus/test";
import { base64 } from "@agntn/encodings/base64";
import { checkMath, hashAlgorithm, readKeyMaterial } from "../../src/utils/openpgp/algorithms.ts";
import { fitsKey } from "../../src/utils/openpgp/certificate.ts";
import { inspect, verify } from "../../src/utils/openpgp/index.ts";
import { readPublicKey } from "../../src/utils/openpgp/keys.ts";
import { type Packet, readPackets } from "../../src/utils/openpgp/packets.ts";
import { openpgpVectors } from "../fixtures.ts";

const { rsa, ed25519, dsa, secp256k1, p256, expired, renewed, rfc9580 } = openpgpVectors;

/* Dearmors a public key block into packets. */
function packetsOf(armored: string): Packet[] {
  const lines = armored.split("\n");
  const start = lines.findIndex((line) => line === "") + 1;
  const end = lines.findIndex((line) => line.startsWith("=") || line.startsWith("-----END"));
  return readPackets(base64.decode(lines.slice(start, end).join("")));
}

/* Armors packets back into a public key block, new format headers, no checksum. */
function armorKey(packets: readonly Packet[]): string {
  const bytes = packets.flatMap(({ tag, body }) => {
    const length =
      body.length < 192
        ? [body.length]
        : [
            0xff,
            body.length >>> 24,
            (body.length >>> 16) & 0xff,
            (body.length >>> 8) & 0xff,
            body.length & 0xff,
          ];
    return [0xc0 | tag, ...length, ...body];
  });
  const data = base64.encode(Uint8Array.from(bytes)).match(/.{1,64}/gu) ?? [];
  return [
    "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    "",
    ...data,
    "-----END PGP PUBLIC KEY BLOCK-----",
    "",
  ].join("\n");
}

/* Flips the last byte of the signature after the subkey, which breaks its binding. */
function breakBinding(armored: string): string {
  const packets = packetsOf(armored);
  const subkey = packets.findIndex((packet) => packet.tag === 14);
  return armorKey(
    packets.map((packet, index) => {
      if (index !== subkey + 1) return packet;
      const body = packet.body.slice();
      body[body.length - 1] = (body.at(-1) ?? 0) ^ 1;
      return { tag: packet.tag, body };
    }),
  );
}

/* Dearmors the signature block of a cleartext message. */
function signatureBytes(message: string): Uint8Array {
  const lines = message.split("\n");
  const start = lines.indexOf("-----BEGIN PGP SIGNATURE-----") + 2;
  const end = lines.findIndex((line) => line.startsWith("="));
  return base64.decode(lines.slice(start, end).join(""));
}

/* Puts other signature bytes into a cleartext message, in place of its own. */
function withSignatures(message: string, bytes: Uint8Array): string {
  const lines = message.split("\n");
  const start = lines.indexOf("-----BEGIN PGP SIGNATURE-----") + 2;
  const end = lines.findIndex((line) => line.startsWith("="));
  const data = base64.encode(bytes).match(/.{1,64}/gu) ?? [];
  return [...lines.slice(0, start), ...data, ...lines.slice(end + 1)].join("\n");
}

/* Flips the last unhashed byte of the subkey binding, where GnuPG keeps the back signature. */
function breakBackSignature(armored: string): string {
  const packets = packetsOf(armored);
  const subkey = packets.findIndex((packet) => packet.tag === 14);
  return armorKey(
    packets.map((packet, index) => {
      if (index !== subkey + 1) return packet;
      const body = packet.body.slice();
      const hashed = ((body[4] ?? 0) << 8) | (body[5] ?? 0);
      const unhashed = ((body[6 + hashed] ?? 0) << 8) | (body[7 + hashed] ?? 0);
      const last = 8 + hashed + unhashed - 1;
      body[last] = (body[last] ?? 0) ^ 1;
      return { tag: packet.tag, body };
    }),
  );
}

describe("OpenPGP cleartext verification", () => {
  it.each([
    ["RSA 3072", rsa, "RSA 3072", "SHA512"],
    ["DSA 2048", dsa, "DSA 2048", "SHA256"],
    ["ECDSA secp256k1", secp256k1, "ECDSA secp256k1", "SHA256"],
  ])("verifies a GnuPG %s signature", (_, vector, algorithm, hash) => {
    const verdict = verify(vector.signed, { publicKey: vector.publicKey });
    expect(verdict).toMatchObject({
      state: "valid",
      identity: "unchecked",
      primaryFingerprint: vector.fingerprint,
      signingFingerprint: vector.fingerprint,
      issuer: vector.fingerprint,
      algorithm,
      hash,
      version: 4,
      warnings: [],
    });
    expect(verdict.reason).toBeUndefined();
  });

  it("gives back the text the signature covers, escapes undone and trailing whitespace cut", () => {
    const { text } = verify(rsa.signed, { publicKey: rsa.publicKey });
    expect(text).toBe(openpgpVectors.text.replaceAll(/[ \t]+\n/gu, "\n"));
  });

  it("verifies through a signing subkey bound to a certify-only primary", () => {
    const verdict = verify(ed25519.signed, {
      publicKey: ed25519.publicKey,
      fingerprint: ed25519.fingerprint,
    });
    expect(verdict).toMatchObject({
      state: "valid",
      identity: "match",
      primaryFingerprint: ed25519.fingerprint,
      signingFingerprint: ed25519.subkey,
      algorithm: "EdDSALegacy Ed25519Legacy",
    });
  });

  it("verifies the version 6 sample of RFC 9580 Appendix A.6", () => {
    const verdict = verify(rfc9580.signed, {
      publicKey: rfc9580.publicKey,
      fingerprint: rfc9580.fingerprint,
    });
    expect(verdict).toMatchObject({
      state: "valid",
      identity: "match",
      version: 6,
      algorithm: "Ed25519",
      hash: "SHA512",
      created: "2022-12-13T16:08:03.000Z",
      text: "What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n",
    });
  });

  it("calls altered text invalid, and says so", () => {
    const altered = rsa.signed.replace("Ten words", "Ten wards");
    expect(verify(altered, { publicKey: rsa.publicKey })).toMatchObject({
      state: "invalid",
      reason: "The text doesn't match what was signed",
    });
  });

  it("calls a changed signature value invalid against the right key", () => {
    const lines = rsa.signed.split("\n");
    const index = lines.findIndex((line) => line.startsWith("-----END")) - 3;
    const line = lines[index] ?? "";
    lines[index] = (line.startsWith("A") ? "B" : "A") + line.slice(1);
    expect(verify(lines.join("\n"), { publicKey: rsa.publicKey })).toMatchObject({
      state: "invalid",
    });
  });

  it("names the issuer when the key block holds a different key", () => {
    const verdict = verify(rsa.signed, { publicKey: ed25519.publicKey });
    expect(verdict).toMatchObject({
      state: "invalid",
      reason: `Signed by ${rsa.fingerprint}, which this key block doesn't hold`,
      primaryFingerprint: ed25519.fingerprint,
      issuer: rsa.fingerprint,
    });
    expect(verdict.signingFingerprint).toBeUndefined();
  });

  it("refuses a signing subkey whose binding doesn't hold", () => {
    expect(verify(ed25519.signed, { publicKey: breakBinding(ed25519.publicKey) })).toMatchObject({
      state: "invalid",
      reason: "The signing subkey isn't bound to this primary key",
    });
  });

  it("refuses a signing subkey that never signed back", () => {
    const key = breakBackSignature(ed25519.publicKey);
    expect(inspect(key)).toMatchObject({ subkeys: [{ bound: true }] });
    expect(verify(ed25519.signed, { publicKey: key })).toMatchObject({
      state: "invalid",
      reason: "The signing subkey has no valid back signature (type 0x19)",
    });
  });

  it("judges the subkey binding as of the signature, so an expired one doesn't count", () => {
    const key = ed25519.expiredBinding;
    expect(verify(ed25519.signed, { publicKey: key })).toMatchObject({
      state: "invalid",
      reason: "The signing subkey isn't bound to this primary key",
    });
    expect(inspect(key)).toMatchObject({ subkeys: [{ bound: false }] });
  });

  it("still counts a binding renewed after the signature, the way GnuPG does", () => {
    expect(verify(renewed.signed, { publicKey: renewed.publicKey })).toMatchObject({
      state: "valid",
      created: "2020-06-01T00:00:00.000Z",
    });
  });

  it("never takes RSA Encrypt-Only (algorithm 2) as a signing algorithm", () => {
    const [packet] = packetsOf(rsa.publicKey);
    if (packet === undefined) throw new Error("No key packet");
    const key = readPublicKey(packet.body);
    expect(fitsKey(key, 1)).toBe(true);
    expect(fitsKey({ ...key, algorithm: 2 }, 2)).toBe(false);
    expect(fitsKey({ ...key, algorithm: 2 }, 1)).toBe(false);
  });

  it("refuses a message with more signatures than anyone signs with", () => {
    const signature = signatureBytes(rsa.signed);
    const many = Uint8Array.from(Array.from({ length: 17 }, () => [...signature]).flat());
    expect(() => verify(withSignatures(rsa.signed, many), { publicKey: rsa.publicKey })).toThrow(
      "at most 16 signatures",
    );
  });

  it("keeps a valid signature when another one in the block can't be checked", () => {
    const both = Uint8Array.from([
      ...signatureBytes(rsa.signedSha384),
      ...signatureBytes(rsa.signed),
    ]);
    expect(verify(withSignatures(rsa.signed, both), { publicKey: rsa.publicKey })).toMatchObject({
      state: "valid",
      hash: "SHA512",
    });
  });

  it("refuses an Ed25519 key at the identity, which ZIP 215 rules would let sign anything", () => {
    const identity = Uint8Array.from([1, ...Array.from({ length: 31 }, () => 0)]);
    const value = Uint8Array.from([...identity, ...Array.from({ length: 32 }, () => 0)]);
    const key = { kind: "eddsa", point: identity } as const;
    expect(checkMath(key, 27, value, new Uint8Array(64).fill(7), hashAlgorithm(10))).toBe(false);
  });

  it("refuses a DSA key whose group lets r = s = 1 verify anything", () => {
    const mpi = (value: number) => [0, value.toString(2).length, value];
    const material = Uint8Array.from([...mpi(23), ...mpi(11), ...mpi(1), ...mpi(1)]);
    expect(() => readKeyMaterial(17, material)).toThrow(
      "OpenPGP DSA key has broken group parameters",
    );
  });

  it("needs a standing direct key signature before a version 6 key signs anything", () => {
    for (const publicKey of [rfc9580.noDirectKey, rfc9580.revokedDirectKey]) {
      expect(verify(rfc9580.signed, { publicKey })).toMatchObject({
        state: "invalid",
        reason: "The key has no valid self-signature, so nothing ties it together",
      });
    }
  });

  it("takes a self-certified User Attribute the way it takes a user ID", () => {
    const verdict = verify(ed25519.signed, { publicKey: ed25519.attributeOnly });
    expect(verdict.state).toBe("valid");
    expect(inspect(ed25519.attributeOnly)).toMatchObject({ userIds: [], uncertifiedUserIds: 0 });
  });

  it("keeps identity apart from the math", () => {
    const mismatch = verify(rsa.signed, { publicKey: rsa.publicKey, fingerprint: dsa.fingerprint });
    expect(mismatch).toMatchObject({ state: "valid", identity: "mismatch" });
    const spaced = rsa.fingerprint.toLowerCase().replaceAll(/(.{4})/gu, "$1 ");
    expect(verify(rsa.signed, { publicKey: rsa.publicKey, fingerprint: spaced }).identity).toBe(
      "match",
    );
  });

  it("refuses a key ID where a fingerprint belongs", () => {
    expect(() =>
      verify(rsa.signed, { publicKey: rsa.publicKey, fingerprint: rsa.fingerprint.slice(-16) }),
    ).toThrow("Pass the full fingerprint, not a key ID");
    expect(() => verify(rsa.signed, { publicKey: rsa.publicKey, fingerprint: "ABCD" })).toThrow(
      "Fingerprint must be 40 hex digits",
    );
  });

  it("holds the math over SHA-1 but calls it inconclusive", () => {
    expect(verify(rsa.signedSha1, { publicKey: rsa.publicKey })).toMatchObject({
      state: "inconclusive",
      hash: "SHA1",
      reason: "The math checks out, but it's SHA1, which RFC 9580 tells verifiers not to accept",
    });
  });

  it("refuses what it can't check instead of calling it invalid", () => {
    expect(() => verify(rsa.signedSha384, { publicKey: rsa.publicKey })).toThrow(
      "OpenPGP signatures over SHA384 aren't supported yet",
    );
    expect(() => verify(p256.signed, { publicKey: p256.publicKey })).toThrow(
      "ECDSA NIST P-256 signatures aren't supported yet",
    );
  });

  it("warns about a revoked key without changing the verdict", () => {
    const verdict = verify(rsa.signed, { publicKey: rsa.revokedKey });
    expect(verdict.state).toBe("valid");
    expect(verdict.warnings).toEqual([
      expect.stringMatching(/^The key was revoked on .+ \(no reason given\)$/u),
    ]);
  });

  it("warns about a key that has expired since", () => {
    const verdict = verify(expired.signed, { publicKey: expired.publicKey });
    expect(verdict).toMatchObject({
      state: "valid",
      warnings: ["The key expired on 2020-01-02T00:00:00.000Z"],
    });
  });
});

describe("OpenPGP cleartext framing", () => {
  it("reads CRLF line endings the same as LF", () => {
    const crlf = rsa.signed.replaceAll("\n", "\r\n");
    expect(verify(crlf, { publicKey: rsa.publicKey }).state).toBe("valid");
  });

  it("ignores trailing whitespace, as RFC 9580 section 7.1 says, but not inner whitespace", () => {
    const padded = rsa.signed.replace("Last line", "Last line \t ");
    expect(verify(padded, { publicKey: rsa.publicKey }).state).toBe("valid");
    const inner = rsa.signed.replace("Last line", "Last  line");
    expect(verify(inner, { publicKey: rsa.publicKey }).state).toBe("invalid");
  });

  it("ignores what a well formed Hash header says", () => {
    const relabeled = rsa.signed.replace("Hash: SHA512", "Hash: SHA256, SHA1");
    expect(verify(relabeled, { publicKey: rsa.publicKey }).state).toBe("valid");
  });

  it.each([
    ["another header", "Comment: trust me", "may only carry Hash headers"],
    ["a malformed Hash header", "Hash: SHA512 and then some", "must list OpenPGP hash names"],
  ])("refuses %s in the cleartext header", (_, header, message) => {
    const tampered = rsa.signed.replace("Hash: SHA512", header);
    expect(() => verify(tampered, { publicKey: rsa.publicKey })).toThrow(message);
  });

  it("warns about text outside the signed block", () => {
    const wrapped = `Send 5 BTC to the address below.\n${rsa.signed}\nP.S. it's legit\n`;
    expect(verify(wrapped, { publicKey: rsa.publicKey })).toMatchObject({
      state: "valid",
      warnings: ["Text outside the signed block isn't covered by the signature"],
    });
  });

  it("ignores a wrong armor checksum, as RFC 9580 section 6.1 asks", () => {
    const bad = rsa.signed.replace(/^=.{4}$/mu, "=AAAA");
    expect(bad).not.toBe(rsa.signed);
    expect(verify(bad, { publicKey: rsa.publicKey }).state).toBe("valid");
  });

  it("cuts trailing whitespace in linear time", () => {
    const line = `${" ".repeat(200_000)}x`;
    const started = performance.now();
    const verdict = verify(rsa.signed.replace("Last line", line), { publicKey: rsa.publicKey });
    expect(verdict.state).toBe("invalid");
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it("tells a private key block apart from a public one", () => {
    const secret = rsa.publicKey.replaceAll("PUBLIC KEY BLOCK", "PRIVATE KEY BLOCK");
    expect(() => verify(rsa.signed, { publicKey: secret })).toThrow("got a private key block");
  });

  it("refuses a positional call instead of guessing", () => {
    /* @ts-expect-error the old positional shape on purpose */
    expect(() => verify(rsa.signed, rsa.publicKey)).toThrow("Pass the options as an object");
  });
});

describe("OpenPGP inspection", () => {
  it("reads a key block with its subkey and certified user ID", () => {
    expect(inspect(ed25519.publicKey)).toMatchObject({
      kind: "public-key",
      primary: {
        fingerprint: ed25519.fingerprint,
        keyId: ed25519.fingerprint.slice(-16),
        version: 4,
        algorithm: "EdDSALegacy Ed25519Legacy",
        flags: ["certify"],
      },
      userIds: ["Ed Tester <ed@example.org>"],
      uncertifiedUserIds: 0,
      subkeys: [{ fingerprint: ed25519.subkey, flags: ["sign"], bound: true }],
    });
  });

  it("reads the version 6 certificate of RFC 9580 Appendix A.3", () => {
    expect(inspect(rfc9580.publicKey)).toMatchObject({
      primary: {
        fingerprint: rfc9580.fingerprint,
        keyId: rfc9580.fingerprint.slice(0, 16),
        version: 6,
      },
      subkeys: [
        { fingerprint: rfc9580.subkey, algorithm: "X25519", flags: ["encrypt"], bound: true },
      ],
    });
  });

  it("leaves out a user ID the key never certified", () => {
    const packets = packetsOf(rsa.publicKey);
    const forged = {
      tag: 13,
      body: new TextEncoder().encode("Satoshi Nakamoto <satoshi@gmx.com>"),
    };
    const inspection = inspect(armorKey([...packets, forged]));
    expect(inspection).toMatchObject({
      userIds: ["RSA Tester <rsa@example.org>"],
      uncertifiedUserIds: 1,
    });
  });

  it("skips Padding and non-critical packets, and refuses an unknown critical one", () => {
    const packets = packetsOf(ed25519.publicKey);
    const filler = new Uint8Array(8);
    const padded = armorKey([...packets, { tag: 21, body: filler }, { tag: 40, body: filler }]);
    expect(inspect(padded)).toMatchObject({ subkeys: [{ bound: true }] });
    expect(verify(ed25519.signed, { publicKey: padded }).state).toBe("valid");
    expect(() => inspect(armorKey([...packets, { tag: 30, body: filler }]))).toThrow(
      "OpenPGP key block holds a packet of type 30",
    );
  });

  it("caps self-signature checks, since a forged one costs as much math as a real one", () => {
    const packets = packetsOf(rsa.publicKey);
    const at = packets.findIndex((packet) => packet.tag === 13) + 1;
    const certification = packets[at];
    if (certification === undefined) throw new Error("No certification after the user ID");
    const forged = certification.body.slice();
    forged[forged.length - 1] = (forged.at(-1) ?? 0) ^ 1;
    const flood = (count: number) =>
      armorKey([
        ...packets.slice(0, at),
        ...Array.from({ length: count }, () => ({ tag: 2, body: forged })),
        ...packets.slice(at),
      ]);
    expect(inspect(flood(100))).toMatchObject({ userIds: ["RSA Tester <rsa@example.org>"] });
    expect(() => inspect(flood(130))).toThrow("needs more than 128 self-signature checks");
  });

  it("shows the revocation and the expiry", () => {
    expect(inspect(rsa.revokedKey)).toMatchObject({
      primary: { revoked: { reason: "no reason given" } },
    });
    expect(inspect(expired.publicKey)).toMatchObject({
      primary: { expires: "2020-01-02T00:00:00.000Z" },
    });
  });

  it("reads a signed message without verifying it", () => {
    expect(inspect(ed25519.signed)).toMatchObject({
      kind: "signed-message",
      hashHeaders: ["SHA512"],
      signatures: [
        { version: 4, algorithm: "EdDSALegacy", hash: "SHA512", issuer: ed25519.subkey },
      ],
      warnings: [],
    });
  });

  it("names a hash it can't compute instead of failing to read it", () => {
    expect(inspect(rsa.signedSha384)).toMatchObject({ signatures: [{ hash: "SHA384" }] });
  });

  it("refuses something that is neither block", () => {
    expect(() => inspect("-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----")).toThrow(
      "got BEGIN PGP MESSAGE",
    );
  });
});
