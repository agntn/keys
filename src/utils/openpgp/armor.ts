import { armor } from "@agntn/encodings/armor";
import { HASH_NAMES } from "./algorithms.ts";

/** What a cleartext signed message splits into. */
export interface Cleartext {
  /** Signed text with dash escapes undone and trailing spaces and tabs cut, lines joined by LF. */
  readonly text: string;
  /** Bytes the signature covers: the same text with CRLF line endings, in UTF-8. */
  readonly canonical: Uint8Array;
  /** Dearmored signature packets. */
  readonly signature: Uint8Array;
  /** Hash names from legacy `Hash:` headers, which RFC 9580 says to check and then ignore. */
  readonly hashHeaders: readonly string[];
  /** Whether text sits before the block or after it, where no signature reaches. */
  readonly outside: boolean;
  /** Whether a line starts with a dash but isn't dash-escaped. */
  readonly unescapedDash: boolean;
}

const ANY_BEGIN = /^-----BEGIN PGP ([A-Z ,/0-9]+)-----\s*$/mu;
const SIGNED_MESSAGE = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIGNATURE_END = "-----END PGP SIGNATURE-----";

/**
 * Whether a line is the given armor line, which may only trail whitespace.
 * @param line - One line of input
 * @param marker - The armor line
 * @returns {boolean} Whether they match
 */
function isLine(line: string, marker: string): boolean {
  return line.trimEnd() === marker;
}

/**
 * Whether a line is blank, the separator RFC 9580 §6.2 puts after the headers.
 * @param line - One line of input
 * @returns {boolean} True for an empty or whitespace line
 */
function isBlank(line: string): boolean {
  return line.trim() === "";
}

/**
 * Names the block the caller handed over instead, so a private key gets told apart.
 * @param text - The whole input
 * @param label - The block that was expected
 * @returns {TypeError} The error to throw
 */
function missingBlock(text: string, label: string): TypeError {
  const found = ANY_BEGIN.exec(text)?.[1];
  if (found?.includes("PRIVATE") === true) {
    return new TypeError(`Expected a PGP ${label}, got a private key block. Pass the public key`);
  }
  const other = found === undefined ? "" : `, got BEGIN PGP ${found}`;
  return new TypeError(`Expected a -----BEGIN PGP ${label}----- block${other}`);
}

/**
 * Dearmors through `@agntn/encodings`, which shrugs off a bad CRC24, but keeps our `TypeError`.
 * @param text - Text holding the block
 * @param label - The block to read
 * @returns {Uint8Array} The packets
 * @throws {TypeError} When the block is cut, not base64 or empty
 */
function dearmor(text: string, label: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    ({ bytes } = armor.decode(text, { label }));
  } catch (error) {
    throw new TypeError(`OpenPGP ${error instanceof Error ? error.message : String(error)}`, {
      cause: error,
    });
  }
  if (bytes.length === 0) throw new TypeError("OpenPGP armor holds no data");
  return bytes;
}

/**
 * Reads one ASCII armor block, RFC 9580 §6.2.
 * @param text - Text holding the block
 * @param label - `PUBLIC KEY BLOCK` or `SIGNATURE`
 * @returns {Uint8Array} The dearmored packets
 * @throws {TypeError} When the block is missing, cut or not base64
 */
export function readArmor(text: string, label: string): Uint8Array {
  const begin = `-----BEGIN PGP ${label}-----`;
  if (!text.split(/\r?\n/u).some((line) => isLine(line, begin))) throw missingBlock(text, label);
  return dearmor(text, label);
}

/**
 * Checks the cleartext headers: well formed `Hash:` only, RFC 9580 §7.1 and §6.2.2.3.
 * @param lines - Header lines
 * @returns {string[]} Hash names
 * @throws {TypeError} On any other header or a malformed list
 */
function hashHeaders(lines: readonly string[]): string[] {
  return lines.flatMap((line) => {
    if (!line.startsWith("Hash: ")) {
      throw new TypeError("A cleartext signed message may only carry Hash headers");
    }
    const names = line
      .slice(6)
      .split(",")
      .map((name) => name.trim());
    if (!names.every((name) => HASH_NAMES.has(name))) {
      throw new TypeError("A cleartext Hash header must list OpenPGP hash names");
    }
    return names;
  });
}

/**
 * Undoes dash escapes and cuts trailing spaces and tabs. A loop, since `/[ \t]+$/` is quadratic.
 * @param line - One line of escaped text
 * @returns {string} The line as signed
 */
function signedLine(line: string): string {
  const unescaped = line.startsWith("- ") ? line.slice(2) : line;
  let end = unescaped.length;
  while (end > 0 && (unescaped[end - 1] === " " || unescaped[end - 1] === "\t")) end--;
  return unescaped.slice(0, end);
}

/**
 * Splits a cleartext signed message into the text it signs and the signature, RFC 9580 §7.
 * @param message - The whole message, `-----BEGIN PGP SIGNED MESSAGE-----` and all
 * @returns {Cleartext} Signed text, its canonical bytes and the signature packets
 * @throws {TypeError} When the frame is broken or a header is not allowed
 */
export function readCleartext(message: string): Cleartext {
  const lines = message.split(/\r?\n/u);
  const begin = lines.findIndex((line) => isLine(line, SIGNED_MESSAGE));
  if (begin === -1) throw missingBlock(message, "SIGNED MESSAGE");
  const blank = lines.findIndex((line, index) => index > begin && isBlank(line));
  if (blank === -1)
    throw new TypeError("Cleartext signed message has no blank line after its header");
  const signatureLine = lines.findIndex(
    (line, index) => index > blank && isLine(line, "-----BEGIN PGP SIGNATURE-----"),
  );
  if (signatureLine === -1) throw new TypeError("Cleartext signed message has no signature block");
  const headers = hashHeaders(lines.slice(begin + 1, blank));
  const body = lines.slice(blank + 1, signatureLine);
  const signed = body.map((line) => signedLine(line));
  const end = lines.findIndex(
    (line, index) => index > signatureLine && line.trim() === SIGNATURE_END,
  );
  if (end === -1) throw new TypeError(`OpenPGP armor has no ${SIGNATURE_END} line`);
  const after = lines.slice(end + 1);
  return {
    text: signed.join("\n"),
    canonical: new TextEncoder().encode(signed.join("\r\n")),
    signature: dearmor(lines.slice(signatureLine, end + 1).join("\n"), "SIGNATURE"),
    hashHeaders: headers,
    outside:
      !lines.slice(0, begin).every((line) => isBlank(line)) ||
      !after.every((line) => isBlank(line)),
    unescapedDash: body.some((line) => line.startsWith("-") && !line.startsWith("- ")),
  };
}
