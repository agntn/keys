/** One OpenPGP packet: its type ID and the body after the header. */
export interface Packet {
  readonly tag: number;
  readonly body: Uint8Array;
}

/** One signature subpacket, RFC 9580 §5.2.3.7. */
export interface Subpacket {
  readonly type: number;
  readonly critical: boolean;
  readonly body: Uint8Array;
}

/** Reads a packet body front to back, refusing a short read. */
export interface Reader {
  /** Whether every byte was read. */
  readonly done: () => boolean;
  /** How many bytes were read so far. */
  readonly offset: () => number;
  /** Reads the next bytes, a copy of them. */
  readonly read: (length: number) => Uint8Array;
  /** Reads whatever is left. */
  readonly rest: () => Uint8Array;
  /** Reads one byte. */
  readonly byte: () => number;
  /** Reads a big endian number of 2 or 4 bytes. */
  readonly uint: (width: 2 | 4) => number;
  /** Reads a multiprecision integer, RFC 9580 §3.2: a bit count, then the big endian bytes. */
  readonly mpi: () => Uint8Array;
}

/**
 * Starts a reader at the first byte.
 * @param bytes - Bytes to read
 * @returns {Reader} The reader
 */
export function createReader(bytes: Uint8Array): Reader {
  let offset = 0;

  /**
   * Reads the next bytes.
   * @param length - How many
   * @returns {Uint8Array} A copy of them
   * @throws {TypeError} When fewer bytes are left
   */
  function read(length: number): Uint8Array {
    if (offset + length > bytes.length)
      throw new TypeError("OpenPGP data ends in the middle of a field");
    const slice = bytes.slice(offset, offset + length);
    offset += length;
    return slice;
  }

  /**
   * Reads a big endian number.
   * @param width - 2 or 4 bytes
   * @returns {number} The unsigned integer
   */
  function uint(width: 2 | 4): number {
    const view = new DataView(read(width).buffer);
    return width === 2 ? view.getUint16(0) : view.getUint32(0);
  }

  return {
    done: () => offset === bytes.length,
    offset: () => offset,
    read,
    rest: () => read(bytes.length - offset),
    byte: () => read(1)[0] ?? 0,
    uint,
    mpi: () => read(Math.ceil(uint(2) / 8)),
  };
}

/**
 * Body length of a new format header. Partial lengths only appear in data packets.
 * @param reader - Reader past the tag byte
 * @returns {number} Body length
 * @throws {TypeError} On a partial body length
 */
function newLength(reader: Reader): number {
  const first = reader.byte();
  if (first < 192) return first;
  if (first < 224) return ((first - 192) << 8) + reader.byte() + 192;
  if (first === 255) return reader.uint(4);
  throw new TypeError("OpenPGP keys and signatures never use partial body lengths");
}

/**
 * Body length of a legacy header, whose low two bits pick the width.
 * @param reader - Reader past the tag byte
 * @param lengthType - Low two bits of the tag byte
 * @returns {number} Body length
 * @throws {TypeError} On an indeterminate length
 */
function legacyLength(reader: Reader, lengthType: number): number {
  if (lengthType === 0) return reader.byte();
  if (lengthType === 1) return reader.uint(2);
  if (lengthType === 2) return reader.uint(4);
  throw new TypeError("OpenPGP keys and signatures never use an indeterminate length");
}

/**
 * Splits bytes into packets, new and legacy headers alike, RFC 9580 §4.2.
 * @param bytes - Dearmored bytes
 * @returns {Packet[]} Packets in order
 * @throws {TypeError} When a header is broken or a body runs past the end
 */
export function readPackets(bytes: Uint8Array): Packet[] {
  const reader = createReader(bytes);
  const packets: Packet[] = [];
  while (!reader.done()) {
    const header = reader.byte();
    if ((header & 0x80) === 0) throw new TypeError("OpenPGP packet header must set bit 7");
    const isNew = (header & 0x40) !== 0;
    const tag = isNew ? header & 0x3f : (header >> 2) & 0x0f;
    const length = isNew ? newLength(reader) : legacyLength(reader, header & 0x03);
    packets.push({ tag, body: reader.read(length) });
  }
  return packets;
}

/**
 * Length of one subpacket, encoded like a new format packet length but without partials.
 * @param reader - Reader at the length
 * @returns {number} Length of the type byte plus the body
 */
function subpacketLength(reader: Reader): number {
  const first = reader.byte();
  if (first < 192) return first;
  if (first < 255) return ((first - 192) << 8) + reader.byte() + 192;
  return reader.uint(4);
}

/**
 * Splits a subpacket area into subpackets.
 * @param bytes - Hashed or unhashed area
 * @returns {Subpacket[]} Subpackets in order
 * @throws {TypeError} When a subpacket is empty or runs past the area
 */
export function readSubpackets(bytes: Uint8Array): Subpacket[] {
  const reader = createReader(bytes);
  const subpackets: Subpacket[] = [];
  while (!reader.done()) {
    const length = subpacketLength(reader);
    if (length === 0) throw new TypeError("OpenPGP subpacket must hold at least its type");
    const type = reader.byte();
    subpackets.push({
      type: type & 0x7f,
      critical: (type & 0x80) !== 0,
      body: reader.read(length - 1),
    });
  }
  return subpackets;
}

/**
 * Whether to skip a packet: Padding, or a non-critical ID from 40 up (RFC 9580 §4.3).
 * @param tag - Packet type ID
 * @returns {boolean} Whether to skip it
 */
export function isIgnorable(tag: number): boolean {
  return tag === 21 || tag >= 40;
}

/**
 * Writes a number as big endian bytes.
 * @param value - Unsigned integer
 * @param width - 2 or 4
 * @returns {Uint8Array} The bytes
 */
export function bigEndian(value: number, width: 2 | 4): Uint8Array {
  const bytes = new Uint8Array(width);
  const view = new DataView(bytes.buffer);
  if (width === 2) view.setUint16(0, value);
  else view.setUint32(0, value);
  return bytes;
}
