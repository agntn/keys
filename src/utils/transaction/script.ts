const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;

/** One opcode of a script; a push carries its data. */
export interface ScriptOperation {
  readonly opcode: number;
  readonly data?: Uint8Array;
  /** The opcode with its length bytes and data, as the script holds them. */
  readonly bytes: Uint8Array;
}

/**
 * Reads the data length a push opcode announces.
 * @param script - Whole script
 * @param offset - Position of the opcode
 * @returns {[number, number]} Length bytes the opcode takes, then the data length
 */
function pushHeader(script: Uint8Array, offset: number): [number, number] {
  const opcode = script[offset] ?? 0;
  if (opcode < OP_PUSHDATA1) return [0, opcode];
  const width = opcode === OP_PUSHDATA1 ? 1 : opcode === OP_PUSHDATA2 ? 2 : 4;
  let length = 0;
  for (let index = width; index >= 1; index--) {
    length = length * 256 + (script[offset + index] ?? 0);
  }
  return [width, length];
}

/**
 * Splits a script into opcodes, stopping where a push runs past the end, as Core's `GetOp` does.
 * @param script - Script bytes
 * @returns {ScriptOperation[]} The opcodes read before the end or the first broken push
 */
export function scriptOperations(script: Uint8Array): ScriptOperation[] {
  const operations: ScriptOperation[] = [];
  let offset = 0;
  while (offset < script.length) {
    const opcode = script[offset] ?? 0;
    if (opcode === 0 || opcode > OP_PUSHDATA4) {
      operations.push({ opcode, bytes: script.subarray(offset, offset + 1) });
      offset += 1;
      continue;
    }
    const [width, length] = pushHeader(script, offset);
    const end = offset + 1 + width + length;
    if (end > script.length) break;
    operations.push({
      opcode,
      data: script.subarray(offset + 1 + width, end),
      bytes: script.subarray(offset, end),
    });
    offset = end;
  }
  return operations;
}

/**
 * The data of every push in a script, skipping other opcodes and empty pushes.
 * @param script - Script bytes
 * @returns {Uint8Array[]} Pushed data in order
 */
export function scriptPushes(script: Uint8Array): Uint8Array[] {
  return scriptOperations(script).flatMap((operation) =>
    operation.data === undefined || operation.data.length === 0 ? [] : [operation.data],
  );
}
