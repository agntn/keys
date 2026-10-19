import {
  SEC1_PUBLIC_KEY_SCHEMA_PATTERN,
  MAX_SCRIPT_HEX_LENGTH,
  type ToolNetwork,
  MAX_DESCRIPTOR_ADDRESSES,
  MAX_DESCRIPTOR_LENGTH,
} from "../tool-parameters.ts";
import { parse as parseDescriptor, type DescriptorOutput } from "../utils/descriptor/index.ts";
import {
  type ScriptAddressType,
  MAX_MULTISIG_KEYS,
  multisig,
  address as scriptAddress,
} from "../utils/script/index.ts";
import {
  type IndexArgument,
  requiredString,
  HEX_BYTES,
  stringArray,
  isUnset,
  optionalIndex,
} from "./arguments.ts";
import { parseNetwork } from "./blockchain.ts";
import { type ToolResult, content } from "./results.ts";

/** Addresses that pay to one script, with the reason a wrapper refuses it. */
export interface ScriptAddressDetails {
  chain: "bitcoin";
  network: string;
  /** The script hashed, written out when the tool built it from keys. */
  script: string;
  addresses: Partial<Record<ScriptAddressType, string>>;
  refused?: Partial<Record<ScriptAddressType, string>>;
  warnings?: string[];
}

const SCRIPT_ADDRESS_TYPES = ["p2sh", "p2wsh", "p2sh-p2wsh"] as const;

/** Labels of the wrappers in the tool text. */
const SCRIPT_ADDRESS_LABELS: Readonly<Record<ScriptAddressType, string>> = {
  p2sh: "P2SH",
  p2wsh: "P2WSH",
  "p2sh-p2wsh": "P2SH-P2WSH",
};

const SEC1_PUBLIC_KEY = new RegExp(SEC1_PUBLIC_KEY_SCHEMA_PATTERN, "u");

/**
 * Reads an optional count that starts at 1, unlike an index.
 * @param value - Raw argument
 * @param argument - Name for the error and the largest value it takes
 * @returns {number | undefined} The count, undefined when left out
 */
function optionalCount(value: unknown, argument: Required<IndexArgument>): number | undefined {
  const { name, maximum } = argument;
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${name} must be an integer from 1 to ${maximum}`);
  }
  return value;
}

/** Script address arguments besides the script, raw until the executor checks them. */
export interface ScriptAddressArguments {
  /** Signatures the multisig needs. */
  readonly threshold?: unknown;
  readonly publicKeys?: unknown;
  /** Whether to sort the keys. */
  readonly sorted?: unknown;
  readonly network?: unknown;
}

/**
 * Reads the script argument, a hex script without the multisig arguments.
 * @param scriptValue - Raw script
 * @param options - Raw threshold and sorted flag, which must both be absent
 * @returns {Uint8Array} The script bytes
 */
function givenScript(scriptValue: unknown, options: ScriptAddressArguments): Uint8Array {
  const { threshold, sorted } = options;
  const script = requiredString(scriptValue, "Script");
  if (script.length > MAX_SCRIPT_HEX_LENGTH || !HEX_BYTES.test(script)) {
    throw new TypeError(`Script must be hex without 0x, at most ${MAX_SCRIPT_HEX_LENGTH} digits`);
  }
  if (threshold !== undefined || sorted !== undefined) {
    throw new TypeError("threshold and sorted go with publicKeys, not with script");
  }
  return Uint8Array.fromHex(script);
}

/**
 * Reads the multisig arguments into their keys and script.
 * @param options - Raw threshold, keys and sorted flag
 * @returns {[readonly string[], Uint8Array]} The keys and the multisig script
 */
function multisigArgument(options: ScriptAddressArguments): [readonly string[], Uint8Array] {
  const keys = stringArray(options.publicKeys, "publicKeys");
  if (keys.length > MAX_MULTISIG_KEYS || !keys.every((key) => SEC1_PUBLIC_KEY.test(key))) {
    throw new TypeError(
      `publicKeys must be 1 to ${MAX_MULTISIG_KEYS} compressed or uncompressed SEC1 keys as hex without 0x`,
    );
  }
  const threshold = optionalCount(options.threshold, { name: "threshold", maximum: keys.length });
  if (threshold === undefined) throw new TypeError("publicKeys need a threshold");
  const { sorted } = options;
  if (sorted !== undefined && typeof sorted !== "boolean") {
    throw new TypeError("sorted must be a boolean");
  }
  return [keys, multisig(threshold, keys, { sorted: sorted === true })];
}

/**
 * Writes the address of each wrapper, or the reason it refuses the script.
 * @param script - Redeem or witness script
 * @param network - Network of the addresses
 * @returns {Pick<ScriptAddressDetails, "addresses" | "refused"> & { lines: string[] }} One per type
 */
function wrapperAddresses(
  script: Uint8Array,
  network: ToolNetwork,
): Pick<ScriptAddressDetails, "addresses" | "refused"> & { lines: string[] } {
  const addresses: Partial<Record<ScriptAddressType, string>> = {};
  const refused: Partial<Record<ScriptAddressType, string>> = {};
  const lines = SCRIPT_ADDRESS_TYPES.map((type) => {
    try {
      addresses[type] = scriptAddress(script, type, { network });
      return `${SCRIPT_ADDRESS_LABELS[type]}: ${addresses[type]}`;
    } catch (error) {
      if (!(error instanceof RangeError)) throw error;
      refused[type] = error.message;
      return `${SCRIPT_ADDRESS_LABELS[type]}: none, ${error.message}`;
    }
  });
  return { addresses, ...(Object.keys(refused).length === 0 ? {} : { refused }), lines };
}

/**
 * Get the P2SH, P2WSH and P2SH-P2WSH addresses of a script or of an m-of-n multisig.
 * @param scriptValue - Redeem or witness script as hex
 * @param options - Multisig threshold, keys and sorted flag, and an optional network name
 * @returns {ToolResult<ScriptAddressDetails>} An address per wrapper, or why it refuses the script
 */
export function getScriptAddress(
  scriptValue: unknown,
  options: ScriptAddressArguments,
): ToolResult<ScriptAddressDetails> {
  const network = parseNetwork(options.network);
  const hasScript = !isUnset(scriptValue);
  const { publicKeys } = options;
  const hasKeys = Array.isArray(publicKeys) ? publicKeys.length > 0 : publicKeys !== undefined;
  if (hasScript === hasKeys)
    throw new TypeError("Pass either script, or publicKeys with threshold");
  const [keys, script] = hasScript
    ? [[], givenScript(scriptValue, options)]
    : multisigArgument(options);
  const { lines, ...wrapped } = wrapperAddresses(script, network);
  const warnings = keys.some((key) => key.length === 130)
    ? ["Uncompressed keys make P2WSH and P2SH-P2WSH spends non-standard, so nodes don't relay them"]
    : [];
  const shownScript = hasKeys ? [`Script: ${script.toHex()} (${script.length} bytes)`] : [];
  return {
    content: content([...shownScript, ...lines, ...warnings].join("\n")),
    details: {
      chain: "bitcoin",
      network,
      script: script.toHex(),
      ...wrapped,
      ...(warnings.length === 0 ? {} : { warnings }),
    },
  };
}

/** Outputs of an output descriptor and the checksum it sums to. */
export interface DescriptorDetails {
  chain: "bitcoin";
  network: string;
  checksum: string;
  /** Whether the descriptor carried that checksum after #. */
  checksumGiven: boolean;
  ranged: boolean;
  outputs: Array<{ index?: number; address: string; script: string }>;
}

/** Descriptor arguments besides the descriptor, raw until the executor checks them. */
export interface DescriptorArguments {
  /** First index of a ranged descriptor. */
  readonly index?: unknown;
  /** Addresses of a ranged descriptor to list. */
  readonly count?: unknown;
  readonly network?: unknown;
}

/**
 * Reads where a ranged descriptor starts and how many addresses it lists.
 * @param ranged - Whether the descriptor has a /* step
 * @param options - Raw first index and count
 * @returns {number[]} The indices to derive, empty for a descriptor without /*
 */
function descriptorIndices(ranged: boolean, options: DescriptorArguments): number[] {
  const start = optionalIndex(options.index, { name: "index" });
  const count = optionalCount(options.count, { name: "count", maximum: MAX_DESCRIPTOR_ADDRESSES });
  if (!ranged) {
    if (start !== undefined || count !== undefined) {
      throw new TypeError("Descriptor has no /* step; leave index and count out");
    }
    return [];
  }
  const first = start ?? 0;
  const length = count ?? 1;
  if (first + length - 1 > 0x7fffffff)
    throw new RangeError("index plus count must stay below 2^31");
  return Array.from({ length }, (_, offset) => first + offset);
}

/**
 * Derive the addresses of a Bitcoin output descriptor and check or compute its checksum.
 * @param descriptorValue - The descriptor, with or without #checksum
 * @param options - First index and count of a ranged descriptor, and an optional network name
 * @returns {ToolResult<DescriptorDetails>} The checksum and the addresses
 */
export function deriveDescriptor(
  descriptorValue: unknown,
  options: DescriptorArguments,
): ToolResult<DescriptorDetails> {
  const text = requiredString(descriptorValue, "Descriptor");
  if (text.length === 0 || text.length > MAX_DESCRIPTOR_LENGTH) {
    throw new RangeError(`Descriptor must be 1 to ${MAX_DESCRIPTOR_LENGTH} characters`);
  }
  const network = parseNetwork(options.network);
  const descriptor = parseDescriptor(text, { network });
  const indices = descriptorIndices(descriptor.ranged, options);
  const shown = (output: DescriptorOutput, index?: number) => ({
    ...(index === undefined ? {} : { index }),
    address: output.address,
    script: output.script.toHex(),
  });
  const outputs = descriptor.ranged
    ? indices.map((index) => shown(descriptor.derive(index), index))
    : [shown(descriptor.derive())];
  const checksumGiven = text.includes("#");
  const lines = [
    `Checksum: ${descriptor.checksum}${checksumGiven ? ", matches the one given" : ""}`,
    ...outputs.map((output) =>
      output.index === undefined
        ? `Address: ${output.address}`
        : `Index ${output.index}: ${output.address}`,
    ),
  ];
  return {
    content: content(lines.join("\n")),
    details: {
      chain: "bitcoin",
      network,
      checksum: descriptor.checksum,
      checksumGiven,
      ranged: descriptor.ranged,
      outputs,
    },
  };
}
