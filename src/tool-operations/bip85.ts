import { BIP85_APPLICATIONS, MAX_EXTENDED_KEY_LENGTH } from "../tool-parameters.ts";
import {
  type BIP85Entropy,
  deriveHex,
  deriveMnemonic,
  deriveWif,
  deriveXprv,
} from "../utils/bip85/index.ts";
import {
  type IndexArgument,
  isUnsetCost,
  oneOf,
  optionalIndex,
  requiredString,
} from "./arguments.ts";
import { parseBIP39Language } from "./bip39.ts";
import { type ToolResult, content } from "./results.ts";

/** An application the tool derives. */
type Application = (typeof BIP85_APPLICATIONS)[number];

/** BIP85 tool arguments besides the root key, unchecked. */
export interface Bip85Arguments {
  readonly application?: unknown;
  readonly index?: unknown;
  readonly words?: unknown;
  readonly language?: unknown;
  readonly bytes?: unknown;
}

/** The child secret, its entropy and path. */
export interface DerivedBip85Details {
  application: Application;
  path: string;
  entropy: string;
  mnemonic?: string;
  wif?: string;
  extendedPrivateKey?: string;
}

/** Entropy, plus the line and field an application adds. */
type Derived = BIP85Entropy & {
  readonly line?: readonly [string, string, keyof DerivedBip85Details];
};

/**
 * Refuses an option of another application. OMP's blank or 0 counts as left out.
 * @param value - Raw argument
 * @param argument - Its name and owning application
 * @returns {void} Nothing; it throws on a misplaced option
 */
function refuseForeign(
  value: unknown,
  argument: {
    readonly name: string;
    readonly owner: Application;
    readonly application: Application;
  },
): void {
  const { name, owner, application } = argument;
  if (!isUnsetCost(value) && application !== owner) {
    throw new TypeError(`${name} belongs to the ${owner} application, not ${application}`);
  }
}

/**
 * Reads a count, OMP's 0 meaning the default.
 * @param value - Raw argument
 * @param argument - Name and largest value
 * @returns {number | undefined} The count, undefined for the default
 */
function optionalCount(value: unknown, argument: IndexArgument): number | undefined {
  return isUnsetCost(value) ? undefined : optionalIndex(value, argument);
}

/**
 * Runs one application with the options it takes.
 * @param rootKey - Checked root key
 * @param application - Checked application
 * @param options - Raw options
 * @returns {Promise<Derived>} Entropy, path and the line to print
 */
async function derive(
  rootKey: string,
  application: Application,
  options: Bip85Arguments,
): Promise<Derived> {
  const index = optionalIndex(options.index, { name: "Index" });
  if (application === "bip39") {
    const words = optionalCount(options.words, { name: "Words", maximum: 24 });
    const language = parseBIP39Language(options.language);
    const child = await deriveMnemonic(rootKey, { index, words, language });
    return { ...child, line: ["Mnemonic", child.mnemonic, "mnemonic"] };
  }
  if (application === "wif") {
    const child = deriveWif(rootKey, { index });
    return { ...child, line: ["WIF", child.wif, "wif"] };
  }
  if (application === "xprv") {
    const child = deriveXprv(rootKey, { index });
    return {
      ...child,
      line: ["Extended private key", child.extendedPrivateKey, "extendedPrivateKey"],
    };
  }
  return deriveHex(rootKey, {
    index,
    bytes: optionalCount(options.bytes, { name: "Bytes", maximum: 64 }),
  });
}

/**
 * Derives one BIP85 child from a master key.
 * @param rootKeyValue - Master xprv or tprv
 * @param options - Application, index and its own options
 * @returns {Promise<ToolResult<DerivedBip85Details>>} Path, entropy and child secret
 */
export async function deriveBip85(
  rootKeyValue: unknown,
  options: Bip85Arguments,
): Promise<ToolResult<DerivedBip85Details>> {
  const rootKey = requiredString(rootKeyValue, "Root key");
  if (rootKey.length > MAX_EXTENDED_KEY_LENGTH) throw new RangeError("Root key is too long");
  const application = oneOf(options.application, {
    name: "Application",
    allowed: BIP85_APPLICATIONS,
  });
  refuseForeign(options.words, { name: "words", owner: "bip39", application });
  refuseForeign(options.language, { name: "language", owner: "bip39", application });
  refuseForeign(options.bytes, { name: "bytes", owner: "hex", application });
  const { path, entropy, line } = await derive(rootKey, application, options);
  const details: DerivedBip85Details = { application, path, entropy: entropy.toHex() };
  const lines = [`Application: ${application}`, `Path: ${path}`, `Entropy: ${details.entropy}`];
  if (line !== undefined) {
    const [label, value, field] = line;
    lines.push(`${label}: ${value}`);
    Object.assign(details, { [field]: value });
  }
  lines.push("This secret is saved in the transcript. Never use it for real funds.");
  return { content: content(lines.join("\n")), details };
}
