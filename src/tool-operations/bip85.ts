import {
  BIP85_APPLICATIONS,
  MAX_BIP85_TOOL_ROLLS,
  MAX_EXTENDED_KEY_LENGTH,
} from "../tool-parameters.ts";
import {
  type BIP85Entropy,
  deriveBase64Password,
  deriveBase85Password,
  deriveDice,
  deriveHex,
  deriveMnemonic,
  deriveNostr,
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
  readonly length?: unknown;
  readonly sides?: unknown;
  readonly rolls?: unknown;
  readonly identity?: unknown;
}

/** The child secret, its entropy and path. */
export interface DerivedBip85Details {
  application: Application;
  path: string;
  entropy: string;
  mnemonic?: string;
  wif?: string;
  extendedPrivateKey?: string;
  password?: string;
  rolls?: readonly number[];
  nsec?: string;
}

/** Entropy, plus the line and the field an application adds. */
type Derived = BIP85Entropy & {
  readonly line?: readonly [label: string, text: string];
  readonly extra?: Partial<DerivedBip85Details>;
};

/** Options only some applications take, and which ones. */
const OPTION_OWNERS = {
  words: ["bip39"],
  language: ["bip39"],
  bytes: ["hex"],
  length: ["base64", "base85"],
  sides: ["dice"],
  rolls: ["dice"],
  identity: ["nostr"],
} as const satisfies Partial<Record<keyof Bip85Arguments, readonly Application[]>>;

/**
 * Refuses the options of another application. OMP's blank or 0 counts as left out.
 * @param options - Raw options
 * @param application - Checked application
 * @returns {void} Nothing; it throws on a misplaced option
 */
function refuseForeign(options: Bip85Arguments, application: Application): void {
  for (const [name, owners] of Object.entries(OPTION_OWNERS)) {
    const mine = owners.some((owner) => owner === application);
    if (!mine && !isUnsetCost(Reflect.get(options, name))) {
      const whose = `the ${owners.join(" and ")} application${owners.length > 1 ? "s" : ""}`;
      throw new TypeError(`${name} belongs to ${whose}, not ${application}`);
    }
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
 * Reads a count its application can't run without.
 * @param value - Raw argument
 * @param argument - Name, largest value and owning application
 * @returns {number} The count
 * @throws {TypeError} When it's left out
 */
function requiredCount(
  value: unknown,
  argument: IndexArgument & { readonly application: Application },
): number {
  const count = optionalCount(value, argument);
  if (count === undefined) {
    throw new TypeError(`${argument.application} needs ${argument.name.toLowerCase()}`);
  }
  return count;
}

/** One application run with the options it takes. */
type Run = (rootKey: string, options: Bip85Arguments) => Derived | Promise<Derived>;

/**
 * Reads the child index every application but nostr ends its path with.
 * @param options - Raw options
 * @returns {number | undefined} The index, undefined for 0
 */
function childIndex(options: Bip85Arguments): number | undefined {
  return optionalIndex(options.index, { name: "Index" });
}

/**
 * Runs one of the two password applications.
 * @param application - base64 or base85
 * @returns {Run} The run that reads length and index
 */
function password(application: "base64" | "base85"): Run {
  const derive = application === "base64" ? deriveBase64Password : deriveBase85Password;
  return (rootKey, options) => {
    const length = requiredCount(options.length, { name: "Length", maximum: 86, application });
    const child = derive(rootKey, { length, index: childIndex(options) });
    return { ...child, line: ["Password", child.password], extra: { password: child.password } };
  };
}

/** How each application reads its options and what it prints. */
const RUNS: Readonly<Record<Application, Run>> = {
  bip39: async (rootKey, options) => {
    const words = optionalCount(options.words, { name: "Words", maximum: 24 });
    const language = parseBIP39Language(options.language);
    const child = await deriveMnemonic(rootKey, { index: childIndex(options), words, language });
    return { ...child, line: ["Mnemonic", child.mnemonic], extra: { mnemonic: child.mnemonic } };
  },
  wif: (rootKey, options) => {
    const child = deriveWif(rootKey, { index: childIndex(options) });
    return { ...child, line: ["WIF", child.wif], extra: { wif: child.wif } };
  },
  xprv: (rootKey, options) => {
    const child = deriveXprv(rootKey, { index: childIndex(options) });
    const { extendedPrivateKey } = child;
    return {
      ...child,
      line: ["Extended private key", extendedPrivateKey],
      extra: { extendedPrivateKey },
    };
  },
  hex: (rootKey, options) =>
    deriveHex(rootKey, {
      index: childIndex(options),
      bytes: optionalCount(options.bytes, { name: "Bytes", maximum: 64 }),
    }),
  base64: password("base64"),
  base85: password("base85"),
  dice: (rootKey, options) => {
    const application = "dice";
    const sides = requiredCount(options.sides, { name: "Sides", application });
    const rolls = requiredCount(options.rolls, {
      name: "Rolls",
      maximum: MAX_BIP85_TOOL_ROLLS,
      application,
    });
    const child = deriveDice(rootKey, { sides, rolls, index: childIndex(options) });
    return { ...child, line: ["Rolls", child.rolls.join(",")], extra: { rolls: child.rolls } };
  },
  nostr: (rootKey, options) => {
    const child = deriveNostr(rootKey, {
      identity: optionalCount(options.identity, { name: "Identity" }),
      index: optionalCount(options.index, { name: "Index" }),
    });
    return { ...child, line: ["nsec", child.nsec], extra: { nsec: child.nsec } };
  },
};

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
  refuseForeign(options, application);
  const { path, entropy, line, extra } = await RUNS[application](rootKey, options);
  const details: DerivedBip85Details = {
    application,
    path,
    entropy: entropy.toHex(),
    ...extra,
  };
  const lines = [`Application: ${application}`, `Path: ${path}`, `Entropy: ${details.entropy}`];
  if (line !== undefined) lines.push(line.join(": "));
  lines.push("This secret is saved in the transcript. Never use it for real funds.");
  return { content: content(lines.join("\n")), details };
}
