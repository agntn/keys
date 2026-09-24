import { execFile } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vite-plus/test";

const execFileAsync = promisify(execFile);
const root = resolve(import.meta.dirname, "..");
const bin = resolve(root, "dist/cli.mjs");
const hook = resolve(root, "test/record-loads.mjs");

/** What one run of the built bin printed, how it exited, and which modules and packages it loaded. */
interface BinRun {
  readonly code: number;
  readonly modules: readonly string[];
  readonly packages: readonly string[];
  readonly stdout: string;
}

/** The streams and exit code execFile attaches to a rejected run. */
interface FailedRun {
  readonly code: number;
  readonly stderr: string;
  readonly stdout: string;
}

/**
 * Reads the exit code and both streams off a rejected execFile call.
 *
 * @param {unknown} error - The rejection.
 * @returns {FailedRun} The run, when the rejection is a failed exit rather than a spawn error.
 */
function failedRun(error: unknown): FailedRun {
  if (
    !(error instanceof Error) ||
    !("code" in error) ||
    typeof error.code !== "number" ||
    !("stdout" in error) ||
    typeof error.stdout !== "string" ||
    !("stderr" in error) ||
    typeof error.stderr !== "string"
  ) {
    throw error;
  }
  return { code: error.code, stdout: error.stdout, stderr: error.stderr };
}

/**
 * The package directory a module URL sits in. pnpm's store paths nest node_modules, so the last
 * one counts.
 *
 * @param {string} url - A module URL the load hook reported.
 * @returns {string | undefined} The package name, or undefined outside node_modules.
 */
function packageOf(url: string): string | undefined {
  const dirs = url.match(/\/node_modules\/((?:@[^/]+\/)?[^/]+)\//gu);
  return dirs?.at(-1)?.replaceAll(/^\/node_modules\/|\/$/gu, "");
}

/**
 * Reads the module URLs a run loaded from the hook's report on stderr.
 *
 * @param {string} stderr - What the child wrote to stderr.
 * @returns {string[]} Every module URL the run loaded.
 */
function loadedModules(stderr: string): string[] {
  const report = /@loaded (\[.*\])/u.exec(stderr)?.[1];
  if (report === undefined) {
    throw new Error(`the load hook reported nothing: ${stderr}`);
  }
  const urls: unknown = JSON.parse(report);
  if (!Array.isArray(urls)) {
    throw new TypeError(`the load hook reported something other than a list: ${report}`);
  }
  return urls.map(String);
}

/**
 * Runs the built bin under the load hook. stdin is closed at once, because the server reads it until
 * it ends, and an unknown command exits 1 on purpose, so that run comes back too. `KEYS_DIST=1`
 * keeps the bundle, which a checkout would otherwise swap for the live source.
 *
 * @param {readonly string[]} args - Arguments for the bin.
 * @param {{ readonly dist?: boolean; readonly path?: string }} options - `dist: false` lets the checkout load the source; `path` runs another copy of the bin.
 * @returns {Promise<BinRun>} The exit code, stdout and the loaded modules and packages.
 */
async function runBin(
  args: readonly string[],
  { dist = true, path = bin }: { readonly dist?: boolean; readonly path?: string } = {},
): Promise<BinRun> {
  const { KEYS_DIST: _inherited, ...environment } = process.env;
  const pending = execFileAsync(process.execPath, ["--import", hook, path, ...args], {
    cwd: root,
    encoding: "utf8",
    env: dist ? { ...environment, KEYS_DIST: "1" } : environment,
    timeout: 10_000,
  });
  pending.child.stdin?.end();
  const { code, stdout, stderr } = await pending.then(
    (run) => ({ code: 0, ...run }),
    (error: unknown) => failedRun(error),
  );
  const modules = loadedModules(stderr);
  const packages = modules.map(packageOf).filter((name) => name !== undefined);
  return { code, modules, packages: [...new Set(packages)], stdout };
}

describe("keys usage paths", () => {
  beforeAll(() => {
    if (!existsSync(bin)) {
      throw new Error("dist/cli.mjs is missing, run pnpm build first");
    }
  });

  it.each([
    { args: ["--help"], code: 0 },
    { args: ["-h"], code: 0 },
    { args: ["mcp", "--help"], code: 0 },
    { args: ["no-such-command"], code: 1 },
  ])("keys $args prints the usage without the server stack", async ({ args, code }) => {
    const run = await runBin(args);
    expect(run.code).toBe(code);
    expect(run.stdout).toMatch(/USAGE.*keys mcp/u);
    expect(run.packages).toContain("citty");
    expect(run.packages).not.toContain("@modelcontextprotocol/sdk");
    expect(run.packages).not.toContain("typebox");
    expect(run.packages).not.toContain("@noble/curves");
    expect(run.packages).not.toContain("@scure/bip39");
  });

  it("keys mcp loads the server stack once it runs", async () => {
    const { code, packages } = await runBin(["mcp"]);
    expect(code).toBe(0);
    expect(packages).toContain("@modelcontextprotocol/sdk");
    expect(packages).toContain("@noble/curves");
  });

  it("keys mcp runs the live source from a checkout and the bundle under KEYS_DIST=1", async () => {
    const sourceRoot = new URL("../src/", import.meta.url).href;
    const live = await runBin(["mcp"], { dist: false });
    const bundled = await runBin(["mcp"]);

    expect(live.code).toBe(0);
    expect(live.modules).toContain(`${sourceRoot}mcp.ts`);
    expect(bundled.code).toBe(0);
    expect(bundled.modules.filter((url) => url.startsWith(sourceRoot))).toEqual([]);
  });

  it("keys mcp keeps the bundle when the package sits under node_modules", async () => {
    const cache = resolve(root, "node_modules/.cache");
    mkdirSync(cache, { recursive: true });
    const copy = mkdtempSync(join(cache, "keys-cli-"));
    try {
      for (const entry of ["dist", "src", "package.json"]) {
        cpSync(resolve(root, entry), join(copy, entry), { recursive: true });
      }
      const run = await runBin(["mcp"], { dist: false, path: join(copy, "dist/cli.mjs") });
      const copiedSource = pathToFileURL(join(copy, "src")).href;

      expect(run.code).toBe(0);
      expect(run.modules.filter((url) => url.startsWith(copiedSource))).toEqual([]);
    } finally {
      rmSync(copy, { recursive: true, force: true });
    }
  });

  it("keys mcp keeps the bundle in a checkout without dev dependencies", async () => {
    const copy = mkdtempSync(join(tmpdir(), "keys-prod-"));
    try {
      for (const entry of ["dist", "src", "package.json"]) {
        cpSync(resolve(root, entry), join(copy, entry), { recursive: true });
      }
      const manifest: unknown = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
      const dependencies =
        typeof manifest === "object" && manifest !== null && "dependencies" in manifest
          ? Object.keys(manifest.dependencies ?? {})
          : [];
      expect(dependencies).not.toContain("typebox");
      for (const name of dependencies) {
        mkdirSync(join(copy, "node_modules", name, ".."), { recursive: true });
        symlinkSync(resolve(root, "node_modules", name), join(copy, "node_modules", name));
      }
      const run = await runBin(["mcp"], { dist: false, path: join(copy, "dist/cli.mjs") });
      const copiedSource = pathToFileURL(join(copy, "src")).href;

      expect(run.code).toBe(0);
      expect(run.modules.filter((url) => url.startsWith(copiedSource))).toEqual([]);
    } finally {
      rmSync(copy, { recursive: true, force: true });
    }
  });
});
