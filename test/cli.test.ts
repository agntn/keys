import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vite-plus/test";

const execFileAsync = promisify(execFile);
const root = resolve(import.meta.dirname, "..");
const bin = resolve(root, "dist/cli.mjs");
const hook = resolve(root, "test/record-loads.mjs");

/** What one run of the built bin printed, how it exited, and which packages it loaded. */
interface BinRun {
  readonly code: number;
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
 * Reads the packages a run loaded from the hook's report on stderr.
 *
 * @param {string} stderr - What the child wrote to stderr.
 * @returns {string[]} Every package the run loaded, once each.
 */
function loadedPackages(stderr: string): string[] {
  const report = /@loaded (\[.*\])/u.exec(stderr)?.[1];
  if (report === undefined) {
    throw new Error(`the load hook reported nothing: ${stderr}`);
  }
  const urls: unknown = JSON.parse(report);
  if (!Array.isArray(urls)) {
    throw new TypeError(`the load hook reported something other than a list: ${report}`);
  }
  const packages = urls.map((url) => packageOf(String(url))).filter((name) => name !== undefined);
  return [...new Set(packages)];
}

/**
 * Runs the built bin under the load hook. stdin is closed at once, because the server reads it until
 * it ends, and an unknown command exits 1 on purpose, so that run comes back too.
 *
 * @param {readonly string[]} args - Arguments for the bin.
 * @returns {Promise<BinRun>} The exit code, stdout and the loaded packages.
 */
async function runBin(args: readonly string[]): Promise<BinRun> {
  const pending = execFileAsync(process.execPath, ["--import", hook, bin, ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 10_000,
  });
  pending.child.stdin?.end();
  const { code, stdout, stderr } = await pending.then(
    (run) => ({ code: 0, ...run }),
    (error: unknown) => failedRun(error),
  );
  return { code, packages: loadedPackages(stderr), stdout };
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
});
