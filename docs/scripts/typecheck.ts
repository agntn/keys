import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";

/** Docus ships its layer as TypeScript source, and it fails its own check under this config. */
const docusSource = /node_modules\/docus\//u;
const vueTsc = createRequire(import.meta.url).resolve("vue-tsc/bin/vue-tsc.js");

let failed = false;
let skipped = 0;
for (const config of ["app", "server", "shared", "node"]) {
  const run = spawnSync(
    process.execPath,
    [vueTsc, "--noEmit", "--pretty", "false", "-p", `.nuxt/tsconfig.${config}.json`],
    { encoding: "utf8" },
  );
  if (run.error) throw run.error;
  const output = `${run.stdout}${run.stderr}`;
  const errors = output.split(/\n(?=\S)/u).filter((entry) => entry.includes(": error TS"));
  const own = errors.filter((entry) => !docusSource.test(entry.slice(0, entry.indexOf("("))));
  skipped += errors.length - own.length;
  if (own.length > 0) {
    console.error(own.join("\n"));
    failed = true;
  } else if (run.status !== 0 && errors.length === 0) {
    console.error(output);
    failed = true;
  }
}
console.log(`vue-tsc: ${failed ? "errors above" : "clean"}, ${skipped} in Docus's own sources skipped.`);
process.exitCode = failed ? 1 : 0;
