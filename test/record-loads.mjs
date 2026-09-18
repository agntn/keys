import { registerHooks } from "node:module";

/** Every module URL Node loaded after this file evaluated, reported as one `@loaded [...]` line on stderr at exit. */
const loaded = [];

registerHooks({
  load(url, context, nextLoad) {
    loaded.push(url);
    return nextLoad(url, context);
  },
});

process.on("exit", () => {
  process.stderr.write(`\n@loaded ${JSON.stringify(loaded)}\n`);
});
