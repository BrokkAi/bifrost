#!/usr/bin/env node

import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { prepareOpenPacks } from "../../plugins/bifrost-agent/bin/open-packs.mjs";

const execFileAsync = promisify(execFile);
const options = {};
const args = process.argv.slice(2);
for (let index = 0; index < args.length; index += 2) {
  const name = args[index];
  if (
    !["--binary", "--cache-dir", "--receipt-path", "--env-path"].includes(
      name,
    ) ||
    !args[index + 1] ||
    Object.hasOwn(options, name)
  ) {
    throw new Error(
      "Usage: prepare-open-packs.mjs --binary PATH --cache-dir DIR --receipt-path FILE --env-path FILE",
    );
  }
  options[name] = path.resolve(args[index + 1]);
}
for (const name of [
  "--binary",
  "--cache-dir",
  "--receipt-path",
  "--env-path",
]) {
  if (!options[name]) throw new Error(`Missing ${name}`);
}

// Release qualification requires an exact profile emitted by the staged binary.
// An older binary or an unavailable compatible release is a failed gate.
const { stdout } = await execFileAsync(
  options["--binary"],
  ["pack-engine-profile"],
  {
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  },
);
const result = await prepareOpenPacks({
  cacheDir: options["--cache-dir"],
  engineProfile: JSON.parse(stdout),
  refresh: true,
});
for (const [name, value] of [
  ["--receipt-path", result.receipt],
  ["--env-path", result.env],
]) {
  await fs.mkdir(path.dirname(options[name]), { recursive: true });
  await fs.writeFile(options[name], `${JSON.stringify(value, null, 2)}\n`, {
    flag: "wx",
  });
}
console.log(JSON.stringify(result.receipt));
