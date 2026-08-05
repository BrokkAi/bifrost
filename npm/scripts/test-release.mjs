import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { platformPackageName } from "../launcher/bifrost.js";
import { ROOT_PACKAGE, tarballBasename, versionFromTag } from "./package-release.mjs";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed:\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

async function main() {
  const args = process.argv.slice(2);
  const dist = args[args.indexOf("--dist") + 1];
  const releaseTag = args[args.indexOf("--release-tag") + 1];
  if (!dist || !releaseTag) {
    throw new Error("Usage: node scripts/test-release.mjs --dist DIRECTORY --release-tag vX.Y.Z");
  }
  const version = versionFromTag(releaseTag);
  const packageName = platformPackageName();
  const absoluteDist = path.resolve(dist);
  const rootTarball = path.join(absoluteDist, tarballBasename(ROOT_PACKAGE, version));
  const platformTarball = path.join(absoluteDist, tarballBasename(packageName, version));
  const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "bifrost-npm-smoke-"));
  try {
    run("npm", [
      "install",
      "--prefix",
      temporaryRoot,
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      rootTarball,
      platformTarball,
    ]);
    const launcher = path.join(
      temporaryRoot,
      "node_modules",
      ".bin",
      process.platform === "win32" ? "bifrost.cmd" : "bifrost",
    );
    const result = run(launcher, ["--version"], { shell: process.platform === "win32" });
    if (!result.stdout.includes(version)) {
      throw new Error(`bifrost --version did not report ${version}: ${result.stdout.trim()}`);
    }
    process.stdout.write(result.stdout);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`npm smoke test: ${error.message}`);
    process.exitCode = 1;
  });
}
