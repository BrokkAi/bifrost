import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { PLATFORMS, ROOT_PACKAGE, tarballBasename, versionFromTag } from "./package-release.mjs";

const VISIBILITY_ATTEMPTS = 20;
const VISIBILITY_DELAY_MS = 15_000;

function parseArgs(argv) {
  const options = { publish: false };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--dist") options.dist = argv[++index];
    else if (argv[index] === "--release-tag") options.releaseTag = argv[++index];
    else if (argv[index] === "--yes-publish") options.publish = true;
    else throw new Error(`unknown argument: ${argv[index]}`);
  }
  if (!options.dist || !options.releaseTag) {
    throw new Error("Usage: node scripts/publish-release.mjs --dist DIRECTORY --release-tag vX.Y.Z [--yes-publish]");
  }
  return options;
}

function packageExists(packageName, version) {
  const result = spawnSync(
    "npm",
    ["view", `${packageName}@${version}`, "version", "--registry=https://registry.npmjs.org"],
    { encoding: "utf8" },
  );
  return result.status === 0 && result.stdout.trim() === version;
}

function validateTarball(tarball, packageName, version) {
  if (!existsSync(tarball)) throw new Error(`missing tarball: ${tarball}`);
  const manifest = JSON.parse(
    execFileSync("tar", ["-xzOf", tarball, "package/package.json"], { encoding: "utf8" }),
  );
  if (manifest.name !== packageName || manifest.version !== version) {
    throw new Error(`${tarball} contains ${manifest.name}@${manifest.version}`);
  }
}

function publishTarball(tarball) {
  const result = spawnSync("npm", ["publish", tarball, "--access", "public"], { stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`npm publish failed for ${tarball}`);
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForVersion(packageName, version) {
  for (let attempt = 1; attempt <= VISIBILITY_ATTEMPTS; attempt += 1) {
    if (packageExists(packageName, version)) return;
    if (attempt < VISIBILITY_ATTEMPTS) {
      process.stderr.write(`waiting for ${packageName}@${version} (${attempt}/${VISIBILITY_ATTEMPTS})\n`);
      await delay(VISIBILITY_DELAY_MS);
    }
  }
  throw new Error(`${packageName}@${version} did not become available from npm`);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const version = versionFromTag(options.releaseTag);
  const dist = path.resolve(options.dist);
  const packages = [...PLATFORMS.map((platform) => platform.packageName), ROOT_PACKAGE];
  const entries = packages.map((packageName) => ({
    packageName,
    tarball: path.join(dist, tarballBasename(packageName, version)),
  }));
  for (const entry of entries) validateTarball(entry.tarball, entry.packageName, version);

  if (!options.publish) {
    for (const entry of entries) process.stdout.write(`would publish ${entry.packageName}@${version}\n`);
    return;
  }

  for (const entry of entries) {
    if (!packageExists(entry.packageName, version)) publishTarball(entry.tarball);
    await waitForVersion(entry.packageName, version);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`npm publication: ${error.message}`);
    process.exitCode = 1;
  });
}
