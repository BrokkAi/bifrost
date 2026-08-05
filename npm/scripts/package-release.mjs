import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFile = promisify(execFileCallback);
const npmRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(npmRoot, "..");

export const ROOT_PACKAGE = "@brokkai/bifrost";

export const RELEASE_DOCUMENTS = [
  "README.md",
  "LICENSE.md",
  "GPL-3.0.md",
  "SOURCE.md",
  "THIRD_PARTY_LICENSES.html",
  "SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt",
];

export const PLATFORMS = [
  {
    packageName: "@brokkai/bifrost-darwin-universal",
    target: "universal-apple-darwin",
    extension: ".tar.gz",
    binary: "bifrost",
    description: "Native universal macOS bundle for @brokkai/bifrost",
    os: ["darwin"],
    cpu: ["x64", "arm64"],
  },
  {
    packageName: "@brokkai/bifrost-linux-x64-gnu",
    target: "x86_64-unknown-linux-gnu",
    extension: ".tar.gz",
    binary: "bifrost",
    description: "Native Linux x64 glibc bundle for @brokkai/bifrost",
    os: ["linux"],
    cpu: ["x64"],
    libc: ["glibc"],
  },
  {
    packageName: "@brokkai/bifrost-linux-x64-musl",
    target: "x86_64-unknown-linux-musl",
    extension: ".tar.gz",
    binary: "bifrost",
    description: "Native Linux x64 musl bundle for @brokkai/bifrost",
    os: ["linux"],
    cpu: ["x64"],
    libc: ["musl"],
  },
  {
    packageName: "@brokkai/bifrost-linux-arm64-gnu",
    target: "aarch64-unknown-linux-gnu",
    extension: ".tar.gz",
    binary: "bifrost",
    description: "Native Linux ARM64 glibc bundle for @brokkai/bifrost",
    os: ["linux"],
    cpu: ["arm64"],
    libc: ["glibc"],
  },
  {
    packageName: "@brokkai/bifrost-android-arm64",
    target: "aarch64-linux-android",
    extension: ".tar.gz",
    binary: "bifrost",
    description: "Native Android ARM64 bundle for @brokkai/bifrost",
    os: ["android"],
    cpu: ["arm64"],
  },
  {
    packageName: "@brokkai/bifrost-win32-x64",
    target: "x86_64-pc-windows-msvc",
    extension: ".zip",
    binary: "bifrost.exe",
    description: "Native Windows x64 bundle for @brokkai/bifrost",
    os: ["win32"],
    cpu: ["x64"],
  },
  {
    packageName: "@brokkai/bifrost-win32-arm64",
    target: "aarch64-pc-windows-msvc",
    extension: ".zip",
    binary: "bifrost.exe",
    description: "Native Windows ARM64 bundle for @brokkai/bifrost",
    os: ["win32"],
    cpu: ["arm64"],
  },
];

export function versionFromTag(tag) {
  const match = /^v(\d+\.\d+\.\d+)$/.exec(tag);
  if (!match) throw new Error(`release tag must look like vX.Y.Z, got: ${tag}`);
  return match[1];
}

export async function cargoVersion() {
  const manifest = await readFile(path.join(repositoryRoot, "Cargo.toml"), "utf8");
  const workspacePackage = manifest.match(/\[workspace\.package\]([\s\S]*?)(?:\n\[|$)/)?.[1];
  const version = workspacePackage?.match(/^version = "([^"]+)"$/m)?.[1];
  if (!version) throw new Error("could not read [workspace.package] version from Cargo.toml");
  return version;
}

function baseManifest(version) {
  return {
    version,
    license: "LGPL-3.0-or-later",
    repository: "https://github.com/BrokkAi/bifrost",
    homepage: "https://bifrost.brokk.ai/",
    bugs: "https://github.com/BrokkAi/bifrost/issues",
    publishConfig: { access: "public" },
  };
}

export function platformManifest(platform, version) {
  return {
    name: platform.packageName,
    ...baseManifest(version),
    description: platform.description,
    os: platform.os,
    cpu: platform.cpu,
    ...(platform.libc ? { libc: platform.libc } : {}),
    preferUnplugged: true,
    files: ["bin/", ...RELEASE_DOCUMENTS],
  };
}

export function rootManifest(version) {
  return {
    name: ROOT_PACKAGE,
    ...baseManifest(version),
    description: "Native Bifrost code analysis CLI, MCP server, and language server",
    type: "module",
    bin: { bifrost: "bin/bifrost.js" },
    files: ["bin/", "README.md", "LICENSE.md"],
    optionalDependencies: Object.fromEntries(
      PLATFORMS.map((platform) => [platform.packageName, version]),
    ),
    engines: { node: ">=18" },
  };
}

export function tarballBasename(packageName, version) {
  return `${packageName.replace(/^@/, "").replace("/", "-")}-${version}.tgz`;
}

function packageDirectory(packageName) {
  return packageName.replace("@", "").replace("/", "-");
}

function archiveName(version, platform) {
  return `bifrost-v${version}-${platform.target}${platform.extension}`;
}

async function writeManifest(directory, manifest) {
  await writeFile(path.join(directory, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

async function sha256(filename) {
  return createHash("sha256").update(await readFile(filename)).digest("hex");
}

async function verifyChecksum(filename) {
  const checksum = (await readFile(`${filename}.sha256`, "utf8")).trim().split(/\s+/)[0];
  if (!/^[a-f0-9]{64}$/i.test(checksum)) {
    throw new Error(`invalid SHA-256 sidecar for ${path.basename(filename)}`);
  }
  const actual = await sha256(filename);
  if (actual !== checksum.toLowerCase()) {
    throw new Error(`checksum mismatch for ${path.basename(filename)}: expected ${checksum}, got ${actual}`);
  }
}

async function extractArchive(filename, destination, expectedRoot) {
  if (filename.endsWith(".zip")) {
    await execFile("unzip", ["-q", filename, "-d", destination]);
  } else {
    await execFile("tar", ["-xzf", filename, "-C", destination]);
  }
  const entries = await readdir(destination, { withFileTypes: true });
  const roots = entries.filter((entry) => entry.isDirectory());
  if (entries.length !== 1 || roots.length !== 1 || roots[0].name !== expectedRoot) {
    throw new Error(`${path.basename(filename)} must contain only ${expectedRoot}`);
  }
  return path.join(destination, expectedRoot);
}

async function validateReleaseBundle(directory, platform) {
  const expected = [...RELEASE_DOCUMENTS, platform.binary].sort();
  const actual = (await readdir(directory)).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${platform.target} release bundle has unexpected entries: ${JSON.stringify(actual)}`);
  }
  const binary = await stat(path.join(directory, platform.binary));
  if (binary.size === 0) throw new Error(`${platform.target} release binary is empty`);
  if (platform.binary !== "bifrost.exe" && (binary.mode & 0o111) === 0) {
    throw new Error(`${platform.target} release binary is not executable`);
  }
}

async function stagePlatform(platform, version, source, stagingRoot) {
  const destination = path.join(stagingRoot, packageDirectory(platform.packageName));
  await mkdir(path.join(destination, "bin"), { recursive: true });
  await cp(path.join(source, platform.binary), path.join(destination, "bin", platform.binary));
  for (const entry of RELEASE_DOCUMENTS) {
    await cp(path.join(source, entry), path.join(destination, entry));
  }
  await writeManifest(destination, platformManifest(platform, version));
  return destination;
}

async function stageRoot(version, stagingRoot) {
  const destination = path.join(stagingRoot, packageDirectory(ROOT_PACKAGE));
  await mkdir(path.join(destination, "bin"), { recursive: true });
  await cp(path.join(npmRoot, "launcher", "bifrost.js"), path.join(destination, "bin", "bifrost.js"));
  await chmod(path.join(destination, "bin", "bifrost.js"), 0o755);
  await cp(path.join(npmRoot, "launcher", "README.md"), path.join(destination, "README.md"));
  await cp(path.join(repositoryRoot, "LICENSE.md"), path.join(destination, "LICENSE.md"));
  await writeManifest(destination, rootManifest(version));
  return destination;
}

async function pack(directory, outputDirectory) {
  let stdout;
  try {
    ({ stdout } = await execFile("npm", [
      "pack",
      directory,
      "--pack-destination",
      outputDirectory,
      "--silent",
    ]));
  } catch (error) {
    throw new Error(
      `npm pack failed for ${path.basename(directory)}: ${error.message}; code=${error.code}; signal=${error.signal}\n${error.stdout ?? ""}\n${error.stderr ?? ""}`,
      { cause: error },
    );
  }
  return path.join(outputDirectory, stdout.trim().split("\n").at(-1));
}

export async function packageRelease({ releaseTag, assetsDirectory, outputDirectory }) {
  const version = versionFromTag(releaseTag);
  const manifestVersion = await cargoVersion();
  if (version !== manifestVersion) {
    throw new Error(`release tag ${releaseTag} does not match Cargo.toml version v${manifestVersion}`);
  }
  const output = path.resolve(outputDirectory ?? path.join(npmRoot, "dist"));
  await rm(output, { recursive: true, force: true });
  await mkdir(output, { recursive: true });
  const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "bifrost-npm-"));
  try {
    for (const platform of PLATFORMS) {
      const archive = path.join(assetsDirectory, archiveName(version, platform));
      await verifyChecksum(archive);
      const extractDirectory = path.join(temporaryRoot, `extract-${packageDirectory(platform.packageName)}`);
      await mkdir(extractDirectory, { recursive: true });
      const expectedRoot = `bifrost-v${version}-${platform.target}`;
      const bundle = await extractArchive(archive, extractDirectory, expectedRoot);
      await validateReleaseBundle(bundle, platform);
      await pack(await stagePlatform(platform, version, bundle, temporaryRoot), output);
    }
    await pack(await stageRoot(version, temporaryRoot), output);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
  return output;
}

function usage() {
  return "Usage: node scripts/package-release.mjs --release-tag vX.Y.Z --assets DIRECTORY [--out DIRECTORY]";
}

async function main() {
  const args = process.argv.slice(2);
  const releaseTag = args[args.indexOf("--release-tag") + 1];
  const assetsDirectory = args[args.indexOf("--assets") + 1];
  const outputArgument = args.includes("--out") ? args[args.indexOf("--out") + 1] : undefined;
  if (!releaseTag || !assetsDirectory) throw new Error(usage());
  await packageRelease({
    releaseTag,
    assetsDirectory: path.resolve(assetsDirectory),
    outputDirectory: outputArgument ? path.resolve(outputArgument) : undefined,
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`npm packaging: ${error.message}`);
    process.exitCode = 1;
  });
}
