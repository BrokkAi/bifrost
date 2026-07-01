#!/usr/bin/env node

import { execFile, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const OWNER = "BrokkAi";
const REPO = "bifrost";
const BINARY_NAME = "bifrost";
const DEFAULT_TOOLSET = "symbol|extended";
const DOWNLOAD_TIMEOUT_MS = 60_000;
export const SUPPORTED_TARGETS = [
  "aarch64-pc-windows-msvc",
  "aarch64-unknown-linux-gnu",
  "universal-apple-darwin",
  "x86_64-pc-windows-msvc",
  "x86_64-unknown-linux-gnu"
];

const thisFile = fileURLToPath(import.meta.url);
const packageDir = path.resolve(path.dirname(thisFile), "..");
const metadataPath = path.join(packageDir, "bifrost-release.json");

export class LauncherError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = "LauncherError";
    this.code = code;
    if (cause) {
      this.cause = cause;
    }
  }
}

export function parseLauncherArgs(args) {
  const parsed = {
    root: null,
    toolset: DEFAULT_TOOLSET,
    passThrough: []
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if ((arg === "--root" || arg === "--workspace-root") && index + 1 < args.length) {
      parsed.root = args[index + 1];
      index += 1;
      continue;
    }
    if (arg.startsWith("--root=")) {
      parsed.root = arg.slice("--root=".length);
      continue;
    }
    if (arg.startsWith("--workspace-root=")) {
      parsed.root = arg.slice("--workspace-root=".length);
      continue;
    }
    if ((arg === "--mcp" || arg === "--toolset") && index + 1 < args.length) {
      parsed.toolset = args[index + 1];
      index += 1;
      continue;
    }
    if (arg.startsWith("--mcp=")) {
      parsed.toolset = arg.slice("--mcp=".length);
      continue;
    }
    if (arg.startsWith("--toolset=")) {
      parsed.toolset = arg.slice("--toolset=".length);
      continue;
    }
    parsed.passThrough.push(arg);
  }

  return parsed;
}

export function looksUnexpandedHostPlaceholder(value) {
  return /\$\{[^}]+}|\{\{[^}]+}}|%[A-Za-z_][A-Za-z0-9_]*%/.test(value);
}

export async function resolveWorkspaceRoot({ env = process.env, argvRoot = null, cwd = process.cwd(), fsImpl = fs } = {}) {
  const raw = firstUsableRootCandidate(env.BIFROST_WORKSPACE_ROOT, argvRoot, cwd);
  if (!raw) {
    throw new LauncherError(
      "missing_workspace_root",
      "Bifrost workspace root is missing. Set BIFROST_WORKSPACE_ROOT or start the host from a workspace directory."
    );
  }

  const resolved = path.resolve(raw);
  let stat;
  try {
    stat = await fsImpl.stat(resolved);
  } catch (error) {
    throw new LauncherError(
      "missing_workspace_root",
      `Bifrost workspace root does not exist: ${resolved}`,
      error
    );
  }
  if (!stat.isDirectory()) {
    throw new LauncherError(
      "missing_workspace_root",
      `Bifrost workspace root is not a directory: ${resolved}`
    );
  }
  return resolved;
}

function firstUsableRootCandidate(...candidates) {
  for (const candidate of candidates) {
    const trimmed = String(candidate ?? "").trim();
    if (!trimmed || looksUnexpandedHostPlaceholder(trimmed)) {
      continue;
    }
    return trimmed;
  }
  return null;
}

export function releaseTargetFor(platform = process.platform, arch = process.arch) {
  if (platform === "darwin" && (arch === "x64" || arch === "arm64")) {
    return "universal-apple-darwin";
  }
  if (platform === "linux" && arch === "x64") {
    return "x86_64-unknown-linux-gnu";
  }
  if (platform === "linux" && arch === "arm64") {
    return "aarch64-unknown-linux-gnu";
  }
  if (platform === "win32" && arch === "x64") {
    return "x86_64-pc-windows-msvc";
  }
  if (platform === "win32" && arch === "arm64") {
    return "aarch64-pc-windows-msvc";
  }
  throw new LauncherError(
    "unsupported_platform",
    `Unsupported platform for Bifrost binary: ${platform}-${arch}. Supported release targets: ${SUPPORTED_TARGETS.join(", ")}.`
  );
}

export function executableNameFor(platform = process.platform) {
  return platform === "win32" ? `${BINARY_NAME}.exe` : BINARY_NAME;
}

export function releaseAssetFor(version, platform = process.platform, arch = process.arch) {
  const tag = releaseTagForVersion(version);
  const target = releaseTargetFor(platform, arch);
  const extension = platform === "win32" ? ".zip" : ".tar.gz";
  const archiveName = `${BINARY_NAME}-${tag}-${target}${extension}`;
  const checksumName = `${archiveName}.sha256`;
  const base = `https://github.com/${OWNER}/${REPO}/releases/download/${tag}`;
  return {
    target,
    archiveName,
    checksumName,
    archiveUrl: `${base}/${archiveName}`,
    checksumUrl: `${base}/${checksumName}`
  };
}

function releaseTagForVersion(version) {
  const trimmed = String(version ?? "").trim();
  if (!trimmed) {
    throw new LauncherError("metadata_error", "Bifrost binary version is empty.");
  }
  return trimmed.startsWith("v") ? trimmed : `v${trimmed}`;
}

export async function readReleaseMetadata(filePath = metadataPath, fsImpl = fs) {
  let parsed;
  try {
    parsed = JSON.parse(await fsImpl.readFile(filePath, "utf8"));
  } catch (error) {
    throw new LauncherError("metadata_error", `Could not read Bifrost release metadata: ${filePath}`, error);
  }
  const version = String(parsed.binaryVersion ?? "").trim().replace(/^v/, "");
  if (!version) {
    throw new LauncherError("metadata_error", "Bifrost release metadata is missing binaryVersion.");
  }
  const archiveSha256 = parsed.archiveSha256 ?? {};
  return { binaryVersion: version, archiveSha256 };
}

export function cacheRootFor(env = process.env, platform = process.platform, homedir = os.homedir()) {
  if (env.BIFROST_LAUNCHER_CACHE_DIR?.trim()) {
    return path.resolve(env.BIFROST_LAUNCHER_CACHE_DIR.trim());
  }
  if (platform === "darwin") {
    return path.join(homedir, "Library", "Caches", "bifrost-agent");
  }
  if (platform === "win32") {
    return path.join(env.LOCALAPPDATA || path.join(homedir, "AppData", "Local"), "Bifrost", "AgentPlugin");
  }
  return path.join(env.XDG_CACHE_HOME || path.join(homedir, ".cache"), "bifrost-agent");
}

export function managedBinaryPath(cacheRoot, version, platform = process.platform, arch = process.arch) {
  return path.join(cacheRoot, "binaries", version, `${platform}-${arch}`, executableNameFor(platform));
}

export async function resolveBifrostBinary(options = {}) {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  const fsImpl = options.fsImpl ?? fs;
  const metadata = options.metadata ?? await readReleaseMetadata(options.metadataPath ?? metadataPath, fsImpl);

  if (env.BIFROST_BINARY_PATH?.trim()) {
    const explicit = path.resolve(env.BIFROST_BINARY_PATH.trim());
    await validateExecutable(explicit, fsImpl, platform, "BIFROST_BINARY_PATH");
    await validateVersion(explicit, metadata.binaryVersion, options);
    return { path: explicit, source: "explicit" };
  }

  releaseTargetFor(platform, arch);
  const cacheRoot = options.cacheRoot ?? cacheRootFor(env, platform);
  const managed = managedBinaryPath(cacheRoot, metadata.binaryVersion, platform, arch);
  let incompatibleBinaryError = null;
  if (await isExecutable(managed, fsImpl, platform)) {
    try {
      await validateVersion(managed, metadata.binaryVersion, options);
      return { path: managed, source: "managed" };
    } catch (error) {
      incompatibleBinaryError = error;
    }
  }

  if (allowsPathLookup(env)) {
    const pathBinary = await findOnPath("bifrost", env.PATH ?? "", env.PATHEXT, process.cwd(), fsImpl, platform);
    if (pathBinary) {
      try {
        await validateVersion(pathBinary, metadata.binaryVersion, options);
        return { path: pathBinary, source: "path" };
      } catch (error) {
        incompatibleBinaryError = error;
      }
    }
  }

  if (env.BIFROST_LAUNCHER_AUTO_INSTALL === "0") {
    if (incompatibleBinaryError instanceof LauncherError) {
      throw incompatibleBinaryError;
    }
    throw new LauncherError(
      "binary_not_found",
      `No compatible Bifrost ${metadata.binaryVersion} binary was found. Set BIFROST_BINARY_PATH, set BIFROST_LAUNCHER_ALLOW_PATH=1 to use PATH, or allow the launcher to install the pinned release.`
    );
  }

  const installed = await installManagedBinary({
    ...options,
    metadata,
    cacheRoot,
    platform,
    arch,
    fsImpl
  });
  return { path: installed, source: "installed" };
}

export async function installManagedBinary(options) {
  const metadata = options.metadata;
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  const fsImpl = options.fsImpl ?? fs;
  const cacheRoot = options.cacheRoot ?? cacheRootFor(options.env ?? process.env, platform);
  const fetchImpl = options.fetchImpl ?? fetch;
  const extractArchiveImpl = options.extractArchiveImpl ?? extractArchive;
  const asset = releaseAssetFor(metadata.binaryVersion, platform, arch);
  const expectedSha256 = normalizeSha256(metadata.archiveSha256?.[asset.target], asset.archiveName);
  const destination = managedBinaryPath(cacheRoot, metadata.binaryVersion, platform, arch);
  const destinationDir = path.dirname(destination);
  const tempDir = await fsImpl.mkdtemp(path.join(os.tmpdir(), "bifrost-agent-"));
  const archivePath = path.join(tempDir, asset.archiveName);
  const extractDir = path.join(tempDir, "extract");
  const tmpDestination = path.join(
    destinationDir,
    `${path.basename(destination)}.${process.pid}.${Date.now()}.${randomUUID()}.download`
  );

  try {
    const [archive, sidecar] = await Promise.all([
      downloadBytes(asset.archiveUrl, fetchImpl, options.downloadTimeoutMs ?? DOWNLOAD_TIMEOUT_MS),
      downloadText(asset.checksumUrl, fetchImpl, options.downloadTimeoutMs ?? DOWNLOAD_TIMEOUT_MS)
    ]);
    const sidecarSha256 = parseSha256(sidecar, asset.archiveName);
    if (sidecarSha256 !== expectedSha256) {
      throw new LauncherError(
        "checksum_mismatch",
        `Checksum sidecar mismatch for ${asset.archiveName}: expected ${expectedSha256}, got ${sidecarSha256}.`
      );
    }
    const actualSha256 = sha256(archive);
    if (actualSha256 !== expectedSha256) {
      throw new LauncherError(
        "checksum_mismatch",
        `Checksum mismatch for ${asset.archiveName}: expected ${expectedSha256}, got ${actualSha256}.`
      );
    }

    await fsImpl.mkdir(extractDir, { recursive: true });
    await fsImpl.writeFile(archivePath, archive);
    await extractArchiveImpl(archivePath, extractDir, platform);
    const extractedBinary = path.join(extractDir, archiveRootName(asset.archiveName), executableNameFor(platform));
    await validateExecutable(extractedBinary, fsImpl, platform, "downloaded Bifrost binary");
    await fsImpl.mkdir(destinationDir, { recursive: true });
    await fsImpl.copyFile(extractedBinary, tmpDestination);
    if (platform !== "win32") {
      await fsImpl.chmod(tmpDestination, 0o755);
    }
    if (await isExecutable(destination, fsImpl, platform) && await isVersionCompatibleBinary(destination, metadata.binaryVersion, options)) {
      return destination;
    }
    try {
      await fsImpl.rename(tmpDestination, destination);
    } catch (error) {
      if (await isExecutable(destination, fsImpl, platform) && await isVersionCompatibleBinary(destination, metadata.binaryVersion, options)) {
        return destination;
      }
      throw error;
    }
    await validateVersion(destination, metadata.binaryVersion, options);
    return destination;
  } catch (error) {
    if (error instanceof LauncherError) {
      throw error;
    }
    throw new LauncherError("install_failed", `Failed to install Bifrost ${metadata.binaryVersion}: ${formatCause(error)}`, error);
  } finally {
    await Promise.allSettled([
      fsImpl.rm(tmpDestination, { force: true }),
      fsImpl.rm(tempDir, { recursive: true, force: true })
    ]);
  }
}

async function extractArchive(archivePath, destination, platform) {
  try {
    if (platform === "win32") {
      await execFileAsync("powershell.exe", [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1] -Force",
        archivePath,
        destination
      ], { windowsHide: true, timeout: 60_000 });
      return;
    }
    await execFileAsync("tar", ["-xzf", archivePath, "-C", destination], { timeout: 60_000 });
  } catch (error) {
    throw new LauncherError("extract_failed", `Failed to extract Bifrost release archive: ${formatCause(error)}`, error);
  }
}

export async function validateVersion(binaryPath, requiredVersion, options = {}) {
  const probe = await probeBifrostVersion(binaryPath, options);
  if (isVersionCompatible(probe.version, requiredVersion)) {
    return;
  }
  const found = probe.version ?? probe.rawOutput ?? "unknown";
  throw new LauncherError(
    "version_mismatch",
    `Bifrost binary at ${binaryPath} is ${found}; expected ${requiredVersion}.`
  );
}

async function isVersionCompatibleBinary(binaryPath, requiredVersion, options) {
  try {
    await validateVersion(binaryPath, requiredVersion, options);
    return true;
  } catch {
    return false;
  }
}

export async function probeBifrostVersion(binaryPath, options = {}) {
  const execFileImpl = options.execFileImpl ?? execFileAsync;
  try {
    const { stdout, stderr } = await execFileImpl(binaryPath, ["--version"], {
      timeout: 10_000,
      windowsHide: true
    });
    const rawOutput = `${stdout ?? ""}${stderr ?? ""}`.trim();
    return { version: parseBifrostVersion(rawOutput), rawOutput };
  } catch (error) {
    throw new LauncherError("failed_launch", `Could not run ${binaryPath} --version: ${formatCause(error)}`, error);
  }
}

export function parseBifrostVersion(output) {
  const match = /\bbifrost\s+v?([0-9]+(?:\.[0-9]+){1,2}(?:[-+][^\s]+)?)/.exec(output);
  return match?.[1] ?? null;
}

export function isVersionCompatible(installed, required) {
  return installed === String(required).trim().replace(/^v/, "");
}

async function validateExecutable(command, fsImpl, platform, label) {
  let stat;
  try {
    stat = await fsImpl.stat(command);
  } catch (error) {
    throw new LauncherError("binary_not_found", `${label} was not found: ${command}`, error);
  }
  if (!stat.isFile()) {
    throw new LauncherError("binary_not_found", `${label} is not a file: ${command}`);
  }
  const mode = platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK;
  try {
    await fsImpl.access(command, mode);
  } catch (error) {
    throw new LauncherError("binary_not_found", `${label} is not executable: ${command}`, error);
  }
}

async function isExecutable(command, fsImpl, platform) {
  try {
    await validateExecutable(command, fsImpl, platform, "Bifrost binary");
    return true;
  } catch {
    return false;
  }
}

export async function findOnPath(command, pathValue, pathExt, cwd, fsImpl = fs, platform = process.platform) {
  if (!pathValue) {
    return null;
  }
  const names = commandNamesForPathLookup(command, pathExt, platform);
  for (const entry of pathValue.split(path.delimiter)) {
    if (!entry || !path.isAbsolute(entry)) {
      continue;
    }
    const resolvedEntry = entry;
    for (const name of names) {
      const candidate = path.join(resolvedEntry, name);
      if (await isExecutable(candidate, fsImpl, platform)) {
        return candidate;
      }
    }
  }
  return null;
}

function allowsPathLookup(env) {
  const value = String(env.BIFROST_LAUNCHER_ALLOW_PATH ?? "").trim().toLowerCase();
  return value === "1" || value === "true";
}

function commandNamesForPathLookup(command, pathExt, platform) {
  if (platform !== "win32" || path.extname(command)) {
    return [command];
  }
  return (pathExt ?? ".COM;.EXE;.BAT;.CMD")
    .split(";")
    .map((extension) => extension.trim().toLowerCase())
    .filter(Boolean)
    .map((extension) => `${command}${extension}`);
}

async function downloadBytes(url, fetchImpl, timeoutMs) {
  const response = await fetchWithTimeout(url, fetchImpl, timeoutMs);
  return Buffer.from(await response.arrayBuffer());
}

async function downloadText(url, fetchImpl, timeoutMs) {
  const response = await fetchWithTimeout(url, fetchImpl, timeoutMs);
  return response.text();
}

async function fetchWithTimeout(url, fetchImpl, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { signal: controller.signal });
    if (!response.ok) {
      throw new LauncherError("download_failed", `Failed to download ${url}: HTTP ${response.status}.`);
    }
    return response;
  } catch (error) {
    if (error instanceof LauncherError) {
      throw error;
    }
    if (error?.name === "AbortError") {
      throw new LauncherError("download_failed", `Timed out downloading ${url} after ${timeoutMs}ms.`, error);
    }
    throw new LauncherError("download_failed", `Failed to download ${url}: ${formatCause(error)}`, error);
  } finally {
    clearTimeout(timeout);
  }
}

export function parseSha256(text, expectedName) {
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const match = /^([a-fA-F0-9]{64})(?:\s+[*]?(.+))?$/.exec(trimmed);
    if (!match) {
      continue;
    }
    const hash = match[1].toLowerCase();
    const name = match[2]?.trim();
    if (!expectedName || !name || path.basename(name) === expectedName) {
      return hash;
    }
  }
  throw new LauncherError("checksum_mismatch", `No SHA-256 checksum found for ${expectedName}.`);
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function normalizeSha256(hash, name) {
  const normalized = String(hash ?? "").trim().toLowerCase().replace(/^sha256:/, "");
  if (!/^[a-f0-9]{64}$/.test(normalized)) {
    throw new LauncherError("metadata_error", `Invalid SHA-256 checksum configured for ${name}.`);
  }
  return normalized;
}

function archiveRootName(archiveName) {
  if (archiveName.endsWith(".tar.gz")) {
    return archiveName.slice(0, -".tar.gz".length);
  }
  if (archiveName.endsWith(".zip")) {
    return archiveName.slice(0, -".zip".length);
  }
  throw new LauncherError("metadata_error", `Unsupported Bifrost archive: ${archiveName}.`);
}

export function buildBifrostArgs(root, toolset, passThrough = []) {
  return ["--root", root, "--mcp", toolset || DEFAULT_TOOLSET, ...passThrough];
}

export function spawnBifrost(binaryPath, args, options = {}) {
  const child = spawn(binaryPath, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    stdio: "inherit"
  });
  child.on("error", (error) => {
    console.error(`Bifrost launcher failed to start ${binaryPath}: ${formatCause(error)}`);
    process.exitCode = 1;
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
  return child;
}

function formatCause(error) {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

async function main() {
  try {
    const parsed = parseLauncherArgs(process.argv.slice(2));
    const root = await resolveWorkspaceRoot({
      env: process.env,
      argvRoot: parsed.root,
      cwd: process.cwd()
    });
    const binary = await resolveBifrostBinary();
    const args = buildBifrostArgs(root, parsed.toolset, parsed.passThrough);
    spawnBifrost(binary.path, args, {
      cwd: root,
      env: process.env
    });
  } catch (error) {
    if (error instanceof LauncherError) {
      console.error(`Bifrost launcher error [${error.code}]: ${error.message}`);
    } else {
      console.error(`Bifrost launcher error: ${formatCause(error)}`);
    }
    process.exit(1);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === thisFile) {
  await main();
}
