#!/usr/bin/env node

import { execFile, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants, realpathSync } from "node:fs";
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
export const DOWNLOAD_TIMEOUT_MS = 60_000;
export const EXTRACTION_TIMEOUT_MS = 60_000;
export const VERSION_PROBE_TIMEOUT_MS = 10_000;
export const STARTUP_MARGIN_MS = 30_000;
const CHILD_SIGNAL_GRACE_MS = 4_000;
export const STALE_INSTALL_ARTIFACT_AGE_MS = 24 * 60 * 60 * 1_000;
export const MINIMUM_MCP_STARTUP_TIMEOUT_MS =
  DOWNLOAD_TIMEOUT_MS + EXTRACTION_TIMEOUT_MS + VERSION_PROBE_TIMEOUT_MS + STARTUP_MARGIN_MS;
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
  const command = args[0];
  if (command === "doctor" || command === "prepare" || command === "prepare-preferred") {
    let json = false;
    for (const arg of args.slice(1)) {
      if (arg === "--json") {
        json = true;
        continue;
      }
      throw new LauncherError(
        "invalid_arguments",
        `${command} accepts only --json and cannot be combined with server arguments.`
      );
    }
    return { command, json };
  }

  const parsed = {
    command: "mcp",
    json: false,
    root: null,
    toolset: DEFAULT_TOOLSET,
    passThrough: []
  };
  let explicitMcpMode = false;
  const selectMcpToolset = (toolset) => {
    if (parsed.command === "lsp") {
      throw new LauncherError(
        "invalid_arguments",
        "--lsp cannot be combined with --mcp or --toolset."
      );
    }
    explicitMcpMode = true;
    parsed.toolset = toolset;
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
    if (arg === "--lsp") {
      if (explicitMcpMode) {
        throw new LauncherError(
          "invalid_arguments",
          "--lsp cannot be combined with --mcp or --toolset."
        );
      }
      parsed.command = "lsp";
      continue;
    }
    if ((arg === "--mcp" || arg === "--toolset") && index + 1 < args.length) {
      selectMcpToolset(args[index + 1]);
      index += 1;
      continue;
    }
    if (arg.startsWith("--mcp=")) {
      selectMcpToolset(arg.slice("--mcp=".length));
      continue;
    }
    if (arg.startsWith("--toolset=")) {
      selectMcpToolset(arg.slice("--toolset=".length));
      continue;
    }
    parsed.passThrough.push(arg);
  }

  return parsed;
}

export function looksUnexpandedHostPlaceholder(value) {
  return /\$\{[^}]+}|\{\{[^}]+}}|%[A-Za-z_][A-Za-z0-9_]*%/.test(value);
}

export async function resolveWorkspaceRoot({
  env = process.env,
  argvRoot = null,
  cwd = process.cwd(),
  allowCwdFallback = true,
  fsImpl = fs
} = {}) {
  const raw = firstUsableRootCandidate(
    env.BIFROST_WORKSPACE_ROOT,
    argvRoot,
    allowCwdFallback ? cwd : null
  );
  if (!raw) {
    if (!allowCwdFallback) {
      return null;
    }
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
  return normalizeReleaseMetadata(parsed);
}

function normalizeReleaseMetadata(metadata) {
  const binaryVersion = normalizeVersion(metadata?.binaryVersion);
  if (!binaryVersion) {
    throw new LauncherError("metadata_error", "Bifrost release metadata is missing binaryVersion.");
  }
  const preferred = parseSemver(binaryVersion, "binaryVersion");
  const minimumBinaryVersion = normalizeVersion(metadata?.minimumBinaryVersion ?? binaryVersion);
  const minimum = parseSemver(minimumBinaryVersion, "minimumBinaryVersion");
  const allowPrerelease = metadata?.allowPrerelease ?? false;
  if (typeof allowPrerelease !== "boolean") {
    throw new LauncherError("metadata_error", "Bifrost release metadata allowPrerelease must be a boolean.");
  }
  if (preferred.major !== minimum.major || preferred.minor !== minimum.minor) {
    throw new LauncherError(
      "metadata_error",
      `Bifrost minimumBinaryVersion ${minimumBinaryVersion} must use the preferred ${preferred.major}.${preferred.minor} minor series.`
    );
  }
  if (compareSemver(minimum, preferred) > 0) {
    throw new LauncherError(
      "metadata_error",
      `Bifrost minimumBinaryVersion ${minimumBinaryVersion} cannot exceed binaryVersion ${binaryVersion}.`
    );
  }
  return {
    binaryVersion,
    minimumBinaryVersion,
    allowPrerelease,
    archiveSha256: metadata?.archiveSha256 ?? {}
  };
}

function normalizeVersion(version) {
  return String(version ?? "").trim().replace(/^v/, "");
}

function parseSemver(version, label = "version") {
  const normalized = normalizeVersion(version);
  const match = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(normalized);
  if (!match) {
    throw new LauncherError("metadata_error", `Invalid Bifrost ${label}: ${version}.`);
  }
  return {
    raw: normalized,
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ?? null
  };
}

function compareSemver(left, right) {
  for (const key of ["major", "minor", "patch"]) {
    if (left[key] !== right[key]) {
      return left[key] - right[key];
    }
  }
  if (left.prerelease === right.prerelease) {
    return 0;
  }
  if (left.prerelease === null) {
    return 1;
  }
  if (right.prerelease === null) {
    return -1;
  }
  return left.prerelease.localeCompare(right.prerelease, "en", { numeric: true });
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
  const assessment = await assessBifrostCandidates(options);
  return resolveAssessedBinary(assessment, options);
}

async function resolveAssessedBinary(assessment, options) {
  if (assessment.status === "ready") {
    return binarySelection(assessment.binaryPath, assessment.source, assessment.selectedVersion, assessment);
  }
  if (assessment.status === "error" || assessment.source === "explicit" || !assessment.autoInstall) {
    throw assessment.error ?? new LauncherError("binary_not_found", assessment.message);
  }

  options.onInstallStart?.({
    version: assessment.preferredVersion,
    cachePath: assessment.cachePath
  });
  const installed = await installManagedBinary({
    ...options,
    metadata: assessment.metadata,
    cacheRoot: assessment.cacheRoot,
    platform: assessment.platform,
    arch: assessment.arch,
    fsImpl: assessment.fsImpl
  });
  options.onInstallComplete?.({
    version: assessment.preferredVersion,
    cachePath: installed
  });
  return binarySelection(installed, "installed", assessment.preferredVersion, assessment);
}

function binarySelection(binaryPath, source, selectedVersion, context) {
  return {
    path: binaryPath,
    source,
    preferredVersion: context.preferredVersion,
    selectedVersion,
    compatibilityMode: selectedVersion === context.preferredVersion ? "exact" : "compatible"
  };
}

export async function inspectBifrostInstallation(options = {}) {
  const env = options.env ?? process.env;
  const autoInstall = env.BIFROST_LAUNCHER_AUTO_INSTALL !== "0";
  try {
    return launcherStatus(await assessBifrostCandidates(options));
  } catch (error) {
    return launcherStatus({
      status: launcherStatusForError(error),
      preferredVersion: null,
      selectedVersion: null,
      compatibilityMode: null,
      source: null,
      binaryPath: null,
      cachePath: null,
      autoInstall,
      message: formatCause(error)
    });
  }
}

export async function prepareBifrostInstallation(options = {}) {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  const autoInstall = env.BIFROST_LAUNCHER_AUTO_INSTALL !== "0";
  let assessment = null;

  try {
    assessment = await assessBifrostCandidates(options);
    const binary = await resolveAssessedBinary(assessment, options);
    return launcherStatus({
      status: "ready",
      preferredVersion: assessment.preferredVersion,
      selectedVersion: binary.selectedVersion,
      compatibilityMode: binary.compatibilityMode,
      source: binary.source,
      binaryPath: binary.path,
      cachePath: assessment.cachePath,
      autoInstall,
      message: readyMessage(assessment.preferredVersion, binary.selectedVersion, binary.source)
    });
  } catch (error) {
    const preferredVersion = assessment?.preferredVersion ?? options.metadata?.binaryVersion ?? null;
    const cachePath = assessment?.cachePath ?? (preferredVersion
      ? managedBinaryPath(options.cacheRoot ?? cacheRootFor(env, platform), preferredVersion, platform, arch)
      : null);
    return launcherStatus({
      status: launcherStatusForError(error),
      preferredVersion,
      selectedVersion: assessment?.selectedVersion ?? null,
      compatibilityMode: assessment?.compatibilityMode ?? null,
      source: assessment?.source ?? null,
      binaryPath: assessment?.binaryPath ?? null,
      cachePath,
      autoInstall,
      message: `${formatCause(error)} ${formatRecoveryMessage(preferredVersion, cachePath)}`
    });
  }
}

export async function preparePreferredBifrostInstallation(options = {}) {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  const fsImpl = options.fsImpl ?? fs;
  const metadata = options.metadata
    ? normalizeReleaseMetadata(options.metadata)
    : await readReleaseMetadata(options.metadataPath ?? metadataPath, fsImpl);
  const cacheRoot = options.cacheRoot ?? cacheRootFor(env, platform);
  const cachePath = managedBinaryPath(cacheRoot, metadata.binaryVersion, platform, arch);

  if (env.BIFROST_LAUNCHER_AUTO_INSTALL === "0") {
    return launcherStatus({
      status: "missing",
      preferredVersion: metadata.binaryVersion,
      selectedVersion: null,
      source: null,
      compatibilityMode: null,
      binaryPath: null,
      cachePath,
      autoInstall: false,
      message: `Preferred Bifrost ${metadata.binaryVersion} preparation is disabled.`
    });
  }

  if (await pathExists(cachePath, fsImpl)) {
    const exact = await inspectCandidate("managed", cachePath, {
      preferredVersion: metadata.binaryVersion,
      selectedVersion: null,
      compatibilityMode: null,
      cachePath,
      autoInstall: true,
      metadata,
      cacheRoot,
      platform,
      arch,
      fsImpl
    }, options);
    if (exact.status === "ready" && exact.compatibilityMode === "exact") {
      return launcherStatus(exact);
    }
  }

  const installed = await installManagedBinary({
    ...options,
    metadata,
    cacheRoot,
    platform,
    arch,
    fsImpl
  });
  return launcherStatus({
    status: "ready",
    preferredVersion: metadata.binaryVersion,
    selectedVersion: metadata.binaryVersion,
    source: "installed",
    compatibilityMode: "exact",
    binaryPath: installed,
    cachePath,
    autoInstall: true,
    message: readyMessage(metadata.binaryVersion, metadata.binaryVersion, "installed")
  });
}

async function assessBifrostCandidates(options = {}) {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  const fsImpl = options.fsImpl ?? fs;
  const metadata = options.metadata
    ? normalizeReleaseMetadata(options.metadata)
    : await readReleaseMetadata(options.metadataPath ?? metadataPath, fsImpl);
  releaseTargetFor(platform, arch);
  const cacheRoot = options.cacheRoot ?? cacheRootFor(env, platform);
  const cachePath = managedBinaryPath(cacheRoot, metadata.binaryVersion, platform, arch);
  const context = {
    preferredVersion: metadata.binaryVersion,
    selectedVersion: null,
    compatibilityMode: null,
    cachePath,
    autoInstall: env.BIFROST_LAUNCHER_AUTO_INSTALL !== "0",
    metadata,
    cacheRoot,
    platform,
    arch,
    fsImpl
  };

  try {
    if (env.BIFROST_BINARY_PATH?.trim()) {
      const explicit = path.resolve(env.BIFROST_BINARY_PATH.trim());
      return inspectCandidate("explicit", explicit, context, options);
    }

    let fallback = null;
    if (await pathExists(cachePath, fsImpl)) {
      const managed = await inspectCandidate("managed", cachePath, context, options);
      if (managed.status === "ready") {
        return managed;
      }
      fallback = managed;
    }

    for (const cached of await compatibleManagedCandidates(context)) {
      const managed = await inspectCandidate("managed", cached.path, context, options);
      if (managed.status === "ready") {
        return managed;
      }
      fallback = managed;
    }

    if (allowsPathLookup(env)) {
      const pathBinary = await findOnPath(
        "bifrost",
        env.PATH ?? "",
        env.PATHEXT,
        options.cwd ?? process.cwd(),
        fsImpl,
        platform
      );
      if (pathBinary) {
        const pathResult = await inspectCandidate("path", pathBinary, context, options);
        if (pathResult.status === "ready") {
          return pathResult;
        }
        fallback = pathResult;
      }
    }

    return fallback ?? {
      ...context,
      status: "missing",
      source: null,
      binaryPath: null,
      error: new LauncherError(
        "binary_not_found",
        `No compatible Bifrost binary was found for preferred ${context.preferredVersion}. Set BIFROST_BINARY_PATH, set BIFROST_LAUNCHER_ALLOW_PATH=1 to use PATH, or allow the launcher to install the pinned release.`
      ),
      message: `No compatible Bifrost binary is available for preferred ${context.preferredVersion}.`
    };
  } catch (error) {
    return {
      ...context,
      status: "error",
      source: null,
      binaryPath: null,
      error: error instanceof LauncherError
        ? error
        : new LauncherError("candidate_inspection_failed", formatCause(error), error),
      message: formatCause(error)
    };
  }
}

async function inspectCandidate(source, binaryPath, context, options) {
  try {
    await validateExecutable(binaryPath, context.fsImpl, context.platform, `${source} Bifrost binary`);
    const selectedVersion = await validateVersion(binaryPath, context.metadata, options);
    const compatibilityMode = selectedVersion === context.preferredVersion ? "exact" : "compatible";
    return {
      ...context,
      status: "ready",
      source,
      binaryPath,
      selectedVersion,
      compatibilityMode,
      error: null,
      message: readyMessage(context.preferredVersion, selectedVersion, source)
    };
  } catch (error) {
    return {
      ...context,
      status: launcherStatusForError(error),
      source,
      binaryPath,
      error,
      message: formatCause(error)
    };
  }
}

async function compatibleManagedCandidates(context) {
  const binariesRoot = path.join(context.cacheRoot, "binaries");
  let entries;
  try {
    entries = await context.fsImpl.readdir(binariesRoot, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "ENOTDIR") {
      return [];
    }
    throw error;
  }
  return entries
    .filter((entry) => entry.isDirectory() && entry.name !== context.preferredVersion)
    .flatMap((entry) => {
      try {
        const parsed = parseSemver(entry.name);
        return isVersionCompatible(entry.name, context.metadata)
          ? [{ version: parsed, path: managedBinaryPath(context.cacheRoot, entry.name, context.platform, context.arch) }]
          : [];
      } catch {
        return [];
      }
    })
    .sort((left, right) => compareSemver(right.version, left.version));
}

function readyMessage(preferredVersion, selectedVersion, source) {
  if (preferredVersion === selectedVersion) {
    return `Bifrost ${selectedVersion} is ready from ${source} in exact mode.`;
  }
  return `Bifrost ${selectedVersion} is ready from ${source} in compatibility mode; preferred ${preferredVersion}.`;
}

function launcherStatus(status) {
  return {
    status: status.status,
    preferredVersion: status.preferredVersion,
    selectedVersion: status.selectedVersion,
    source: status.source,
    compatibilityMode: status.compatibilityMode,
    binaryPath: status.binaryPath,
    cachePath: status.cachePath,
    autoInstall: status.autoInstall,
    message: status.message
  };
}

function launcherStatusForError(error) {
  if (error instanceof LauncherError) {
    if (error.code === "version_mismatch") {
      return "incompatible";
    }
    if (error.code === "binary_not_found") {
      return "missing";
    }
  }
  return "error";
}

async function pathExists(candidate, fsImpl) {
  try {
    await fsImpl.stat(candidate);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "ENOTDIR") {
      return false;
    }
    throw error;
  }
}

export async function cleanupStaleInstallArtifacts(options = {}) {
  const fsImpl = options.fsImpl ?? fs;
  const tempRoot = options.tempRoot ?? os.tmpdir();
  const destinationDir = options.destinationDir;
  const now = options.now ?? Date.now();
  const staleBefore = now - (options.maxAgeMs ?? STALE_INSTALL_ARTIFACT_AGE_MS);
  const locations = [
    {
      directory: tempRoot,
      matches: (name) => /^bifrost-agent-[A-Za-z0-9]{6}$/.test(name),
      recursive: true
    },
    ...(destinationDir ? [{
      directory: destinationDir,
      matches: (name) => /^bifrost(?:\.exe)?\.\d+\.\d+\.[0-9a-f-]+\.download$/i.test(name),
      recursive: false
    }] : [])
  ];

  for (const location of locations) {
    let entries;
    try {
      entries = await fsImpl.readdir(location.directory, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!location.matches(entry.name) || (location.recursive && !entry.isDirectory())) {
        continue;
      }
      const artifactPath = path.join(location.directory, entry.name);
      try {
        const stat = await fsImpl.stat(artifactPath);
        if (stat.mtimeMs < staleBefore) {
          await fsImpl.rm(artifactPath, { recursive: location.recursive, force: true });
        }
      } catch {
        // Cleanup must never prevent a launch or a fresh installation.
      }
    }
  }
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
  const tempRoot = options.tempRoot ?? os.tmpdir();
  await cleanupStaleInstallArtifacts({ fsImpl, tempRoot, destinationDir });
  const tempDir = await fsImpl.mkdtemp(path.join(tempRoot, "bifrost-agent-"));
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
    if (await isExecutable(destination, fsImpl, platform) && await isExactVersionBinary(destination, metadata.binaryVersion, options)) {
      return destination;
    }
    try {
      await fsImpl.rename(tmpDestination, destination);
    } catch (error) {
      if (await isExecutable(destination, fsImpl, platform) && await isExactVersionBinary(destination, metadata.binaryVersion, options)) {
        return destination;
      }
      throw error;
    }
    const installedVersion = await validateVersion(destination, metadata, options);
    if (installedVersion !== metadata.binaryVersion) {
      throw new LauncherError(
        "version_mismatch",
        `Downloaded Bifrost binary at ${destination} is ${installedVersion}; expected exact pinned version ${metadata.binaryVersion}.`
      );
    }
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
      ], { windowsHide: true, timeout: EXTRACTION_TIMEOUT_MS });
      return;
    }
    await execFileAsync("tar", ["-xzf", archivePath, "-C", destination], { timeout: EXTRACTION_TIMEOUT_MS });
  } catch (error) {
    throw new LauncherError("extract_failed", `Failed to extract Bifrost release archive: ${formatCause(error)}`, error);
  }
}

export async function validateVersion(binaryPath, compatibility, options = {}) {
  const probe = await probeBifrostVersion(binaryPath, options);
  if (isVersionCompatible(probe.version, compatibility)) {
    return probe.version;
  }
  const found = probe.version ?? probe.rawOutput ?? "unknown";
  const metadata = typeof compatibility === "string"
    ? normalizeReleaseMetadata({ binaryVersion: compatibility })
    : normalizeReleaseMetadata(compatibility);
  throw new LauncherError(
    "version_mismatch",
    `Bifrost binary at ${binaryPath} is ${found}; expected ${metadata.minimumBinaryVersion} through the stable ${parseSemver(metadata.binaryVersion).major}.${parseSemver(metadata.binaryVersion).minor} series (preferred ${metadata.binaryVersion}).`
  );
}

async function isExactVersionBinary(binaryPath, requiredVersion, options) {
  try {
    const found = await validateVersion(binaryPath, requiredVersion, options);
    return found === normalizeVersion(requiredVersion);
  } catch {
    return false;
  }
}

export async function probeBifrostVersion(binaryPath, options = {}) {
  const execFileImpl = options.execFileImpl ?? execFileAsync;
  try {
    const { stdout, stderr } = await execFileImpl(binaryPath, ["--version"], {
      timeout: VERSION_PROBE_TIMEOUT_MS,
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

export function isVersionCompatible(installed, compatibility) {
  if (!installed) {
    return false;
  }
  try {
    const metadata = typeof compatibility === "string"
      ? normalizeReleaseMetadata({ binaryVersion: compatibility })
      : normalizeReleaseMetadata(compatibility);
    const candidate = parseSemver(installed);
    const preferred = parseSemver(metadata.binaryVersion);
    const minimum = parseSemver(metadata.minimumBinaryVersion);
    return candidate.major === preferred.major
      && candidate.minor === preferred.minor
      && compareSemver(candidate, minimum) >= 0
      && (metadata.allowPrerelease || candidate.prerelease === null);
  } catch {
    return false;
  }
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
  const bytes = await fetchWithTimeout(url, fetchImpl, timeoutMs, (response) => response.arrayBuffer());
  return Buffer.from(bytes);
}

async function downloadText(url, fetchImpl, timeoutMs) {
  return fetchWithTimeout(url, fetchImpl, timeoutMs, (response) => response.text());
}

async function fetchWithTimeout(url, fetchImpl, timeoutMs, readBody) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { signal: controller.signal });
    if (!response.ok) {
      throw new LauncherError("download_failed", `Failed to download ${url}: HTTP ${response.status}.`);
    }
    return await readBody(response);
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
  const rootArgs = root ? ["--root", root] : [];
  return [...rootArgs, "--mcp", toolset || DEFAULT_TOOLSET, ...passThrough];
}

export function buildBifrostLspArgs(root, passThrough = []) {
  const rootArgs = root ? ["--root", root] : [];
  return [...rootArgs, "--lsp", ...passThrough];
}

export async function resolveBifrostLaunch(options = {}) {
  const env = options.env ?? process.env;
  const root = await resolveWorkspaceRoot({
    env: {},
    argvRoot: options.root,
    cwd: options.root,
    allowCwdFallback: false
  });
  const binary = await resolveBifrostBinary({ ...options, env });
  const launch = {
    command: binary.path,
    args: buildBifrostArgs(root, options.toolset, options.passThrough),
    cwd: root,
    env,
    source: binary.source,
    preferredVersion: binary.preferredVersion,
    selectedVersion: binary.selectedVersion,
    compatibilityMode: binary.compatibilityMode
  };
  schedulePreferredBifrostPreparation(launch, options);
  return launch;
}

export async function resolveBifrostLspLaunch(options = {}) {
  const env = options.env ?? process.env;
  const root = await resolveWorkspaceRoot({
    env: {},
    argvRoot: options.root,
    cwd: options.root,
    allowCwdFallback: false
  });
  const binary = await resolveBifrostBinary({ ...options, env });
  const launch = {
    command: binary.path,
    args: buildBifrostLspArgs(root, options.passThrough),
    cwd: root,
    env,
    source: binary.source,
    preferredVersion: binary.preferredVersion,
    selectedVersion: binary.selectedVersion,
    compatibilityMode: binary.compatibilityMode
  };
  schedulePreferredBifrostPreparation(launch, options);
  return launch;
}

export function spawnBifrost(binaryPath, args, options = {}) {
  const child = spawn(binaryPath, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    stdio: "inherit"
  });
  let forwardedSignal = null;
  let forcedKillTimer = null;
  const signalHandlers = new Map(
    ["SIGINT", "SIGTERM"].map((signal) => [
      signal,
      () => {
        if (child.exitCode === null && child.signalCode === null) {
          forwardedSignal ??= signal;
          child.kill(signal);
          forcedKillTimer ??= setTimeout(() => {
            if (child.exitCode === null && child.signalCode === null) {
              child.kill("SIGKILL");
            }
          }, CHILD_SIGNAL_GRACE_MS);
        }
      }
    ])
  );
  const removeSignalHandlers = () => {
    if (forcedKillTimer) {
      clearTimeout(forcedKillTimer);
      forcedKillTimer = null;
    }
    for (const [signal, handler] of signalHandlers) {
      process.off(signal, handler);
    }
  };
  for (const [signal, handler] of signalHandlers) {
    process.on(signal, handler);
  }

  child.once("error", (error) => {
    removeSignalHandlers();
    console.error(`Bifrost launcher failed to start ${binaryPath}: ${formatCause(error)}`);
    process.exitCode = 1;
  });
  child.once("exit", (code, signal) => {
    removeSignalHandlers();
    const exitSignal = signal ?? forwardedSignal;
    if (exitSignal) {
      process.kill(process.pid, exitSignal);
      return;
    }
    process.exit(code ?? 1);
  });
  return child;
}

export function schedulePreferredBifrostPreparation(launch, options = {}) {
  const env = options.env ?? launch.env ?? process.env;
  if (
    launch.compatibilityMode !== "compatible" ||
    env.BIFROST_LAUNCHER_AUTO_INSTALL === "0"
  ) {
    return null;
  }
  const spawnImpl = options.spawnImpl ?? spawn;
  try {
    const helper = spawnImpl(process.execPath, [thisFile, "prepare-preferred"], {
      detached: true,
      env,
      stdio: "ignore",
      windowsHide: true
    });
    helper.once("error", () => {});
    helper.unref();
    return helper;
  } catch {
    return null;
  }
}

export function formatLauncherStatus(status) {
  const details = [
    `status=${status.status}`,
    `preferred=${status.preferredVersion ?? "unknown"}`,
    `selected=${status.selectedVersion ?? "none"}`,
    `source=${status.source ?? "none"}`,
    `compatibility=${status.compatibilityMode ?? "none"}`,
    `binary=${status.binaryPath ?? "none"}`,
    `cache=${status.cachePath ?? "unknown"}`,
    `auto-install=${status.autoInstall ? "enabled" : "disabled"}`
  ];
  return `${details.join(" ")}\n${status.message}`;
}

function installProgressHandlers() {
  return {
    onInstallStart: ({ version, cachePath }) => {
      console.error(`Bifrost launcher: preparing pinned Bifrost ${version} at ${cachePath}.`);
    },
    onInstallComplete: ({ version, cachePath }) => {
      console.error(`Bifrost launcher: prepared Bifrost ${version} at ${cachePath}.`);
    }
  };
}

function formatRecoveryMessage(requiredVersion, cachePath) {
  return `Expected ${requiredVersion ?? "unknown"}; cache ${cachePath ?? "unknown"}. ` +
    "Bifrost server startup did not complete, so the requested host integration was not registered. " +
    "Run this launcher with doctor, then prepare, and start a fresh host task.";
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
    if (
      parsed.command === "doctor" ||
      parsed.command === "prepare" ||
      parsed.command === "prepare-preferred"
    ) {
      const status = parsed.command === "doctor"
        ? await inspectBifrostInstallation()
        : parsed.command === "prepare"
          ? await prepareBifrostInstallation(installProgressHandlers())
          : await preparePreferredBifrostInstallation();
      console.log(parsed.json ? JSON.stringify(status) : formatLauncherStatus(status));
      process.exitCode = status.status === "ready" ? 0 : 1;
      return;
    }
    let launch;
    if (parsed.command === "lsp") {
      launch = await resolveBifrostLspLaunch({
        ...installProgressHandlers(),
        root: parsed.root,
        env: process.env,
        passThrough: parsed.passThrough
      });
    } else {
      const root = await resolveWorkspaceRoot({
        env: process.env,
        argvRoot: parsed.root,
        cwd: process.cwd(),
        allowCwdFallback: false
      });
      launch = await resolveBifrostLaunch({
        ...installProgressHandlers(),
        root,
        env: process.env,
        toolset: parsed.toolset,
        passThrough: parsed.passThrough
      });
    }
    if (launch.compatibilityMode === "compatible") {
      console.error(
        `Bifrost launcher: preferred ${launch.preferredVersion}, selected compatible ${launch.selectedVersion} from ${launch.source}.`
      );
    }
    spawnBifrost(launch.command, launch.args, {
      cwd: launch.cwd,
      env: launch.env
    });
  } catch (error) {
    if (error instanceof LauncherError) {
      console.error(`Bifrost launcher error [${error.code}]: ${error.message}`);
    } else {
      console.error(`Bifrost launcher error: ${formatCause(error)}`);
    }
    if (isBinaryRecoveryError(error)) {
      const metadata = await readReleaseMetadata().catch(() => null);
      const requiredVersion = metadata?.binaryVersion ?? "unknown";
      const cachePath = metadata
        ? managedBinaryPath(cacheRootFor(process.env), metadata.binaryVersion)
        : "unknown";
      console.error(`Bifrost launcher recovery: ${formatRecoveryMessage(requiredVersion, cachePath)}`);
    }
    process.exit(1);
  }
}

function isBinaryRecoveryError(error) {
  return error instanceof LauncherError && [
    "binary_not_found",
    "candidate_inspection_failed",
    "checksum_mismatch",
    "download_failed",
    "extract_failed",
    "failed_launch",
    "install_failed",
    "version_mismatch"
  ].includes(error.code);
}

// `thisFile` comes from `import.meta.url`, which Node has already resolved
// through symlinks, so the entry path has to be resolved the same way before
// the two can be compared. Resolving only with `path.resolve` normalizes
// without following links, so any invocation whose path crosses one -- every
// macOS temp directory, since `os.tmpdir()` returns `/var/folders/...` and
// `/var` links to `/private/var` -- failed this test and exited 0 having done
// nothing at all, with no output on either stream (#2427).
//
// `realpathSync` throws when the entry does not exist on disk, which is the
// normal shape for an eval or stdin entry rather than an error, so that case
// falls back to the unresolved path and simply does not match.
function isDirectExecution(entryPath) {
  if (!entryPath) {
    return false;
  }
  try {
    return realpathSync(entryPath) === thisFile;
  } catch {
    return path.resolve(entryPath) === thisFile;
  }
}

if (isDirectExecution(process.argv[1])) {
  await main();
}
