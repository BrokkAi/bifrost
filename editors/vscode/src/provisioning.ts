import { execFile } from "child_process";
import { createHash } from "crypto";
import { promises as fs } from "fs";
import os from "os";
import path from "path";
import extractZip from "extract-zip";
import * as tar from "tar";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const OWNER = "BrokkAi";
const REPO = "bifrost";
const BINARY_NAME = "bifrost";

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export interface PlatformSpec {
  platform: NodeJS.Platform;
  arch: NodeJS.Architecture;
}

export interface ReleaseAsset {
  target: string;
  archiveName: string;
  checksumName: string;
  archiveUrl: string;
  checksumUrl: string;
}

export interface InstallOptions extends PlatformSpec {
  storageDir: string;
  version: string;
  minimumBinaryVersion?: string;
  allowPrerelease?: boolean;
  expectedSha256: string;
  fetchImpl?: typeof fetch;
  log?: (message: string) => void;
}

export interface VersionProbe {
  version: string | null;
  rawOutput: string;
}

export interface BinaryCompatibility {
  binaryVersion: string;
  minimumBinaryVersion: string;
  allowPrerelease: boolean;
}

export interface ManagedBinarySelection {
  path: string;
  version: string;
  compatibilityMode: "exact" | "compatible";
}

export interface ManagedBinaryPreparation {
  selected: ManagedBinarySelection;
  preferredInstall: Promise<string | null> | null;
}

export async function selectManagedBinaryAndPreparePreferred(
  findSelection: () => Promise<ManagedBinarySelection | null>,
  installPreferred: () => Promise<string>,
  log: (message: string) => void
): Promise<ManagedBinaryPreparation | null> {
  const selected = await findSelection();
  if (!selected) {
    return null;
  }
  if (selected.compatibilityMode === "exact") {
    return { selected, preferredInstall: null };
  }

  const preferredInstall = Promise.resolve()
    .then(installPreferred)
    .catch((error: unknown) => {
      log(`Preferred managed Bifrost preparation failed: ${formatError(error)}`);
      return null;
    });
  return { selected, preferredInstall };
}

export async function activatePreparedManagedBinary(
  preparation: ManagedBinaryPreparation,
  isSelectedBinaryActive: (selectedPath: string) => boolean,
  activate: (preferredPath: string) => Promise<void>
): Promise<boolean> {
  const preferredPath = await preparation.preferredInstall;
  if (!preferredPath || !isSelectedBinaryActive(preparation.selected.path)) {
    return false;
  }
  await activate(preferredPath);
  return true;
}

export function releaseTargetFor(
  platform: NodeJS.Platform = process.platform,
  arch: NodeJS.Architecture = process.arch
): string {
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
  throw new Error(`Unsupported platform for Bifrost binary: ${platform}-${arch}`);
}

export function executableNameFor(platform: NodeJS.Platform = process.platform): string {
  return platform === "win32" ? `${BINARY_NAME}.exe` : BINARY_NAME;
}

export function releaseTagForVersion(version: string): string {
  const trimmed = version.trim();
  if (!trimmed) {
    throw new Error("Bifrost binary version is empty");
  }
  return trimmed.startsWith("v") ? trimmed : `v${trimmed}`;
}

export function releaseAssetFor(
  version: string,
  platform: NodeJS.Platform = process.platform,
  arch: NodeJS.Architecture = process.arch
): ReleaseAsset {
  const tag = releaseTagForVersion(version);
  const target = releaseTargetFor(platform, arch);
  const extension = platform === "win32" ? ".zip" : ".tar.gz";
  const archiveName = `${BINARY_NAME}-${tag}-${target}${extension}`;
  const checksumName = `${archiveName}.sha256`;
  const releaseBase = `https://github.com/${OWNER}/${REPO}/releases/download/${tag}`;
  return {
    target,
    archiveName,
    checksumName,
    archiveUrl: `${releaseBase}/${archiveName}`,
    checksumUrl: `${releaseBase}/${checksumName}`
  };
}

export function managedBinaryDir(
  storageDir: string,
  version: string,
  platform: NodeJS.Platform = process.platform,
  arch: NodeJS.Architecture = process.arch
): string {
  return path.join(storageDir, "binaries", version, `${platform}-${arch}`);
}

export function managedBinaryPath(
  storageDir: string,
  version: string,
  platform: NodeJS.Platform = process.platform,
  arch: NodeJS.Architecture = process.arch
): string {
  return path.join(
    managedBinaryDir(storageDir, version, platform, arch),
    executableNameFor(platform)
  );
}

export async function findManagedBinary(
  storageDir: string,
  version: string,
  platform: NodeJS.Platform = process.platform,
  arch: NodeJS.Architecture = process.arch
): Promise<string | null> {
  const candidate = managedBinaryPath(storageDir, version, platform, arch);
  try {
    await fs.access(candidate);
    return candidate;
  } catch {
    return null;
  }
}

export async function findCompatibleManagedBinary(
  storageDir: string,
  compatibility: BinaryCompatibility,
  platform: NodeJS.Platform = process.platform,
  arch: NodeJS.Architecture = process.arch,
  probeImpl: (binaryPath: string) => Promise<VersionProbe> = probeBifrostVersion
): Promise<ManagedBinarySelection | null> {
  const normalized = normalizeBinaryCompatibility(compatibility);
  const binariesDir = path.join(storageDir, "binaries");
  let entries: string[];
  try {
    entries = await fs.readdir(binariesDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw error;
  }

  const compatibleVersions = entries
    .filter((entry) => isVersionCompatible(entry, normalized))
    .sort((left, right) => compareVersions(right, left));
  const exactIndex = compatibleVersions.indexOf(normalized.binaryVersion);
  if (exactIndex > 0) {
    compatibleVersions.splice(exactIndex, 1);
    compatibleVersions.unshift(normalized.binaryVersion);
  }

  for (const version of compatibleVersions) {
    const candidate = managedBinaryPath(storageDir, version, platform, arch);
    try {
      await fs.access(candidate);
      const probe = await probeImpl(candidate);
      if (probe.version !== version || !isVersionCompatible(probe.version, normalized)) {
        continue;
      }
      return {
        path: candidate,
        version,
        compatibilityMode: version === normalized.binaryVersion ? "exact" : "compatible"
      };
    } catch {
      continue;
    }
  }
  return null;
}

export async function installManagedBinary(options: InstallOptions): Promise<string> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const log = options.log ?? (() => undefined);
  const asset = releaseAssetFor(options.version, options.platform, options.arch);
  const destinationDir = managedBinaryDir(
    options.storageDir,
    options.version,
    options.platform,
    options.arch
  );
  const destination = managedBinaryPath(
    options.storageDir,
    options.version,
    options.platform,
    options.arch
  );
  const tmpDestination = `${destination}.download`;
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-vscode-"));
  const archivePath = path.join(tempDir, asset.archiveName);
  const extractDir = path.join(tempDir, "extract");

  try {
    log(`Downloading Bifrost ${options.version} from ${asset.archiveUrl}`);
    const [archive, checksumText] = await Promise.all([
      downloadBytes(fetchImpl, asset.archiveUrl),
      downloadText(fetchImpl, asset.checksumUrl)
    ]);
    const expectedHash = normalizeSha256(options.expectedSha256, asset.archiveName);
    const sidecarHash = parseSha256(checksumText, asset.archiveName);
    if (sidecarHash !== expectedHash) {
      throw new Error(
        `Checksum sidecar mismatch for ${asset.archiveName}: expected ${expectedHash}, got ${sidecarHash}`
      );
    }
    const actualHash = sha256(archive);
    if (expectedHash !== actualHash) {
      throw new Error(
        `Checksum mismatch for ${asset.archiveName}: expected ${expectedHash}, got ${actualHash}`
      );
    }

    await fs.mkdir(extractDir, { recursive: true });
    await fs.writeFile(archivePath, archive);
    await extractArchive(archivePath, extractDir, options.platform);

    const extractedBinary = path.join(
      extractDir,
      archiveRootName(asset.archiveName),
      executableNameFor(options.platform)
    );
    await fs.access(extractedBinary);

    await fs.mkdir(destinationDir, { recursive: true });
    await fs.copyFile(extractedBinary, tmpDestination);
    if (options.platform !== "win32") {
      await fs.chmod(tmpDestination, 0o755);
    }
    await fs.rename(tmpDestination, destination);
    await cleanupOldManagedVersions(options.storageDir, {
      binaryVersion: options.version,
      minimumBinaryVersion: options.minimumBinaryVersion ?? options.version,
      allowPrerelease: options.allowPrerelease ?? false
    });
    log(`Installed Bifrost ${options.version} at ${destination}`);
    return destination;
  } finally {
    await Promise.all([
      fs.rm(tmpDestination, { force: true }),
      fs.rm(tempDir, { recursive: true, force: true })
    ]);
  }
}

export async function cleanupOldManagedVersions(
  storageDir: string,
  compatibility: string | BinaryCompatibility
): Promise<void> {
  const binariesDir = path.join(storageDir, "binaries");
  let entries: string[];
  try {
    entries = await fs.readdir(binariesDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }

  await Promise.all(
    entries
      .filter((entry) => !isVersionCompatible(entry, compatibility))
      .map((entry) => fs.rm(path.join(binariesDir, entry), { recursive: true, force: true }))
  );
}

export function parseSha256(text: string, expectedName?: string): string {
  for (const line of text.split(/\r?\n/)) {
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
  throw new Error(
    expectedName ? `No SHA-256 checksum found for ${expectedName}` : "No SHA-256 checksum found"
  );
}

export function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function normalizeSha256(hash: string, name = "archive"): string {
  const normalized = hash
    .trim()
    .toLowerCase()
    .replace(/^sha256:/, "");
  if (!/^[a-f0-9]{64}$/.test(normalized)) {
    throw new Error(`Invalid SHA-256 checksum configured for ${name}`);
  }
  return normalized;
}

export function parseBifrostVersion(output: string): string | null {
  const match = /\bbifrost\s+v?([0-9]+(?:\.[0-9]+){1,2}(?:[-+][^\s]+)?)/.exec(output);
  return match?.[1] ?? null;
}

export async function probeBifrostVersion(binaryPath: string): Promise<VersionProbe> {
  const { stdout, stderr } = await execFileAsync(binaryPath, ["--version"], {
    timeout: 10000,
    windowsHide: true
  });
  const rawOutput = `${stdout}${stderr}`.trim();
  return {
    version: parseBifrostVersion(rawOutput),
    rawOutput
  };
}

export function isVersionCompatible(
  installed: string | null,
  compatibility: string | BinaryCompatibility
): boolean {
  if (!installed) {
    return false;
  }
  if (typeof compatibility === "string") {
    return normalizeVersion(installed) === normalizeVersion(compatibility);
  }
  try {
    const normalized = normalizeBinaryCompatibility(compatibility);
    const candidate = parseVersion(installed, "installed version");
    const preferred = parseVersion(normalized.binaryVersion, "binaryVersion");
    const minimum = parseVersion(normalized.minimumBinaryVersion, "minimumBinaryVersion");
    return (
      candidate.major === preferred.major &&
      candidate.minor === preferred.minor &&
      compareParsedVersions(candidate, minimum) >= 0 &&
      (normalized.allowPrerelease || candidate.prerelease === null)
    );
  } catch {
    return false;
  }
}

export function normalizeBinaryCompatibility(
  compatibility: BinaryCompatibility
): BinaryCompatibility {
  const binaryVersion = normalizeVersion(compatibility.binaryVersion);
  const minimumBinaryVersion = normalizeVersion(compatibility.minimumBinaryVersion);
  const preferred = parseVersion(binaryVersion, "binaryVersion");
  const minimum = parseVersion(minimumBinaryVersion, "minimumBinaryVersion");
  if (typeof compatibility.allowPrerelease !== "boolean") {
    throw new Error("Bifrost allowPrerelease must be a boolean");
  }
  if (preferred.major !== minimum.major || preferred.minor !== minimum.minor) {
    throw new Error(
      `Bifrost minimumBinaryVersion ${minimumBinaryVersion} must use the preferred ${preferred.major}.${preferred.minor} minor series`
    );
  }
  if (compareParsedVersions(minimum, preferred) > 0) {
    throw new Error(
      `Bifrost minimumBinaryVersion ${minimumBinaryVersion} cannot exceed binaryVersion ${binaryVersion}`
    );
  }
  return { binaryVersion, minimumBinaryVersion, allowPrerelease: compatibility.allowPrerelease };
}

interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  prerelease: string | null;
}

function normalizeVersion(version: string): string {
  return version.trim().replace(/^v/, "");
}

function parseVersion(version: string, label: string): ParsedVersion {
  const normalized = normalizeVersion(version);
  const match =
    /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(
      normalized
    );
  if (!match) {
    throw new Error(`Invalid Bifrost ${label}: ${version}`);
  }
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ?? null
  };
}

function compareVersions(left: string, right: string): number {
  return compareParsedVersions(parseVersion(left, "version"), parseVersion(right, "version"));
}

function compareParsedVersions(left: ParsedVersion, right: ParsedVersion): number {
  for (const key of ["major", "minor", "patch"] as const) {
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

async function downloadBytes(fetchImpl: typeof fetch, url: string): Promise<Buffer> {
  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(`Failed to download ${url}: HTTP ${response.status}`);
  }
  return Buffer.from(await response.arrayBuffer());
}

async function downloadText(fetchImpl: typeof fetch, url: string): Promise<string> {
  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(`Failed to download ${url}: HTTP ${response.status}`);
  }
  return response.text();
}

async function extractArchive(
  archivePath: string,
  destination: string,
  platform: NodeJS.Platform
): Promise<void> {
  if (platform === "win32") {
    await extractZip(archivePath, { dir: destination });
    return;
  }
  await tar.x({ file: archivePath, cwd: destination });
}

function archiveRootName(archiveName: string): string {
  if (archiveName.endsWith(".tar.gz")) {
    return archiveName.slice(0, -".tar.gz".length);
  }
  if (archiveName.endsWith(".zip")) {
    return archiveName.slice(0, -".zip".length);
  }
  throw new Error(`Unsupported Bifrost archive: ${archiveName}`);
}
