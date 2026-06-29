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
  expectedSha256: string;
  fetchImpl?: typeof fetch;
  log?: (message: string) => void;
}

export interface VersionProbe {
  version: string | null;
  rawOutput: string;
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
  return path.join(managedBinaryDir(storageDir, version, platform, arch), executableNameFor(platform));
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
    await cleanupOldManagedVersions(options.storageDir, options.version);
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
  keepVersion: string
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
      .filter((entry) => entry !== keepVersion)
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
    expectedName
      ? `No SHA-256 checksum found for ${expectedName}`
      : "No SHA-256 checksum found"
  );
}

export function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function normalizeSha256(hash: string, name = "archive"): string {
  const normalized = hash.trim().toLowerCase().replace(/^sha256:/, "");
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

export function isVersionCompatible(installed: string | null, required: string): boolean {
  return installed === required.trim().replace(/^v/, "");
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
