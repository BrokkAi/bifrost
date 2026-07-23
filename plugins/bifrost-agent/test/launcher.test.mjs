import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  DOWNLOAD_TIMEOUT_MS,
  EXTRACTION_TIMEOUT_MS,
  LauncherError,
  MINIMUM_MCP_STARTUP_TIMEOUT_MS,
  STARTUP_MARGIN_MS,
  VERSION_PROBE_TIMEOUT_MS,
  buildBifrostArgs,
  cacheRootFor,
  findOnPath,
  formatLauncherStatus,
  installManagedBinary,
  inspectBifrostInstallation,
  isVersionCompatible,
  looksUnexpandedHostPlaceholder,
  managedBinaryPath,
  parseLauncherArgs,
  prepareBifrostInstallation,
  readReleaseMetadata,
  releaseAssetFor,
  releaseTargetFor,
  resolveBifrostBinary,
  resolveBifrostLaunch,
  resolveWorkspaceRoot,
  sha256
} from "../bin/bifrost-launcher.mjs";

const execFileAsync = promisify(execFile);
const testDir = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(testDir, "..");
const repoRoot = path.resolve(packageDir, "../..");

async function writeExecutableFixture(filePath, contents = "binary") {
  await fsp.mkdir(path.dirname(filePath), { recursive: true });
  await fsp.writeFile(filePath, contents);
  if (process.platform !== "win32") {
    await fsp.chmod(filePath, 0o755);
  }
  return filePath;
}

function createFakeManagedRelease(version = "0.7.2") {
  const platform = "linux";
  const arch = "x64";
  const asset = releaseAssetFor(version, platform, arch);
  const archive = Buffer.from("fake archive");
  const archiveHash = sha256(archive);
  const state = { fetchCount: 0 };
  return {
    platform,
    arch,
    metadata: {
      binaryVersion: version,
      archiveSha256: { [asset.target]: archiveHash }
    },
    state,
    fetchImpl: async (url) => {
      state.fetchCount += 1;
      if (url.endsWith(".sha256")) {
        return new Response(`${archiveHash}  ${asset.archiveName}\n`);
      }
      return new Response(archive);
    },
    extractArchiveImpl: async (_archivePath, extractDir) => {
      const binaryPath = path.join(extractDir, asset.archiveName.replace(/\.tar\.gz$/, ""), "bifrost");
      await writeExecutableFixture(binaryPath, "#!/bin/sh\nexit 0\n");
    }
  };
}

test("resolves workspace root by env, args, then cwd", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const envRoot = path.join(temp, "env");
  const argRoot = path.join(temp, "arg");
  const cwdRoot = path.join(temp, "cwd");
  await fsp.mkdir(envRoot);
  await fsp.mkdir(argRoot);
  await fsp.mkdir(cwdRoot);

  assert.equal(
    await resolveWorkspaceRoot({ env: { BIFROST_WORKSPACE_ROOT: envRoot }, argvRoot: argRoot, cwd: cwdRoot }),
    envRoot
  );
  assert.equal(
    await resolveWorkspaceRoot({ env: {}, argvRoot: argRoot, cwd: cwdRoot }),
    argRoot
  );
  assert.equal(
    await resolveWorkspaceRoot({ env: {}, argvRoot: "${workspaceFolder}", cwd: cwdRoot }),
    cwdRoot
  );
});

test("rejects missing and non-directory workspace roots", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const filePath = path.join(temp, "file.txt");
  await fsp.writeFile(filePath, "not a dir");

  await assert.rejects(
    resolveWorkspaceRoot({ env: { BIFROST_WORKSPACE_ROOT: path.join(temp, "missing") }, cwd: temp }),
    (error) => error instanceof LauncherError && error.code === "missing_workspace_root"
  );
  await assert.rejects(
    resolveWorkspaceRoot({ env: { BIFROST_WORKSPACE_ROOT: filePath }, cwd: temp }),
    /not a directory/
  );
});

test("detects unresolved host placeholders", () => {
  assert.equal(looksUnexpandedHostPlaceholder("${workspaceFolder}"), true);
  assert.equal(looksUnexpandedHostPlaceholder("{{workspace}}"), true);
  assert.equal(looksUnexpandedHostPlaceholder("%WORKSPACE%"), true);
  assert.equal(looksUnexpandedHostPlaceholder("/actual/workspace"), false);
});

test("maps runtime platforms to release targets", () => {
  assert.equal(releaseTargetFor("darwin", "arm64"), "universal-apple-darwin");
  assert.equal(releaseTargetFor("darwin", "x64"), "universal-apple-darwin");
  assert.equal(releaseTargetFor("linux", "x64"), "x86_64-unknown-linux-gnu");
  assert.equal(releaseTargetFor("linux", "arm64"), "aarch64-unknown-linux-gnu");
  assert.equal(releaseTargetFor("win32", "x64"), "x86_64-pc-windows-msvc");
  assert.equal(releaseTargetFor("win32", "arm64"), "aarch64-pc-windows-msvc");
  assert.throws(
    () => releaseTargetFor("freebsd", "x64"),
    (error) => error instanceof LauncherError && error.code === "unsupported_platform"
  );
});

test("constructs release asset URLs", () => {
  const asset = releaseAssetFor("0.7.2", "linux", "x64");
  assert.equal(asset.archiveName, "bifrost-v0.7.2-x86_64-unknown-linux-gnu.tar.gz");
  assert.equal(asset.checksumName, "bifrost-v0.7.2-x86_64-unknown-linux-gnu.tar.gz.sha256");
  assert.equal(
    asset.archiveUrl,
    "https://github.com/BrokkAi/bifrost/releases/download/v0.7.2/bifrost-v0.7.2-x86_64-unknown-linux-gnu.tar.gz"
  );
});

test("finds compatible bifrost on PATH", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const binaryPath = path.join(temp, process.platform === "win32" ? "bifrost.exe" : "bifrost");
  await writeExecutableFixture(binaryPath, "#!/bin/sh\nexit 0\n");

  const resolved = await resolveBifrostBinary({
    env: { PATH: temp, BIFROST_LAUNCHER_ALLOW_PATH: "1", BIFROST_LAUNCHER_AUTO_INSTALL: "0" },
    cacheRoot: path.join(temp, "cache"),
    metadata: {
      binaryVersion: "0.7.2",
      archiveSha256: { [releaseTargetFor()]: "a".repeat(64) }
    },
    execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
  });

  assert.equal(resolved.path, binaryPath);
  assert.equal(resolved.source, "path");
});

test("does not use PATH unless explicitly allowed", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const binaryPath = path.join(temp, process.platform === "win32" ? "bifrost.exe" : "bifrost");
  await writeExecutableFixture(binaryPath, "#!/bin/sh\nexit 0\n");

  await assert.rejects(
    resolveBifrostBinary({
      env: { PATH: temp, BIFROST_LAUNCHER_AUTO_INSTALL: "0" },
      cacheRoot: path.join(temp, "cache"),
      metadata: {
        binaryVersion: "0.7.2",
        archiveSha256: { [releaseTargetFor()]: "a".repeat(64) }
      },
      execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
    }),
    (error) => error instanceof LauncherError && error.code === "binary_not_found"
  );
});

test("ignores empty and relative PATH entries", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const relativeDir = path.join(temp, "relative-bin");
  await fsp.mkdir(relativeDir);
  const binaryPath = path.join(relativeDir, process.platform === "win32" ? "bifrost.exe" : "bifrost");
  await writeExecutableFixture(binaryPath, "#!/bin/sh\nexit 0\n");

  assert.equal(
    await findOnPath("bifrost", `${path.delimiter}relative-bin`, undefined, temp),
    null
  );
});

test("preserves PATH version mismatch when auto install is disabled", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const binaryPath = path.join(temp, process.platform === "win32" ? "bifrost.exe" : "bifrost");
  await writeExecutableFixture(binaryPath, "#!/bin/sh\nexit 0\n");

  await assert.rejects(
    resolveBifrostBinary({
      env: { PATH: temp, BIFROST_LAUNCHER_ALLOW_PATH: "1", BIFROST_LAUNCHER_AUTO_INSTALL: "0" },
      metadata: {
        binaryVersion: "0.7.2",
        archiveSha256: { [releaseTargetFor()]: "a".repeat(64) }
      },
      execFileImpl: async () => ({ stdout: "bifrost 0.7.1\n", stderr: "" })
    }),
    (error) => error instanceof LauncherError && error.code === "version_mismatch"
  );
});

test("uses compatible managed cache entry before PATH", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const cacheRoot = path.join(temp, "cache");
  const managed = managedBinaryPath(cacheRoot, "0.7.2");
  await writeExecutableFixture(managed, "#!/bin/sh\nexit 0\n");

  const resolved = await resolveBifrostBinary({
    env: { PATH: "", BIFROST_LAUNCHER_AUTO_INSTALL: "0" },
    cacheRoot,
    metadata: {
      binaryVersion: "0.7.2",
      archiveSha256: { [releaseTargetFor()]: "a".repeat(64) }
    },
    execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
  });

  assert.equal(resolved.path, managed);
  assert.equal(resolved.source, "managed");
});

test("reports no binary when auto install is disabled", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  await assert.rejects(
    resolveBifrostBinary({
      env: { PATH: "", BIFROST_LAUNCHER_AUTO_INSTALL: "0" },
      cacheRoot: temp,
      metadata: {
        binaryVersion: "0.7.2",
        archiveSha256: { [releaseTargetFor()]: "a".repeat(64) }
      },
      execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
    }),
    (error) => error instanceof LauncherError && error.code === "binary_not_found"
  );
});

test("rejects checksum mismatch during managed install", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const target = releaseTargetFor("linux", "x64");
  const metadata = {
    binaryVersion: "0.7.2",
    archiveSha256: { [target]: "a".repeat(64) }
  };
  const fetchImpl = async (url) => {
    if (url.endsWith(".sha256")) {
      return new Response(`${"b".repeat(64)}  bifrost-v0.7.2-x86_64-unknown-linux-gnu.tar.gz\n`);
    }
    return new Response(Buffer.from("archive"));
  };

  await assert.rejects(
    installManagedBinary({
      metadata,
      cacheRoot: temp,
      platform: "linux",
      arch: "x64",
      fetchImpl,
      extractArchiveImpl: async () => {}
    }),
    (error) => error instanceof LauncherError && error.code === "checksum_mismatch"
  );
});

test("reports download timeout during managed install", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const target = releaseTargetFor("linux", "x64");
  const metadata = {
    binaryVersion: "0.7.2",
    archiveSha256: { [target]: "a".repeat(64) }
  };
  const fetchImpl = async (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => {
      const error = new Error("aborted");
      error.name = "AbortError";
      reject(error);
    });
  });

  await assert.rejects(
    installManagedBinary({
      metadata,
      cacheRoot: temp,
      platform: "linux",
      arch: "x64",
      fetchImpl,
      downloadTimeoutMs: 1,
      extractArchiveImpl: async () => {}
    }),
    (error) => error instanceof LauncherError && error.code === "download_failed"
  );
});

test("keeps the download timeout active while reading response bodies", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const target = releaseTargetFor("linux", "x64");
  const stalledBody = (signal) => new Promise((_resolve, reject) => {
    signal.addEventListener("abort", () => {
      const error = new Error("aborted while reading body");
      error.name = "AbortError";
      reject(error);
    });
  });
  const fetchImpl = async (_url, { signal }) => ({
    ok: true,
    arrayBuffer: () => stalledBody(signal),
    text: () => stalledBody(signal)
  });

  await assert.rejects(
    installManagedBinary({
      metadata: {
        binaryVersion: "0.7.2",
        archiveSha256: { [target]: "a".repeat(64) }
      },
      cacheRoot: temp,
      platform: "linux",
      arch: "x64",
      fetchImpl,
      downloadTimeoutMs: 1,
      extractArchiveImpl: async () => {}
    }),
    (error) => error instanceof LauncherError &&
      error.code === "download_failed" &&
      /Timed out downloading/.test(error.message)
  );
});

test("installs verified managed binary", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const release = createFakeManagedRelease();

  const installed = await installManagedBinary({
    ...release,
    cacheRoot: temp,
    execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
  });

  assert.equal(installed, path.join(temp, "binaries", "0.7.2", "linux-x64", "bifrost"));
  assert.equal(fs.existsSync(installed), true);
});

test("uses unique managed install temp destinations", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const release = createFakeManagedRelease();
  const copiedDestinations = [];
  const fsImpl = {
    ...fsp,
    copyFile: async (source, destination) => {
      copiedDestinations.push(destination);
      await fsp.copyFile(source, destination);
    }
  };

  await Promise.all([
    installManagedBinary({
      ...release,
      cacheRoot: temp,
      fsImpl,
      execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
    }),
    installManagedBinary({
      ...release,
      cacheRoot: temp,
      fsImpl,
      execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
    })
  ]);

  assert.equal(copiedDestinations.length, 2);
  assert.notEqual(copiedDestinations[0], copiedDestinations[1]);
});

test("shared MCP manifest launches package-local executable without treating package cwd as workspace", async () => {
  if (process.platform === "win32") {
    return;
  }
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const recordPath = path.join(temp, "args.txt");
  const stubBinary = path.join(temp, "bifrost-stub");
  const metadata = await readReleaseMetadata(path.join(packageDir, "bifrost-release.json"));
  await writeExecutableFixture(stubBinary, `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "bifrost ${metadata.binaryVersion}"
  exit 0
fi
printf '%s\\n' "$@" > "${recordPath}"
`);

  const mcpConfig = JSON.parse(await fsp.readFile(path.join(packageDir, ".mcp.json"), "utf8"));
  const server = mcpConfig.mcpServers.bifrost;
  const command = path.resolve(packageDir, server.command);
  await execFileAsync(command, server.args, {
    cwd: packageDir,
    env: {
      ...process.env,
      BIFROST_BINARY_PATH: stubBinary,
      BIFROST_LAUNCHER_AUTO_INSTALL: "0"
    }
  });

  assert.deepEqual(
    (await fsp.readFile(recordPath, "utf8")).trim().split(/\r?\n/),
    ["--mcp", "symbol|extended"]
  );
  assert.equal(command.startsWith(repoRoot), true);
});

test("Claude MCP manifest resolves the launcher from the installed plugin outside the workspace", async () => {
  if (process.platform === "win32") {
    return;
  }
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const workspace = path.join(temp, "workspace");
  const recordPath = path.join(temp, "args.txt");
  const stubBinary = path.join(temp, "bifrost-stub");
  const metadata = await readReleaseMetadata(path.join(packageDir, "bifrost-release.json"));
  await fsp.mkdir(workspace);
  await writeExecutableFixture(stubBinary, `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "bifrost ${metadata.binaryVersion}"
  exit 0
fi
printf '%s\\n' "$@" > "${recordPath}"
`);

  const mcpConfig = JSON.parse(await fsp.readFile(path.join(packageDir, "claude-mcp.json"), "utf8"));
  const server = mcpConfig.mcpServers.bifrost;
  const command = server.command.replace("${CLAUDE_PLUGIN_ROOT}", packageDir);
  await execFileAsync(command, server.args, {
    cwd: workspace,
    env: {
      ...process.env,
      BIFROST_BINARY_PATH: stubBinary,
      BIFROST_LAUNCHER_AUTO_INSTALL: "0"
    }
  });

  assert.deepEqual(
    (await fsp.readFile(recordPath, "utf8")).trim().split(/\r?\n/),
    ["--mcp", "symbol|extended"]
  );
  assert.equal(path.isAbsolute(command), true);
  assert.equal(command.startsWith(packageDir), true);
});

test("resolves an explicit reusable launch without allowing env root override", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const workspace = path.join(temp, "workspace");
  const otherWorkspace = path.join(temp, "other");
  const binaryPath = path.join(temp, process.platform === "win32" ? "bifrost.exe" : "bifrost");
  await fsp.mkdir(workspace);
  await fsp.mkdir(otherWorkspace);
  await fsp.writeFile(binaryPath, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    await fsp.chmod(binaryPath, 0o755);
  }
  const env = {
    BIFROST_BINARY_PATH: binaryPath,
    BIFROST_WORKSPACE_ROOT: otherWorkspace,
    BIFROST_LAUNCHER_AUTO_INSTALL: "0"
  };

  const resolved = await resolveBifrostLaunch({
    root: workspace,
    env,
    toolset: "symbol|extended",
    metadata: { binaryVersion: "0.8.4", archiveSha256: {} },
    execFileImpl: async () => ({ stdout: "bifrost 0.8.4\n", stderr: "" })
  });

  assert.equal(resolved.command, binaryPath);
  assert.equal(resolved.cwd, path.resolve(workspace));
  assert.equal(resolved.env, env);
  assert.equal(resolved.source, "explicit");
  assert.deepEqual(resolved.args, ["--root", path.resolve(workspace), "--mcp", "symbol|extended"]);
});

test("builds final Bifrost MCP args with explicit root and toolset", () => {
  assert.deepEqual(
    buildBifrostArgs("/workspace", "symbol|extended", ["--extra"]),
    ["--root", "/workspace", "--mcp", "symbol|extended", "--extra"]
  );
});

test("builds rootless Bifrost MCP args when the host supplies no explicit root", () => {
  assert.deepEqual(
    buildBifrostArgs(null, "symbol|extended", ["--extra"]),
    ["--mcp", "symbol|extended", "--extra"]
  );
});

test("does not infer an analyzer root from package cwd for plugin launches", async () => {
  assert.equal(
    await resolveWorkspaceRoot({ env: {}, argvRoot: null, cwd: packageDir, allowCwdFallback: false }),
    null
  );
});

test("parses launcher args", () => {
  assert.deepEqual(parseLauncherArgs(["--workspace-root", "/workspace", "--mcp", "core", "--flag"]), {
    command: "serve",
    json: false,
    root: "/workspace",
    toolset: "core",
    passThrough: ["--flag"]
  });
  assert.deepEqual(parseLauncherArgs(["doctor"]), { command: "doctor", json: false });
  assert.deepEqual(parseLauncherArgs(["prepare", "--json"]), { command: "prepare", json: true });
  assert.deepEqual(parseLauncherArgs(["--root", "doctor", "--mcp", "prepare", "--flag", "doctor"]), {
    command: "serve",
    json: false,
    root: "doctor",
    toolset: "prepare",
    passThrough: ["--flag", "doctor"]
  });
  assert.throws(
    () => parseLauncherArgs(["doctor", "--root", "/workspace"]),
    (error) => error instanceof LauncherError && error.code === "invalid_arguments"
  );
  assert.throws(
    () => parseLauncherArgs(["doctor", "prepare"]),
    (error) => error instanceof LauncherError && error.code === "invalid_arguments"
  );
});

test("exposes cache root override and version compatibility helper", async () => {
  const cacheOverride = "/tmp/bifrost-cache";
  assert.equal(cacheRootFor({ BIFROST_LAUNCHER_CACHE_DIR: cacheOverride }), path.resolve(cacheOverride));
  assert.equal(isVersionCompatible("0.7.2", "v0.7.2"), true);
  assert.equal(await findOnPath("definitely-not-bifrost", "", undefined, process.cwd()), null);
});

test("exports a cold-start budget covering download, extraction, probe, and margin", () => {
  assert.equal(DOWNLOAD_TIMEOUT_MS, 60_000);
  assert.equal(EXTRACTION_TIMEOUT_MS, 60_000);
  assert.equal(VERSION_PROBE_TIMEOUT_MS, 10_000);
  assert.equal(STARTUP_MARGIN_MS, 30_000);
  assert.equal(MINIMUM_MCP_STARTUP_TIMEOUT_MS, 160_000);
});

test("doctor reports a compatible managed binary without creating cache directories", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const cacheRoot = path.join(temp, "cache");
  const managed = managedBinaryPath(cacheRoot, "0.7.2");
  await writeExecutableFixture(managed);

  const ready = await inspectBifrostInstallation({
    env: { PATH: "" },
    cacheRoot,
    metadata: { binaryVersion: "0.7.2", archiveSha256: {} },
    execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
  });
  assert.deepEqual(ready, {
    status: "ready",
    requiredVersion: "0.7.2",
    source: "managed",
    binaryPath: managed,
    cachePath: managed,
    autoInstall: true,
    message: "Bifrost 0.7.2 is ready from managed."
  });

  const absentCache = path.join(temp, "absent-cache");
  const missing = await inspectBifrostInstallation({
    env: { PATH: "" },
    cacheRoot: absentCache,
    metadata: { binaryVersion: "0.7.2", archiveSha256: {} },
    fetchImpl: async () => {
      throw new Error("doctor must not download");
    }
  });
  assert.equal(missing.status, "missing");
  assert.equal(missing.cachePath, managedBinaryPath(absentCache, "0.7.2"));
  assert.equal(fs.existsSync(absentCache), false, "doctor must not create the cache root");
});

test("doctor reports incompatible managed and missing explicit binaries", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const cacheRoot = path.join(temp, "cache");
  const managed = managedBinaryPath(cacheRoot, "0.7.2");
  await writeExecutableFixture(managed);

  const incompatible = await inspectBifrostInstallation({
    env: { PATH: "" },
    cacheRoot,
    metadata: { binaryVersion: "0.7.2", archiveSha256: {} },
    execFileImpl: async () => ({ stdout: "bifrost 0.7.1\n", stderr: "" })
  });
  assert.equal(incompatible.status, "incompatible");
  assert.equal(incompatible.source, "managed");
  assert.equal(incompatible.binaryPath, managed);

  const explicitPath = path.join(temp, "missing-bifrost");
  const missing = await inspectBifrostInstallation({
    env: { PATH: "", BIFROST_BINARY_PATH: explicitPath },
    cacheRoot,
    metadata: { binaryVersion: "0.7.2", archiveSha256: {} }
  });
  assert.equal(missing.status, "missing");
  assert.equal(missing.source, "explicit");
  assert.equal(missing.binaryPath, explicitPath);
});

test("doctor reports cache access failures as errors", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const cacheRoot = path.join(temp, "cache");
  const denied = Object.assign(new Error("permission denied"), { code: "EACCES" });
  const result = await inspectBifrostInstallation({
    env: { PATH: "" },
    cacheRoot,
    metadata: { binaryVersion: "0.7.2", archiveSha256: {} },
    fsImpl: {
      ...fsp,
      stat: async (candidate) => {
        assert.equal(candidate, managedBinaryPath(cacheRoot, "0.7.2"));
        throw denied;
      }
    }
  });

  assert.equal(result.status, "error");
  assert.equal(result.source, null);
  assert.equal(result.cachePath, managedBinaryPath(cacheRoot, "0.7.2"));
  assert.match(result.message, /permission denied/);
});

test("doctor honors a compatible explicitly configured binary", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const explicitPath = path.join(temp, process.platform === "win32" ? "bifrost.exe" : "bifrost");
  await writeExecutableFixture(explicitPath);

  const ready = await inspectBifrostInstallation({
    env: { PATH: "", BIFROST_BINARY_PATH: explicitPath },
    cacheRoot: path.join(temp, "cache"),
    metadata: { binaryVersion: "0.7.2", archiveSha256: {} },
    execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
  });
  assert.equal(ready.status, "ready");
  assert.equal(ready.source, "explicit");
  assert.equal(ready.binaryPath, explicitPath);
});

test("prepare installs and then reuses a verified managed binary", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const cacheRoot = path.join(temp, "cache");
  const release = createFakeManagedRelease();
  const options = {
    ...release,
    env: { PATH: "" },
    cacheRoot,
    execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
  };
  const progress = [];

  const installed = await prepareBifrostInstallation({
    ...options,
    onInstallStart: (event) => progress.push(["start", event]),
    onInstallComplete: (event) => progress.push(["complete", event])
  });
  assert.equal(installed.status, "ready");
  assert.equal(installed.source, "installed");
  assert.equal(release.state.fetchCount, 2);
  assert.deepEqual(progress.map(([phase]) => phase), ["start", "complete"]);
  assert.equal(progress[0][1].version, "0.7.2");
  assert.equal(progress[0][1].cachePath, managedBinaryPath(cacheRoot, "0.7.2", "linux", "x64"));

  const reused = await prepareBifrostInstallation({
    ...options,
    fetchImpl: async () => {
      throw new Error("cache reuse must not fetch");
    }
  });
  assert.equal(reused.status, "ready");
  assert.equal(reused.source, "managed");
});

test("prepare reports missing when automatic installation is disabled", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const result = await prepareBifrostInstallation({
    env: { PATH: "", BIFROST_LAUNCHER_AUTO_INSTALL: "0" },
    cacheRoot: path.join(temp, "cache"),
    metadata: { binaryVersion: "0.7.2", archiveSha256: {} }
  });
  assert.equal(result.status, "missing");
  assert.equal(result.autoInstall, false);
  assert.match(result.message, /No compatible Bifrost 0\.7\.2 binary was found/);
  assert.match(result.message, /doctor, then prepare/);
  assert.match(result.message, /fresh host task/);
});

test("doctor CLI emits the stable JSON status shape on every platform", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const cacheRoot = path.join(temp, "cache");
  const launcher = path.join(packageDir, "bin", "bifrost-launcher.mjs");
  let stdout = "";
  await assert.rejects(
    execFileAsync(process.execPath, [launcher, "doctor", "--json"], {
      env: {
        ...process.env,
        BIFROST_BINARY_PATH: "",
        BIFROST_LAUNCHER_ALLOW_PATH: "0",
        BIFROST_LAUNCHER_AUTO_INSTALL: "0",
        BIFROST_LAUNCHER_CACHE_DIR: cacheRoot
      }
    }),
    (error) => {
      stdout = error.stdout;
      assert.equal(error.stderr, "");
      return error.code === 1;
    }
  );
  const status = JSON.parse(stdout);
  assert.deepEqual(Object.keys(status), [
    "status",
    "requiredVersion",
    "source",
    "binaryPath",
    "cachePath",
    "autoInstall",
    "message"
  ]);
  assert.equal(status.status, "missing");
  assert.equal(status.source, null);
  assert.equal(status.cachePath, managedBinaryPath(cacheRoot, status.requiredVersion));
  assert.match(formatLauncherStatus(status), /^status=missing /);
});

test("serve-mode setup failures keep stdout clean and explain recovery on stderr", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const metadata = await readReleaseMetadata(path.join(packageDir, "bifrost-release.json"));
  const cacheRoot = path.join(temp, "cache");
  const launcher = path.join(packageDir, "bin", "bifrost-launcher.mjs");

  await assert.rejects(
    execFileAsync(process.execPath, [launcher, "--root", temp, "--mcp", "symbol|extended"], {
      env: {
        ...process.env,
        BIFROST_BINARY_PATH: "",
        BIFROST_LAUNCHER_ALLOW_PATH: "0",
        BIFROST_LAUNCHER_AUTO_INSTALL: "0",
        BIFROST_LAUNCHER_CACHE_DIR: cacheRoot
      }
    }),
    (error) => {
      assert.equal(error.stdout, "");
      assert.match(error.stderr, /binary_not_found/);
      assert.match(error.stderr, new RegExp(`expected ${metadata.binaryVersion}`, "i"));
      assert.match(error.stderr, new RegExp(cacheRoot.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
      assert.match(error.stderr, /doctor, then prepare/);
      assert.match(error.stderr, /fresh host task/);
      return true;
    }
  );
});

test(
  "serve forwards termination and reaps a child that does not exit",
  { skip: process.platform === "win32" },
  async () => {
    const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-signal-test-"));
    const metadata = await readReleaseMetadata(path.join(packageDir, "bifrost-release.json"));
    const binary = path.join(temp, "bifrost");
    await writeExecutableFixture(
      binary,
      `#!/usr/bin/env node
if (process.argv.includes("--version")) {
  console.log("bifrost ${metadata.binaryVersion}");
  process.exit(0);
}
process.on("SIGTERM", () => console.error("bifrost-child-saw-term"));
console.error("bifrost-child-ready");
setInterval(() => {}, 1_000);
`
    );

    const launcher = spawn(
      process.execPath,
      [path.join(packageDir, "bin", "bifrost-launcher.mjs"), "--root", temp, "--mcp", "symbol"],
      {
        env: {
          ...process.env,
          BIFROST_BINARY_PATH: binary,
          BIFROST_LAUNCHER_ALLOW_PATH: "0",
          BIFROST_LAUNCHER_AUTO_INSTALL: "0",
          BIFROST_LAUNCHER_CACHE_DIR: path.join(temp, "cache")
        },
        stdio: ["ignore", "pipe", "pipe"]
      }
    );
    const stderr = [];
    launcher.stderr.setEncoding("utf8");
    launcher.stderr.on("data", (chunk) => stderr.push(chunk));
    const closed = new Promise((resolve, reject) => {
      launcher.once("error", reject);
      launcher.once("close", (code, signal) => resolve({ code, signal }));
    });
    const ready = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timed out waiting for fake Bifrost")), 10_000);
      launcher.stderr.on("data", () => {
        if (stderr.join("").includes("bifrost-child-ready")) {
          clearTimeout(timeout);
          resolve();
        }
      });
    });

    try {
      await ready;
      assert.equal(launcher.kill("SIGTERM"), true);
      let closeTimeout;
      const result = await Promise.race([
        closed,
        new Promise((_, reject) => {
          closeTimeout = setTimeout(
            () => reject(new Error("launcher did not reap fake Bifrost")),
            10_000
          );
        })
      ]);
      clearTimeout(closeTimeout);
      assert.equal(result.code, null);
      assert.equal(result.signal, "SIGKILL");
      assert.match(stderr.join(""), /bifrost-child-saw-term/);
    } finally {
      if (launcher.exitCode === null && launcher.signalCode === null) {
        launcher.kill("SIGTERM");
        await Promise.race([
          closed,
          new Promise((resolve) => setTimeout(resolve, 6_000))
        ]);
      }
      if (launcher.exitCode === null && launcher.signalCode === null) {
        launcher.kill("SIGKILL");
      }
    }
  }
);
