import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  LauncherError,
  buildBifrostArgs,
  cacheRootFor,
  findOnPath,
  installManagedBinary,
  isVersionCompatible,
  looksUnexpandedHostPlaceholder,
  managedBinaryPath,
  parseLauncherArgs,
  readReleaseMetadata,
  releaseAssetFor,
  releaseTargetFor,
  resolveBifrostBinary,
  resolveWorkspaceRoot,
  sha256
} from "../bin/bifrost-launcher.mjs";

const execFileAsync = promisify(execFile);
const testDir = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(testDir, "..");
const repoRoot = path.resolve(packageDir, "../..");

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
  await fsp.writeFile(binaryPath, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    await fsp.chmod(binaryPath, 0o755);
  }

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
  await fsp.writeFile(binaryPath, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    await fsp.chmod(binaryPath, 0o755);
  }

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
  await fsp.writeFile(binaryPath, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    await fsp.chmod(binaryPath, 0o755);
  }

  assert.equal(
    await findOnPath("bifrost", `${path.delimiter}relative-bin`, undefined, temp),
    null
  );
});

test("preserves PATH version mismatch when auto install is disabled", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const binaryPath = path.join(temp, process.platform === "win32" ? "bifrost.exe" : "bifrost");
  await fsp.writeFile(binaryPath, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    await fsp.chmod(binaryPath, 0o755);
  }

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
  await fsp.mkdir(path.dirname(managed), { recursive: true });
  await fsp.writeFile(managed, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    await fsp.chmod(managed, 0o755);
  }

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

test("installs verified managed binary", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const target = releaseTargetFor("linux", "x64");
  const archive = Buffer.from("fake archive");
  const archiveHash = sha256(archive);
  const metadata = {
    binaryVersion: "0.7.2",
    archiveSha256: { [target]: archiveHash }
  };
  const fetchImpl = async (url) => {
    if (url.endsWith(".sha256")) {
      return new Response(`${archiveHash}  bifrost-v0.7.2-x86_64-unknown-linux-gnu.tar.gz\n`);
    }
    return new Response(archive);
  };
  const extractArchiveImpl = async (_archivePath, extractDir) => {
    const binaryDir = path.join(extractDir, "bifrost-v0.7.2-x86_64-unknown-linux-gnu");
    await fsp.mkdir(binaryDir, { recursive: true });
    const binaryPath = path.join(binaryDir, "bifrost");
    await fsp.writeFile(binaryPath, "#!/bin/sh\nexit 0\n");
    await fsp.chmod(binaryPath, 0o755);
  };

  const installed = await installManagedBinary({
    metadata,
    cacheRoot: temp,
    platform: "linux",
    arch: "x64",
    fetchImpl,
    extractArchiveImpl,
    execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
  });

  assert.equal(installed, path.join(temp, "binaries", "0.7.2", "linux-x64", "bifrost"));
  assert.equal(fs.existsSync(installed), true);
});

test("uses unique managed install temp destinations", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const target = releaseTargetFor("linux", "x64");
  const archive = Buffer.from("fake archive");
  const archiveHash = sha256(archive);
  const metadata = {
    binaryVersion: "0.7.2",
    archiveSha256: { [target]: archiveHash }
  };
  const fetchImpl = async (url) => {
    if (url.endsWith(".sha256")) {
      return new Response(`${archiveHash}  bifrost-v0.7.2-x86_64-unknown-linux-gnu.tar.gz\n`);
    }
    return new Response(archive);
  };
  const copiedDestinations = [];
  const fsImpl = {
    ...fsp,
    copyFile: async (source, destination) => {
      copiedDestinations.push(destination);
      await fsp.copyFile(source, destination);
    }
  };
  const extractArchiveImpl = async (_archivePath, extractDir) => {
    const binaryDir = path.join(extractDir, "bifrost-v0.7.2-x86_64-unknown-linux-gnu");
    await fsp.mkdir(binaryDir, { recursive: true });
    const binaryPath = path.join(binaryDir, "bifrost");
    await fsp.writeFile(binaryPath, "#!/bin/sh\nexit 0\n");
    await fsp.chmod(binaryPath, 0o755);
  };

  await Promise.all([
    installManagedBinary({
      metadata,
      cacheRoot: temp,
      platform: "linux",
      arch: "x64",
      fetchImpl,
      fsImpl,
      extractArchiveImpl,
      execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
    }),
    installManagedBinary({
      metadata,
      cacheRoot: temp,
      platform: "linux",
      arch: "x64",
      fetchImpl,
      fsImpl,
      extractArchiveImpl,
      execFileImpl: async () => ({ stdout: "bifrost 0.7.2\n", stderr: "" })
    })
  ]);

  assert.equal(copiedDestinations.length, 2);
  assert.notEqual(copiedDestinations[0], copiedDestinations[1]);
});

test("shared MCP manifest launches package-local executable from workspace cwd", async () => {
  if (process.platform === "win32") {
    return;
  }
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-launcher-test-"));
  const workspace = path.join(temp, "workspace");
  await fsp.mkdir(workspace);
  const recordPath = path.join(temp, "args.txt");
  const stubBinary = path.join(temp, "bifrost-stub");
  const metadata = await readReleaseMetadata(path.join(packageDir, "bifrost-release.json"));
  await fsp.writeFile(stubBinary, `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "bifrost ${metadata.binaryVersion}"
  exit 0
fi
printf '%s\\n' "$@" > "${recordPath}"
`);
  await fsp.chmod(stubBinary, 0o755);

  const mcpConfig = JSON.parse(await fsp.readFile(path.join(packageDir, ".mcp.json"), "utf8"));
  const server = mcpConfig.mcpServers.bifrost;
  const command = path.resolve(packageDir, server.command);
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
    ["--root", await fsp.realpath(workspace), "--mcp", "symbol|extended"]
  );
  assert.equal(command.startsWith(repoRoot), true);
});

test("builds final Bifrost MCP args with explicit root and toolset", () => {
  assert.deepEqual(
    buildBifrostArgs("/workspace", "symbol|extended", ["--extra"]),
    ["--root", "/workspace", "--mcp", "symbol|extended", "--extra"]
  );
});

test("parses launcher args", () => {
  assert.deepEqual(parseLauncherArgs(["--workspace-root", "/workspace", "--mcp", "core", "--flag"]), {
    root: "/workspace",
    toolset: "core",
    passThrough: ["--flag"]
  });
});

test("exposes cache root override and version compatibility helper", async () => {
  assert.equal(cacheRootFor({ BIFROST_LAUNCHER_CACHE_DIR: "/tmp/bifrost-cache" }), "/tmp/bifrost-cache");
  assert.equal(isVersionCompatible("0.7.2", "v0.7.2"), true);
  assert.equal(await findOnPath("definitely-not-bifrost", "", undefined, process.cwd()), null);
});
