const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const Module = require("node:module");
const tar = require("tar");

const originalLoad = Module._load;
Module._load = function loadWithVscodeShim(request, parent, isMain) {
  if (request === "vscode") {
    return {
      workspace: {
        workspaceFolders: [],
        createFileSystemWatcher: (pattern) => ({ pattern })
      }
    };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const lifecycle = require("../out-test/lifecycle.js");
const provisioning = require("../out-test/provisioning.js");

test("maps VS Code runtime platforms to release targets", () => {
  assert.equal(provisioning.releaseTargetFor("darwin", "arm64"), "universal-apple-darwin");
  assert.equal(provisioning.releaseTargetFor("darwin", "x64"), "universal-apple-darwin");
  assert.equal(provisioning.releaseTargetFor("linux", "x64"), "x86_64-unknown-linux-gnu");
  assert.equal(provisioning.releaseTargetFor("linux", "arm64"), "aarch64-unknown-linux-gnu");
  assert.equal(provisioning.releaseTargetFor("win32", "x64"), "x86_64-pc-windows-msvc");
  assert.equal(provisioning.releaseTargetFor("win32", "arm64"), "aarch64-pc-windows-msvc");
  assert.throws(() => provisioning.releaseTargetFor("freebsd", "x64"), /Unsupported platform/);
});

test("constructs release archive names and URLs", () => {
  const asset = provisioning.releaseAssetFor("0.6.8", "linux", "x64");
  assert.equal(asset.archiveName, "bifrost-v0.6.8-x86_64-unknown-linux-gnu.tar.gz");
  assert.equal(asset.checksumName, "bifrost-v0.6.8-x86_64-unknown-linux-gnu.tar.gz.sha256");
  assert.equal(
    asset.archiveUrl,
    "https://github.com/BrokkAi/bifrost/releases/download/v0.6.8/bifrost-v0.6.8-x86_64-unknown-linux-gnu.tar.gz"
  );

  const windows = provisioning.releaseAssetFor("v0.6.8", "win32", "arm64");
  assert.equal(windows.archiveName, "bifrost-v0.6.8-aarch64-pc-windows-msvc.zip");
  assert.equal(windows.checksumName, "bifrost-v0.6.8-aarch64-pc-windows-msvc.zip.sha256");
});

test("parses and validates SHA-256 sidecars", () => {
  const hash = "a".repeat(64);
  assert.equal(provisioning.parseSha256(`${hash}  bifrost-v0.6.8-target.tar.gz\n`, "bifrost-v0.6.8-target.tar.gz"), hash);
  assert.equal(provisioning.parseSha256(`${hash} *bifrost-v0.6.8-target.tar.gz\n`, "bifrost-v0.6.8-target.tar.gz"), hash);
  assert.throws(
    () => provisioning.parseSha256(`${hash}  other-file\n`, "bifrost-v0.6.8-target.tar.gz"),
    /No SHA-256 checksum/
  );
});

test("installs verified binary and cleans old managed versions", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const oldDir = path.join(temp, "binaries", "0.6.7", "linux-x64");
  fs.mkdirSync(oldDir, { recursive: true });
  fs.writeFileSync(path.join(oldDir, "bifrost"), "old");

  const archiveName = "bifrost-v0.6.8-x86_64-unknown-linux-gnu.tar.gz";
  const stage = "bifrost-v0.6.8-x86_64-unknown-linux-gnu";
  const releaseDir = path.join(temp, "release");
  const stageDir = path.join(releaseDir, stage);
  const archivePath = path.join(temp, archiveName);
  fs.mkdirSync(stageDir, { recursive: true });
  fs.writeFileSync(path.join(stageDir, "bifrost"), "new-binary");
  tar.c({ gzip: true, file: archivePath, cwd: releaseDir, sync: true }, [stage]);

  const archive = fs.readFileSync(archivePath);
  const checksum = provisioning.sha256(archive);
  const fetchImpl = async (url) => {
    if (url.endsWith(".sha256")) {
      return new Response(`${checksum}  ${archiveName}\n`);
    }
    return new Response(archive);
  };

  const installed = await provisioning.installManagedBinary({
    storageDir: temp,
    version: "0.6.8",
    expectedSha256: checksum,
    platform: "linux",
    arch: "x64",
    fetchImpl
  });

  assert.equal(installed, path.join(temp, "binaries", "0.6.8", "linux-x64", "bifrost"));
  assert.equal(fs.readFileSync(installed, "utf8"), "new-binary");
  assert.equal(fs.existsSync(path.join(temp, "binaries", "0.6.7")), false);
});

test("rejects checksum mismatch during install", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const expectedSha256 = "a".repeat(64);
  const fetchImpl = async (url) => {
    if (url.endsWith(".sha256")) {
      return new Response(`${"b".repeat(64)}  bifrost-v0.6.8-x86_64-unknown-linux-gnu.tar.gz\n`);
    }
    return new Response(Buffer.from("not-a-real-archive"));
  };

  await assert.rejects(
    provisioning.installManagedBinary({
      storageDir: temp,
      version: "0.6.8",
      expectedSha256,
      platform: "linux",
      arch: "x64",
      fetchImpl
    }),
    /Checksum sidecar mismatch/
  );
});

test("rejects archive bytes that do not match the pinned checksum", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const expectedSha256 = "a".repeat(64);
  const fetchImpl = async (url) => {
    if (url.endsWith(".sha256")) {
      return new Response(`${expectedSha256}  bifrost-v0.6.8-x86_64-unknown-linux-gnu.tar.gz\n`);
    }
    return new Response(Buffer.from("not-a-real-archive"));
  };

  await assert.rejects(
    provisioning.installManagedBinary({
      storageDir: temp,
      version: "0.6.8",
      expectedSha256,
      platform: "linux",
      arch: "x64",
      fetchImpl
    }),
    /Checksum mismatch/
  );
});

test("resolves launch mode precedence", () => {
  assert.equal(lifecycle.resolveLaunchMode("auto", "/tmp/bifrost", "/managed/bifrost"), "path");
  assert.equal(lifecycle.resolveLaunchMode("auto", "bifrost", "/managed/bifrost"), "managed");
  assert.equal(lifecycle.resolveLaunchMode("auto", "bifrost", null), "path");
  assert.equal(lifecycle.resolveLaunchMode("bundled", "bifrost", null), "managed");
  assert.equal(lifecycle.resolveLaunchMode("path", "bifrost", "/managed/bifrost"), "path");
});

test("builds managed launch config when bundled mode has an installed binary", () => {
  const config = lifecycle.buildLaunchConfig(
    "/workspace",
    "/extension",
    "bundled",
    "bifrost",
    ["--flag"],
    true,
    123,
    "/managed/bifrost"
  );
  assert.equal(config.command, "/managed/bifrost");
  assert.equal(config.label, "managed");
  assert.deepEqual(config.args, ["--root", "/workspace", "--server", "lsp", "--flag"]);
  assert.equal(config.env.BIFROST_LSP_DEBUG, "1");
  assert.equal(config.env.BIFROST_LSP_SLOW_MS, "123");
});

test("parses bifrost --version output", () => {
  assert.equal(provisioning.parseBifrostVersion("bifrost 0.6.8\n"), "0.6.8");
  assert.equal(provisioning.parseBifrostVersion("bifrost v0.6.8\n"), "0.6.8");
  assert.equal(provisioning.parseBifrostVersion("not bifrost\n"), null);
  assert.equal(provisioning.isVersionCompatible("0.6.8", "v0.6.8"), true);
});
