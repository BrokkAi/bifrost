import assert from "node:assert/strict";
import fs from "node:fs";
import Module, { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import * as tar from "tar";
import type * as LifecycleModule from "../src/lifecycle";
import type * as ProvisioningModule from "../src/provisioning";

interface LauncherModule {
  SUPPORTED_TARGETS: string[];
  releaseTargetFor(platform: NodeJS.Platform, arch: NodeJS.Architecture): string;
}

type ModuleLoader = (
  request: string,
  parent: NodeModule | null | undefined,
  isMain: boolean
) => unknown;

const moduleWithLoader = Module as typeof Module & { _load: ModuleLoader };
const originalLoad = moduleWithLoader._load;
moduleWithLoader._load = function loadWithVscodeShim(request, parent, isMain) {
  if (request === "vscode") {
    return {
      workspace: {
        workspaceFolders: [],
        createFileSystemWatcher: (pattern: unknown) => ({ pattern })
      }
    };
  }
  return originalLoad(request, parent, isMain);
};

const loadModule = createRequire(__filename);
const lifecycle = loadModule("../src/lifecycle") as typeof LifecycleModule;
const provisioning = loadModule("../src/provisioning") as typeof ProvisioningModule;
const extensionRoot = path.resolve(__dirname, "../..");
const repositoryRoot = path.resolve(extensionRoot, "../..");

function requestUrl(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === "string") {
    return input;
  }
  return input instanceof URL ? input.href : input.url;
}

void test("maps VS Code runtime platforms to release targets", () => {
  assert.equal(provisioning.releaseTargetFor("darwin", "arm64"), "universal-apple-darwin");
  assert.equal(provisioning.releaseTargetFor("darwin", "x64"), "universal-apple-darwin");
  assert.equal(provisioning.releaseTargetFor("linux", "x64"), "x86_64-unknown-linux-gnu");
  assert.equal(provisioning.releaseTargetFor("linux", "arm64"), "aarch64-unknown-linux-gnu");
  assert.equal(provisioning.releaseTargetFor("win32", "x64"), "x86_64-pc-windows-msvc");
  assert.equal(provisioning.releaseTargetFor("win32", "arm64"), "aarch64-pc-windows-msvc");
  assert.throws(() => provisioning.releaseTargetFor("freebsd", "x64"), /Unsupported platform/);
});

void test("keeps VS Code and agent plugin release targets aligned", async () => {
  const launcher = (await import(
    pathToFileURL(path.join(repositoryRoot, "plugins/bifrost-agent/bin/bifrost-launcher.mjs")).href
  )) as LauncherModule;
  const cases = [
    ["darwin", "arm64"],
    ["darwin", "x64"],
    ["linux", "x64"],
    ["linux", "arm64"],
    ["win32", "x64"],
    ["win32", "arm64"]
  ] satisfies Array<[NodeJS.Platform, NodeJS.Architecture]>;

  assert.deepEqual(
    cases.map(([platform, arch]) => provisioning.releaseTargetFor(platform, arch)),
    cases.map(([platform, arch]) => launcher.releaseTargetFor(platform, arch))
  );
  assert.deepEqual(
    new Set(cases.map(([platform, arch]) => provisioning.releaseTargetFor(platform, arch))),
    new Set(launcher.SUPPORTED_TARGETS)
  );
});

void test("constructs release archive names and URLs", () => {
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

void test("parses and validates SHA-256 sidecars", () => {
  const hash = "a".repeat(64);
  assert.equal(
    provisioning.parseSha256(
      `${hash}  bifrost-v0.6.8-target.tar.gz\n`,
      "bifrost-v0.6.8-target.tar.gz"
    ),
    hash
  );
  assert.equal(
    provisioning.parseSha256(
      `${hash} *bifrost-v0.6.8-target.tar.gz\n`,
      "bifrost-v0.6.8-target.tar.gz"
    ),
    hash
  );
  assert.throws(
    () => provisioning.parseSha256(`${hash}  other-file\n`, "bifrost-v0.6.8-target.tar.gz"),
    /No SHA-256 checksum/
  );
});

void test("installs verified binary and cleans old managed versions", async () => {
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
  const fetchImpl: typeof fetch = (url) => {
    if (requestUrl(url).endsWith(".sha256")) {
      return Promise.resolve(new Response(`${checksum}  ${archiveName}\n`));
    }
    return Promise.resolve(new Response(archive));
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

void test("rejects checksum mismatch during install", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const expectedSha256 = "a".repeat(64);
  const fetchImpl: typeof fetch = (url) => {
    if (requestUrl(url).endsWith(".sha256")) {
      return Promise.resolve(
        new Response(`${"b".repeat(64)}  bifrost-v0.6.8-x86_64-unknown-linux-gnu.tar.gz\n`)
      );
    }
    return Promise.resolve(new Response(Buffer.from("not-a-real-archive")));
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

void test("rejects archive bytes that do not match the pinned checksum", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const expectedSha256 = "a".repeat(64);
  const fetchImpl: typeof fetch = (url) => {
    if (requestUrl(url).endsWith(".sha256")) {
      return Promise.resolve(
        new Response(`${expectedSha256}  bifrost-v0.6.8-x86_64-unknown-linux-gnu.tar.gz\n`)
      );
    }
    return Promise.resolve(new Response(Buffer.from("not-a-real-archive")));
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

void test("resolves launch mode precedence", () => {
  assert.equal(lifecycle.resolveLaunchMode("auto", "/tmp/bifrost", "/managed/bifrost"), "path");
  assert.equal(lifecycle.resolveLaunchMode("auto", "bifrost", "/managed/bifrost"), "managed");
  assert.equal(lifecycle.resolveLaunchMode("auto", "bifrost", null), "path");
  assert.equal(lifecycle.resolveLaunchMode("bundled", "bifrost", null), "managed");
  assert.equal(lifecycle.resolveLaunchMode("path", "bifrost", "/managed/bifrost"), "path");
});

void test("builds managed launch config when bundled mode has an installed binary", () => {
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
  assert.deepEqual(config.args, ["--root", "/workspace", "--lsp", "--flag"]);
  assert.equal(config.env.BIFROST_LSP_DEBUG, "1");
  assert.equal(config.env.BIFROST_LSP_SLOW_MS, "123");
});

void test("builds managed MCP config with searchtools toolset", () => {
  const config = lifecycle.buildMcpConfig(
    "/workspace",
    "/extension",
    "bundled",
    "bifrost",
    "/managed/bifrost"
  );
  assert.deepEqual(config, {
    mcpServers: {
      bifrost: {
        command: "/managed/bifrost",
        args: ["--root", "/workspace", "--mcp", "searchtools"]
      }
    }
  });
});

void test("builds path MCP config from configured server path", () => {
  const config = lifecycle.buildMcpConfig(
    "/workspace",
    "/extension",
    "path",
    "/custom/bin/bifrost",
    null
  );
  assert.deepEqual(config.mcpServers.bifrost, {
    command: "/custom/bin/bifrost",
    args: ["--root", "/workspace", "--mcp", "searchtools"]
  });
});

void test("normalizes configured server path before validating and spawning", () => {
  const config = lifecycle.buildLaunchConfig(
    "/workspace",
    "/extension",
    "path",
    "  /custom/bin/bifrost  ",
    [],
    false,
    2000,
    null
  );

  assert.equal(config.command, "/custom/bin/bifrost");
});

void test("builds path MCP config from local development binary", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const extensionDir = path.join(temp, "editors", "vscode");
  const binaryPath = path.join(temp, "target", "debug", "bifrost");
  fs.mkdirSync(path.dirname(binaryPath), { recursive: true });
  fs.mkdirSync(extensionDir, { recursive: true });
  fs.writeFileSync(binaryPath, "binary");

  const config = lifecycle.buildMcpConfig("/workspace", extensionDir, "path", "bifrost", null);
  assert.deepEqual(config.mcpServers.bifrost, {
    command: binaryPath,
    args: ["--root", "/workspace", "--mcp", "searchtools"]
  });
});

void test("validates configured absolute launch command before startup", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const binaryPath = path.join(temp, "bifrost");
  fs.writeFileSync(binaryPath, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    fs.chmodSync(binaryPath, 0o755);
  }

  await lifecycle.validateLaunchCommand({
    command: binaryPath,
    args: ["--root", "/workspace", "--lsp"],
    cwd: "/workspace",
    env: process.env,
    label: "path"
  });
});

void test("rejects unnormalized absolute launch command before startup", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const binaryPath = path.join(temp, "bifrost");
  fs.writeFileSync(binaryPath, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    fs.chmodSync(binaryPath, 0o755);
  }

  await assert.rejects(
    lifecycle.validateLaunchCommand({
      command: ` ${binaryPath} `,
      args: ["--root", "/workspace", "--lsp"],
      cwd: "/workspace",
      env: process.env,
      label: "path"
    }),
    /Bifrost binary was not found/
  );
});

void test("rejects missing configured absolute launch command before startup", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const binaryPath = path.join(temp, "missing-bifrost");

  await assert.rejects(
    lifecycle.validateLaunchCommand({
      command: binaryPath,
      args: ["--root", "/workspace", "--lsp"],
      cwd: "/workspace",
      env: process.env,
      label: "path"
    }),
    /Bifrost binary was not found/
  );
});

void test("validates relative launch command from workspace cwd before startup", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const binaryPath = path.join(temp, "target", "debug", "bifrost");
  fs.mkdirSync(path.dirname(binaryPath), { recursive: true });
  fs.writeFileSync(binaryPath, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    fs.chmodSync(binaryPath, 0o755);
  }

  await lifecycle.validateLaunchCommand({
    command: "./target/debug/bifrost",
    args: ["--root", temp, "--lsp"],
    cwd: temp,
    env: process.env,
    label: "path"
  });
});

void test("validates relative PATH launch command from workspace cwd before startup", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const binaryPath = path.join(
    temp,
    "target",
    "debug",
    process.platform === "win32" ? "bifrost.exe" : "bifrost"
  );
  fs.mkdirSync(path.dirname(binaryPath), { recursive: true });
  fs.writeFileSync(binaryPath, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    fs.chmodSync(binaryPath, 0o755);
  }

  await lifecycle.validateLaunchCommand({
    command: "bifrost",
    args: ["--root", temp, "--lsp"],
    cwd: temp,
    env: { ...process.env, PATH: path.join("target", "debug") },
    label: "path"
  });
});

void test("validates PATH launch command before startup", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const binaryPath = path.join(temp, process.platform === "win32" ? "bifrost.exe" : "bifrost");
  fs.writeFileSync(binaryPath, "#!/bin/sh\nexit 0\n");
  if (process.platform !== "win32") {
    fs.chmodSync(binaryPath, 0o755);
  }

  await lifecycle.validateLaunchCommand({
    command: "bifrost",
    args: ["--root", "/workspace", "--lsp"],
    cwd: "/workspace",
    env: { ...process.env, PATH: temp },
    label: "path"
  });
});

void test("rejects missing PATH launch command before startup", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));

  await assert.rejects(
    lifecycle.validateLaunchCommand({
      command: "bifrost",
      args: ["--root", "/workspace", "--lsp"],
      cwd: "/workspace",
      env: { ...process.env, PATH: temp },
      label: "path"
    }),
    /was not found on PATH/
  );
});

void test("preserves PATH candidate validation errors before startup", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const binaryPath = path.join(temp, process.platform === "win32" ? "bifrost.exe" : "bifrost");
  fs.mkdirSync(binaryPath);

  await assert.rejects(
    lifecycle.validateLaunchCommand({
      command: "bifrost",
      args: ["--root", "/workspace", "--lsp"],
      cwd: "/workspace",
      env: { ...process.env, PATH: temp },
      label: "path"
    }),
    /Bifrost server path is not a file/
  );
});

void test("builds MCP host commands from config", () => {
  const commands = lifecycle.buildMcpHostCommands({
    mcpServers: {
      bifrost: {
        command: "/custom bin/bifrost",
        args: ["--root", "/workspace path", "--mcp", "searchtools"]
      }
    }
  });

  assert.equal(
    commands.codex,
    'codex mcp add bifrost -- "/custom bin/bifrost" --root "/workspace path" --mcp searchtools'
  );
  assert.equal(
    commands.claudeCode,
    'claude mcp add --scope user bifrost -- "/custom bin/bifrost" --root "/workspace path" --mcp searchtools'
  );
});

void test("builds complete runtime settings snapshots for initialization and pulls", () => {
  const formatter = { include: ["*.rs"], command: "rustfmt" };
  const settings = lifecycle.buildBifrostInitializationOptions(
    "/workspace",
    ["src", "  ", "/absolute/root"],
    ["target"],
    [formatter],
    true
  );

  assert.deepEqual(settings, {
    roots: [path.join("/workspace", "src"), "/absolute/root"],
    exclude: [path.join("/workspace", "target")],
    formatterCommands: [formatter],
    unrecognizedSymbolDiagnostics: true
  });
  assert.deepEqual(lifecycle.buildBifrostInitializationOptions("/workspace", [], [], [], false), {
    roots: [],
    exclude: [],
    formatterCommands: [],
    unrecognizedSymbolDiagnostics: false
  });
});

void test("selects formatter commands from user settings only", () => {
  const globalRule = { command: "/user/formatter" };
  const workspaceRule = { command: "/workspace/untrusted-formatter" };

  assert.deepEqual(
    lifecycle.selectTrustedFormatterCommands({
      globalValue: [globalRule],
      workspaceValue: [workspaceRule]
    }),
    { rules: [globalRule], ignoredWorkspaceRules: true }
  );
  assert.deepEqual(lifecycle.selectTrustedFormatterCommands(undefined), {
    rules: [],
    ignoredWorkspaceRules: false
  });
});

void test("requires restart only for process launch settings", () => {
  const changed = (section: string): boolean => section === "bifrost.serverPath";
  assert.equal(lifecycle.bifrostConfigurationChangeRequiresRestart(changed), true);

  for (const runtimeSetting of ["roots", "exclude", "formatterCommands"]) {
    assert.equal(
      lifecycle.bifrostConfigurationChangeRequiresRestart(
        (section) => section === `bifrost.${runtimeSetting}`
      ),
      false
    );
  }
});

void test("detects existing bifrost gitignore entries", () => {
  assert.equal(lifecycle.gitignoreIncludesBifrostEntry(".bifrost\n"), true);
  assert.equal(lifecycle.gitignoreIncludesBifrostEntry("/.bifrost/\n"), true);
  assert.equal(lifecycle.gitignoreIncludesBifrostEntry("# .bifrost\nnode_modules\n"), false);
  assert.equal(lifecycle.gitignoreIncludesBifrostEntry(".bifrost-cache\n"), false);
});

void test("appends bifrost gitignore entry when missing", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const gitignorePath = path.join(temp, ".gitignore");
  fs.writeFileSync(gitignorePath, "target");

  assert.equal(await lifecycle.workspaceGitignoreNeedsBifrostEntry(temp), true);
  await lifecycle.appendBifrostGitignoreEntry(temp);

  assert.equal(fs.readFileSync(gitignorePath, "utf8"), "target\n.bifrost\n");
  assert.equal(await lifecycle.workspaceGitignoreNeedsBifrostEntry(temp), false);
});

void test("creates gitignore with bifrost entry when missing", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));

  assert.equal(await lifecycle.workspaceGitignoreNeedsBifrostEntry(temp), true);
  await lifecycle.appendBifrostGitignoreEntry(temp);

  assert.equal(fs.readFileSync(path.join(temp, ".gitignore"), "utf8"), ".bifrost\n");
});

void test("parses bifrost --version output", () => {
  assert.equal(provisioning.parseBifrostVersion("bifrost 0.6.8\n"), "0.6.8");
  assert.equal(provisioning.parseBifrostVersion("bifrost v0.6.8\n"), "0.6.8");
  assert.equal(provisioning.parseBifrostVersion("not bifrost\n"), null);
  assert.equal(provisioning.isVersionCompatible("0.6.8", "v0.6.8"), true);
});
