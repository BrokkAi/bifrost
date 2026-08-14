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

void test("installs verified binary and preserves compatible managed versions", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const oldDir = path.join(temp, "binaries", "0.6.7", "linux-x64");
  fs.mkdirSync(oldDir, { recursive: true });
  fs.writeFileSync(path.join(oldDir, "bifrost"), "old");
  const incompatibleDir = path.join(temp, "binaries", "0.5.9", "linux-x64");
  fs.mkdirSync(incompatibleDir, { recursive: true });
  fs.writeFileSync(path.join(incompatibleDir, "bifrost"), "incompatible");

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
    minimumBinaryVersion: "0.6.7",
    allowPrerelease: false,
    expectedSha256: checksum,
    platform: "linux",
    arch: "x64",
    fetchImpl
  });

  assert.equal(installed, path.join(temp, "binaries", "0.6.8", "linux-x64", "bifrost"));
  assert.equal(fs.readFileSync(installed, "utf8"), "new-binary");
  assert.equal(fs.existsSync(path.join(temp, "binaries", "0.6.7")), true);
  assert.equal(fs.existsSync(path.join(temp, "binaries", "0.5.9")), false);
});

void test("selects exact then newest compatible managed binaries", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const versions = ["0.9.1", "0.9.5", "0.9.3", "0.8.9"];
  for (const version of versions) {
    const binary = provisioning.managedBinaryPath(temp, version, "linux", "x64");
    fs.mkdirSync(path.dirname(binary), { recursive: true });
    fs.writeFileSync(binary, version);
  }
  const compatibility = {
    binaryVersion: "0.9.3",
    minimumBinaryVersion: "0.9.0",
    allowPrerelease: false
  };
  const probe = (binary: string) =>
    Promise.resolve({
      version: fs.readFileSync(binary, "utf8"),
      rawOutput: ""
    });

  const exact = await provisioning.findCompatibleManagedBinary(
    temp,
    compatibility,
    "linux",
    "x64",
    probe
  );
  assert.equal(exact?.version, "0.9.3");
  assert.equal(exact?.compatibilityMode, "exact");

  fs.rmSync(path.join(temp, "binaries", "0.9.3"), { recursive: true });
  const newest = await provisioning.findCompatibleManagedBinary(
    temp,
    compatibility,
    "linux",
    "x64",
    probe
  );
  assert.equal(newest?.version, "0.9.5");
  assert.equal(newest?.compatibilityMode, "compatible");
});

void test("starts a compatible binary while preparing and activating the preferred binary", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const fallbackPath = provisioning.managedBinaryPath(temp, "0.9.1", "linux", "x64");
  fs.mkdirSync(path.dirname(fallbackPath), { recursive: true });
  fs.writeFileSync(fallbackPath, "0.9.1");
  let finishInstall: ((path: string) => void) | undefined;
  const install = new Promise<string>((resolve) => {
    finishInstall = resolve;
  });
  let installStarted = false;
  const preparation = await provisioning.selectManagedBinaryAndPreparePreferred(
    () =>
      provisioning.findCompatibleManagedBinary(
        temp,
        { binaryVersion: "0.9.4", minimumBinaryVersion: "0.9.0", allowPrerelease: false },
        "linux",
        "x64",
        (binary) => Promise.resolve({ version: fs.readFileSync(binary, "utf8"), rawOutput: "" })
      ),
    () => {
      installStarted = true;
      return install;
    },
    () => undefined
  );

  assert.equal(preparation?.selected.path, fallbackPath);
  assert.equal(preparation?.selected.version, "0.9.1");
  assert.ok(preparation);
  assert.equal(installStarted, true);

  const activations: string[] = [];
  const activation = provisioning.activatePreparedManagedBinary(
    preparation,
    (selectedPath) => selectedPath === fallbackPath,
    (preferredPath) => {
      activations.push(preferredPath);
      return Promise.resolve();
    }
  );
  finishInstall!("/managed/0.9.4/bifrost");

  assert.equal(await activation, true);
  assert.deepEqual(activations, ["/managed/0.9.4/bifrost"]);
});

void test("does not prepare the preferred binary when the exact binary is selected", async () => {
  let installStarted = false;
  const preparation = await provisioning.selectManagedBinaryAndPreparePreferred(
    () =>
      Promise.resolve({
        path: "/managed/0.9.4/bifrost",
        version: "0.9.4",
        compatibilityMode: "exact"
      }),
    () => {
      installStarted = true;
      return Promise.resolve("/managed/0.9.4/bifrost");
    },
    () => undefined
  );

  assert.equal(preparation?.selected.version, "0.9.4");
  assert.equal(preparation?.preferredInstall, null);
  assert.equal(installStarted, false);
});

void test("keeps the compatible binary active when preferred preparation fails", async () => {
  const messages: string[] = [];
  const preparation = await provisioning.selectManagedBinaryAndPreparePreferred(
    () =>
      Promise.resolve({
        path: "/managed/0.9.1/bifrost",
        version: "0.9.1",
        compatibilityMode: "compatible"
      }),
    () => Promise.reject(new Error("release unavailable")),
    (message) => messages.push(message)
  );
  let activated = false;
  assert.ok(preparation);

  assert.equal(
    await provisioning.activatePreparedManagedBinary(
      preparation,
      () => true,
      () => {
        activated = true;
        return Promise.resolve();
      }
    ),
    false
  );
  assert.equal(activated, false);
  assert.deepEqual(messages, ["Preferred managed Bifrost preparation failed: release unavailable"]);
});

void test("does not replace a server that moved on before preferred preparation completed", async () => {
  const preparation = await provisioning.selectManagedBinaryAndPreparePreferred(
    () =>
      Promise.resolve({
        path: "/managed/0.9.1/bifrost",
        version: "0.9.1",
        compatibilityMode: "compatible"
      }),
    () => Promise.resolve("/managed/0.9.4/bifrost"),
    () => undefined
  );
  let activated = false;
  assert.ok(preparation);

  assert.equal(
    await provisioning.activatePreparedManagedBinary(
      preparation,
      () => false,
      () => {
        activated = true;
        return Promise.resolve();
      }
    ),
    false
  );
  assert.equal(activated, false);
});

void test("skips mislabeled, prerelease, and cross-minor managed binaries", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const reported = new Map([
    ["0.9.4", "0.9.2"],
    ["0.9.3-rc.1", "0.9.3-rc.1"],
    ["0.8.9", "0.8.9"]
  ]);
  for (const version of reported.keys()) {
    const binary = provisioning.managedBinaryPath(temp, version, "linux", "x64");
    fs.mkdirSync(path.dirname(binary), { recursive: true });
    fs.writeFileSync(binary, version);
  }

  const selected = await provisioning.findCompatibleManagedBinary(
    temp,
    { binaryVersion: "0.9.5", minimumBinaryVersion: "0.9.0", allowPrerelease: false },
    "linux",
    "x64",
    (binary) => {
      const directoryVersion = path.basename(path.dirname(path.dirname(binary)));
      return Promise.resolve({ version: reported.get(directoryVersion) ?? null, rawOutput: "" });
    }
  );
  assert.equal(selected, null);
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

void test("detects legacy bifrost gitignore entries", () => {
  assert.equal(lifecycle.gitignoreIncludesLegacyBifrostEntry("/.bifrost/\n"), true);
  assert.equal(lifecycle.gitignoreIncludesLegacyBifrostEntry(".bifrost/**\n"), false);
});

void test("distinguishes accepting, declining, and deferring the bifrost gitignore prompt", () => {
  assert.equal(lifecycle.decideBifrostGitignorePrompt("Replace"), "accept");
  assert.equal(
    lifecycle.decideBifrostGitignorePrompt(lifecycle.BIFROST_GITIGNORE_DONT_ASK_AGAIN),
    "decline"
  );
  assert.equal(
    lifecycle.decideBifrostGitignorePrompt(lifecycle.BIFROST_GITIGNORE_ASK_AGAIN_LATER),
    "defer"
  );
  assert.equal(lifecycle.decideBifrostGitignorePrompt(undefined), "defer");
});

void test("does not request migration when the gitignore has no legacy entry", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const gitignorePath = path.join(temp, ".gitignore");
  fs.writeFileSync(gitignorePath, "target\n.bifrost/cache/\n");

  assert.equal(await lifecycle.workspaceGitignoreIncludesLegacyBifrostEntry(temp), false);
});

void test("does not request migration when gitignore is missing", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));

  assert.equal(await lifecycle.workspaceGitignoreIncludesLegacyBifrostEntry(temp), false);
});

void test("classifies and replaces only exact legacy bifrost ignore entries", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  const gitignorePath = path.join(temp, ".gitignore");
  fs.writeFileSync(gitignorePath, "target\r\n /.bifrost/  \r\n!.bifrost/keep\r\n.bifrost/**\r\n");

  assert.equal(await lifecycle.workspaceGitignoreIncludesLegacyBifrostEntry(temp), true);
  await lifecycle.replaceLegacyBifrostGitignoreEntry(temp);

  assert.equal(
    fs.readFileSync(gitignorePath, "utf8"),
    "target\r\n .bifrost/cache/  \r\n!.bifrost/keep\r\n.bifrost/**\r\n"
  );
  assert.equal(await lifecycle.workspaceGitignoreIncludesLegacyBifrostEntry(temp), false);
});

void test("legacy bifrost ignore takes priority over a cache-only entry", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-vscode-test-"));
  fs.writeFileSync(path.join(temp, ".gitignore"), ".bifrost/cache/\n.bifrost/\n");

  assert.equal(await lifecycle.workspaceGitignoreIncludesLegacyBifrostEntry(temp), true);
});

void test("parses bifrost --version output", () => {
  assert.equal(provisioning.parseBifrostVersion("bifrost 0.6.8\n"), "0.6.8");
  assert.equal(provisioning.parseBifrostVersion("bifrost v0.6.8\n"), "0.6.8");
  assert.equal(provisioning.parseBifrostVersion("not bifrost\n"), null);
  assert.equal(provisioning.isVersionCompatible("0.6.8", "v0.6.8"), true);
  const compatibility = {
    binaryVersion: "0.6.8",
    minimumBinaryVersion: "0.6.3",
    allowPrerelease: false
  };
  assert.equal(provisioning.isVersionCompatible("0.6.3", compatibility), true);
  assert.equal(provisioning.isVersionCompatible("0.6.9", compatibility), true);
  assert.equal(provisioning.isVersionCompatible("0.6.2", compatibility), false);
  assert.equal(provisioning.isVersionCompatible("0.7.0", compatibility), false);
  assert.equal(provisioning.isVersionCompatible("0.6.9-rc.1", compatibility), false);
});
