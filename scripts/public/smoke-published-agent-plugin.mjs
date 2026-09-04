#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const SCRIPT_PATH = fileURLToPath(import.meta.url);
const DEFAULT_REPOSITORY = "BrokkAi/bifrost";
const ARCHIVE_NAME = "bifrost-agent-v{version}.tar.gz";
const MCP_PROTOCOL_VERSION = "2025-11-25";

/**
 * Post-release consumer smoke for the published Bifrost agent plugin.
 *
 * This intentionally does not use the checkout's plugin directory. It fetches
 * the release archive, installs the preferred binary into a fresh launcher
 * cache, and invokes MCP through each published host adapter. That catches
 * both stale release metadata/checksums and a host-specific MCP registration
 * failure that package unit tests cannot see.
 */

export function parseArgs(args) {
  const options = {
    repository: DEFAULT_REPOSITORY,
    keepTemp: false,
    archive: null,
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--help" || arg === "-h") {
      options.help = true;
      continue;
    }
    if (arg === "--keep-temp") {
      options.keepTemp = true;
      continue;
    }
    if (arg === "--version" || arg === "--repository" || arg === "--archive") {
      const value = args[++index];
      if (!value || value.startsWith("--")) {
        throw new Error(`${arg} requires a value`);
      }
      if (arg === "--version") options.version = value;
      if (arg === "--repository") options.repository = value;
      if (arg === "--archive") options.archive = value;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }
  return options;
}

export function normalizeVersion(value) {
  const version = String(value ?? "").trim().replace(/^v/u, "");
  assert.match(
    version,
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u,
    "--version must be a valid semver version",
  );
  return version;
}

export function releaseArchiveUrl(repository, version) {
  const normalized = normalizeVersion(version);
  assert.match(repository, /^[^/]+\/[^/]+$/u, "--repository must be OWNER/REPOSITORY");
  return `https://github.com/${repository}/releases/download/v${normalized}/${ARCHIVE_NAME.replace("{version}", normalized)}`;
}

export function mcpLaunchFromPackage(pluginDir, host) {
  const root = path.resolve(pluginDir);
  if (host === "codex") {
    return {
      command: path.join(root, "bin", "bifrost-launcher.mjs"),
      args: ["--mcp", "symbol|extended"],
      cwd: root,
      env: {},
      adapter: path.join(root, ".mcp.json"),
    };
  }
  if (host === "claude") {
    return {
      command: path.join(root, "bin", "bifrost-launcher.mjs"),
      args: ["--mcp", "symbol|extended"],
      cwd: root,
      env: { CLAUDE_PLUGIN_ROOT: root },
      adapter: path.join(root, "claude-mcp.json"),
    };
  }
  throw new Error(`Unsupported host adapter: ${host}`);
}

export async function validatePublishedPackage(pluginDir, expectedVersion) {
  const version = normalizeVersion(expectedVersion);
  const packageManifest = await readJson(path.join(pluginDir, "package.json"));
  const release = await readJson(path.join(pluginDir, "bifrost-release.json"));
  const portable = await readJson(path.join(pluginDir, "plugin.json"));
  const codex = await readJson(path.join(pluginDir, ".codex-plugin", "plugin.json"));
  const claude = await readJson(path.join(pluginDir, ".claude-plugin", "plugin.json"));
  const portableMcp = await readJson(path.join(pluginDir, "mcp.json"));
  const codexMcp = await readJson(path.join(pluginDir, ".mcp.json"));
  const claudeMcp = await readJson(path.join(pluginDir, "claude-mcp.json"));

  for (const [label, actual] of [
    ["package.json", packageManifest.version],
    ["bifrost-release.json", release.binaryVersion],
    ["plugin.json", portable.version],
    [".codex-plugin/plugin.json", codex.version],
    [".claude-plugin/plugin.json", claude.version],
  ]) {
    assert.equal(normalizeVersion(actual), version, `${label} must be for Bifrost ${version}`);
  }
  assert.equal(portable.name, "bifrost", "portable plugin must use the bifrost name");
  assert.equal(codex.name, portable.name, "Codex plugin name must match the portable plugin");
  assert.equal(claude.name, portable.name, "Claude plugin name must match the portable plugin");

  const portableServer = portableMcp.mcpServers?.bifrost;
  assert.equal(portableServer?.command, "./bin/bifrost-launcher.mjs");
  assert.deepEqual(portableServer?.args, ["--mcp", "symbol|extended"]);

  assert.equal(codex.mcpServers, "./.mcp.json", "Codex must select its package adapter");
  const codexServer = codexMcp.mcpServers?.bifrost;
  assert.equal(codexServer?.command, "./bin/bifrost-launcher.mjs");
  assert.equal(codexServer?.cwd, ".");
  assert.deepEqual(codexServer?.args, ["--mcp", "symbol|extended"]);

  assert.equal(claude.mcpServers, "./claude-mcp.json", "Claude must select its package adapter");
  const claudeServer = claudeMcp.mcpServers?.bifrost;
  assert.equal(
    claudeServer?.command,
    "${CLAUDE_PLUGIN_ROOT}/bin/bifrost-launcher.mjs",
    "Claude must resolve its launcher from the installed package root",
  );
  assert.deepEqual(claudeServer?.args, ["--mcp", "symbol|extended"]);

  const launcher = path.join(pluginDir, "bin", "bifrost-launcher.mjs");
  const launcherStat = await fs.stat(launcher);
  assert.ok(launcherStat.isFile(), "published package is missing its launcher");
  return { version, release, packageManifest };
}

export function assertPolicyCatalog(response, host) {
  assert.equal(response.result?.isError, false, `${host} list_policies returned an MCP error`);
  const content = response.result?.structuredContent;
  assert.equal(content?.schema_version, 1, `${host} returned the wrong policy catalog schema`);
  const packs = content?.packs;
  assert.ok(Array.isArray(packs) && packs.length === 2, `${host} returned the wrong policy catalog envelope`);
  const codeSmells = packs.find((pack) => pack.id === "bifrost.code-smells");
  const security = packs.find((pack) => pack.id === "bifrost.security");
  assert.ok(codeSmells, `${host} omitted the bifrost.code-smells pack`);
  assert.ok(security, `${host} omitted the bifrost.security pack`);
  assert.ok(
    Array.isArray(codeSmells.policies) && codeSmells.policies.length > 0,
    `${host} returned no code-smell policies`,
  );
  assert.ok(
    Array.isArray(security.policies) && security.policies.length > 0,
    `${host} returned no security policies`,
  );
  return codeSmells;
}

export function validateMarketplaceManifests(codexMarketplace, claudeMarketplace) {
  assert.equal(codexMarketplace.name, "brokk", "Codex marketplace must use the Brokk owner namespace");
  const codexEntry = codexMarketplace.plugins?.find((plugin) => plugin.name === "bifrost");
  assert.ok(codexEntry, "Codex marketplace does not expose the bifrost plugin");
  assert.deepEqual(
    codexEntry.source,
    { source: "local", path: "./plugins/bifrost-agent" },
    "Codex marketplace must point at the published plugin directory",
  );
  assert.equal(codexEntry.policy?.installation, "AVAILABLE");
  assert.equal(codexEntry.policy?.authentication, "ON_INSTALL");

  assert.equal(claudeMarketplace.name, "brokk", "Claude marketplace must use the Brokk owner namespace");
  const claudeEntry = claudeMarketplace.plugins?.find((plugin) => plugin.name === "bifrost");
  assert.ok(claudeEntry, "Claude marketplace does not expose the bifrost plugin");
  assert.equal(
    claudeEntry.source,
    "./plugins/bifrost-agent",
    "Claude marketplace must point at the published plugin directory",
  );
  return { codex: codexEntry, claude: claudeEntry };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(usage());
    return;
  }
  if (!options.version) {
    throw new Error("Missing required --version; choose the exact release to smoke");
  }
  const version = normalizeVersion(options.version);
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-post-release-smoke-"));
  try {
    const archivePath = path.join(tempRoot, "bifrost-agent.tar.gz");
    const archiveSource = options.archive ?? releaseArchiveUrl(options.repository, version);
    await fetchArchive(archiveSource, archivePath);
    const extractionRoot = path.join(tempRoot, "extracted");
    await fs.mkdir(extractionRoot);
    await execFileAsync("tar", ["-xzf", archivePath, "-C", extractionRoot]);
    const pluginDir = path.join(extractionRoot, "bifrost-agent");
    await validatePublishedPackage(pluginDir, version);
    const [codexMarketplace, claudeMarketplace] = await Promise.all([
      fetchJson(`https://raw.githubusercontent.com/${options.repository}/v${version}/.agents/plugins/marketplace.json`),
      fetchJson(`https://raw.githubusercontent.com/${options.repository}/v${version}/.claude-plugin/marketplace.json`),
    ]);
    validateMarketplaceManifests(codexMarketplace, claudeMarketplace);
    console.log(`Release tag v${version} exposes both Codex and Claude marketplaces.`);

    const cacheDir = path.join(tempRoot, "launcher-cache");
    const launcherEnv = {
      ...process.env,
      BIFROST_LAUNCHER_CACHE_DIR: cacheDir,
      BIFROST_LAUNCHER_ALLOW_PATH: "0",
      BIFROST_LAUNCHER_AUTO_INSTALL: "1",
    };
    const prepared = await runLauncher(pluginDir, ["prepare-preferred", "--json"], launcherEnv);
    assert.equal(prepared.status, "ready", `preferred release preparation failed: ${prepared.message}`);
    assert.equal(normalizeVersion(prepared.preferredVersion), version);
    assert.equal(normalizeVersion(prepared.selectedVersion), version);
    assert.equal(prepared.compatibilityMode, "exact");
    assert.equal(prepared.source, "installed", "clean post-release smoke must install the managed binary");
    assert.ok(prepared.binaryPath, "launcher did not report the installed binary path");

    const doctorEnv = { ...launcherEnv, BIFROST_LAUNCHER_AUTO_INSTALL: "0" };
    const doctor = await runLauncher(pluginDir, ["doctor", "--json"], doctorEnv);
    assert.equal(doctor.status, "ready", `launcher doctor failed: ${doctor.message}`);
    assert.equal(normalizeVersion(doctor.preferredVersion), version);
    assert.equal(normalizeVersion(doctor.selectedVersion), version);
    assert.equal(doctor.compatibilityMode, "exact");
    assert.equal(doctor.source, "managed");
    console.log(`Launcher passed checksum-verified install and doctor for Bifrost ${version}.`);

    const workspace = path.join(tempRoot, "workspace");
    await fs.mkdir(workspace);
    await fs.writeFile(path.join(workspace, "PostReleaseSmoke.java"), "class PostReleaseSmoke {}\n");
    const mcpEnv = {
      ...doctorEnv,
      BIFROST_WORKSPACE_ROOT: workspace,
    };
    for (const host of ["codex", "claude"]) {
      const launch = mcpLaunchFromPackage(pluginDir, host);
      await assertAdapterConfig(launch.adapter, host);
      const response = await callListPolicies(launch, { ...mcpEnv, ...launch.env }, workspace);
      assertPolicyCatalog(response, host);
      console.log(`${host} adapter passed an actual MCP list_policies call.`);
    }
    console.log("Post-release Bifrost agent plugin smoke passed.");
    if (options.keepTemp) {
      console.log(`Kept smoke directory: ${tempRoot}`);
    }
  } finally {
    if (!options.keepTemp) {
      await fs.rm(tempRoot, { recursive: true, force: true });
    }
  }
}

async function fetchArchive(source, destination) {
  if (/^https?:\/\//u.test(source)) {
    console.log(`Downloading published agent plugin: ${source}`);
    const response = await fetch(source, { redirect: "follow" });
    if (!response.ok) {
      throw new Error(`Could not download published agent plugin (${response.status} ${response.statusText}): ${source}`);
    }
    const body = Buffer.from(await response.arrayBuffer());
    if (body.length < 128) {
      throw new Error(`Published agent plugin archive is unexpectedly small (${body.length} bytes)`);
    }
    await fs.writeFile(destination, body);
    return;
  }
  await fs.copyFile(path.resolve(source), destination);
}

async function fetchJson(source) {
  const response = await fetch(source, { redirect: "follow" });
  if (!response.ok) {
    throw new Error(`Could not download published marketplace manifest (${response.status} ${response.statusText}): ${source}`);
  }
  return response.json();
}

async function runLauncher(pluginDir, args, env) {
  const launcher = path.join(pluginDir, "bin", "bifrost-launcher.mjs");
  const { stdout, stderr } = await execFileAsync(process.execPath, [launcher, ...args], {
    cwd: pluginDir,
    env,
    maxBuffer: 1024 * 1024,
  }).catch((error) => {
    throw new Error(
      `Launcher ${args.join(" ")} failed with exit ${error.code ?? "unknown"}: ${error.stderr ?? error.message}`,
      { cause: error },
    );
  });
  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new Error(`Launcher ${args.join(" ")} did not return JSON: ${stdout}\n${stderr}`, { cause: error });
  }
}

async function assertAdapterConfig(adapterPath, host) {
  const config = await readJson(adapterPath);
  const server = config.mcpServers?.bifrost;
  assert.ok(server, `${host} adapter does not define the bifrost MCP server`);
  assert.deepEqual(server.args, ["--mcp", "symbol|extended"]);
  if (host === "codex") {
    assert.equal(server.command, "./bin/bifrost-launcher.mjs");
    assert.equal(server.cwd, ".");
  } else {
    assert.equal(server.command, "${CLAUDE_PLUGIN_ROOT}/bin/bifrost-launcher.mjs");
  }
}

async function callListPolicies(launch, env, workspace) {
  const child = spawn(process.execPath, [launch.command, ...launch.args], {
    cwd: workspace,
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stderr = [];
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  const reader = readline.createInterface({ input: child.stdout });
  const closePromise = new Promise((resolve) => child.once("close", (code, signal) => resolve({ code, signal })));
  try {
    await waitForSpawn(child);
    const initialize = await roundTrip(child, reader, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { roots: { listChanged: true } },
        clientInfo: { name: "bifrost-post-release-smoke", version: "1" },
      },
    });
    assert.ok(initialize.result, "MCP initialize did not return a result");
    writeMessage(child, { jsonrpc: "2.0", method: "notifications/initialized" });
    return await roundTrip(child, reader, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "list_policies", arguments: {} },
    });
  } catch (error) {
    const logs = stderr.join("").trim();
    throw new Error(`${error.message}${logs ? `\nMCP stderr:\n${logs}` : ""}`, { cause: error });
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.stdin.end();
    await Promise.race([closePromise, new Promise((resolve) => setTimeout(resolve, 10_000))]);
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
    reader.close();
  }
}

function waitForSpawn(child) {
  return new Promise((resolve, reject) => {
    child.once("spawn", resolve);
    child.once("error", reject);
  });
}

function writeMessage(child, message) {
  child.stdin.write(`${JSON.stringify(message)}\n`);
}

function roundTrip(child, reader, message) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for MCP ${message.method} response`));
    }, 90_000);
    const onLine = (line) => {
      let response;
      try {
        response = JSON.parse(line);
      } catch (error) {
        cleanup();
        reject(new Error(`MCP emitted non-JSON stdout: ${error.message}`));
        return;
      }
      if (response.id !== message.id) return;
      cleanup();
      if (response.error) {
        reject(new Error(`MCP ${message.method} failed: ${JSON.stringify(response.error)}`));
        return;
      }
      resolve(response);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      clearTimeout(timeout);
      reader.off("line", onLine);
      child.off("error", onError);
    };
    reader.on("line", onLine);
    child.on("error", onError);
    writeMessage(child, message);
  });
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

function usage() {
  return `Usage: node scripts/public/smoke-published-agent-plugin.mjs --version <version> [options]

Downloads the exact published bifrost-agent-v<version>.tar.gz archive, performs
a fresh checksum-verified launcher install, runs doctor, and calls list_policies
through both the Codex and Claude MCP adapters.

Options:
  --version <version>       Required exact release version, for example 0.10.1
  --repository <owner/repo> Published GitHub repository (default: ${DEFAULT_REPOSITORY})
  --archive <path-or-url>   Use a local archive or alternate URL instead of GitHub
  --keep-temp               Keep the isolated download/cache directory for debugging
  --help                    Show this help

Prerequisites: Node.js 22+, network access to the GitHub release and the
published Bifrost binary archive for this platform. The smoke does not mutate
Codex or Claude user configuration and does not require model/API credentials.
`;
}

if (process.argv[1] && path.resolve(process.argv[1]) === SCRIPT_PATH) {
  try {
    await main();
  } catch (error) {
    console.error(`Post-release smoke failed: ${error.message}`);
    process.exitCode = 1;
  }
}
