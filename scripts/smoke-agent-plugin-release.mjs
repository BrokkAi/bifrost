#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import { toolInventoryFromMarkdown, unavailableSkillTools } from "./skill-tool-contract.mjs";

const execFileAsync = promisify(execFile);
const codexHandshake = JSON.parse(
  await fs.readFile(
    new URL("../tests/fixtures/mcp/codex-sandbox-state-handshake.json", import.meta.url),
    "utf8"
  )
);
const recordedCodexVersion = validateRecordedCodexHandshake(codexHandshake);
const options = parseArgs(process.argv.slice(2));
const pluginDir = await requiredDirectory(options.pluginDir, "plugin-dir");
const cacheDir = path.resolve(required(options.cacheDir, "cache-dir"));
const binaryPath = options.binaryPath
  ? await requiredFile(options.binaryPath, "binary-path")
  : null;
await assertEmptyCache(cacheDir);

const portableLaunch = await resolvePortablePluginLaunch(pluginDir);
const claudeLaunch = await resolveClaudePluginLaunch(pluginDir);

await smokeLaunch("portable Agent Plugins v1 package", portableLaunch, path.join(cacheDir, "portable"), true);
console.log(
  `Portable Agent Plugins v1 package passed launcher resolution, the recorded Codex ${recordedCodexVersion} ` +
  "handshake replay, and the MCP roots smoke."
);
await smokeLaunch("Claude Code plugin package", claudeLaunch, path.join(cacheDir, "claude"), false);
console.log("Claude Code plugin package passed MCP roots and list_policies smoke.");

async function smokeLaunch(label, launch, launcherCacheDir, includeCodexSandbox) {
  await assertEmptyCache(launcherCacheDir);
  const launcherEnv = {
    ...process.env,
    BIFROST_BINARY_PATH: binaryPath ?? "",
    BIFROST_LAUNCHER_ALLOW_PATH: "0",
    BIFROST_LAUNCHER_AUTO_INSTALL: binaryPath ? "0" : "1",
    BIFROST_LAUNCHER_CACHE_DIR: launcherCacheDir,
    CLAUDE_PLUGIN_ROOT: pluginDir,
  };

  await prepare(launch.command, os.tmpdir(), launcherEnv, binaryPath ? "explicit" : "installed");
  if (includeCodexSandbox) {
    await withDisposableSmokeWorkspace((workspace) =>
      assertCodexSandboxWorkspaceBinding(launch, workspace, launcherEnv)
    );
  }
  await withDisposableSmokeWorkspace((workspace) =>
    assertMcpRootsWorkspaceBinding(launch, workspace, launcherEnv)
  );
  await assertNoPluginWorkspaceCache(pluginDir);
  console.log(`Passed ${label} MCP launch smoke.`);
}

function validateRecordedCodexHandshake(fixture) {
  const version = fixture.initialize?.params?.clientInfo?.version;
  assert.match(version ?? "", /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
  assert.equal(fixture.initialize.params.clientInfo.name, "codex-mcp-client");
  assert.equal(fixture.initialize.params.clientInfo.title, "Codex");
  assert.equal(
    fixture.initialize.params.capabilities?.roots,
    undefined,
    "Recorded Codex handshake must not invent roots support"
  );
  assert.match(fixture.source ?? "", new RegExp(version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  return version;
}

function parseArgs(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error(
        "Usage: smoke-agent-plugin-release.mjs --plugin-dir <dir> --cache-dir <empty-dir> " +
        "[--binary-path <bifrost>]"
      );
    }
    options[key.slice(2).replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase())] = value;
  }
  return options;
}

function required(value, name) {
  if (!value) {
    throw new Error(`Missing required --${name}`);
  }
  return value;
}

async function requiredDirectory(value, name) {
  const directory = path.resolve(required(value, name));
  const stat = await fs.stat(directory);
  if (!stat.isDirectory()) {
    throw new Error(`--${name} must be a directory: ${directory}`);
  }
  return directory;
}

async function requiredFile(value, name) {
  const file = path.resolve(required(value, name));
  const stat = await fs.stat(file);
  if (!stat.isFile()) {
    throw new Error(`--${name} must be a file: ${file}`);
  }
  return file;
}

async function resolvePortablePluginLaunch(pluginRoot) {
  const manifestPath = path.join(pluginRoot, "plugin.json");
  const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
  assert.equal(
    manifest.$schema,
    "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
    `${manifestPath} must use the Agent Plugins v1 plugin schema`
  );
  const mcpConfigPath = path.join(pluginRoot, "mcp.json");
  const mcpConfig = JSON.parse(await fs.readFile(mcpConfigPath, "utf8"));
  assert.equal(
    mcpConfig.$schema,
    "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
    `${mcpConfigPath} must use the Agent Plugins v1 MCP schema`
  );
  const server = mcpConfig.mcpServers?.bifrost;
  assert.ok(server, `${mcpConfigPath} must define the bifrost MCP server`);
  assert.equal(server.type, "stdio", `${mcpConfigPath} must declare stdio transport`);
  assert.equal(
    server.command,
    "./bin/bifrost-launcher.mjs",
    `${mcpConfigPath} must resolve the package-local launcher`
  );
  assert.deepEqual(server.args, ["--mcp", "symbol|extended"]);
  const command = path.resolve(pluginRoot, server.command);
  await fs.access(command);
  return { command, cwd: pluginRoot, args: server.args, manifestPath, mcpConfigPath };
}

async function resolveClaudePluginLaunch(pluginRoot) {
  const manifestPath = path.join(pluginRoot, ".claude-plugin", "plugin.json");
  const mcpConfigPath = path.join(pluginRoot, "claude-mcp.json");
  const mcpConfig = JSON.parse(await fs.readFile(mcpConfigPath, "utf8"));
  const server = mcpConfig.mcpServers?.bifrost;
  assert.ok(server, `${mcpConfigPath} must define the bifrost MCP server`);
  assert.equal(
    server.command,
    "${CLAUDE_PLUGIN_ROOT}/bin/bifrost-launcher.mjs",
    `${mcpConfigPath} must resolve the package-local launcher through Claude's plugin root`
  );
  assert.deepEqual(server.args, ["--mcp", "symbol|extended"]);
  const command = path.join(pluginRoot, "bin", "bifrost-launcher.mjs");
  await fs.access(command);
  return { command, cwd: pluginRoot, args: server.args, manifestPath, mcpConfigPath };
}

async function assertEmptyCache(directory) {
  try {
    const entries = await fs.readdir(directory);
    if (entries.length > 0) {
      throw new Error(`--cache-dir must be empty to keep the launcher smoke isolated: ${directory}`);
    }
  } catch (error) {
    if (error.code === "ENOENT") {
      await fs.mkdir(directory, { recursive: true });
      return;
    }
    throw error;
  }
}

async function withDisposableSmokeWorkspace(scenario) {
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-agent-smoke-workspace-"));
  try {
    await fs.writeFile(
      path.join(workspace, "BifrostReleaseSmoke.java"),
      "public class BifrostReleaseSmokeWorkspace {}\n"
    );
    await fs.writeFile(
      path.join(workspace, "BifrostPolicySmoke.py"),
      "def evaluate_untrusted(value):\n    return eval(value)\n"
    );
    return await scenario(workspace);
  } finally {
    await fs.rm(workspace, { recursive: true, force: true });
  }
}

async function prepare(launcherPath, cwd, env, expectedSource) {
  const { stdout } = await execFileAsync(process.execPath, [launcherPath, "prepare", "--json"], {
    cwd,
    env,
    maxBuffer: 1024 * 1024,
  });
  let status;
  try {
    status = JSON.parse(stdout);
  } catch (error) {
    throw new Error(`Packaged launcher prepare output was not JSON: ${error.message}`);
  }
  assert.equal(status.status, "ready", `Packaged launcher prepare failed: ${status.message ?? "unknown error"}`);
  assert.equal(
    status.source,
    expectedSource,
    expectedSource === "explicit"
      ? "Packaged launcher did not use the requested build artifact"
      : "Packaged launcher did not perform a cold managed install"
  );
  assert.equal(status.autoInstall, expectedSource !== "explicit");
  assert.match(status.binaryPath ?? "", /bifrost(?:\.exe)?$/);
}

async function assertCodexSandboxWorkspaceBinding(codexLaunch, workspaceRoot, env) {
  const canonicalWorkspace = await fs.realpath(workspaceRoot);
  const { logs } = await withMcpServer(codexLaunch, env, async ({ child, reader }) => {
    const serverRequests = [];
    reader.on("line", (line) => {
      try {
        const message = JSON.parse(line);
        if (message.method) {
          serverRequests.push(message.method);
        }
      } catch {
        // The request helpers report malformed protocol output with context.
      }
    });

    const initializeRequest = fixtureMessage("initialize");
    initializeRequest.id = 1;
    const initialize = await roundTrip(child, reader, initializeRequest);
    assert.ok(initialize.result, "MCP initialize did not return a result");
    assert.deepEqual(
      initialize.result.capabilities?.experimental?.["codex/sandbox-state-meta"],
      {},
      "Rootless Bifrost did not advertise Codex sandbox-state metadata"
    );
    writeMessage(child, fixtureMessage("initialized"));
    const toolList = await roundTrip(child, reader, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    const tools = toolList.result?.tools;
    assert.ok(Array.isArray(tools), "MCP tools/list did not return a tools array");
    await assertPortableSkillToolContract(codexLaunch.cwd, tools);
    assert.ok(tools.some((tool) => tool.name === "search_symbols"), "MCP tools/list did not advertise search_symbols");
    assert.ok(tools.some((tool) => tool.name === "get_summaries"), "MCP tools/list did not advertise get_summaries");
    assert.ok(tools.some((tool) => tool.name === "get_symbol_sources"), "MCP tools/list did not advertise get_symbol_sources");
    assert.ok(tools.some((tool) => tool.name === "list_policies"), "MCP tools/list did not advertise list_policies");
    assert.ok(tools.some((tool) => tool.name === "run_policy"), "MCP tools/list did not advertise run_policy");
    const search = await roundTrip(
      child,
      reader,
      codexToolCall(3, workspaceRoot, "bifrost-release-smoke", "BifrostReleaseSmokeWorkspace")
    );
    assert.equal(search.result?.isError, false, `MCP search_symbols returned an error: ${JSON.stringify(search)}`);
    assertWorkspaceSymbolHit(search, "Codex sandbox metadata");
    assert.deepEqual(serverRequests, [], `Codex-shaped handshake unexpectedly requested client roots: ${serverRequests}`);
  });

  assert.match(logs, /workspace_protocol=codex-sandbox-state/);
  assert.ok(
    logs.includes(
      `bound MCP workspace source=codex/sandbox-state-meta root=${canonicalWorkspace} ` +
      "thread_id=bifrost-release-smoke"
    ),
    `Codex bind log did not prove the expected workspace root: ${logs}`
  );
  assert.doesNotMatch(logs, /permissionProfile|writableRoots/);
  await assertWorkspaceCache(workspaceRoot, "Codex sandbox metadata");
}

async function assertMcpRootsWorkspaceBinding(codexLaunch, workspaceRoot, env) {
  const { logs } = await withMcpServer(codexLaunch, env, async ({ child, reader }) => {
    const initialize = await roundTrip(child, reader, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: { roots: { listChanged: true } },
        clientInfo: { name: "bifrost-release-smoke", version: "1" },
      },
    });
    assert.ok(initialize.result, "MCP initialize did not return a result");
    assert.equal(
      initialize.result.capabilities?.experimental?.["codex/sandbox-state-meta"],
      undefined,
      "A roots-capable client must not negotiate Codex metadata binding"
    );
    const searchRequest = {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "search_symbols",
        arguments: { patterns: ["BifrostReleaseSmokeWorkspace"] },
      },
    };
    const rootsRequestPromise = waitForMethod(child, reader, "roots/list");
    writeMessage(child, { jsonrpc: "2.0", method: "notifications/initialized" });
    // RMCP requests roots when a tool call first needs a workspace.
    const searchPromise = roundTrip(child, reader, searchRequest);
    const rootsRequest = await rootsRequestPromise;
    writeMessage(child, {
      jsonrpc: "2.0",
      id: rootsRequest.id,
      result: {
        roots: [{ uri: pathToFileURL(workspaceRoot).href, name: "release-smoke-workspace" }],
      },
    });
    const search = await searchPromise;
    assert.equal(search.result?.isError, false, `MCP roots search_symbols returned an error: ${JSON.stringify(search)}`);
    assertWorkspaceSymbolHit(search, "MCP roots");
    const catalog = await roundTrip(child, reader, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "list_policies", arguments: {} },
    });
    assert.equal(catalog.result?.isError, false, `MCP list_policies returned an error: ${JSON.stringify(catalog)}`);
    assert.equal(catalog.result?.structuredContent?.id, "bifrost.code-smells");
    const policies = catalog.result?.structuredContent?.policies;
    assert.ok(Array.isArray(policies) && policies.length > 0, "MCP list_policies returned no built-in policies");
    const policyIds = policies.map((entry) => entry.id);
    assert.equal(new Set(policyIds).size, policyIds.length, "MCP list_policies returned duplicate policy IDs");
    assert.ok(
      policyIds.includes("bifrost.correctness.dynamic-evaluation"),
      `MCP list_policies omitted the policy exercised by this smoke: ${JSON.stringify(policyIds)}`
    );
    const policy = await roundTrip(child, reader, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "run_policy",
        arguments: {
          policy_ids: ["bifrost.correctness.dynamic-evaluation"],
          evaluation_date: "2026-07-28",
          fail_on: "never",
        },
      },
    });
    assert.equal(policy.result?.isError, false, `MCP built-in policy run returned an error: ${JSON.stringify(policy)}`);
    assert.equal(policy.result?.structuredContent?.status, "clean");
    assert.equal(
      policy.result?.structuredContent?.report?.runs?.[0]?.findings?.[0]?.primary?.path,
      "BifrostPolicySmoke.py"
    );
  });

  assert.match(logs, /source=roots\/list/);
  await assertWorkspaceCache(workspaceRoot, "MCP roots");
}

function assertWorkspaceSymbolHit(response, scenario) {
  const files = response.result?.structuredContent?.files;
  assert.ok(Array.isArray(files) && files.length > 0, `${scenario} search returned no files`);
  const fixtureFile = files.find((file) => file.path === "BifrostReleaseSmoke.java");
  assert.ok(fixtureFile, `${scenario} search did not return the disposable workspace file`);
  assert.ok(
    fixtureFile.classes?.some((hit) => hit.symbol === "BifrostReleaseSmokeWorkspace"),
    `${scenario} search did not return the disposable workspace symbol`
  );
}

async function assertWorkspaceCache(workspaceRoot, scenario) {
  // The store file carries the schema version that wrote it
  // (`bifrost_cache.v<N>.db`), so match the family rather than one name.
  const cacheDir = analyzerCacheDir(workspaceRoot);
  const entries = await fs.readdir(cacheDir).catch((error) => {
    throw new Error(`${scenario} did not keep analyzer storage in the bound disposable workspace`, {
      cause: error,
    });
  });
  const stores = entries.filter((entry) => /^bifrost_cache\.v\d+\.db$/.test(entry));
  assert.ok(
    stores.length > 0,
    `${scenario} did not keep analyzer storage in the bound disposable workspace; ${cacheDir} holds ${JSON.stringify(entries)}`
  );
}

function analyzerCacheDir(workspaceRoot) {
  return path.join(workspaceRoot, ".bifrost", "cache");
}

function fixtureMessage(name) {
  assert.ok(codexHandshake[name], `Recorded Codex handshake is missing ${name}`);
  return structuredClone(codexHandshake[name]);
}

function codexToolCall(id, workspaceRoot, threadId, pattern) {
  const message = fixtureMessage("toolCall");
  const sandboxCwd = pathToFileURL(workspaceRoot).href;
  const metadata = message.params?._meta;
  const sandboxState = metadata?.["codex/sandbox-state-meta"];
  assert.ok(sandboxState, "Recorded Codex tool call is missing sandbox-state metadata");
  assert.deepEqual(
    message.params?.arguments?.patterns,
    ["__BIFROST_SYMBOL_PATTERN__"],
    "Recorded Codex tool call search arguments drifted"
  );
  assert.equal(metadata.threadId, "__BIFROST_THREAD_ID__", "Recorded Codex thread id placeholder drifted");
  assert.equal(
    sandboxState.sandboxCwd,
    "__BIFROST_SANDBOX_CWD__",
    "Recorded Codex sandbox cwd placeholder drifted"
  );
  assert.deepEqual(
    sandboxState.permissionProfile?.writableRoots,
    ["__BIFROST_SANDBOX_CWD__"],
    "Recorded Codex writable roots placeholder drifted"
  );
  message.id = id;
  message.params.arguments = { patterns: [pattern] };
  metadata.threadId = threadId;
  sandboxState.sandboxCwd = sandboxCwd;
  if (Array.isArray(sandboxState.permissionProfile?.writableRoots)) {
    sandboxState.permissionProfile.writableRoots = [sandboxCwd];
  }
  return message;
}

async function assertNoPluginWorkspaceCache(pluginCwd) {
  await assert.rejects(
    fs.readdir(analyzerCacheDir(pluginCwd)),
    { code: "ENOENT" },
    "Packaged MCP launch wrote analyzer storage under the plugin directory"
  );
}

async function assertPortableSkillToolContract(pluginRoot, tools) {
  const advertisedToolNames = new Set(tools.map((tool) => tool.name));
  const skillsRoot = path.join(pluginRoot, "skills");
  const skillDirectories = (await fs.readdir(skillsRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  assert.ok(skillDirectories.length > 0, `Packaged plugin has no portable skills under ${skillsRoot}`);

  const skillContracts = [];
  for (const skillDirectory of skillDirectories) {
    const skillPath = path.join(skillsRoot, skillDirectory, "SKILL.md");
    const skill = await fs.readFile(skillPath, "utf8");
    const skillToolNames = toolInventoryFromMarkdown(skill);
    skillContracts.push({ skillPath, skillToolNames });
  }

  const missingInventories = skillContracts
    .filter(({ skillToolNames }) => skillToolNames.length === 0)
    .map(({ skillPath }) => skillPath);
  assert.deepEqual(
    missingInventories,
    [],
    `Portable skills must declare Bifrost MCP tools in a Markdown table with a Tool column: ${JSON.stringify(missingInventories)}`
  );

  const unavailableReferences = skillContracts.flatMap(({ skillPath, skillToolNames }) =>
    unavailableSkillTools(skillToolNames, advertisedToolNames).map((toolName) => ({ skillPath, toolName }))
  );
  assert.deepEqual(
    unavailableReferences,
    [],
    `Portable skills advertise tools absent from the packaged MCP server: ${JSON.stringify(unavailableReferences)}`
  );
}

async function withMcpServer(codexLaunch, env, scenario) {
  const child = spawn(process.execPath, [codexLaunch.command, ...codexLaunch.args], {
    cwd: codexLaunch.cwd,
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stderr = [];
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  const reader = readline.createInterface({ input: child.stdout });
  const closePromise = new Promise((resolve) => {
    child.once("close", (code, signal) => resolve({ code, signal }));
  });

  let value;
  let scenarioError;
  try {
    await waitForSpawn(child);
    value = await scenario({ child, reader });
  } catch (error) {
    scenarioError = error;
  }

  let shutdown;
  let shutdownError;
  try {
    shutdown = await stop(child, closePromise);
  } catch (error) {
    shutdownError = error;
  } finally {
    reader.close();
  }
  const logs = stderr.join("");
  const failure = scenarioError ?? shutdownError;
  if (failure) {
    const diagnosticLogs = logs.trim() ? `\nMCP stderr:\n${logs.trimEnd()}` : "";
    throw new Error(
      `${failure.message}\nPlugin manifest: ${codexLaunch.manifestPath}\nMCP config: ${codexLaunch.mcpConfigPath}${diagnosticLogs}`,
      { cause: failure }
    );
  }
  if (!shutdown.forcedSignal && (shutdown.code !== 0 || shutdown.signal)) {
    throw new Error(
      `Packaged plugin MCP launcher exited with ${shutdown.signal ?? shutdown.code}; ` +
      `manifest=${codexLaunch.manifestPath}; config=${codexLaunch.mcpConfigPath}: ${logs}`
    );
  }
  return { value, logs };
}

function waitForMethod(child, reader, method) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for MCP server request ${method}`));
    }, 90_000);
    const onLine = (line) => {
      let message;
      try {
        message = JSON.parse(line);
      } catch (error) {
        cleanup();
        reject(new Error(`MCP emitted non-JSON stdout: ${error.message}`));
        return;
      }
      if (message.method !== method) {
        return;
      }
      cleanup();
      resolve(message);
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
  });
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
      reject(new Error(`Timed out waiting for MCP response to ${message.method}`));
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
      if (response.id !== message.id) {
        return;
      }
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

async function stop(child, closePromise) {
  if (child.exitCode === null && child.signalCode === null && !child.stdin.writableEnded) {
    child.stdin.end();
  }
  let closed = await waitForClose(closePromise, 10_000);
  if (closed) {
    return { ...closed, forcedSignal: null };
  }

  const termSent = child.kill("SIGTERM");
  closed = await waitForClose(closePromise, 7_000);
  if (closed) {
    return { ...closed, forcedSignal: termSent ? "SIGTERM" : null };
  }

  const killSent = child.kill("SIGKILL");
  closed = await waitForClose(closePromise, 5_000);
  if (!closed) {
    throw new Error("Packaged MCP launcher did not close after SIGKILL");
  }
  return { ...closed, forcedSignal: killSent ? "SIGKILL" : null };
}

function waitForClose(closePromise, timeoutMs) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), timeoutMs);
    closePromise.then((result) => {
      clearTimeout(timeout);
      resolve(result);
    });
  });
}
