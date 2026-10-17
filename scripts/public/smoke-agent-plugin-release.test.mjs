import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);
const smokeScript = fileURLToPath(new URL("./smoke-agent-plugin-release.mjs", import.meta.url));
const fakeLauncher = `#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
if (args[0] === "prepare") {
  if (args[1] !== "--json") process.exit(2);
  process.stdout.write(JSON.stringify({
    status: "ready",
    source: "explicit",
    autoInstall: false,
    binaryPath: process.env.BIFROST_BINARY_PATH,
  }) + "\\n");
  process.exit(0);
}
if (args[0] !== "--mcp" || args[1] !== "symbol|extended") process.exit(2);

function record(event) {
  fs.appendFileSync(process.env.BIFROST_SMOKE_TRACE, JSON.stringify({
    ...event,
    pid: process.pid,
  }) + "\\n");
}
function send(message) {
  process.stdout.write(JSON.stringify(message) + "\\n");
}

record({
  type: "mcp-start",
  offline: process.env.BIFROST_OPEN_PACKS_OFFLINE,
  policyPackRoot: process.env.BIFROST_OPEN_POLICY_PACK_ROOT ?? null,
});

const reader = readline.createInterface({ input: process.stdin });
let rootsSupported = false;
let workspaceRoot;
let workspaceSource;
let pendingSearch;
const rootsRequestId = "fake-roots-" + process.pid;

function respondSearch(request) {
  const cacheDir = path.join(workspaceRoot, ".bifrost", "cache");
  fs.mkdirSync(cacheDir, { recursive: true });
  fs.writeFileSync(path.join(cacheDir, "bifrost_cache.v1.db"), "fake analyzer cache");
  record({ type: "workspace-bound", source: workspaceSource });
  send({
    jsonrpc: "2.0",
    id: request.id,
    result: {
      isError: false,
      structuredContent: {
        files: [{
          path: "BifrostReleaseSmoke.java",
          classes: [{ symbol: "BifrostReleaseSmokeWorkspace" }],
        }],
      },
    },
  });
}

reader.on("line", (line) => {
  const message = JSON.parse(line);
  if (message.id === rootsRequestId && message.result) {
    workspaceRoot = fileURLToPath(message.result.roots[0].uri);
    workspaceSource = "roots/list";
    process.stderr.write(
      "workspace_protocol=roots-list\\n" +
      "bound MCP workspace source=roots/list root=" + workspaceRoot + "\\n"
    );
    respondSearch(pendingSearch);
    pendingSearch = undefined;
    return;
  }

  if (message.method === "initialize") {
    rootsSupported = Boolean(message.params?.capabilities?.roots);
    record({
      type: "initialize",
      mode: rootsSupported ? "roots" : "codex-sandbox-state",
      hasSandboxState: Boolean(message.params?._meta?.["codex/sandbox-state-meta"]),
    });
    const capabilities = { tools: {} };
    if (!rootsSupported) {
      capabilities.experimental = { "codex/sandbox-state-meta": {} };
    }
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        protocolVersion: message.params.protocolVersion,
        capabilities,
        serverInfo: { name: "bifrost-test-fake", version: "1" },
      },
    });
    return;
  }

  if (message.method === "notifications/initialized") return;

  if (message.method === "tools/list") {
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        tools: [
          "search_symbols",
          "get_summaries",
          "get_symbol_sources",
          "list_policies",
          "run_policy",
        ].map((name) => ({ name })),
      },
    });
    return;
  }

  if (message.method !== "tools/call") return;
  const name = message.params.name;
  const arguments_ = message.params.arguments ?? {};
  record({ type: "tool-call", name, arguments: arguments_ });

  if (name === "search_symbols") {
    if (rootsSupported) {
      pendingSearch = message;
      send({
        jsonrpc: "2.0",
        id: rootsRequestId,
        method: "roots/list",
        params: {},
      });
    } else {
      const sandboxState = message.params?._meta?.["codex/sandbox-state-meta"];
      if (!sandboxState?.sandboxCwd) {
        throw new Error("Codex search_symbols call is missing sandbox-state metadata");
      }
      workspaceRoot = fileURLToPath(sandboxState.sandboxCwd);
      workspaceSource = "codex/sandbox-state-meta";
      record({
        type: "codex-sandbox-binding",
        threadId: message.params._meta.threadId,
        sandboxCwd: sandboxState.sandboxCwd,
        writableRoots: sandboxState.permissionProfile?.writableRoots,
      });
      process.stderr.write(
        "workspace_protocol=codex-sandbox-state\\n" +
        "bound MCP workspace source=codex/sandbox-state-meta root=" + fs.realpathSync(workspaceRoot) +
        " thread_id=" + message.params._meta.threadId + "\\n"
      );
      respondSearch(message);
    }
    return;
  }

  if (name === "list_policies") {
    const packs = process.env.BIFROST_FAKE_MODE === "nonempty-catalog"
      ? [{ id: "bifrost.code-smells", policies: [{ id: "bifrost.code-smells.example" }] }]
      : [];
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: { isError: false, structuredContent: { schema_version: 2, packs } },
    });
    return;
  }

  if (name === "run_policy" && Array.isArray(arguments_.policy_ids)) {
    if (process.env.BIFROST_FAKE_MODE === "accept-absent-selector") {
      send({
        jsonrpc: "2.0",
        id: message.id,
        result: { isError: false, structuredContent: { report: { runs: [] } } },
      });
      return;
    }
    send({
      jsonrpc: "2.0",
      id: message.id,
      error: {
        code: -32602,
        message: "unknown built-in policy id: bifrost.correctness.dynamic-evaluation",
      },
    });
    return;
  }

  if (name === "run_policy" && Array.isArray(arguments_.policy_files)) {
    const policyPath = path.join(workspaceRoot, arguments_.policy_files[0]);
    const policy = fs.readFileSync(policyPath, "utf8");
    const fixture = fs.readFileSync(path.join(workspaceRoot, "BifrostPolicySmoke.py"), "utf8");
    const policyIdPresent = policy.includes("host.smoke.dynamic-evaluation");
    const fixtureHasEval = fixture.includes("eval(value)");
    if (!policyIdPresent || !fixtureHasEval) {
      throw new Error("host policy smoke did not receive its rule and planted fixture");
    }
    const findings = process.env.BIFROST_FAKE_MODE === "missing-positive-finding"
      ? []
      : [{ primary: { path: "BifrostPolicySmoke.py" } }];
    record({
      type: "host-policy-positive",
      policyFile: arguments_.policy_files[0],
      policyIdPresent,
      fixtureHasEval,
      findingPath: "BifrostPolicySmoke.py",
    });
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        isError: false,
        structuredContent: {
          report: {
            runs: [{ findings }],
          },
        },
      },
    });
  }
});
`;

test("release smoke exercises empty-core policy behavior through every packaged adapter", {
}, async () => {
  const { stdout, tracePath, tempRoot, error } = await runSmoke("normal");
  try {
    assert.equal(error, undefined, error?.stderr ?? error?.message);
    assert.match(stdout, /Claude Code plugin package passed MCP roots and list_policies smoke/u);
    const events = (await fs.readFile(tracePath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const sessions = events.filter((event) => event.type === "mcp-start");
    assert.equal(sessions.length, 5, "expected sandbox and roots sessions for portable and Codex, plus Claude roots");
    assert.ok(
      sessions.every((session) => session.offline === "1" && session.policyPackRoot === null),
      "every plugin MCP process must exercise the isolated offline core",
    );

    const initializations = events.filter((event) => event.type === "initialize");
    assert.deepEqual(
      initializations.map((event) => event.mode),
      ["codex-sandbox-state", "roots", "codex-sandbox-state", "roots", "roots"],
    );
    assert.equal(initializations.filter((event) => event.hasSandboxState).length, 0);

    const rootsSessions = new Set(
      initializations.filter((event) => event.mode === "roots").map((event) => event.pid),
    );
    for (const pid of rootsSessions) {
      const calls = events.filter((event) => event.type === "tool-call" && event.pid === pid);
      assert.deepEqual(calls.map((event) => event.name), [
        "search_symbols",
        "list_policies",
        "run_policy",
        "run_policy",
      ]);
      assert.deepEqual(calls[1].arguments, {});
      assert.deepEqual(calls[2].arguments.policy_ids, ["bifrost.correctness.dynamic-evaluation"]);
      assert.deepEqual(calls[3].arguments.policy_files, ["host-smoke.rqlp"]);
    }

    const hostPolicyRuns = events.filter((event) => event.type === "host-policy-positive");
    assert.equal(hostPolicyRuns.length, 3);
    assert.ok(hostPolicyRuns.every((event) =>
      event.policyFile === "host-smoke.rqlp" &&
      event.policyIdPresent &&
      event.fixtureHasEval &&
      event.findingPath === "BifrostPolicySmoke.py"
    ));
    const workspaceBindings = events.filter((event) => event.type === "workspace-bound");
    assert.equal(workspaceBindings.length, 5);
    assert.equal(workspaceBindings.filter((event) => event.source === "codex/sandbox-state-meta").length, 2);
    assert.equal(workspaceBindings.filter((event) => event.source === "roots/list").length, 3);
    const codexBindings = events.filter((event) => event.type === "codex-sandbox-binding");
    assert.equal(codexBindings.length, 2);
    assert.ok(codexBindings.every((event) =>
      event.threadId === "bifrost-release-smoke" &&
      event.sandboxCwd.startsWith("file:") &&
      JSON.stringify(event.writableRoots) === JSON.stringify([event.sandboxCwd])
    ));
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
});

test("release smoke rejects catalog, selector, and host-policy contract regressions", async (t) => {
  const cases = [
    ["nonempty-catalog", /core MCP implicitly supplied product rules/u],
    ["accept-absent-selector", /Missing expected rejection/u],
    ["missing-positive-finding", /BifrostPolicySmoke\.py/u],
  ];
  for (const [mode, expectedError] of cases) {
    await t.test(mode, async () => {
      const result = await runSmoke(mode);
      try {
        assert.ok(result.error, `smoke unexpectedly accepted fake mode ${mode}: ${result.stdout}`);
        assert.match(result.error.stderr ?? result.error.message, expectedError);
      } finally {
        await fs.rm(result.tempRoot, { recursive: true, force: true });
      }
    });
  }
});

async function runSmoke(mode) {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-agent-release-smoke-test-"));
  try {
    const pluginDir = path.join(tempRoot, "plugin");
    const tracePath = path.join(tempRoot, "mcp-trace.jsonl");
    const inheritedPackRoot = path.join(tempRoot, "inherited-packs");
    const cacheDir = path.join(tempRoot, "launcher-cache");
    const binaryPath = path.join(tempRoot, `bifrost${process.platform === "win32" ? ".exe" : ""}`);
    await writePluginFixture(pluginDir);
    await fs.mkdir(inheritedPackRoot);
    try {
      await fs.link(process.execPath, binaryPath);
    } catch (error) {
      if (!new Set(["EXDEV", "EPERM", "EACCES"]).has(error.code)) throw error;
      await fs.copyFile(process.execPath, binaryPath);
    }

    let stdout;
    let error;
    try {
      ({ stdout } = await execute(process.execPath, [
        smokeScript,
        "--plugin-dir", pluginDir,
        "--cache-dir", cacheDir,
        "--binary-path", binaryPath,
      ], {
        env: {
          ...process.env,
          BIFROST_SMOKE_TRACE: tracePath,
          BIFROST_OPEN_POLICY_PACK_ROOT: inheritedPackRoot,
          BIFROST_OPEN_PACKS_OFFLINE: "0",
          BIFROST_FAKE_MODE: mode,
        },
        timeout: 60_000,
        maxBuffer: 4 * 1024 * 1024,
      }));
    } catch (caught) {
      error = caught;
    }

    return { stdout, tracePath, tempRoot, error };
  } catch (error) {
    await fs.rm(tempRoot, { recursive: true, force: true });
    throw error;
  }
}

async function writePluginFixture(pluginDir) {
  await fs.mkdir(path.join(pluginDir, "bin"), { recursive: true });
  await fs.mkdir(path.join(pluginDir, "skills", "smoke"), { recursive: true });
  await fs.mkdir(path.join(pluginDir, ".codex-plugin"), { recursive: true });
  await fs.mkdir(path.join(pluginDir, ".claude-plugin"), { recursive: true });
  await fs.writeFile(path.join(pluginDir, "bin", "bifrost-launcher.mjs"), fakeLauncher);
  await fs.chmod(path.join(pluginDir, "bin", "bifrost-launcher.mjs"), 0o755);
  await writeJson(path.join(pluginDir, "plugin.json"), {
    $schema: "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
    name: "bifrost",
  });
  await writeJson(path.join(pluginDir, "mcp.json"), {
    $schema: "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
    mcpServers: {
      bifrost: {
        type: "stdio",
        command: "./bin/bifrost-launcher.mjs",
        args: ["--mcp", "symbol|extended"],
      },
    },
  });
  await writeJson(path.join(pluginDir, ".codex-plugin", "plugin.json"), {
    name: "bifrost",
    mcpServers: "./.mcp.json",
  });
  await writeJson(path.join(pluginDir, ".mcp.json"), {
    mcpServers: {
      bifrost: {
        command: "./bin/bifrost-launcher.mjs",
        cwd: ".",
        args: ["--mcp", "symbol|extended"],
        startup_timeout_sec: 180,
        tool_timeout_sec: 300,
      },
    },
  });
  await writeJson(path.join(pluginDir, ".claude-plugin", "plugin.json"), {
    name: "bifrost",
  });
  await writeJson(path.join(pluginDir, "claude-mcp.json"), {
    mcpServers: {
      bifrost: {
        command: "${CLAUDE_PLUGIN_ROOT}/bin/bifrost-launcher.mjs",
        args: ["--mcp", "symbol|extended"],
      },
    },
  });
  await fs.writeFile(path.join(pluginDir, "skills", "smoke", "SKILL.md"), [
    "| Tool | Purpose |",
    "| --- | --- |",
    "| `search_symbols` | Search symbols. |",
    "| `get_summaries` | Read summaries. |",
    "| `get_symbol_sources` | Read source. |",
    "| `list_policies` | List policies. |",
    "| `run_policy` | Run policies. |",
    "",
  ].join("\n"));
}

async function writeJson(filePath, value) {
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`);
}
