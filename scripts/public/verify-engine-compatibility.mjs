#!/usr/bin/env node

// The engine ships MCP; #2771 moved LSP to a separate host. Verify the shipped
// transport and the deliberate legacy diagnostic before staging its archive.
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";

import { roundTrip, waitForSpawn, writeMessage } from "./mcp-smoke-transport.mjs";

const [binaryArgument, versionOption, engineVersion, ...extra] = process.argv.slice(2);
assert.ok(binaryArgument && engineVersion && versionOption === "--engine-version" && extra.length === 0,
  "Usage: verify-engine-compatibility.mjs BINARY --engine-version VERSION");
const binary = path.resolve(binaryArgument);
const version = execFileSync(binary, ["--version"], { encoding: "utf8", timeout: 30_000 });
assert.equal(version.match(/^bifrost (\S+)(?:\s|$)/u)?.[1], engineVersion);

for (const arguments_ of [["--lsp"], ["--server", "lsp"]]) {
  const result = spawnSync(binary, arguments_, { encoding: "utf8", timeout: 30_000 });
  if (result.error) throw result.error;
  assert.equal(result.status, 1, `${arguments_.join(" ")}: ${result.stderr}`);
  assert.equal(result.stdout, "", "Legacy LSP flags must not emit a protocol response");
  assert.match(result.stderr, /the LSP server has moved out of this repository/u);
}

const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-engine-compatibility-"));
const child = spawn(binary, ["--mcp", "symbol"], {
  cwd: workspace,
  stdio: ["pipe", "pipe", "pipe"],
});
const stderr = [];
child.stderr.on("data", (chunk) => stderr.push(chunk.toString()));
const reader = readline.createInterface({ input: child.stdout });
try {
  await waitForSpawn(child);
  // This revision is covered by the engine's real-process wire contract,
  // rather than merely being a revision accepted by the underlying SDK.
  const protocolVersion = "2025-11-25";
  const response = await roundTrip(child, reader, {
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: {
      protocolVersion, capabilities: {},
      clientInfo: { name: "bifrost-release-compatibility", version: engineVersion },
    },
  });
  assert.equal(response.result?.protocolVersion, protocolVersion);
  assert.equal(response.result?.serverInfo?.name, "bifrost");
  assert.equal(response.result?.serverInfo?.version, engineVersion);
  assert.ok(response.result?.capabilities?.tools, "MCP must advertise its tools interface");
  writeMessage(child, { jsonrpc: "2.0", method: "notifications/initialized" });
  const inventory = await roundTrip(child, reader, {
    jsonrpc: "2.0", id: 2, method: "tools/list", params: {},
  });
  assert.ok(inventory.result?.tools?.some((tool) => tool.name === "search_symbols"),
    "The shipped symbol toolset must expose search_symbols");
} catch (error) {
  throw new Error(`${error.message}\nMCP stderr:\n${stderr.join("")}`, { cause: error });
} finally {
  const exited = child.exitCode !== null || child.signalCode !== null;
  const closed = exited ? null : once(child, "close");
  const killTimeout = exited ? null : setTimeout(() => child.kill("SIGKILL"), 30_000);
  if (!exited) child.kill();
  if (closed) await closed;
  if (killTimeout) clearTimeout(killTimeout);
  reader.close();
  await fs.rm(workspace, { recursive: true, force: true });
}
console.log(`Verified Bifrost MCP compatibility with engine ${engineVersion} and legacy LSP diagnostics.`);
