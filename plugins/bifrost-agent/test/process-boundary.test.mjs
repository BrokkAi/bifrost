import assert from "node:assert/strict";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createSdkSessionClient } from "../extensions/bifrost-session.ts";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(testDir, "fixtures", "fake-mcp-server.mjs");

test("SDK process boundary initializes, discovers, calls, cancels, and cleans up stdio MCP", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-pi-mcp-test-"));
  const recordPath = path.join(temp, "events.jsonl");
  const client = createSdkSessionClient({
    command: process.execPath,
    args: [fixture, "--root", temp, "--mcp", "symbol|extended"],
    cwd: temp,
    env: { ...process.env, BIFROST_FAKE_MCP_RECORD: recordPath },
    source: "explicit",
  });

  try {
    await client.connect();
    const tools = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name), ["fake_lookup", "slow_lookup"]);
    assert.deepEqual(tools[0].inputSchema.required, ["symbol"]);

    const result = await client.callTool("fake_lookup", { symbol: "Widget" }, {
      signal: undefined,
      timeout: 1_000,
    });
    assert.equal(result.content[0].text, "found Widget");
    assert.deepEqual(result.structuredContent, { symbol: "Widget", file: "src/fake.rs" });

    const controller = new AbortController();
    const slowCall = client.callTool("slow_lookup", {}, {
      signal: controller.signal,
      timeout: 5_000,
    });
    await waitForRecord(recordPath, (events) => events.some((event) => event.type === "call" && event.params.name === "slow_lookup"));
    controller.abort();
    await assert.rejects(slowCall, /abort|cancel/i);
    await waitForRecord(recordPath, (events) => events.some((event) => event.type === "cancelled"));
  } finally {
    await client.close();
  }

  const events = await readRecords(recordPath);
  const started = events.find((event) => event.type === "started");
  assert.deepEqual(started.args, ["--root", temp, "--mcp", "symbol|extended"]);
  assert.equal(started.cwd, temp);
  await waitFor(() => !isProcessAlive(started.pid));
});

test("SDK initialization failure cleanup waits for the child process to exit", async () => {
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "bifrost-pi-mcp-failed-init-test-"));
  const recordPath = path.join(temp, "events.jsonl");
  const client = createSdkSessionClient({
    command: process.execPath,
    args: [fixture, "--root", temp, "--mcp", "symbol"],
    cwd: temp,
    env: {
      ...process.env,
      BIFROST_FAKE_MCP_RECORD: recordPath,
      BIFROST_FAKE_MCP_FAIL_INIT: "1",
    },
    source: "explicit",
  });

  try {
    await assert.rejects(client.connect(), /not supported/);
  } finally {
    await client.close();
  }

  const events = await readRecords(recordPath);
  const started = events.find((event) => event.type === "started");
  assert.ok(started, "fake MCP child did not record startup");
  assert.equal(isProcessAlive(started.pid), false);
});

async function readRecords(recordPath) {
  try {
    const text = await fsp.readFile(recordPath, "utf8");
    return text.trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  } catch (error) {
    if (error.code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

async function waitForRecord(recordPath, predicate) {
  await waitFor(async () => predicate(await readRecords(recordPath)));
}

async function waitFor(predicate, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.fail(`condition was not met within ${timeoutMs}ms`);
}

function isProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") {
      return false;
    }
    throw error;
  }
}
