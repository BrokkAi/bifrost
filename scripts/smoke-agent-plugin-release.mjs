#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import readline from "node:readline";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const options = parseArgs(process.argv.slice(2));
const pluginDir = await requiredDirectory(options.pluginDir, "plugin-dir");
const workspace = await requiredDirectory(options.workspace, "workspace");
const cacheDir = path.resolve(required(options.cacheDir, "cache-dir"));
await assertEmptyCache(cacheDir);

const launcher = path.join(pluginDir, "bin", "bifrost-launcher.mjs");
await fs.access(launcher);

const launcherEnv = {
  ...process.env,
  BIFROST_BINARY_PATH: "",
  BIFROST_LAUNCHER_ALLOW_PATH: "0",
  BIFROST_LAUNCHER_AUTO_INSTALL: "1",
  BIFROST_LAUNCHER_CACHE_DIR: cacheDir,
};

await prepare(launcher, pluginDir, launcherEnv);
await assertMcpTools(launcher, workspace, launcherEnv);
console.log("Packaged agent plugin prepared and advertised search_symbols over MCP.");

function parseArgs(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error("Usage: smoke-agent-plugin-release.mjs --plugin-dir <dir> --workspace <dir> --cache-dir <empty-dir>");
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

async function assertEmptyCache(directory) {
  try {
    const entries = await fs.readdir(directory);
    if (entries.length > 0) {
      throw new Error(`--cache-dir must be empty to prove a cold install: ${directory}`);
    }
  } catch (error) {
    if (error.code === "ENOENT") {
      await fs.mkdir(directory, { recursive: true });
      return;
    }
    throw error;
  }
}

async function prepare(launcherPath, cwd, env) {
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
  assert.equal(status.source, "installed", "Packaged launcher did not perform a cold managed install");
  assert.match(status.binaryPath ?? "", /bifrost(?:\.exe)?$/);
}

async function assertMcpTools(launcherPath, cwd, env) {
  const child = spawn(process.execPath, [launcherPath, "--root", cwd, "--mcp", "symbol|extended"], {
    cwd,
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stderr = [];
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  const reader = readline.createInterface({ input: child.stdout });

  try {
    await waitForSpawn(child);
    const initialize = await roundTrip(child, reader, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "bifrost-release-smoke", version: "1" },
      },
    });
    assert.ok(initialize.result, "MCP initialize did not return a result");
    writeMessage(child, { jsonrpc: "2.0", method: "notifications/initialized" });
    const toolList = await roundTrip(child, reader, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    const tools = toolList.result?.tools;
    assert.ok(Array.isArray(tools), "MCP tools/list did not return a tools array");
    assert.ok(tools.some((tool) => tool.name === "search_symbols"), "MCP tools/list did not advertise search_symbols");
  } finally {
    reader.close();
    await stop(child);
  }

  if (child.exitCode && child.exitCode !== 0) {
    throw new Error(`Packaged MCP launcher exited with ${child.exitCode}: ${stderr.join("")}`);
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

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  child.kill("SIGTERM");
  await new Promise((resolve) => {
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, 5_000);
    child.once("exit", () => {
      clearTimeout(timeout);
      resolve();
    });
  });
}
