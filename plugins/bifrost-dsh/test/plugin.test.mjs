import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildMcpClientConfig,
  DEFAULT_SERVER_NAME,
  DEFAULT_TOOL_CALL_TIMEOUT_MS,
  DEFAULT_TOOLSETS,
  name as pluginName,
} from "../src/index.js";
import { readCargoVersion } from "../../../scripts/release-version.mjs";

const packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(packageDir, "..", "..");
const manifest = JSON.parse(fs.readFileSync(path.join(packageDir, "package.json"), "utf8"));

// dsh normalizes server names against this budget before hashing overlong ones.
const SERVER_NAME_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;

test("vendored launcher files are byte-identical to plugins/bifrost-agent", () => {
  const pairs = [
    ["plugins/bifrost-agent/bin/bifrost-launcher.mjs", "bin/bifrost-launcher.mjs"],
    ["plugins/bifrost-agent/bifrost-release.json", "bifrost-release.json"],
  ];
  for (const [sourceRelative, targetRelative] of pairs) {
    const source = fs.readFileSync(path.join(repoRoot, sourceRelative));
    const target = fs.readFileSync(path.join(packageDir, targetRelative));
    assert.ok(
      source.equals(target),
      `${targetRelative} differs from ${sourceRelative}; run npm run sync-launcher`,
    );
  }
});

test("package version matches the workspace version in Cargo.toml", () => {
  const cargoVersion = readCargoVersion(
    fs.readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8"),
  );
  assert.equal(manifest.version, cargoVersion);
});

test("manifest declares the dsh bundle contract", () => {
  assert.equal(manifest.name, "@brokkai/dsh-plugin-bifrost");
  assert.deepEqual(manifest.dsh, { bundle: { patch: "./cordis.patch.yml" } });
  assert.ok(manifest.keywords.includes("dsh-plugin"));
  assert.equal(typeof manifest.engines.dsh, "string");
  for (const packaged of ["src", "bin", "bifrost-release.json", "cordis.patch.yml"]) {
    assert.ok(manifest.files.includes(packaged), `files must include ${packaged}`);
  }
});

test("patch row keeps the dsh rename invariant", () => {
  // The row name must match package.json name; the module name is the loader
  // diagnostic identity. Exact-content assertion doubles as a YAML lint.
  const patch = fs.readFileSync(path.join(packageDir, "cordis.patch.yml"), "utf8");
  assert.match(patch, /^- insert:\n {4}- id: bifrost\n {6}name: '@brokkai\/dsh-plugin-bifrost'\n$/m);
  assert.equal(pluginName, "dsh-plugin-bifrost");
});

test("buildMcpClientConfig defaults bind the process working directory", () => {
  const config = buildMcpClientConfig({}, "/plugin/bin/bifrost-launcher.mjs", {}, "/work/project");
  assert.deepEqual(config, {
    transport: "stdio",
    serverName: DEFAULT_SERVER_NAME,
    command: process.execPath,
    args: ["/plugin/bin/bifrost-launcher.mjs", "--root", "/work/project", "--mcp", DEFAULT_TOOLSETS],
    env: {},
    cwd: "/work/project",
    toolCallTimeoutMs: DEFAULT_TOOL_CALL_TIMEOUT_MS,
    failOnStartupError: false,
  });
  assert.match(config.serverName, SERVER_NAME_PATTERN);
  for (const arg of config.args) {
    assert.ok(!arg.includes("${"), `args must not contain host placeholders: ${arg}`);
  }
});

test("buildMcpClientConfig prefers explicit root over environment over cwd", () => {
  const environment = { BIFROST_WORKSPACE_ROOT: "/env/root" };
  const fromEnv = buildMcpClientConfig({}, "/l.mjs", environment, "/cwd");
  assert.equal(fromEnv.cwd, "/env/root");
  assert.deepEqual(fromEnv.args.slice(1, 3), ["--root", "/env/root"]);
  const fromConfig = buildMcpClientConfig({ root: "/explicit" }, "/l.mjs", environment, "/cwd");
  assert.equal(fromConfig.cwd, "/explicit");
  assert.deepEqual(fromConfig.args.slice(1, 3), ["--root", "/explicit"]);
});

test("buildMcpClientConfig applies user overrides", () => {
  const config = buildMcpClientConfig(
    {
      root: "/r",
      toolsets: "symbol",
      serverName: "bifrost_alt",
      env: { BIFROST_BINARY_PATH: "/opt/bifrost" },
      toolCallTimeoutMs: 10_000,
      failOnStartupError: true,
    },
    "/l.mjs",
    {},
    "/cwd",
  );
  assert.deepEqual(config.args, ["/l.mjs", "--root", "/r", "--mcp", "symbol"]);
  assert.equal(config.serverName, "bifrost_alt");
  assert.deepEqual(config.env, { BIFROST_BINARY_PATH: "/opt/bifrost" });
  assert.equal(config.toolCallTimeoutMs, 10_000);
  assert.equal(config.failOnStartupError, true);
});
