import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  assertPolicyCatalog,
  mcpLaunchFromPackage,
  normalizeVersion,
  parseArgs,
  releaseArchiveUrl,
  validateMarketplaceManifests,
  validatePublishedPackage,
} from "./smoke-published-agent-plugin.mjs";

const packageDir = path.resolve("plugins/bifrost-agent");
const packageManifest = JSON.parse(await fs.readFile(path.join(packageDir, "package.json"), "utf8"));

test("requires an exact release version and builds the canonical archive URL", () => {
  assert.equal(normalizeVersion("v0.10.1"), "0.10.1");
  assert.equal(
    releaseArchiveUrl("BrokkAi/bifrost", "0.10.1"),
    "https://github.com/BrokkAi/bifrost/releases/download/v0.10.1/bifrost-agent-v0.10.1.tar.gz",
  );
  assert.throws(() => normalizeVersion("latest"), /valid semver/u);
  assert.throws(() => releaseArchiveUrl("BrokkAi", "0.10.1"), /OWNER\/REPOSITORY/u);
});

test("parses only the safe post-release smoke options", () => {
  assert.deepEqual(parseArgs(["--version", "0.10.1", "--keep-temp"]), {
    repository: "BrokkAi/bifrost",
    keepTemp: true,
    archive: null,
    version: "0.10.1",
  });
  assert.throws(() => parseArgs(["--version"]), /requires a value/u);
  assert.throws(() => parseArgs(["--unknown"]), /Unknown argument/u);
});

test("validates the checked-in package layout without a network or host", async () => {
  const result = await validatePublishedPackage(packageDir, packageManifest.version);
  assert.equal(result.version, packageManifest.version);
  assert.deepEqual(mcpLaunchFromPackage(packageDir, "codex").args, ["--mcp", "symbol|extended"]);
  assert.equal(
    mcpLaunchFromPackage(packageDir, "claude").env.CLAUDE_PLUGIN_ROOT,
    packageDir,
  );
});

test("rejects a Codex adapter that silently falls back to the package cwd", async () => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-post-release-contract-"));
  try {
    const fixture = path.join(tempRoot, "bifrost-agent");
    await fs.cp(packageDir, fixture, { recursive: true });
    const mcpPath = path.join(fixture, ".mcp.json");
    const mcp = JSON.parse(await fs.readFile(mcpPath, "utf8"));
    mcp.mcpServers.bifrost.cwd = "..";
    await fs.writeFile(mcpPath, `${JSON.stringify(mcp, null, 2)}\n`);
    await assert.rejects(
      validatePublishedPackage(fixture, packageManifest.version),
      /expected values|must|cwd/iu,
    );
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
});

test("requires the policy pack and at least one policy from a successful MCP call", () => {
  const response = {
    result: {
      isError: false,
      structuredContent: {
        id: "bifrost.code-smells",
        policies: [{ id: "bifrost.correctness.dynamic-evaluation" }],
      },
    },
  };
  assert.equal(assertPolicyCatalog(response, "Codex").id, "bifrost.code-smells");
  assert.throws(
    () => assertPolicyCatalog({ result: { isError: true } }, "Claude"),
    /MCP error/u,
  );
  assert.throws(
    () => assertPolicyCatalog({ result: { isError: false, structuredContent: { id: "bifrost.code-smells", policies: [] } } }, "Claude"),
    /no policies/u,
  );
});

test("requires both release-tag marketplace entries to point at the package", () => {
  const codex = {
    plugins: [
      {
        name: "brokk",
        source: { source: "local", path: "./plugins/bifrost-agent" },
        policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
      },
    ],
  };
  const claude = { plugins: [{ name: "brokk", source: "./plugins/bifrost-agent" }] };
  assert.deepEqual(validateMarketplaceManifests(codex, claude).claude.source, "./plugins/bifrost-agent");
  assert.throws(
    () => validateMarketplaceManifests({ plugins: [] }, claude),
    /Codex marketplace/u,
  );
  assert.throws(
    () => validateMarketplaceManifests(codex, { plugins: [{ name: "brokk", source: "./wrong" }] }),
    /Claude marketplace/u,
  );
});
