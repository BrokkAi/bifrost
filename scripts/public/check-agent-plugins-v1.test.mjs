import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { validateAgentPluginDirectory } from "./check-agent-plugins-v1.mjs";

const version = "1.2.3";

test("validates the portable package and keeps Cursor settings in its adapter", async () => {
  await withFixture(async (pluginDir) => {
    const result = validateAgentPluginDirectory(pluginDir, version);
    assert.deepEqual(result, { name: "bifrost", version, skills: ["sample"] });
  });
});

test("accepts an MCP-only portable package", async () => {
  await withFixture(async (pluginDir) => {
    await fs.rm(path.join(pluginDir, "skills"), { recursive: true });
    const result = validateAgentPluginDirectory(pluginDir, version);
    assert.deepEqual(result, { name: "bifrost", version, skills: [] });
  });
});

test("rejects host-specific settings in the portable MCP file", async () => {
  await withFixture(async (pluginDir) => {
    const mcpPath = path.join(pluginDir, "mcp.json");
    const mcp = JSON.parse(await fs.readFile(mcpPath, "utf8"));
    mcp.mcpServers.bifrost.startup_timeout_sec = 180;
    await fs.writeFile(mcpPath, `${JSON.stringify(mcp, null, 2)}\n`);
    assert.throws(
      () => validateAgentPluginDirectory(pluginDir, version),
      /must not contain host-specific MCP settings/,
    );
  });
});

test("rejects an unknown portable manifest field", async () => {
  await withFixture(async (pluginDir) => {
    const manifestPath = path.join(pluginDir, "plugin.json");
    const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
    manifest.agents = ["./agents/reviewer.md"];
    await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    assert.throws(
      () => validateAgentPluginDirectory(pluginDir, version),
      /must contain only portable Agent Plugins v1 fields/,
    );
  });
});

test("rejects a client variable in the portable launcher command", async () => {
  await withFixture(async (pluginDir) => {
    const mcpPath = path.join(pluginDir, "mcp.json");
    const mcp = JSON.parse(await fs.readFile(mcpPath, "utf8"));
    mcp.mcpServers.bifrost.command = "${CURSOR_PLUGIN_ROOT}/bin/bifrost-launcher.mjs";
    await fs.writeFile(mcpPath, `${JSON.stringify(mcp, null, 2)}\n`);
    assert.throws(
      () => validateAgentPluginDirectory(pluginDir, version),
      /must use the portable relative launcher/,
    );
  });
});

test("rejects a portable MCP server without a transport type", async () => {
  await withFixture(async (pluginDir) => {
    const mcpPath = path.join(pluginDir, "mcp.json");
    const mcp = JSON.parse(await fs.readFile(mcpPath, "utf8"));
    delete mcp.mcpServers.bifrost.type;
    await fs.writeFile(mcpPath, `${JSON.stringify(mcp, null, 2)}\n`);
    assert.throws(
      () => validateAgentPluginDirectory(pluginDir, version),
      /must not contain host-specific MCP settings/,
    );
  });
});

test("rejects a portable manifest version mismatch", async () => {
  await withFixture(async (pluginDir) => {
    assert.throws(
      () => validateAgentPluginDirectory(pluginDir, "1.2.4"),
      /version must match Cargo.toml/,
    );
  });
});

test("rejects a Codex adapter name that differs from the portable plugin", async () => {
  await withFixture(async (pluginDir) => {
    const manifestPath = path.join(pluginDir, ".codex-plugin", "plugin.json");
    const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
    manifest.name = "brokk";
    await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    assert.throws(
      () => validateAgentPluginDirectory(pluginDir, version),
      /name must match the portable plugin name/,
    );
  });
});

test("rejects a nested portable skill", async () => {
  await withFixture(async (pluginDir) => {
    const nestedSkill = path.join(pluginDir, "skills", "sample", "nested");
    await fs.mkdir(nestedSkill);
    await fs.writeFile(path.join(nestedSkill, "SKILL.md"), "---\nname: nested\n---\n");
    assert.throws(
      () => validateAgentPluginDirectory(pluginDir, version),
      /must not contain nested portable skills/,
    );
  });
});

async function withFixture(run) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agent-plugins-v1-test-"));
  try {
    await fs.mkdir(path.join(directory, "skills", "sample"), { recursive: true });
    await fs.mkdir(path.join(directory, ".codex-plugin"), { recursive: true });
    await fs.mkdir(path.join(directory, ".cursor-plugin"), { recursive: true });
    await fs.writeFile(path.join(directory, "skills", "sample", "SKILL.md"), "---\nname: sample\n---\n");
    await fs.writeFile(path.join(directory, "plugin.json"), `${JSON.stringify(pluginManifest(), null, 2)}\n`);
    await fs.writeFile(path.join(directory, "mcp.json"), `${JSON.stringify(portableMcp(), null, 2)}\n`);
    await fs.writeFile(
      path.join(directory, ".codex-plugin", "plugin.json"),
      `${JSON.stringify(codexManifest(), null, 2)}\n`,
    );
    await fs.writeFile(path.join(directory, ".mcp.json"), `${JSON.stringify(codexMcp(), null, 2)}\n`);
    await fs.writeFile(
      path.join(directory, ".cursor-plugin", "plugin.json"),
      `${JSON.stringify({ mcpServers: "./cursor-mcp.json" }, null, 2)}\n`,
    );
    await fs.writeFile(path.join(directory, "cursor-mcp.json"), `${JSON.stringify(cursorMcp(), null, 2)}\n`);
    return await run(directory);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}

function pluginManifest() {
  return {
    $schema: "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
    name: "bifrost",
    version,
    description: "Test plugin.",
    author: { name: "Brokk", url: "https://brokk.ai" },
    homepage: "https://brokk.ai",
    repository: "https://github.com/BrokkAi/bifrost",
    license: "Apache-2.0",
    keywords: ["bifrost"],
  };
}

function portableMcp() {
  return {
    $schema: "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
    mcpServers: {
      bifrost: {
        type: "stdio",
        command: "./bin/bifrost-launcher.mjs",
        args: ["--mcp", "symbol|extended"],
      },
    },
  };
}

function codexManifest() {
  return {
    name: "bifrost",
    version,
    description: "Test Codex adapter.",
    author: { name: "Brokk", url: "https://brokk.ai" },
    homepage: "https://brokk.ai",
    repository: "https://github.com/BrokkAi/bifrost",
    license: "Apache-2.0",
    keywords: ["bifrost"],
    mcpServers: "./.mcp.json",
  };
}

function codexMcp() {
  return {
    mcpServers: {
      bifrost: {
        command: "./bin/bifrost-launcher.mjs",
        cwd: ".",
        args: ["--mcp", "symbol|extended"],
        startup_timeout_sec: 180,
        tool_timeout_sec: 300,
      },
    },
  };
}

function cursorMcp() {
  return {
    mcpServers: {
      bifrost: {
        type: "stdio",
        command: "${CURSOR_PLUGIN_ROOT}/bin/bifrost-launcher.mjs",
      },
    },
  };
}
