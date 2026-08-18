/**
 * DeepSeek Harness (dsh) bundle for Bifrost.
 *
 * Cordis namespace plugin: `apply` loads one `@deepseek-ai/dsh-mcp-client`
 * instance that spawns the shared Bifrost launcher (`bin/bifrost-launcher.mjs`)
 * as a stdio MCP server. The launcher resolves, verifies, and starts the native
 * `bifrost` binary; Bifrost tools then appear to the model as
 * `mcp__bifrost__<tool>`.
 *
 * The workspace root is explicit: dsh's MCP bridge is not known to answer the
 * MCP `roots/list` request, so the analyzer root comes from plugin config,
 * then `BIFROST_WORKSPACE_ROOT`, then the harness process working directory.
 * It must never silently become the plugin install directory.
 */

import { fileURLToPath } from "node:url";

/** Cordis plugin name used by loader diagnostics. */
export const name = "dsh-plugin-bifrost";

/** Default Bifrost MCP toolset expression, matching every other agent-plugin surface. */
export const DEFAULT_TOOLSETS = "symbol|extended";

/**
 * Default per-tool-call timeout. The first call on a cold workspace can pay
 * managed binary download, extraction, and analyzer warm-up; the dsh
 * mcp-client default of 60s is too short for that.
 */
export const DEFAULT_TOOL_CALL_TIMEOUT_MS = 240_000;

/** Local namespace for model-facing tool names (`mcp__<serverName>__<tool>`). */
export const DEFAULT_SERVER_NAME = "bifrost";

/**
 * Build the `@deepseek-ai/dsh-mcp-client` stdio config for one Bifrost server.
 * Pure so tests can assert argument construction without a harness installed.
 *
 * `config` is the row config from the profile patch: `root`, `toolsets`,
 * `serverName`, `env`, `toolCallTimeoutMs`, `failOnStartupError` are
 * recognized; everything is optional.
 */
export function buildMcpClientConfig(config, launcherPath, environment, workingDirectory) {
  const root = config.root ?? environment.BIFROST_WORKSPACE_ROOT ?? workingDirectory;
  return {
    transport: "stdio",
    serverName: config.serverName ?? DEFAULT_SERVER_NAME,
    command: process.execPath,
    args: [launcherPath, "--root", root, "--mcp", config.toolsets ?? DEFAULT_TOOLSETS],
    env: config.env ?? {},
    cwd: root,
    toolCallTimeoutMs: config.toolCallTimeoutMs ?? DEFAULT_TOOL_CALL_TIMEOUT_MS,
    failOnStartupError: config.failOnStartupError ?? false,
  };
}

/**
 * Start the plugin when Harness loads it. The mcp-client import is dynamic so
 * this module stays loadable (and unit-testable) without a harness install;
 * at runtime the dsh CLI provides the package.
 */
export async function apply(ctx, config = {}) {
  const launcherPath = fileURLToPath(new URL("../bin/bifrost-launcher.mjs", import.meta.url));
  const mcpClient = await import("@deepseek-ai/dsh-mcp-client");
  ctx.plugin(mcpClient, buildMcpClientConfig(config, launcherPath, process.env, process.cwd()));
}
