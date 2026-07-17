import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { resolveBifrostLaunch, type BifrostLaunch } from "../bin/bifrost-launcher.mjs";
import {
  mapToolResult,
  toolLabel,
  toolParameters,
  type McpToolDescription,
  type McpToolResult,
} from "./mcp-adapter.ts";

const CONNECT_TIMEOUT_MS = 60_000;
const CALL_TIMEOUT_MS = 300_000;
const TOOLSET = "symbol|extended";

export interface BifrostSessionClient {
  connect(): Promise<void>;
  listTools(): Promise<McpToolDescription[]>;
  callTool(
    name: string,
    args: Record<string, unknown>,
    options: { signal: AbortSignal | undefined; timeout: number },
  ): Promise<McpToolResult>;
  onClose(handler: () => void): void;
  close(): Promise<void>;
}

export interface BifrostSessionDependencies {
  resolveLaunch(root: string): Promise<BifrostLaunch>;
  createClient(launch: BifrostLaunch): BifrostSessionClient;
  reportError(message: string): void;
}

type ConnectionState = "disconnected" | "connecting" | "connected" | "error";

export interface BifrostSessionController {
  start(workspace: string): Promise<void>;
  shutdown(): Promise<void>;
  status(): { state: ConnectionState; workspace?: string; toolCount: number };
}

export function createBifrostSession(
  pi: ExtensionAPI,
  dependencies: BifrostSessionDependencies = defaultDependencies(),
): BifrostSessionController {
  let generation = 0;
  let state: ConnectionState = "disconnected";
  let workspace: string | undefined;
  let activeClient: BifrostSessionClient | undefined;
  let activeToolNames = new Set<string>();
  const startingClients = new Set<BifrostSessionClient>();
  const closedClients = new WeakSet<BifrostSessionClient>();
  const ownedToolNames = new Set<string>();

  const closeOnce = async (client: BifrostSessionClient | undefined) => {
    if (!client || closedClients.has(client)) {
      return;
    }
    closedClients.add(client);
    try {
      await client.close();
    } catch (error) {
      dependencies.reportError(`Bifrost MCP cleanup failed: ${formatError(error)}`);
    }
  };

  const registerDiscoveredTools = (tools: McpToolDescription[]) => {
    assertNoToolCollisions(tools, pi.getAllTools().map((tool) => tool.name), ownedToolNames);
    for (const tool of tools) {
      if (ownedToolNames.has(tool.name)) {
        continue;
      }
      pi.registerTool({
        name: tool.name,
        label: toolLabel(tool),
        description: `${tool.description ?? `Bifrost MCP tool ${tool.name}.`} Output is limited to 2,000 lines or 50 KB; the full MCP result remains in tool details.`,
        promptSnippet: tool.description ?? `Use Bifrost ${tool.name}.`,
        parameters: toolParameters(tool),
        async execute(_toolCallId, params, signal) {
          const client = activeClient;
          if (!client || state !== "connected" || !activeToolNames.has(tool.name)) {
            throw new Error(`Bifrost tool ${tool.name} is unavailable because the MCP session is not connected.`);
          }
          try {
            const result = await client.callTool(tool.name, params, {
              signal,
              timeout: CALL_TIMEOUT_MS,
            });
            return mapToolResult(tool.name, result);
          } catch (error) {
            const message = formatError(error);
            if (message.startsWith(`Bifrost tool ${tool.name} failed:`)) {
              throw error;
            }
            throw new Error(`Bifrost tool ${tool.name} failed: ${message}`, { cause: error });
          }
        },
      });
      ownedToolNames.add(tool.name);
    }
  };

  const start = async (nextWorkspace: string) => {
    const ticket = ++generation;
    state = "connecting";
    workspace = nextWorkspace;
    activeToolNames = new Set();

    const previous = activeClient;
    activeClient = undefined;
    await Promise.all([
      closeOnce(previous),
      ...Array.from(startingClients, (client) => closeOnce(client)),
    ]);
    if (ticket !== generation) {
      return;
    }

    let client: BifrostSessionClient | undefined;
    try {
      const launch = await dependencies.resolveLaunch(nextWorkspace);
      if (ticket !== generation) {
        return;
      }

      client = dependencies.createClient(launch);
      client.onClose(() => {
        if (ticket !== generation || activeClient !== client) {
          return;
        }
        activeClient = undefined;
        activeToolNames = new Set();
        state = "error";
        dependencies.reportError("Bifrost MCP connection closed unexpectedly.");
      });
      startingClients.add(client);
      await client.connect();
      if (ticket !== generation) {
        await closeOnce(client);
        return;
      }

      const tools = await client.listTools();
      if (ticket !== generation) {
        await closeOnce(client);
        return;
      }

      registerDiscoveredTools(tools);
      activeClient = client;
      activeToolNames = new Set(tools.map((tool) => tool.name));
      state = "connected";
    } catch (error) {
      await closeOnce(client);
      if (ticket === generation) {
        state = "error";
        activeClient = undefined;
        activeToolNames = new Set();
        dependencies.reportError(`Bifrost MCP startup failed: ${formatError(error)}`);
      }
    } finally {
      if (client) {
        startingClients.delete(client);
      }
    }
  };

  const shutdown = async () => {
    ++generation;
    state = "disconnected";
    activeToolNames = new Set();
    const current = activeClient;
    activeClient = undefined;
    await Promise.all([
      closeOnce(current),
      ...Array.from(startingClients, (client) => closeOnce(client)),
    ]);
  };

  return {
    start,
    shutdown,
    status: () => ({ state, workspace, toolCount: activeToolNames.size }),
  };
}

export function assertNoToolCollisions(
  tools: McpToolDescription[],
  configuredNames: Iterable<string>,
  ownedNames: ReadonlySet<string> = new Set(),
): void {
  const discovered = new Set<string>();
  for (const tool of tools) {
    if (!tool.name.trim()) {
      throw new Error("Bifrost advertised a tool without a name.");
    }
    if (discovered.has(tool.name)) {
      throw new Error(`Bifrost advertised duplicate tool name: ${tool.name}.`);
    }
    discovered.add(tool.name);
  }

  const configured = new Set(configuredNames);
  const collisions = Array.from(discovered)
    .filter((name) => configured.has(name) && !ownedNames.has(name))
    .sort();
  if (collisions.length > 0) {
    throw new Error(`Bifrost tool name collision: ${collisions.join(", ")}.`);
  }
}

export function createSdkSessionClient(launch: BifrostLaunch): BifrostSessionClient {
  const client = new Client({ name: "bifrost-pi", version: "1" });
  const transport = new StdioClientTransport({
    command: launch.command,
    args: launch.args,
    cwd: launch.cwd,
    env: stringEnvironment(launch.env),
    stderr: "inherit",
  });

  return {
    connect: () => client.connect(transport, { timeout: CONNECT_TIMEOUT_MS }),
    async listTools() {
      const response = await client.listTools(undefined, { timeout: CONNECT_TIMEOUT_MS });
      return response.tools as McpToolDescription[];
    },
    async callTool(name, args, options) {
      return await client.callTool(
        { name, arguments: args },
        undefined,
        options,
      ) as McpToolResult;
    },
    onClose(handler) {
      client.onclose = handler;
    },
    close: () => client.close(),
  };
}

function defaultDependencies(): BifrostSessionDependencies {
  return {
    resolveLaunch: (root) => resolveBifrostLaunch({ root, env: process.env, toolset: TOOLSET }),
    createClient: createSdkSessionClient,
    reportError: (message) => console.error(message),
  };
}

function stringEnvironment(env: NodeJS.ProcessEnv): Record<string, string> {
  return Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
