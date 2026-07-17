import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { resolveBifrostLaunch, type BifrostLaunch } from "../bin/bifrost-launcher.mjs";
import {
  BIFROST_CAPABILITIES,
  normalizeCapabilities,
  piToolName,
  serverToolsetExpression,
  toolBelongsToSelection,
  type BifrostCapability,
} from "./bifrost-capabilities.ts";
import {
  mapToolResult,
  toolLabel,
  toolParameters,
  type McpToolDescription,
  type McpToolResult,
} from "./mcp-adapter.ts";

const CONNECT_TIMEOUT_MS = 60_000;
const CALL_TIMEOUT_MS = 300_000;

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
  resolveLaunch(root: string, toolset: string): Promise<BifrostLaunch>;
  createClient(launch: BifrostLaunch): BifrostSessionClient;
  reportError(message: string): void;
}

type ConnectionState = "disconnected" | "connecting" | "connected" | "error";

export interface BifrostSessionStatus {
  state: ConnectionState;
  workspace?: string;
  toolCount: number;
  capabilities: BifrostCapability[];
  error?: string;
}

export interface BifrostSessionController {
  start(workspace: string, capabilities: readonly BifrostCapability[]): Promise<boolean>;
  applySelection(capabilities: readonly BifrostCapability[]): Promise<boolean>;
  shutdown(): Promise<void>;
  status(): BifrostSessionStatus;
  setErrorHandler(handler: (message: string) => void): void;
}

export function createBifrostSession(
  pi: ExtensionAPI,
  dependencies: BifrostSessionDependencies = defaultDependencies(),
): BifrostSessionController {
  let generation = 0;
  let reportError = dependencies.reportError;
  let state: ConnectionState = "disconnected";
  let workspace: string | undefined;
  let selectedCapabilities: BifrostCapability[] = [];
  let currentToolset = "";
  let lastError: string | undefined;
  let activeClient: BifrostSessionClient | undefined;
  let advertisedMcpToolNames = new Set<string>();
  let activeMcpToolNames = new Set<string>();
  const startingClients = new Set<BifrostSessionClient>();
  const closePromises = new WeakMap<BifrostSessionClient, Promise<void>>();
  const ownedPiToolNames = new Set<string>();

  const closeOnce = (client: BifrostSessionClient | undefined): Promise<void> => {
    if (!client) {
      return Promise.resolve();
    }
    const existing = closePromises.get(client);
    if (existing) {
      return existing;
    }
    const closing = client.close().catch((error: unknown) => {
      reportError(`Bifrost MCP cleanup failed: ${formatError(error)}`);
    });
    closePromises.set(client, closing);
    return closing;
  };

  const reconcileActiveTools = (
    capabilities: readonly BifrostCapability[],
    advertisedNames: ReadonlySet<string>,
  ) => {
    const activeNames = new Set(pi.getActiveTools());
    for (const ownedName of ownedPiToolNames) {
      activeNames.delete(ownedName);
    }
    activeMcpToolNames = new Set();
    for (const mcpName of advertisedNames) {
      if (toolBelongsToSelection(mcpName, capabilities)) {
        activeMcpToolNames.add(mcpName);
        activeNames.add(piToolName(mcpName));
      }
    }
    pi.setActiveTools(Array.from(activeNames));
  };

  const registerDiscoveredTools = (tools: McpToolDescription[]) => {
    assertNoToolCollisions(tools, pi.getAllTools().map((tool) => tool.name), ownedPiToolNames);
    for (const tool of tools) {
      const registeredName = piToolName(tool.name);
      if (ownedPiToolNames.has(registeredName)) {
        continue;
      }
      pi.registerTool({
        name: registeredName,
        label: `Bifrost: ${toolLabel(tool)}`,
        description: `${tool.description ?? `Bifrost MCP tool ${tool.name}.`} This is the namespaced Pi form of ${tool.name}. Output is limited to 2,000 lines or 50 KB; the full MCP result remains in tool details.`,
        promptSnippet: tool.description ?? `Use Bifrost ${tool.name}.`,
        parameters: toolParameters(tool),
        async execute(_toolCallId, params, signal) {
          const client = activeClient;
          if (
            !client
            || state !== "connected"
            || !advertisedMcpToolNames.has(tool.name)
            || !activeMcpToolNames.has(tool.name)
          ) {
            throw new Error(`Bifrost tool ${registeredName} is unavailable because its capability is not active.`);
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
      ownedPiToolNames.add(registeredName);
    }
  };

  const connectSelection = async (capabilities: readonly BifrostCapability[]): Promise<boolean> => {
    if (!workspace) {
      throw new Error("Cannot configure Bifrost before a workspace is set.");
    }
    const normalized = normalizeCapabilities(capabilities);
    const desiredToolset = serverToolsetExpression(normalized);
    if (
      sameCapabilities(normalized, selectedCapabilities)
      && desiredToolset === currentToolset
      && (!desiredToolset || activeClient)
    ) {
      if (!desiredToolset) {
        state = "disconnected";
      }
      reconcileActiveTools(normalized, advertisedMcpToolNames);
      return true;
    }
    if (desiredToolset === currentToolset && activeClient) {
      selectedCapabilities = normalized;
      state = "connected";
      lastError = undefined;
      reconcileActiveTools(normalized, advertisedMcpToolNames);
      return true;
    }

    const ticket = ++generation;
    const previousState = state;
    const previousClient = activeClient;
    const previousAdvertised = advertisedMcpToolNames;
    state = previousClient ? previousState : desiredToolset ? "connecting" : "disconnected";
    lastError = undefined;

    if (!desiredToolset) {
      state = "disconnected";
      activeClient = undefined;
      advertisedMcpToolNames = new Set();
      selectedCapabilities = normalized;
      currentToolset = "";
      reconcileActiveTools(normalized, advertisedMcpToolNames);
      await closeOnce(previousClient);
      return true;
    }

    let client: BifrostSessionClient | undefined;
    try {
      const launch = await dependencies.resolveLaunch(workspace, desiredToolset);
      if (ticket !== generation) {
        return false;
      }
      client = dependencies.createClient(launch);
      startingClients.add(client);
      client.onClose(() => {
        if (activeClient !== client) {
          return;
        }
        activeClient = undefined;
        advertisedMcpToolNames = new Set();
        reconcileActiveTools([], advertisedMcpToolNames);
        state = "error";
        lastError = "Bifrost MCP connection closed unexpectedly.";
        reportError(lastError);
      });
      await client.connect();
      if (ticket !== generation) {
        await closeOnce(client);
        return false;
      }
      const tools = await client.listTools();
      if (ticket !== generation) {
        await closeOnce(client);
        return false;
      }
      const discoveredNames = new Set(tools.map((tool) => tool.name));
      assertCapabilitiesAvailable(normalized, discoveredNames);
      registerDiscoveredTools(tools);

      activeClient = client;
      advertisedMcpToolNames = discoveredNames;
      selectedCapabilities = normalized;
      currentToolset = desiredToolset;
      state = "connected";
      reconcileActiveTools(normalized, discoveredNames);
      await closeOnce(previousClient);
      return true;
    } catch (error) {
      await closeOnce(client);
      if (ticket === generation) {
        const previousIsUsable = previousClient !== undefined && activeClient === previousClient;
        activeClient = previousIsUsable ? previousClient : undefined;
        advertisedMcpToolNames = previousIsUsable ? previousAdvertised : new Set();
        state = previousIsUsable ? previousState : "error";
        if (!previousIsUsable) {
          currentToolset = "";
        }
        lastError = `Bifrost MCP configuration failed: ${formatError(error)}`;
        reconcileActiveTools(
          previousIsUsable ? selectedCapabilities : [],
          advertisedMcpToolNames,
        );
        reportError(lastError);
      }
      return false;
    } finally {
      if (client) {
        startingClients.delete(client);
      }
    }
  };

  const start = async (nextWorkspace: string, capabilities: readonly BifrostCapability[]) => {
    const startTicket = ++generation;
    workspace = nextWorkspace;
    selectedCapabilities = [];
    currentToolset = "";
    lastError = undefined;
    advertisedMcpToolNames = new Set();
    activeMcpToolNames = new Set();
    const previous = activeClient;
    activeClient = undefined;
    await Promise.all([
      closeOnce(previous),
      ...Array.from(startingClients, (client) => closeOnce(client)),
    ]);
    if (startTicket !== generation) {
      return false;
    }
    return await connectSelection(capabilities);
  };

  const shutdown = async () => {
    ++generation;
    state = "disconnected";
    lastError = undefined;
    selectedCapabilities = [];
    currentToolset = "";
    advertisedMcpToolNames = new Set();
    reconcileActiveTools([], advertisedMcpToolNames);
    const current = activeClient;
    activeClient = undefined;
    await Promise.all([
      closeOnce(current),
      ...Array.from(startingClients, (client) => closeOnce(client)),
    ]);
  };

  return {
    start,
    applySelection: connectSelection,
    shutdown,
    status: () => ({
      state,
      workspace,
      toolCount: activeMcpToolNames.size,
      capabilities: [...selectedCapabilities],
      ...(lastError ? { error: lastError } : {}),
    }),
    setErrorHandler(handler) {
      reportError = handler;
    },
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
  const collisions = Array.from(discovered, piToolName)
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
    resolveLaunch: (root, toolset) => resolveBifrostLaunch({ root, env: process.env, toolset }),
    createClient: createSdkSessionClient,
    reportError: () => {},
  };
}

function assertCapabilitiesAvailable(
  capabilities: readonly BifrostCapability[],
  discoveredNames: ReadonlySet<string>,
): void {
  const unavailable = capabilities.filter((id) => {
    const definition = BIFROST_CAPABILITIES.find((capability) => capability.id === id);
    return !definition?.toolNames.some((name) => discoveredNames.has(name));
  });
  if (unavailable.length > 0) {
    throw new Error(`Selected Bifrost capabilities are unavailable: ${unavailable.join(", ")}.`);
  }
}

function sameCapabilities(
  left: readonly BifrostCapability[],
  right: readonly BifrostCapability[],
): boolean {
  return left.length === right.length && left.every((capability, index) => capability === right[index]);
}

function stringEnvironment(env: NodeJS.ProcessEnv): Record<string, string> {
  return Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
