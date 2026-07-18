import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
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
import { mapToolResult, toolLabel, toolParameters } from "./mcp-adapter.ts";

const CONNECT_TIMEOUT_MS = 60_000;
const CALL_TIMEOUT_MS = 300_000;

export interface BifrostSessionClient {
  connect(): Promise<void>;
  listTools(): Promise<Tool[]>;
  callTool(
    name: string,
    args: Record<string, unknown>,
    options: { signal: AbortSignal | undefined; timeout: number },
  ): Promise<CallToolResult>;
  onClose(handler: () => void): void;
  close(): Promise<void>;
}

export interface BifrostSessionDependencies {
  resolveLaunch(root: string, toolset: string): Promise<BifrostLaunch>;
  createClient(launch: BifrostLaunch): BifrostSessionClient;
  reportError(error: Error): void;
}

type ConnectionState = "disconnected" | "connecting" | "connected" | "error";

export interface BifrostSessionStatus {
  state: ConnectionState;
  workspace?: string;
  toolCount: number;
  capabilities: BifrostCapability[];
  error?: Error;
}

export interface BifrostSessionController {
  start(workspace: string, capabilities: readonly BifrostCapability[]): Promise<boolean>;
  applySelection(capabilities: readonly BifrostCapability[]): Promise<boolean>;
  shutdown(): Promise<void>;
  status(): BifrostSessionStatus;
  setErrorHandler(handler: (error: Error) => void): void;
}

/** All lifecycle state for one Pi session's Bifrost connection, owned as a single record. */
interface SessionLifecycle {
  generation: number;
  connection: ConnectionState;
  workspace: string | undefined;
  selectedCapabilities: BifrostCapability[];
  currentToolset: string;
  lastError: Error | undefined;
  activeClient: BifrostSessionClient | undefined;
  advertisedMcpToolNames: Set<string>;
  activeMcpToolNames: Set<string>;
}

function createLifecycle(): SessionLifecycle {
  return {
    generation: 0,
    connection: "disconnected",
    workspace: undefined,
    selectedCapabilities: [],
    currentToolset: "",
    lastError: undefined,
    activeClient: undefined,
    advertisedMcpToolNames: new Set(),
    activeMcpToolNames: new Set(),
  };
}

export function createBifrostSession(
  pi: ExtensionAPI,
  dependencies: BifrostSessionDependencies = defaultDependencies(),
): BifrostSessionController {
  const lifecycle = createLifecycle();
  let reportError = dependencies.reportError;
  const startingClients = new Set<BifrostSessionClient>();
  const closePromises = new WeakMap<BifrostSessionClient, Promise<void>>();
  const closingClientPromises = new Set<Promise<void>>();
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
      reportError(new Error("Bifrost MCP cleanup failed.", { cause: error }));
    });
    closePromises.set(client, closing);
    closingClientPromises.add(closing);
    void closing.then(() => closingClientPromises.delete(closing));
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
    lifecycle.activeMcpToolNames = new Set();
    for (const mcpName of advertisedNames) {
      if (toolBelongsToSelection(mcpName, capabilities)) {
        lifecycle.activeMcpToolNames.add(mcpName);
        activeNames.add(piToolName(mcpName));
      }
    }
    pi.setActiveTools(Array.from(activeNames));
  };

  const registerDiscoveredTools = (tools: Tool[]) => {
    assertToolsHaveUniqueNames(tools);
    for (const tool of tools) {
      const registeredName = piToolName(tool.name);
      pi.registerTool({
        name: registeredName,
        label: `Bifrost: ${toolLabel(tool)}`,
        description: `${tool.description ?? `Bifrost MCP tool ${tool.name}.`} Output is limited to 2,000 lines or 50 KB.`,
        parameters: toolParameters(tool),
        async execute(_toolCallId, params, signal) {
          const client = lifecycle.activeClient;
          if (
            !client
            || lifecycle.connection !== "connected"
            || !lifecycle.advertisedMcpToolNames.has(tool.name)
            || !lifecycle.activeMcpToolNames.has(tool.name)
          ) {
            throw new Error(`Bifrost tool ${registeredName} is unavailable because its capability is not active.`);
          }
          let result: CallToolResult;
          try {
            result = await client.callTool(tool.name, params, {
              signal,
              timeout: CALL_TIMEOUT_MS,
            });
          } catch (cause) {
            const reason = cause instanceof Error ? `: ${cause.message}` : ".";
            throw new Error(`Bifrost tool ${tool.name} failed${reason}`, { cause });
          }
          return mapToolResult(tool.name, result);
        },
      });
      ownedPiToolNames.add(registeredName);
    }
  };

  const connectSelection = async (capabilities: readonly BifrostCapability[]): Promise<boolean> => {
    if (!lifecycle.workspace) {
      throw new Error("Cannot configure Bifrost before a workspace is set.");
    }
    const workspace = lifecycle.workspace;
    const normalized = normalizeCapabilities(capabilities);
    const desiredToolset = serverToolsetExpression(normalized);
    const ticket = ++lifecycle.generation;
    await Promise.all(
      Array.from(startingClients)
        .filter((client) => client !== lifecycle.activeClient)
        .map((client) => closeOnce(client)),
    );
    if (ticket !== lifecycle.generation) {
      return false;
    }
    if (
      sameCapabilities(normalized, lifecycle.selectedCapabilities)
      && desiredToolset === lifecycle.currentToolset
      && (!desiredToolset || lifecycle.activeClient)
    ) {
      if (!desiredToolset) {
        lifecycle.connection = "disconnected";
      }
      reconcileActiveTools(normalized, lifecycle.advertisedMcpToolNames);
      if (lifecycle.activeClient) {
        startingClients.delete(lifecycle.activeClient);
      }
      return true;
    }
    if (desiredToolset === lifecycle.currentToolset && lifecycle.activeClient) {
      lifecycle.selectedCapabilities = normalized;
      lifecycle.connection = "connected";
      lifecycle.lastError = undefined;
      reconcileActiveTools(normalized, lifecycle.advertisedMcpToolNames);
      startingClients.delete(lifecycle.activeClient);
      return true;
    }

    const previousConnection = lifecycle.connection;
    const previousClient = lifecycle.activeClient;
    const previousAdvertised = lifecycle.advertisedMcpToolNames;
    lifecycle.connection = previousClient ? previousConnection : desiredToolset ? "connecting" : "disconnected";
    lifecycle.lastError = undefined;

    if (!desiredToolset) {
      lifecycle.connection = "disconnected";
      lifecycle.activeClient = undefined;
      lifecycle.advertisedMcpToolNames = new Set();
      lifecycle.selectedCapabilities = normalized;
      lifecycle.currentToolset = "";
      reconcileActiveTools(normalized, lifecycle.advertisedMcpToolNames);
      await closeOnce(previousClient);
      return ticket === lifecycle.generation
        && lifecycle.connection === "disconnected"
        && lifecycle.activeClient === undefined;
    }

    let client: BifrostSessionClient | undefined;
    try {
      const launch = await dependencies.resolveLaunch(workspace, desiredToolset);
      if (ticket !== lifecycle.generation) {
        return false;
      }
      client = dependencies.createClient(launch);
      const candidate = client;
      startingClients.add(candidate);
      candidate.onClose(() => {
        if (lifecycle.activeClient !== candidate) {
          return;
        }
        lifecycle.activeClient = undefined;
        lifecycle.advertisedMcpToolNames = new Set();
        reconcileActiveTools([], lifecycle.advertisedMcpToolNames);
        lifecycle.connection = "error";
        lifecycle.lastError = new Error("Bifrost MCP connection closed unexpectedly.");
        if (!startingClients.has(candidate)) {
          reportError(lifecycle.lastError);
        }
      });
      await candidate.connect();
      if (ticket !== lifecycle.generation) {
        await closeOnce(client);
        return false;
      }
      const tools = await client.listTools();
      if (ticket !== lifecycle.generation) {
        await closeOnce(client);
        return false;
      }
      const discoveredNames = new Set(tools.map((tool) => tool.name));
      assertCapabilitiesAvailable(normalized, discoveredNames);
      registerDiscoveredTools(tools);

      lifecycle.activeClient = client;
      lifecycle.advertisedMcpToolNames = discoveredNames;
      lifecycle.selectedCapabilities = normalized;
      lifecycle.currentToolset = desiredToolset;
      lifecycle.connection = "connected";
      reconcileActiveTools(normalized, discoveredNames);
      await closeOnce(previousClient);

      if (
        ticket !== lifecycle.generation
        || lifecycle.activeClient !== client
        || lifecycle.connection !== "connected"
      ) {
        return false;
      }
      return true;
    } catch (cause) {
      await closeOnce(client);
      if (ticket === lifecycle.generation) {
        const previousIsUsable = previousClient !== undefined && lifecycle.activeClient === previousClient;
        lifecycle.activeClient = previousIsUsable ? previousClient : undefined;
        lifecycle.advertisedMcpToolNames = previousIsUsable ? previousAdvertised : new Set();
        lifecycle.connection = previousIsUsable ? previousConnection : "error";
        if (!previousIsUsable) {
          lifecycle.currentToolset = "";
        }
        const reason = cause instanceof Error ? `: ${cause.message}` : ".";
        lifecycle.lastError = new Error(`Bifrost MCP configuration failed${reason}`, { cause });
        reconcileActiveTools(
          previousIsUsable ? lifecycle.selectedCapabilities : [],
          lifecycle.advertisedMcpToolNames,
        );
      }
      return false;
    } finally {
      if (client) {
        startingClients.delete(client);
      }
    }
  };

  const start = async (nextWorkspace: string, capabilities: readonly BifrostCapability[]) => {
    const startTicket = ++lifecycle.generation;
    lifecycle.workspace = nextWorkspace;
    lifecycle.selectedCapabilities = [];
    lifecycle.currentToolset = "";
    lifecycle.lastError = undefined;
    lifecycle.advertisedMcpToolNames = new Set();
    lifecycle.activeMcpToolNames = new Set();
    const previous = lifecycle.activeClient;
    lifecycle.activeClient = undefined;
    await Promise.all([
      closeOnce(previous),
      ...Array.from(startingClients, (client) => closeOnce(client)),
      ...closingClientPromises,
    ]);
    if (startTicket !== lifecycle.generation) {
      return false;
    }
    return await connectSelection(capabilities);
  };

  const shutdown = async () => {
    ++lifecycle.generation;
    lifecycle.connection = "disconnected";
    lifecycle.workspace = undefined;
    lifecycle.lastError = undefined;
    lifecycle.selectedCapabilities = [];
    lifecycle.currentToolset = "";
    lifecycle.advertisedMcpToolNames = new Set();
    reconcileActiveTools([], lifecycle.advertisedMcpToolNames);
    const current = lifecycle.activeClient;
    lifecycle.activeClient = undefined;
    await Promise.all([
      closeOnce(current),
      ...Array.from(startingClients, (client) => closeOnce(client)),
      ...closingClientPromises,
    ]);
  };

  return {
    start,
    applySelection: connectSelection,
    shutdown,
    status: () => ({
      state: lifecycle.connection,
      workspace: lifecycle.workspace,
      toolCount: lifecycle.activeMcpToolNames.size,
      capabilities: [...lifecycle.selectedCapabilities],
      ...(lifecycle.lastError ? { error: lifecycle.lastError } : {}),
    }),
    setErrorHandler(handler) {
      reportError = handler;
    },
  };
}

export function assertToolsHaveUniqueNames(tools: Tool[]): void {
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
}

class AwaitableCloseClient extends Client {
  private closePromise: Promise<void> | undefined;

  override close(): Promise<void> {
    this.closePromise ??= super.close();
    return this.closePromise;
  }
}

export function createSdkSessionClient(launch: BifrostLaunch): BifrostSessionClient {
  const client = new AwaitableCloseClient({ name: "bifrost-pi", version: "1" });
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
      return response.tools;
    },
    async callTool(name, args, options) {
      return await client.callTool({ name, arguments: args }, undefined, options) as CallToolResult;
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
  const missingRequirements: string[] = [];
  for (const id of capabilities) {
    const definition = BIFROST_CAPABILITIES.find((capability) => capability.id === id);
    for (const alternatives of definition?.toolRequirements ?? []) {
      if (!alternatives.some((toolName) => discoveredNames.has(toolName))) {
        missingRequirements.push(alternatives.join(" or "));
      }
    }
    if (
      definition
      && "toolVariants" in definition
      && !definition.toolVariants.some((variant) =>
        variant.every((toolName) => discoveredNames.has(toolName))
      )
    ) {
      missingRequirements.push(
        definition.toolVariants.map((variant) => variant.join(" + ")).join(" or "),
      );
    }
  }
  if (missingRequirements.length > 0) {
    throw new Error(`Bifrost did not advertise expected tools: ${missingRequirements.join(", ")}.`);
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
