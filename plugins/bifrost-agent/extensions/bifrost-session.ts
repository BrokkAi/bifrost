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
import {
  createBoundedToolError,
  mapToolResult,
  renderToolCall,
  renderToolResult,
  toolLabel,
  toolParameters,
} from "./mcp-adapter.ts";

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
  lastOperationError?: Error;
}

export interface BifrostSessionController {
  start(workspace: string, capabilities: readonly BifrostCapability[]): Promise<boolean>;
  applySelection(capabilities: readonly BifrostCapability[]): Promise<boolean>;
  shutdown(): Promise<void>;
  status(): BifrostSessionStatus;
  setErrorHandler(handler: (error: Error) => void): void;
}

interface ConnectedSession {
  kind: "connected";
  client: BifrostSessionClient;
  toolset: string;
  advertisedMcpToolNames: Set<string>;
  lastOperationError?: Error;
}

type PublishedConnection =
  | { kind: "disconnected" }
  | { kind: "connecting" }
  | ConnectedSession
  | { kind: "error"; error: Error };

interface SessionState {
  generation: number;
  workspace: string | undefined;
  desiredCapabilities: BifrostCapability[];
  published: PublishedConnection;
}

class BifrostSession implements BifrostSessionController {
  private readonly pi: ExtensionAPI;
  private readonly dependencies: BifrostSessionDependencies;
  private readonly state: SessionState = {
    generation: 0,
    workspace: undefined,
    desiredCapabilities: [],
    published: { kind: "disconnected" },
  };

  private reportError: (error: Error) => void;
  private readonly ownedClients = new Set<BifrostSessionClient>();
  private readonly startingClients = new Set<BifrostSessionClient>();
  private readonly closedClients = new WeakSet<BifrostSessionClient>();
  private readonly closePromises = new WeakMap<BifrostSessionClient, Promise<void>>();
  private readonly ownedPiToolNames = new Set<string>();

  constructor(pi: ExtensionAPI, dependencies: BifrostSessionDependencies) {
    this.pi = pi;
    this.dependencies = dependencies;
    this.reportError = dependencies.reportError;
  }

  setErrorHandler(handler: (error: Error) => void): void {
    this.reportError = handler;
  }

  status(): BifrostSessionStatus {
    const published = this.state.published;
    const lastOperationError = published.kind === "error"
      ? published.error
      : published.kind === "connected"
        ? published.lastOperationError
        : undefined;
    return {
      state: published.kind,
      workspace: this.state.workspace,
      toolCount: published.kind === "connected"
        ? this.effectiveActiveMcpToolNames(published).size
        : 0,
      capabilities: [...this.state.desiredCapabilities],
      ...(lastOperationError ? { lastOperationError } : {}),
    };
  }

  async start(
    nextWorkspace: string,
    capabilities: readonly BifrostCapability[],
  ): Promise<boolean> {
    const normalized = normalizeCapabilities(capabilities);
    const ticket = ++this.state.generation;

    this.state.workspace = nextWorkspace;
    this.state.desiredCapabilities = normalized;
    if (serverToolsetExpression(normalized)) {
      this.publishConnecting();
    } else {
      this.publishDisconnected(normalized);
    }

    try {
      await this.joinCleanup();
    } catch (cause) {
      if (ticket === this.state.generation) {
        this.publishFailure(configurationError(cause), normalized);
      }
      return false;
    }
    if (ticket !== this.state.generation) {
      return false;
    }
    if (normalized.length === 0) {
      return true;
    }
    return await this.connectSelection(normalized);
  }

  async applySelection(capabilities: readonly BifrostCapability[]): Promise<boolean> {
    return await this.connectSelection(capabilities);
  }

  async shutdown(): Promise<void> {
    ++this.state.generation;
    this.state.workspace = undefined;
    this.publishDisconnected([]);
    await this.joinCleanup();
  }

  private async connectSelection(
    capabilities: readonly BifrostCapability[],
  ): Promise<boolean> {
    const workspace = this.state.workspace;
    if (!workspace) {
      throw new Error("Cannot configure Bifrost before a workspace is set.");
    }

    const normalized = normalizeCapabilities(capabilities);
    const desiredToolset = serverToolsetExpression(normalized);
    const previousDesired = [...this.state.desiredCapabilities];
    const ticket = ++this.state.generation;
    const activeClient = this.connected()?.client;
    try {
      await Promise.all(
        Array.from(this.ownedClients)
          .filter((client) => client !== activeClient)
          .map((client) => this.closeOnce(client)),
      );
    } catch (cause) {
      if (ticket === this.state.generation) {
        this.publishOperationFailure(configurationError(cause), previousDesired);
      }
      return false;
    }
    if (ticket !== this.state.generation) {
      return false;
    }

    const previous = this.connected();
    const currentToolset = previous?.toolset ?? "";
    if (previous && desiredToolset === currentToolset) {
      try {
        assertCapabilitiesAvailable(normalized, previous.advertisedMcpToolNames);
      } catch (cause) {
        this.publishConnected(
          previous.client,
          previous.toolset,
          previousDesired,
          previous.advertisedMcpToolNames,
          configurationError(cause),
        );
        return false;
      }
      this.publishConnected(
        previous.client,
        previous.toolset,
        normalized,
        previous.advertisedMcpToolNames,
      );
      return true;
    }

    if (
      !previous
      && !desiredToolset
      && sameCapabilities(normalized, this.state.desiredCapabilities)
    ) {
      this.publishDisconnected(normalized);
      return true;
    }

    if (!desiredToolset) {
      this.publishDisconnected(normalized);
      try {
        await this.closeOnce(previous?.client);
      } catch (cause) {
        if (ticket === this.state.generation) {
          this.publishFailure(configurationError(cause), previousDesired);
        }
        return false;
      }
      return ticket === this.state.generation
        && this.state.published.kind === "disconnected";
    }

    if (previous) {
      this.publishConnected(
        previous.client,
        previous.toolset,
        previousDesired,
        previous.advertisedMcpToolNames,
      );
    } else {
      this.publishConnecting();
    }

    let client: BifrostSessionClient | undefined;
    try {
      const launch = await this.dependencies.resolveLaunch(workspace, desiredToolset);
      if (ticket !== this.state.generation) {
        return false;
      }

      client = this.dependencies.createClient(launch);
      const candidate = client;
      this.ownedClients.add(candidate);
      this.startingClients.add(candidate);
      candidate.onClose(() => {
        this.closedClients.add(candidate);
        this.handleClientClose(candidate);
      });
      await candidate.connect();
      if (ticket !== this.state.generation) {
        await this.closeOnce(candidate);
        return false;
      }

      const tools = await candidate.listTools();
      if (ticket !== this.state.generation) {
        await this.closeOnce(candidate);
        return false;
      }
      if (this.closedClients.has(candidate)) {
        throw new Error("Bifrost MCP connection closed during startup.");
      }

      const discoveredNames = new Set(tools.map((tool) => tool.name));
      assertCapabilitiesAvailable(normalized, discoveredNames);
      this.registerDiscoveredTools(tools);
      this.publishConnecting();
      await this.closeOnce(previous?.client);

      if (ticket !== this.state.generation) {
        await this.closeOnce(candidate);
        return false;
      }
      if (this.closedClients.has(candidate)) {
        await this.closeOnce(candidate);
        if (ticket === this.state.generation) {
          this.publishFailure(
            new Error("Bifrost MCP connection closed during configuration."),
            previousDesired,
          );
        }
        return false;
      }
      this.publishConnected(candidate, desiredToolset, normalized, discoveredNames);
      return true;
    } catch (cause) {
      let operationCause = cause;
      try {
        await this.closeOnce(client);
      } catch (cleanupCause) {
        operationCause = new AggregateError(
          [cause, cleanupCause],
          "Bifrost configuration and cleanup both failed.",
        );
      }
      if (ticket === this.state.generation) {
        const error = configurationError(operationCause);
        if (previous && this.connected()?.client === previous.client) {
          this.publishConnected(
            previous.client,
            previous.toolset,
            previousDesired,
            previous.advertisedMcpToolNames,
            error,
          );
        } else {
          this.publishFailure(error, previousDesired);
        }
      }
      return false;
    } finally {
      if (client) {
        this.startingClients.delete(client);
      }
    }
  }

  private publishConnected(
    client: BifrostSessionClient,
    toolset: string,
    capabilities: readonly BifrostCapability[],
    advertisedMcpToolNames: ReadonlySet<string>,
    lastOperationError?: Error,
  ): void {
    const normalized = normalizeCapabilities(capabilities);
    const advertised = new Set(advertisedMcpToolNames);
    this.applyPiToolSelection(selectedMcpToolNames(normalized, advertised));
    this.state.desiredCapabilities = normalized;
    this.state.published = {
      kind: "connected",
      client,
      toolset,
      advertisedMcpToolNames: advertised,
      ...(lastOperationError ? { lastOperationError } : {}),
    };
  }

  private publishConnecting(): void {
    this.state.published = { kind: "connecting" };
    this.applyPiToolSelection(new Set());
  }

  private publishDisconnected(capabilities: readonly BifrostCapability[]): void {
    this.state.desiredCapabilities = normalizeCapabilities(capabilities);
    this.state.published = { kind: "disconnected" };
    this.applyPiToolSelection(new Set());
  }

  private publishFailure(
    error: Error,
    capabilities: readonly BifrostCapability[] = this.state.desiredCapabilities,
  ): void {
    this.state.desiredCapabilities = normalizeCapabilities(capabilities);
    this.state.published = { kind: "error", error };
    this.applyPiToolSelection(new Set());
  }

  private publishOperationFailure(
    error: Error,
    capabilities: readonly BifrostCapability[],
  ): void {
    const connected = this.connected();
    if (connected) {
      this.publishConnected(
        connected.client,
        connected.toolset,
        capabilities,
        connected.advertisedMcpToolNames,
        error,
      );
    } else {
      this.publishFailure(error, capabilities);
    }
  }

  private handleClientClose(client: BifrostSessionClient): void {
    const published = this.connected();
    if (published?.client !== client) {
      return;
    }
    const error = new Error("Bifrost MCP connection closed unexpectedly.");
    this.publishFailure(error);
    if (!this.startingClients.has(client)) {
      this.reportError(error);
    }
  }

  private connected(): ConnectedSession | undefined {
    return this.state.published.kind === "connected" ? this.state.published : undefined;
  }

  private applyPiToolSelection(requestedMcpToolNames: ReadonlySet<string>): void {
    const nextPiToolNames = new Set(this.pi.getActiveTools());
    for (const ownedName of this.ownedPiToolNames) {
      nextPiToolNames.delete(ownedName);
    }
    for (const mcpName of requestedMcpToolNames) {
      nextPiToolNames.add(piToolName(mcpName));
    }
    this.pi.setActiveTools(Array.from(nextPiToolNames));
  }

  private effectiveActiveMcpToolNames(connected: ConnectedSession): Set<string> {
    const actualPiToolNames = new Set(this.pi.getActiveTools());
    return new Set(
      Array.from(selectedMcpToolNames(
        this.state.desiredCapabilities,
        connected.advertisedMcpToolNames,
      )).filter((mcpName) => actualPiToolNames.has(piToolName(mcpName))),
    );
  }

  private registerDiscoveredTools(tools: Tool[]): void {
    assertToolsHaveUniqueNames(tools);
    for (const tool of tools) {
      const registeredName = piToolName(tool.name);
      this.pi.registerTool({
        name: registeredName,
        label: `Bifrost: ${toolLabel(tool)}`,
        description: `${tool.description ?? `Bifrost MCP tool ${tool.name}.`} Output is truncated to the first 2,000 lines or 50 KB; full output is saved to a temporary file.`,
        parameters: toolParameters(tool),
        execute: async (_toolCallId, params, signal) =>
          await this.executeTool(tool, registeredName, params, signal),
        renderCall: (args, theme, context) =>
          renderToolCall(registeredName, args, context.expanded, theme),
        renderResult: renderToolResult,
      });
      this.ownedPiToolNames.add(registeredName);
    }
  }

  private async executeTool(
    tool: Tool,
    registeredName: string,
    params: Record<string, unknown>,
    signal: AbortSignal | undefined,
  ) {
    const published = this.connected();
    if (
      !published
      || !published.advertisedMcpToolNames.has(tool.name)
      || !this.effectiveActiveMcpToolNames(published).has(tool.name)
    ) {
      throw new Error(`Bifrost tool ${registeredName} is unavailable because its capability is not active.`);
    }

    let result: CallToolResult;
    try {
      result = await published.client.callTool(tool.name, params, {
        signal,
        timeout: CALL_TIMEOUT_MS,
      });
    } catch (cause) {
      const reason = cause instanceof Error ? `: ${cause.message}` : ".";
      throw await createBoundedToolError(`Bifrost tool ${tool.name} failed${reason}`, cause);
    }
    return await mapToolResult(tool.name, result);
  }

  private closeOnce(client: BifrostSessionClient | undefined): Promise<void> {
    if (!client) {
      return Promise.resolve();
    }
    const existing = this.closePromises.get(client);
    if (existing) {
      return existing;
    }
    const closing = client.close().then(
      () => {
        this.ownedClients.delete(client);
      },
      (cause: unknown) => {
        this.closePromises.delete(client);
        throw new Error("Bifrost MCP cleanup failed.", { cause });
      },
    );
    this.closePromises.set(client, closing);
    return closing;
  }

  private async joinCleanup(): Promise<void> {
    const results = await Promise.allSettled(
      Array.from(this.ownedClients, (client) => this.closeOnce(client)),
    );
    const failures = results
      .filter((result): result is PromiseRejectedResult => result.status === "rejected")
      .map((result) => result.reason);
    if (failures.length === 1) {
      throw failures[0];
    }
    if (failures.length > 1) {
      throw new AggregateError(failures, "Multiple Bifrost MCP clients failed to close.");
    }
  }
}

export function createBifrostSession(
  pi: ExtensionAPI,
  dependencies: BifrostSessionDependencies = defaultDependencies(),
): BifrostSessionController {
  return new BifrostSession(pi, dependencies);
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

/**
 * MCP SDK 1.29 starts `this.close()` without awaiting it when initialization
 * fails. Each adapter instance connects once and closes idempotently; retaining
 * that virtual call's promise makes the one-shot client join SDK-owned teardown.
 */
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

function selectedMcpToolNames(
  capabilities: readonly BifrostCapability[],
  advertisedNames: ReadonlySet<string>,
): Set<string> {
  return new Set(
    Array.from(advertisedNames)
      .filter((mcpName) => toolBelongsToSelection(mcpName, capabilities)),
  );
}

function configurationError(cause: unknown): Error {
  const reason = cause instanceof Error ? `: ${cause.message}` : ".";
  return new Error(`Bifrost MCP configuration failed${reason}`, { cause });
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
