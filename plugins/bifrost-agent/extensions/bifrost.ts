import { join } from "node:path";

import { getAgentDir, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

import {
  DEFAULT_BIFROST_CAPABILITIES,
  type BifrostCapability,
} from "./bifrost-capabilities.ts";
import {
  createBifrostSession,
  type BifrostSessionController,
} from "./bifrost-session.ts";
import { showBifrostSettings } from "./bifrost-settings-component.ts";
import {
  createBifrostSettingsStore,
  type BifrostSettingsStore,
} from "./bifrost-settings.ts";

export const BIFROST_PROMPT_NOTE = "Bifrost MCP tools are namespaced as bifrost_<name> in Pi. When a Bifrost skill refers to query_code, for example, call bifrost_query_code. Bifrost is fixed to the current Pi workspace; do not activate another workspace.";

interface BifrostExtensionDependencies {
  createSession(pi: ExtensionAPI): BifrostSessionController;
  settingsStore: BifrostSettingsStore;
}

export default function bifrostExtension(pi: ExtensionAPI) {
  configureBifrostExtension(pi, defaultDependencies());
}

export function configureBifrostExtension(
  pi: ExtensionAPI,
  dependencies: BifrostExtensionDependencies,
): void {
  const session = dependencies.createSession(pi);
  let uiContext: {
    hasUI: boolean;
    ui: { notify(message: string, level: "error"): void };
  } | undefined;
  session.setErrorHandler((error) => {
    if (uiContext?.hasUI) {
      uiContext.ui.notify(error.message, "error");
    }
  });

  pi.on("session_start", async (_event, ctx) => {
    uiContext = ctx;
    let capabilities: readonly BifrostCapability[];
    try {
      capabilities = await dependencies.settingsStore.load(ctx.cwd) ?? DEFAULT_BIFROST_CAPABILITIES;
    } catch (cause) {
      const error = new Error(
        "Could not load Bifrost settings. Bifrost tools are disabled until the settings are updated.",
        { cause },
      );
      if (!ctx.hasUI) {
        throw error;
      }
      ctx.ui.notify(error.message, "error");
      capabilities = [];
    }
    const started = await session.start(ctx.cwd, capabilities);
    if (!started) {
      const error = session.status().lastOperationError ?? new Error("Bifrost failed to start.");
      if (ctx.hasUI) {
        ctx.ui.notify(error.message, "error");
      } else {
        throw error;
      }
    }
  });

  pi.on("session_shutdown", async () => {
    try {
      await session.shutdown();
    } catch (cause) {
      const error = cause instanceof Error
        ? cause
        : new Error("Bifrost MCP cleanup failed.", { cause });
      if (!uiContext?.hasUI) {
        throw error;
      }
      uiContext.ui.notify(error.message, "error");
    } finally {
      uiContext = undefined;
    }
  });

  pi.on("before_agent_start", async (event) => {
    const status = session.status();
    if (status.state !== "connected" || status.toolCount === 0) {
      return;
    }
    return { systemPrompt: `${event.systemPrompt}\n\n${BIFROST_PROMPT_NOTE}` };
  });

  pi.registerCommand("bifrost", {
    description: "Configure Bifrost tools for this workspace.",
    handler: async (_args, ctx) => {
      if (ctx.mode !== "tui") {
        ctx.ui.notify("/bifrost requires TUI mode.", "error");
        return;
      }

      const initialStatus = session.status();
      if (!initialStatus.workspace) {
        ctx.ui.notify("Bifrost has not started a workspace session.", "error");
        return;
      }
      await showBifrostSettings(
        ctx,
        initialStatus.workspace,
        session,
        dependencies.settingsStore,
      );
    },
  });
}

function defaultDependencies(): BifrostExtensionDependencies {
  return {
    createSession: createBifrostSession,
    settingsStore: createBifrostSettingsStore(join(getAgentDir(), "bifrost", "workspaces")),
  };
}
