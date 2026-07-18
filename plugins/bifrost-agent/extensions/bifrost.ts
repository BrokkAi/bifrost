import { join } from "node:path";

import {
  getAgentDir,
  getSettingsListTheme,
  type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import { Container, type SettingItem, SettingsList, Text } from "@earendil-works/pi-tui";

import {
  BIFROST_CAPABILITIES,
  DEFAULT_BIFROST_CAPABILITIES,
  normalizeCapabilities,
  type BifrostCapability,
} from "./bifrost-capabilities.ts";
import {
  createBifrostSession,
  type BifrostSessionController,
} from "./bifrost-session.ts";
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
      const workspace = initialStatus.workspace;
      let desired = new Set<BifrostCapability>(initialStatus.capabilities);
      let pending = Promise.resolve();

      await ctx.ui.custom<void>((tui, theme, _keybindings, done) => {
        const items = capabilitySettingItems(desired);
        const container = new Container();
        const header = new Text("", 1, 1);
        const updateHeader = () => {
          const status = session.status();
          header.setText(
            theme.fg("accent", theme.bold("Bifrost Toolsets"))
              + `\n${theme.fg("muted", `${status.state} · ${status.workspace ?? workspace}`)}`,
          );
        };
        updateHeader();
        container.addChild(header);

        let settingsList: SettingsList;
        settingsList = new SettingsList(
          items,
          Math.min(items.length + 2, 15),
          getSettingsListTheme(),
          (id, newValue) => {
            const capability = id as BifrostCapability;
            pending = pending.then(async () => {
              const previous = session.status().capabilities;
              const requestedSet = new Set<BifrostCapability>(previous);
              if (newValue === "enabled") {
                requestedSet.add(capability);
              } else {
                requestedSet.delete(capability);
              }
              const requested = normalizeCapabilities(requestedSet);
              const applied = await session.applySelection(requested);
              if (!applied) {
                desired = new Set(session.status().capabilities);
                updateSettingValues(settingsList, desired);
                updateHeader();
                ctx.ui.notify(
                  session.status().lastOperationError?.message
                    ?? "Bifrost could not apply that selection.",
                  "error",
                );
                tui.requestRender();
                return;
              }

              try {
                await dependencies.settingsStore.save(workspace, requested);
                desired = new Set(session.status().capabilities);
                updateSettingValues(settingsList, desired);
                updateHeader();
                tui.requestRender();
              } catch (cause) {
                const rolledBack = await session.applySelection(previous);
                desired = new Set(session.status().capabilities);
                updateSettingValues(settingsList, desired);
                updateHeader();
                tui.requestRender();
                const consequence = rolledBack
                  ? "The previous runtime selection was restored. Check the settings directory and try again."
                  : "The previous runtime selection could not be restored. Restart Pi before retrying.";
                throw new Error(`Could not save Bifrost settings. ${consequence}`, { cause });
              }
            }).catch((error: unknown) => {
              updateHeader();
              tui.requestRender();
              ctx.ui.notify(
                error instanceof Error ? error.message : "Bifrost could not update its settings. Restart Pi and try again.",
                "error",
              );
            });
          },
          () => done(undefined),
          { enableSearch: true },
        );
        container.addChild(settingsList);

        return {
          render: (width) => {
            updateHeader();
            return container.render(width);
          },
          invalidate: () => container.invalidate(),
          handleInput: (data) => {
            settingsList.handleInput(data);
            tui.requestRender();
          },
        };
      });
      await pending;
    },
  });
}

function capabilitySettingItems(
  selected: ReadonlySet<BifrostCapability>,
): SettingItem[] {
  return BIFROST_CAPABILITIES.map((capability) => ({
    id: capability.id,
    label: capability.label,
    description: capability.description,
    currentValue: selected.has(capability.id) ? "enabled" : "disabled",
    values: ["enabled", "disabled"],
  }));
}

function updateSettingValues(
  settingsList: SettingsList,
  selected: ReadonlySet<BifrostCapability>,
): void {
  for (const capability of BIFROST_CAPABILITIES) {
    settingsList.updateValue(
      capability.id,
      selected.has(capability.id) ? "enabled" : "disabled",
    );
  }
}

function defaultDependencies(): BifrostExtensionDependencies {
  return {
    createSession: createBifrostSession,
    settingsStore: createBifrostSettingsStore(join(getAgentDir(), "bifrost", "workspaces")),
  };
}
