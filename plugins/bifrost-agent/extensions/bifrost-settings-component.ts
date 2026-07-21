import {
  getSettingsListTheme,
  type ExtensionCommandContext,
  type Theme,
} from "@earendil-works/pi-coding-agent";
import {
  Container,
  type SettingItem,
  SettingsList,
  Text,
  type TUI,
} from "@earendil-works/pi-tui";

import {
  BIFROST_CAPABILITIES,
  normalizeCapabilities,
  type BifrostCapability,
} from "./bifrost-capabilities.ts";
import type { BifrostSessionController } from "./bifrost-session.ts";
import type { BifrostSettingsStore } from "./bifrost-settings.ts";

interface BifrostSettingsComponentOptions {
  tui: Pick<TUI, "requestRender">;
  theme: Theme;
  workspace: string;
  session: BifrostSessionController;
  settingsStore: BifrostSettingsStore;
  notifyError(message: string): void;
  close(): void;
}

class BifrostSettingsComponent extends Container {
  private readonly header = new Text("", 1, 1);
  private readonly settingsList: SettingsList;
  private readonly options: BifrostSettingsComponentOptions;
  private pending: Promise<void> = Promise.resolve();
  private mounted = true;

  constructor(options: BifrostSettingsComponentOptions) {
    super();
    this.options = options;

    this.updateHeader();
    this.addChild(this.header);

    this.settingsList = new SettingsList(
      capabilitySettingItems(new Set(options.session.status().capabilities)),
      Math.min(BIFROST_CAPABILITIES.length + 2, 15),
      getSettingsListTheme(),
      (id, newValue) => {
        const capability = BIFROST_CAPABILITIES.find((candidate) => candidate.id === id)?.id;
        if (capability) {
          this.enqueueSelection(capability, newValue === "enabled");
        }
      },
      options.close,
      { enableSearch: true },
    );
    this.addChild(this.settingsList);
  }

  handleInput(data: string): void {
    this.settingsList.handleInput(data);
    this.requestRender();
  }

  override render(width: number): string[] {
    this.updateHeader();
    return super.render(width);
  }

  override invalidate(): void {
    super.invalidate();
    this.updateHeader();
  }

  dispose(): void {
    this.mounted = false;
  }

  async whenSettled(): Promise<void> {
    await this.pending;
  }

  private enqueueSelection(capability: BifrostCapability, enabled: boolean): void {
    this.pending = this.pending
      .then(() => this.applySelection(capability, enabled))
      .catch((error: unknown) => {
        this.refreshFromSession();
        this.options.notifyError(
          error instanceof Error
            ? error.message
            : "Bifrost could not update its settings. Restart Pi and try again.",
        );
      });
  }

  private async applySelection(
    capability: BifrostCapability,
    enabled: boolean,
  ): Promise<void> {
    const previous = this.options.session.status().capabilities;
    const requestedSet = new Set<BifrostCapability>(previous);
    if (enabled) {
      requestedSet.add(capability);
    } else {
      requestedSet.delete(capability);
    }
    const requested = normalizeCapabilities(requestedSet);
    const applied = await this.options.session.applySelection(requested);
    if (!applied) {
      this.refreshFromSession();
      this.options.notifyError(
        this.options.session.status().lastOperationError?.message
          ?? "Bifrost could not apply that selection.",
      );
      return;
    }

    try {
      await this.options.settingsStore.save(this.options.workspace, requested);
      this.refreshFromSession();
    } catch (cause) {
      const rolledBack = await this.options.session.applySelection(previous);
      this.refreshFromSession();
      const consequence = rolledBack
        ? "The previous runtime selection was restored. Check the settings directory and try again."
        : "The previous runtime selection could not be restored. Restart Pi before retrying.";
      throw new Error(`Could not save Bifrost settings. ${consequence}`, { cause });
    }
  }

  private refreshFromSession(): void {
    const selected = new Set(this.options.session.status().capabilities);
    for (const capability of BIFROST_CAPABILITIES) {
      this.settingsList.updateValue(
        capability.id,
        selected.has(capability.id) ? "enabled" : "disabled",
      );
    }
    this.updateHeader();
    this.requestRender();
  }

  private updateHeader(): void {
    const status = this.options.session.status();
    this.header.setText(
      this.options.theme.fg("accent", this.options.theme.bold("Bifrost Toolsets"))
        + `\n${this.options.theme.fg("muted", `${status.state} · ${status.workspace ?? this.options.workspace}`)}`,
    );
  }

  private requestRender(): void {
    if (this.mounted) {
      this.options.tui.requestRender();
    }
  }
}

export async function showBifrostSettings(
  ctx: ExtensionCommandContext,
  workspace: string,
  session: BifrostSessionController,
  settingsStore: BifrostSettingsStore,
): Promise<void> {
  let component: BifrostSettingsComponent | undefined;
  await ctx.ui.custom<void>((tui, theme, _keybindings, done) => {
    component = new BifrostSettingsComponent({
      tui,
      theme,
      workspace,
      session,
      settingsStore,
      notifyError: (message) => ctx.ui.notify(message, "error"),
      close: () => done(undefined),
    });
    return component;
  });
  await component?.whenSettled();
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
