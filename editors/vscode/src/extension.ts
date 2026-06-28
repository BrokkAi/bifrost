import * as vscode from "vscode";
import {
  CloseAction,
  ErrorAction,
  LanguageClient,
  LanguageClientOptions,
  RevealOutputChannelOn,
  ServerOptions,
  State
} from "vscode-languageclient/node";
import {
  BifrostLaunchConfig,
  BifrostInitializationOptions,
  buildLaunchConfig,
  formatError,
  LaunchMode,
  parseExtraArgs,
  parsePathSettings,
  sourceFileWatchers,
  spawnBifrostServer,
  supportedWorkspaceRoot
} from "./lifecycle";

let client: LanguageClient | undefined;
let statusBarItem: vscode.StatusBarItem | undefined;
let outputChannel: vscode.OutputChannel | undefined;
let lastLaunchConfig: BifrostLaunchConfig | undefined;
let extensionActive = false;

export function activate(context: vscode.ExtensionContext): void {
  extensionActive = true;
  outputChannel = vscode.window.createOutputChannel("Bifrost");
  context.subscriptions.push(outputChannel);

  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.text = "$(circle-slash) Bifrost";
  statusBarItem.tooltip = "Click to start the Bifrost language server.";
  statusBarItem.command = "bifrost.startServer";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  context.subscriptions.push(
    vscode.commands.registerCommand("bifrost.startServer", () => startClient(context)),
    vscode.commands.registerCommand("bifrost.stopServer", stopClient),
    vscode.commands.registerCommand("bifrost.restartServer", () => restartClient(context)),
    vscode.commands.registerCommand("bifrost.showOutput", () => outputChannel?.show(true))
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      if (client?.state === State.Running) {
        void restartClient(context);
      }
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("bifrost") && client?.state === State.Running) {
        void promptRestartAfterConfigurationChange(context);
      }
    })
  );

  void startClient(context);
}

export function deactivate(): Thenable<void> | undefined {
  extensionActive = false;
  return stopClient({ updateUi: false });
}

async function startClient(context: vscode.ExtensionContext): Promise<void> {
  if (client?.state === State.Running || client?.state === State.Starting) {
    setStatus("$(check) Bifrost", "Bifrost language server is already running.");
    return;
  }

  const root = supportedWorkspaceRoot();
  if (!root) {
    setStatus("$(warning) Bifrost", "Open a folder to start Bifrost.");
    log("No workspace folder is open; Bifrost language server was not started.");
    return;
  }

  const config = vscode.workspace.getConfiguration("bifrost");
  const command = config.get<string>("serverPath") || "bifrost";
  const mode = config.get<LaunchMode>("launchMode") || "auto";
  const debug = config.get<boolean>("debug") ?? false;
  const slowRequestMs = config.get<number>("slowRequestMs") ?? 2000;
  const extraArgs = parseExtraArgs(config.get<string[]>("extraArgs") ?? []);
  const roots = parsePathSettings(config.get<string[]>("roots") ?? [], root);
  const exclude = parsePathSettings(config.get<string[]>("exclude") ?? [], root);
  const initializationOptions: BifrostInitializationOptions = {};
  if (roots.length > 0) {
    initializationOptions.roots = roots;
  }
  if (exclude.length > 0) {
    initializationOptions.exclude = exclude;
  }

  let launchConfig: BifrostLaunchConfig;
  try {
    launchConfig = buildLaunchConfig(
      root,
      context.extensionUri.fsPath,
      mode,
      command,
      extraArgs,
      debug,
      slowRequestMs
    );
  } catch (error) {
    const message = formatError(error);
    setStatus("$(error) Bifrost", message);
    log(`Startup configuration failed: ${message}`);
    void vscode.window.showErrorMessage(`Bifrost: ${message}`);
    return;
  }

  lastLaunchConfig = launchConfig;
  setStatus("$(sync~spin) Bifrost", "Starting Bifrost language server...");
  log(`Starting Bifrost language server using ${launchConfig.label} launch mode.`);

  const serverOptions: ServerOptions = async () => {
    const handle = spawnBifrostServer(launchConfig, log);
    log(`Command: ${handle.commandLine}`);
    return handle.process;
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "java" },
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "typescriptreact" },
      { scheme: "file", language: "rust" },
      { scheme: "file", language: "go" },
      { scheme: "file", language: "python" },
      { scheme: "file", language: "c" },
      { scheme: "file", language: "cpp" },
      { scheme: "file", language: "csharp" },
      { scheme: "file", language: "php" },
      { scheme: "file", language: "scala" },
      { scheme: "file", language: "ruby" }
    ],
    outputChannel,
    initializationOptions,
    revealOutputChannelOn: RevealOutputChannelOn.Error,
    initializationFailedHandler: (error) => {
      const message = formatError(error);
      log(`Bifrost language server failed to initialize: ${message}`);
      setStatus("$(error) Bifrost", message);
      return false;
    },
    errorHandler: {
      error: (error) => {
        const message = formatError(error);
        log(`Bifrost language server connection error: ${message}`);
        setStatus("$(error) Bifrost", message);
        return { action: ErrorAction.Shutdown, handled: true };
      },
      closed: () => {
        log("Bifrost language server connection closed.");
        setStatus("$(circle-slash) Bifrost", "Bifrost language server is stopped.");
        return { action: CloseAction.DoNotRestart, handled: true };
      }
    },
    synchronize: {
      fileEvents: sourceFileWatchers()
    }
  };

  client = new LanguageClient("bifrost", "Bifrost", serverOptions, clientOptions);
  try {
    await client.start();
    const modeLabel = lastLaunchConfig?.label ?? "unknown";
    setStatus(
      "$(check) Bifrost",
      `Bifrost language server is running (${modeLabel}). Click to restart.`
    );
    setStatusCommand("bifrost.restartServer");
    log("Bifrost language client started.");
  } catch (error) {
    const message = formatError(error);
    setStatus("$(error) Bifrost", `${message}\n\nClick to retry.`);
    setStatusCommand("bifrost.startServer");
    log(`Bifrost language client failed to start: ${message}`);
    outputChannel?.show(true);
  }
}

async function stopClient(options: { updateUi?: boolean } = {}): Promise<void> {
  const updateUi = options.updateUi ?? true;
  const current = client;
  if (!current) {
    if (updateUi) {
      setStatus("$(circle-slash) Bifrost", "Bifrost language server is stopped.");
    }
    return;
  }

  if (current.state !== State.Running && current.state !== State.Starting) {
    client = undefined;
    if (updateUi) {
      setStatus("$(circle-slash) Bifrost", "Bifrost language server is stopped.");
    }
    return;
  }

  if (updateUi) {
    setStatus("$(sync~spin) Bifrost", "Stopping Bifrost language server...");
  }
  try {
    await current.stop();
    log("Bifrost language client stopped.");
  } catch (error) {
    log(`Bifrost language client failed to stop: ${formatError(error)}`);
  } finally {
    client = undefined;
    if (updateUi) {
      setStatus("$(circle-slash) Bifrost", "Bifrost language server is stopped.");
      setStatusCommand("bifrost.startServer");
    }
  }
}

async function restartClient(context: vscode.ExtensionContext): Promise<void> {
  log("Restarting Bifrost language server...");
  await stopClient();
  await startClient(context);
}

async function promptRestartAfterConfigurationChange(
  context: vscode.ExtensionContext
): Promise<void> {
  const choice = await vscode.window.showInformationMessage(
    "Bifrost settings changed. Restart the language server to apply them?",
    "Restart",
    "Later"
  );
  if (choice === "Restart") {
    await restartClient(context);
  }
}

function setStatus(text: string, tooltip: string): void {
  if (!extensionActive || !statusBarItem) {
    return;
  }
  statusBarItem.text = text;
  statusBarItem.tooltip = tooltip;
}

function setStatusCommand(command: string): void {
  if (!extensionActive || !statusBarItem) {
    return;
  }
  statusBarItem.command = command;
}

function log(message: string): void {
  const timestamp = new Date().toISOString();
  outputChannel?.appendLine(`[${timestamp}] ${message}`);
}
