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
  BifrostFormatterCommandRule,
  BifrostInitializationOptions,
  bifrostConfigurationChangeRequiresRestart,
  buildBifrostInitializationOptions,
  buildLaunchConfig,
  buildMcpConfig,
  buildMcpHostCommands,
  BifrostMcpConfig,
  formatError,
  LaunchMode,
  appendBifrostGitignoreEntry,
  parseExtraArgs,
  selectTrustedFormatterCommands,
  sourceFileWatchers,
  spawnBifrostServer,
  supportedWorkspaceRoot,
  validateLaunchCommand,
  workspaceGitignoreNeedsBifrostEntry
} from "./lifecycle";
import {
  findManagedBinary,
  installManagedBinary,
  isVersionCompatible,
  probeBifrostVersion,
  releaseAssetFor,
  releaseTargetFor
} from "./provisioning";
import {
  queryResultRange,
  RqlQueryDocument,
  RqlQueryResponse,
  RqlQueryResultItem,
  runRqlQuery
} from "./rql_query";
import { RqlQueryResultsProvider } from "./rql_results";
import {
  RQL_QUERY_HOVER_METHOD,
  RqlValidationController,
  VALIDATE_RQL_QUERY_METHOD,
  WireDiagnostic,
  WireHover,
  handleRqlServerClosed,
  queryHoverParams,
  validationDocument
} from "./rql_validation";
import { RQL_LANGUAGE_ID } from "./rql_query";

let client: LanguageClient | undefined;
let statusBarItem: vscode.StatusBarItem | undefined;
let outputChannel: vscode.OutputChannel | undefined;
let rqlQueryResults: RqlQueryResultsProvider | undefined;
let rqlDiagnostics: vscode.DiagnosticCollection | undefined;
let rqlValidation: RqlValidationController<vscode.CancellationToken> | undefined;
let lastLaunchConfig: BifrostLaunchConfig | undefined;
let startInFlight: Promise<void> | undefined;
let extensionActive = false;
const BIFROST_GITIGNORE_DECLINED_KEY_PREFIX = "bifrost.gitignorePromptDeclined:";

export function activate(context: vscode.ExtensionContext): void {
  extensionActive = true;
  outputChannel = vscode.window.createOutputChannel("Bifrost");
  context.subscriptions.push(outputChannel);
  rqlQueryResults = new RqlQueryResultsProvider();
  context.subscriptions.push(rqlQueryResults);
  rqlDiagnostics = vscode.languages.createDiagnosticCollection("Bifrost RQL");
  context.subscriptions.push(rqlDiagnostics);
  rqlValidation = createRqlValidationController();
  context.subscriptions.push(
    vscode.window.createTreeView("bifrost.queryResults", {
      treeDataProvider: rqlQueryResults,
      showCollapseAll: true
    })
  );

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
    vscode.commands.registerCommand("bifrost.showOutput", () => outputChannel?.show(true)),
    vscode.commands.registerCommand("bifrost.runRqlQuery", (resource?: vscode.Uri) =>
      runRqlQueryForEditor(resource)
    ),
    vscode.commands.registerCommand("bifrost.openRqlQueryResult", (result: RqlQueryResultItem) =>
      openRqlQueryResult(result)
    ),
    vscode.commands.registerCommand("bifrost.copyMcpConfig", () => copyMcpConfig(context)),
    vscode.commands.registerCommand("bifrost.openMcpSetup", () => openMcpSetup(context))
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      if (client?.state === State.Running) {
        void restartClient(context);
      }
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (
        client?.state === State.Running &&
        bifrostConfigurationChangeRequiresRestart((section) =>
          event.affectsConfiguration(section)
        )
      ) {
        void promptRestartAfterConfigurationChange(context);
      }
    }),
    vscode.workspace.onDidOpenTextDocument((document) => {
      rqlValidation?.schedule(validationDocument(document));
    }),
    vscode.workspace.onDidChangeTextDocument((event) => {
      rqlValidation?.schedule(validationDocument(event.document));
    }),
    vscode.workspace.onDidCloseTextDocument((document) => {
      rqlValidation?.close(document.uri.toString());
    }),
    vscode.languages.registerHoverProvider(
      { scheme: "file", language: RQL_LANGUAGE_ID },
      {
        provideHover: async (document, position, token) => {
          const currentClient = client;
          if (currentClient?.state !== State.Running) {
            return undefined;
          }
          try {
            const hover = await currentClient.sendRequest<WireHover | null>(
              RQL_QUERY_HOVER_METHOD,
              queryHoverParams(document.getText(), {
                line: position.line,
                character: position.character
              }),
              token
            );
            return hover ? vscodeHover(hover) : undefined;
          } catch {
            return undefined;
          }
        }
      }
    )
  );

  void startClient(context);
}

async function runRqlQueryForEditor(resource?: vscode.Uri): Promise<void> {
  const document = resource
    ? await vscode.workspace.openTextDocument(resource)
    : vscode.window.activeTextEditor?.document;
  const queryDocument: RqlQueryDocument | undefined = document
    ? {
        languageId: document.languageId,
        text: document.getText()
      }
    : undefined;
  const currentClient = client;
  const response = await runRqlQuery(queryDocument, {
    isReady: () => currentClient?.state === State.Running,
    sendRequest: (method, params) => currentClient!.sendRequest<RqlQueryResponse>(method, params),
    showError: (message) => {
      void vscode.window.showErrorMessage(message);
    },
    showWarning: (message) => {
      void vscode.window.showWarningMessage(message);
    }
  });
  if (!response || !rqlQueryResults) {
    return;
  }

  rqlQueryResults.update(response);
  await vscode.commands.executeCommand("bifrost.queryResults.focus");
  if (response.results.length === 0) {
    void vscode.window.showInformationMessage("Bifrost RQL query returned no results.");
  }
}

async function openRqlQueryResult(result: RqlQueryResultItem): Promise<void> {
  const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(result.uri));
  const editor = await vscode.window.showTextDocument(document, { preview: true });
  if (result.result_type === "reference_site") {
    const resultRange = queryResultRange(result);
    if (!resultRange) {
      return;
    }
    const startLine = Math.min(Math.max(0, resultRange.start_line - 1), document.lineCount - 1);
    const endLine = Math.min(Math.max(startLine, resultRange.end_line - 1), document.lineCount - 1);
    const startColumn = Math.min(
      Math.max(0, resultRange.start_column - 1),
      document.lineAt(startLine).text.length
    );
    const endColumn = Math.min(
      Math.max(0, resultRange.end_column - 1),
      document.lineAt(endLine).text.length
    );
    const start = new vscode.Position(startLine, startColumn);
    const end = new vscode.Position(endLine, endColumn);
    const range = new vscode.Range(start, end);
    editor.selection = new vscode.Selection(start, end);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    return;
  }
  const resultStartLine = result.result_type === "file" ? 1 : result.start_line;
  const resultEndLine = result.result_type === "file" ? resultStartLine : result.end_line;
  const startLine = Math.min(Math.max(0, resultStartLine - 1), document.lineCount - 1);
  const endLine = Math.min(Math.max(startLine, resultEndLine - 1), document.lineCount - 1);
  const start = new vscode.Position(startLine, 0);
  const end = document.lineAt(endLine).range.end;
  const range = new vscode.Range(start, end);
  editor.selection = new vscode.Selection(start, end);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
}

export function deactivate(): Thenable<void> | undefined {
  extensionActive = false;
  return stopClient({ updateUi: false });
}

async function startClient(context: vscode.ExtensionContext): Promise<void> {
  if (startInFlight) {
    setStatus("$(sync~spin) Bifrost", "Bifrost language server is already starting.");
    log("Bifrost language server startup is already in progress.");
    return startInFlight;
  }

  const startPromise = startClientInner(context);
  startInFlight = startPromise;
  try {
    await startPromise;
  } finally {
    if (startInFlight === startPromise) {
      startInFlight = undefined;
    }
  }
}

async function startClientInner(context: vscode.ExtensionContext): Promise<void> {
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
  void promptAppendBifrostGitignore(context, root);

  const config = vscode.workspace.getConfiguration("bifrost");
  const command = config.get<string>("serverPath") || "bifrost";
  const mode = config.get<LaunchMode>("launchMode") || "auto";
  const debug = config.get<boolean>("debug") ?? false;
  const slowRequestMs = config.get<number>("slowRequestMs") ?? 2000;
  const extraArgs = parseExtraArgs(config.get<string[]>("extraArgs") ?? []);
  const initializationOptions = currentBifrostRuntimeSettings(root, config);

  let launchConfig: BifrostLaunchConfig;
  try {
    const managedBinaryPath = await prepareManagedBinary(context, mode, command);
    launchConfig = buildLaunchConfig(
      root,
      context.extensionUri.fsPath,
      mode,
      command,
      extraArgs,
      debug,
      slowRequestMs,
      managedBinaryPath
    );
  } catch (error) {
    const message = formatError(error);
    setStatus("$(error) Bifrost", message);
    log(`Startup configuration failed: ${message}`);
    void vscode.window.showErrorMessage(`Bifrost: ${message}`);
    return;
  }

  lastLaunchConfig = launchConfig;
  try {
    await validateLaunchCommand(launchConfig);
  } catch (error) {
    const message = formatError(error);
    setStatus("$(error) Bifrost", `${message}\n\nClick to retry.`);
    setStatusCommand("bifrost.startServer");
    log(`Bifrost launch validation failed: ${message}`);
    void vscode.window.showErrorMessage(`Bifrost: ${message}`);
    return;
  }

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
      { scheme: "file", language: "ruby" },
      { scheme: "file", language: RQL_LANGUAGE_ID }
    ],
    outputChannel,
    initializationOptions,
    middleware: {
      workspace: {
        configuration: async (params, token, next) => {
          if (params.items.length === 1 && params.items[0].section === "bifrost") {
            const currentRoot = supportedWorkspaceRoot() ?? root;
            return [
              currentBifrostRuntimeSettings(
                currentRoot,
                vscode.workspace.getConfiguration("bifrost")
              )
            ];
          }
          return next(params, token);
        }
      }
    },
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
        if (client?.state === State.Starting) {
          return { action: ErrorAction.Continue, handled: true };
        }
        return { action: ErrorAction.Shutdown, handled: true };
      },
      closed: () => {
        log("Bifrost language server connection closed.");
        handleRqlServerClosed(rqlValidation);
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
    for (const document of vscode.workspace.textDocuments) {
      rqlValidation?.schedule(validationDocument(document));
    }
  } catch (error) {
    const message = formatError(error);
    setStatus("$(error) Bifrost", `${message}\n\nClick to retry.`);
    setStatusCommand("bifrost.startServer");
    log(`Bifrost language client failed to start: ${message}`);
    outputChannel?.show(true);
  }
}

function trustedFormatterCommands(
  config: vscode.WorkspaceConfiguration
): BifrostFormatterCommandRule[] {
  const inspected = config.inspect<BifrostFormatterCommandRule[]>("formatterCommands");
  const selection = selectTrustedFormatterCommands(inspected);
  if (selection.ignoredWorkspaceRules) {
    log(
      "Ignoring workspace-scoped bifrost.formatterCommands; configure formatter commands in user settings."
    );
  }
  return selection.rules;
}

function currentBifrostRuntimeSettings(
  root: string,
  config: vscode.WorkspaceConfiguration
): BifrostInitializationOptions {
  return buildBifrostInitializationOptions(
    root,
    config.get<string[]>("roots") ?? [],
    config.get<string[]>("exclude") ?? [],
    trustedFormatterCommands(config),
    config.get<boolean>("unrecognizedSymbolDiagnostics") ?? false
  );
}

async function stopClient(options: { updateUi?: boolean } = {}): Promise<void> {
  rqlValidation?.stop();
  const updateUi = options.updateUi ?? true;
  const startup = startInFlight;
  if (startup) {
    if (updateUi) {
      setStatus("$(sync~spin) Bifrost", "Waiting for Bifrost startup to finish...");
    }
    await startup.catch((error) => {
      log(`Bifrost startup completed with error before stop: ${formatError(error)}`);
    });
  }

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

function createRqlValidationController(): RqlValidationController<vscode.CancellationToken> {
  return new RqlValidationController<vscode.CancellationToken>({
    validate: async (query, token) => {
      const currentClient = client;
      if (currentClient?.state !== State.Running) {
        throw new Error("Bifrost is not running");
      }
      return currentClient.sendRequest<{ diagnostics: WireDiagnostic[] }>(
        VALIDATE_RQL_QUERY_METHOD,
        { query },
        token
      );
    },
    publish: (uri, diagnostics) => {
      rqlDiagnostics?.set(vscode.Uri.parse(uri), diagnostics.map(vscodeDiagnostic));
    },
    clear: (uri) => {
      rqlDiagnostics?.delete(vscode.Uri.parse(uri));
    },
    isCurrent: (expected) => {
      const current = vscode.workspace.textDocuments.find(
        (document) => document.uri.toString() === expected.uri
      );
      return current?.languageId === RQL_LANGUAGE_ID && current.version === expected.version;
    },
    createCancellationSource: () => new vscode.CancellationTokenSource(),
    setTimer: (callback, delayMs) => setTimeout(callback, delayMs),
    clearTimer: (timer) => clearTimeout(timer as NodeJS.Timeout)
  });
}

function vscodeDiagnostic(diagnostic: WireDiagnostic): vscode.Diagnostic {
  const value = new vscode.Diagnostic(
    vscodeRange(diagnostic.range),
    diagnostic.message,
    vscode.DiagnosticSeverity.Error
  );
  value.code = diagnostic.code;
  value.source = diagnostic.source;
  return value;
}

function vscodeHover(hover: WireHover): vscode.Hover {
  const contents = new vscode.MarkdownString(hover.contents.value);
  contents.isTrusted = false;
  return new vscode.Hover(contents, hover.range ? vscodeRange(hover.range) : undefined);
}

function vscodeRange(range: {
  start: { line: number; character: number };
  end: { line: number; character: number };
}): vscode.Range {
  return new vscode.Range(
    range.start.line,
    range.start.character,
    range.end.line,
    range.end.character
  );
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

async function promptAppendBifrostGitignore(
  context: vscode.ExtensionContext,
  workspaceRoot: string
): Promise<void> {
  const declinedKey = `${BIFROST_GITIGNORE_DECLINED_KEY_PREFIX}${workspaceRoot}`;
  if (context.workspaceState.get<boolean>(declinedKey)) {
    return;
  }

  let needsEntry: boolean;
  try {
    needsEntry = await workspaceGitignoreNeedsBifrostEntry(workspaceRoot);
  } catch (error) {
    log(`Failed to inspect .gitignore for Bifrost cache entry: ${formatError(error)}`);
    return;
  }

  if (!needsEntry) {
    await context.workspaceState.update(declinedKey, undefined);
    return;
  }

  const choice = await vscode.window.showInformationMessage(
    "Bifrost stores workspace cache data in .bifrost. Add .bifrost to .gitignore?",
    "Add",
    "No"
  );
  if (choice !== "Add") {
    await context.workspaceState.update(declinedKey, true);
    log("User declined adding .bifrost to .gitignore.");
    return;
  }

  try {
    await appendBifrostGitignoreEntry(workspaceRoot);
    await context.workspaceState.update(declinedKey, undefined);
    log("Added .bifrost to .gitignore.");
  } catch (error) {
    const message = formatError(error);
    log(`Failed to update .gitignore for Bifrost cache entry: ${message}`);
    void vscode.window.showWarningMessage(`Bifrost could not update .gitignore: ${message}`);
  }
}

async function copyMcpConfig(context: vscode.ExtensionContext): Promise<void> {
  try {
    const mcpConfig = await resolveMcpConfig(context);
    await copyText(`${JSON.stringify(mcpConfig, null, 2)}\n`, "Bifrost MCP configuration");
  } catch (error) {
    const message = formatError(error);
    log(`MCP configuration generation failed: ${message}`);
    void vscode.window.showErrorMessage(`Bifrost: ${message}`);
  }
}

async function openMcpSetup(context: vscode.ExtensionContext): Promise<void> {
  let mcpConfig: BifrostMcpConfig;
  try {
    mcpConfig = await resolveMcpConfig(context);
  } catch (error) {
    const message = formatError(error);
    log(`MCP setup failed: ${message}`);
    void vscode.window.showErrorMessage(`Bifrost: ${message}`);
    return;
  }

  const hostCommands = buildMcpHostCommands(mcpConfig);
  const choice = await vscode.window.showQuickPick(
    [
      {
        label: "Copy generic mcp.json",
        detail: "Copy a JSON mcpServers entry for hosts that use mcp.json.",
        action: "json" as const
      },
      {
        label: "Copy Codex CLI command",
        detail: "Copy a codex mcp add command using the resolved Bifrost binary.",
        action: "codex" as const
      },
      {
        label: "Copy Claude Code command",
        detail: "Copy a claude mcp add command using the resolved Bifrost binary.",
        action: "claude" as const
      },
      {
        label: "Open Bifrost MCP docs",
        detail: "Open the MCP setup documentation in the Bifrost repository.",
        action: "docs" as const
      }
    ],
    {
      title: "Bifrost MCP Setup",
      placeHolder: "Choose an MCP setup action"
    }
  );

  if (!choice) {
    log("Bifrost MCP setup was dismissed.");
    return;
  }

  if (choice.action === "json") {
    await copyText(`${JSON.stringify(mcpConfig, null, 2)}\n`, "Bifrost MCP configuration");
  } else if (choice.action === "codex") {
    await copyText(`${hostCommands.codex}\n`, "Bifrost Codex MCP command");
  } else if (choice.action === "claude") {
    await copyText(`${hostCommands.claudeCode}\n`, "Bifrost Claude Code MCP command");
  } else {
    await vscode.env.openExternal(
      vscode.Uri.parse("https://github.com/BrokkAi/bifrost#integrating-with-mcp-hosts")
    );
    log("Opened Bifrost MCP documentation.");
  }
}

async function resolveMcpConfig(context: vscode.ExtensionContext): Promise<BifrostMcpConfig> {
  const root = supportedWorkspaceRoot();
  if (!root) {
    throw new Error("Open a folder to generate a Bifrost MCP configuration.");
  }

  const config = vscode.workspace.getConfiguration("bifrost");
  const command = config.get<string>("serverPath") || "bifrost";
  const mode = config.get<LaunchMode>("launchMode") || "auto";
  const managedBinaryPath = await prepareManagedBinary(context, mode, command);
  return buildMcpConfig(
    root,
    context.extensionUri.fsPath,
    mode,
    command,
    managedBinaryPath
  );
}

async function copyText(text: string, label: string): Promise<void> {
  await vscode.env.clipboard.writeText(text);
  log(`Copied ${label} to the clipboard.`);
  void vscode.window.showInformationMessage(`${label} copied to clipboard.`);
}

async function prepareManagedBinary(
  context: vscode.ExtensionContext,
  mode: LaunchMode,
  configuredPath: string
): Promise<string | null> {
  const configured = configuredPath.trim();
  if (mode === "path" || (mode === "auto" && configured && configured !== "bifrost")) {
    return null;
  }

  const binaryVersion = requiredBinaryVersion(context);
  const archiveSha256 = requiredArchiveSha256(context, binaryVersion);
  const storageDir = context.globalStorageUri.fsPath;
  try {
    releaseTargetFor();
  } catch (error) {
    const message = formatError(error);
    log(`Managed Bifrost binary is unavailable: ${message}`);
    if (mode === "bundled") {
      throw error;
    }
    return null;
  }

  let binaryPath = await findManagedBinary(storageDir, binaryVersion);
  if (!binaryPath) {
    binaryPath = await promptAndInstallManagedBinary(
      context,
      mode,
      binaryVersion,
      archiveSha256
    );
    if (!binaryPath && mode === "bundled") {
      throw new Error(`Bifrost ${binaryVersion} is not installed for ${process.platform}-${process.arch}.`);
    }
    return binaryPath;
  }

  return verifyManagedBinary(context, mode, binaryVersion, archiveSha256, binaryPath);
}

async function verifyManagedBinary(
  context: vscode.ExtensionContext,
  mode: LaunchMode,
  binaryVersion: string,
  archiveSha256: string,
  binaryPath: string
): Promise<string | null> {
  try {
    const probe = await probeBifrostVersion(binaryPath);
    if (isVersionCompatible(probe.version, binaryVersion)) {
      return binaryPath;
    }
    const found = probe.version ?? (probe.rawOutput || "unknown");
    log(`Managed Bifrost version mismatch: expected ${binaryVersion}, found ${found}.`);
    const choice = await vscode.window.showWarningMessage(
      `Bifrost ${binaryVersion} is required, but the managed binary is ${found}.`,
      "Update",
      mode === "auto" ? "Use PATH" : "Cancel"
    );
    if (choice === "Update") {
      return tryInstallManagedBinaryForMode(context, mode, binaryVersion, archiveSha256);
    }
    if (mode === "bundled") {
      throw new Error(`Managed Bifrost binary version ${found} does not match required ${binaryVersion}.`);
    }
    return null;
  } catch (error) {
    const message = formatError(error);
    log(`Managed Bifrost binary failed version check: ${message}`);
    const choice = await vscode.window.showWarningMessage(
      "The managed Bifrost binary could not be run. Reinstall it?",
      "Reinstall",
      mode === "auto" ? "Use PATH" : "Cancel"
    );
    if (choice === "Reinstall") {
      return tryInstallManagedBinaryForMode(context, mode, binaryVersion, archiveSha256);
    }
    if (mode === "bundled") {
      throw new Error(`Managed Bifrost binary is not runnable: ${message}`);
    }
    return null;
  }
}

async function promptAndInstallManagedBinary(
  context: vscode.ExtensionContext,
  mode: LaunchMode,
  binaryVersion: string,
  archiveSha256: string
): Promise<string | null> {
  const choice = await vscode.window.showInformationMessage(
    `Install Bifrost ${binaryVersion} for ${process.platform}-${process.arch}?`,
    "Install",
    mode === "auto" ? "Use PATH" : "Cancel"
  );
  if (choice !== "Install") {
    log("Managed Bifrost install was skipped.");
    return null;
  }
  return tryInstallManagedBinaryForMode(context, mode, binaryVersion, archiveSha256);
}

async function tryInstallManagedBinaryForMode(
  context: vscode.ExtensionContext,
  mode: LaunchMode,
  binaryVersion: string,
  archiveSha256: string
): Promise<string | null> {
  try {
    return await installManagedBinaryForContext(context, binaryVersion, archiveSha256);
  } catch (error) {
    if (mode === "bundled") {
      throw error;
    }
    void vscode.window.showWarningMessage(
      "Bifrost install failed. Falling back to a local development build or PATH binary."
    );
    return null;
  }
}

async function installManagedBinaryForContext(
  context: vscode.ExtensionContext,
  binaryVersion: string,
  archiveSha256: string
): Promise<string> {
  setStatus("$(sync~spin) Bifrost", `Installing Bifrost ${binaryVersion}...`);
  try {
    return await installManagedBinary({
      storageDir: context.globalStorageUri.fsPath,
      version: binaryVersion,
      expectedSha256: archiveSha256,
      platform: process.platform,
      arch: process.arch,
      log
    });
  } catch (error) {
    const message = formatError(error);
    log(`Managed Bifrost install failed: ${message}`);
    throw error;
  }
}

function requiredBinaryVersion(context: vscode.ExtensionContext): string {
  const packageJson = context.extension.packageJSON as {
    bifrost?: { binaryVersion?: string };
  };
  const version = packageJson.bifrost?.binaryVersion?.trim();
  if (!version) {
    throw new Error("Extension package metadata is missing bifrost.binaryVersion.");
  }
  return version.replace(/^v/, "");
}

function requiredArchiveSha256(
  context: vscode.ExtensionContext,
  binaryVersion: string
): string {
  const packageJson = context.extension.packageJSON as {
    bifrost?: {
      archiveSha256?: Record<string, string>;
    };
  };
  const target = releaseAssetFor(binaryVersion).target;
  const hash = packageJson.bifrost?.archiveSha256?.[target]?.trim();
  if (!hash) {
    throw new Error(`Extension package metadata is missing bifrost.archiveSha256.${target}.`);
  }
  return hash;
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
