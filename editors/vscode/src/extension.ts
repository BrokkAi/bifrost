import * as vscode from "vscode";
import type { LanguageClientOptions, ServerOptions } from "vscode-languageclient/node";
import {
  CloseAction,
  ErrorAction,
  LanguageClient,
  RevealOutputChannelOn,
  State
} from "vscode-languageclient/node";
import type {
  BifrostLaunchConfig,
  BifrostFormatterCommandRule,
  BifrostInitializationOptions,
  BifrostMcpConfig,
  LaunchMode
} from "./lifecycle";
import {
  BIFROST_GITIGNORE_ASK_AGAIN_LATER,
  BIFROST_GITIGNORE_DONT_ASK_AGAIN,
  bifrostConfigurationChangeRequiresRestart,
  buildBifrostInitializationOptions,
  buildLaunchConfig,
  buildMcpConfig,
  buildMcpHostCommands,
  decideBifrostGitignorePrompt,
  formatError,
  parseExtraArgs,
  replaceLegacyBifrostGitignoreEntry,
  selectTrustedFormatterCommands,
  sourceFileWatchers,
  spawnBifrostServer,
  supportedWorkspaceRoot,
  validateLaunchCommand,
  workspaceGitignoreIncludesLegacyBifrostEntry
} from "./lifecycle";
import {
  activatePreparedManagedBinary,
  findCompatibleManagedBinary,
  installManagedBinary,
  normalizeBinaryCompatibility,
  releaseAssetFor,
  releaseTargetFor,
  selectManagedBinaryAndPreparePreferred
} from "./provisioning";
import type { BinaryCompatibility, ManagedBinaryPreparation } from "./provisioning";
import type {
  RqlQueryDocument,
  RqlQueryNavigationTarget,
  RqlQueryResponse,
  RqlQueryResultItem
} from "./rql_query";
import {
  codePointColumnToUtf16,
  formatRqlQueryOutput,
  queryResultRange,
  runRqlQuery
} from "./rql_query";
import { RqlQueryResultsProvider } from "./rql_results";
import type {
  PolicySourceLocation,
  PolicySuppressionAuthoringParams,
  PolicySuppressionAuthoringResponse,
  PolicySuppressionDestination,
  RqlPolicyDocument,
  RqlPolicyResponse
} from "./rql_policy";
import {
  PREPARE_POLICY_SUPPRESSION_METHOD,
  decodePolicySuppressionAuthoringResponse,
  ExpectedPolicySuppressionWrite,
  isPolicyFindingSuppressible,
  isPolicySuppressionDestination,
  normalizeSuppressionReason,
  PolicyRunTracker,
  policyLocationRange,
  policyReportCompletedWithoutFindings,
  runRqlPolicy,
  utcEvaluationDate
} from "./rql_policy";
import {
  effectivePolicyFindingSourceVersion,
  PolicyFindingItem,
  type PolicyDisplayStepTarget,
  type PolicyFindingTarget
} from "./rql_policy_results";
import { RqlPolicyResultsProvider } from "./rql_policy_results";
import type { RuneIrRange, RuneIrResponse } from "./rune_ir";
import { RUNE_IR_LANGUAGE_ID, RUNE_IR_SOURCE_LANGUAGE_IDS, showRuneIr } from "./rune_ir";
import type { WireDiagnostic, WireHover } from "./rql_validation";
import {
  RQL_POLICY_LANGUAGE_ID,
  RqlValidationController,
  handleRqlServerClosed,
  hoverRequest,
  rqlFileDocumentSelectors,
  validationDocument,
  validationRequest
} from "./rql_validation";
let client: LanguageClient | undefined;
let statusBarItem: vscode.StatusBarItem | undefined;
let outputChannel: vscode.OutputChannel | undefined;
let rqlQueryResults: RqlQueryResultsProvider | undefined;
let rqlPolicyResults: RqlPolicyResultsProvider | undefined;
let activePolicyRunCancellation: vscode.CancellationTokenSource | undefined;
const policyRunTracker = new PolicyRunTracker();
let rqlDiagnostics: vscode.DiagnosticCollection | undefined;
let rqlValidation: RqlValidationController<vscode.CancellationToken> | undefined;
let lastLaunchConfig: BifrostLaunchConfig | undefined;
let startInFlight: Promise<void> | undefined;
let pendingManagedBinaryPreparation: ManagedBinaryPreparation | undefined;
let extensionActive = false;
const expectedPolicySuppressionWrite = new ExpectedPolicySuppressionWrite();
const BIFROST_GITIGNORE_DECLINED_KEY_PREFIX = "bifrost.legacyGitignoreMigrationDeclined:";

export function activate(context: vscode.ExtensionContext): void {
  extensionActive = true;
  outputChannel = vscode.window.createOutputChannel("Bifrost");
  context.subscriptions.push(outputChannel);
  rqlQueryResults = new RqlQueryResultsProvider();
  context.subscriptions.push(rqlQueryResults);
  rqlPolicyResults = new RqlPolicyResultsProvider();
  context.subscriptions.push(rqlPolicyResults);
  rqlDiagnostics = vscode.languages.createDiagnosticCollection("Bifrost RQL");
  context.subscriptions.push(rqlDiagnostics);
  rqlValidation = createRqlValidationController();
  context.subscriptions.push(
    vscode.window.createTreeView("bifrost.queryResults", {
      treeDataProvider: rqlQueryResults,
      showCollapseAll: true
    }),
    vscode.window.createTreeView("bifrost.policyResults", {
      treeDataProvider: rqlPolicyResults,
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
    vscode.commands.registerCommand("bifrost.clearRqlPolicyResults", () => {
      cancelActivePolicyRun();
      rqlPolicyResults?.clear();
    }),
    vscode.commands.registerCommand("bifrost.runRqlQuery", (resource?: vscode.Uri) =>
      runRqlQueryForEditor(resource)
    ),
    vscode.commands.registerCommand("bifrost.runRqlPolicy", (resource?: vscode.Uri) =>
      runRqlPolicyForEditor(resource)
    ),
    vscode.commands.registerCommand("bifrost.showRuneIr", () => showRuneIrForEditor()),
    vscode.commands.registerCommand(
      "bifrost.openRqlQueryResult",
      (result: RqlQueryResultItem | RqlQueryNavigationTarget) => openRqlQueryResult(result)
    ),
    vscode.commands.registerCommand("bifrost.openRqlPolicyFinding", (target: PolicyFindingTarget) =>
      openRqlPolicyFinding(target)
    ),
    vscode.commands.registerCommand(
      "bifrost.suppressRqlPolicyFinding",
      (target: PolicyFindingTarget | PolicyFindingItem) => suppressRqlPolicyFinding(target)
    ),
    vscode.commands.registerCommand(
      "bifrost.openRqlPolicyDisplayStep",
      (target: PolicyDisplayStepTarget) => openRqlPolicyDisplayStep(target)
    ),
    vscode.commands.registerCommand("bifrost.copyMcpConfig", () => copyMcpConfig(context)),
    vscode.commands.registerCommand("bifrost.openMcpSetup", () => openMcpSetup(context))
  );

  const policyWorkspaceWatcher = vscode.workspace.createFileSystemWatcher(
    "**/*.{java,go,c,cc,cpp,cxx,h,hpp,hh,hxx,inc,js,mjs,cjs,jsx,ts,tsx,py,rs,php,scala,kt,kts,cs,rb,rql,rqlp,json,toml}"
  );
  const markWorkspacePolicyResultsStale = async (uri: vscode.Uri): Promise<void> => {
    if (!isGeneratedWorkspacePath(uri)) {
      if (expectedPolicySuppressionWrite.isPending(uri.toString())) {
        try {
          const content = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString("utf8");
          if (expectedPolicySuppressionWrite.observe(uri.toString(), content)) {
            return;
          }
        } catch {
          expectedPolicySuppressionWrite.clear(uri.toString());
        }
      }
      markPolicyResultsStale("workspace changed");
    }
  };
  context.subscriptions.push(
    policyWorkspaceWatcher,
    policyWorkspaceWatcher.onDidChange(markWorkspacePolicyResultsStale),
    policyWorkspaceWatcher.onDidCreate(markWorkspacePolicyResultsStale),
    policyWorkspaceWatcher.onDidDelete(markWorkspacePolicyResultsStale)
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      markPolicyResultsStale("workspace folders changed");
      if (client?.state === State.Running) {
        void restartClient(context);
      }
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (
        event.affectsConfiguration("bifrost.roots") ||
        event.affectsConfiguration("bifrost.exclude")
      ) {
        markPolicyResultsStale("analyzer scope changed");
      }
      if (
        client?.state === State.Running &&
        bifrostConfigurationChangeRequiresRestart((section) => event.affectsConfiguration(section))
      ) {
        void promptRestartAfterConfigurationChange(context);
      }
    }),
    vscode.workspace.onDidOpenTextDocument((document) => {
      rqlValidation?.schedule(validationDocument(document));
    }),
    vscode.workspace.onDidChangeTextDocument((event) => {
      rqlValidation?.schedule(validationDocument(event.document));
      markPolicyResultsStale(
        event.document.languageId === "bifrost-rql-policy" ? "policy changed" : "workspace changed"
      );
    }),
    vscode.workspace.onDidCloseTextDocument((document) => {
      rqlValidation?.close(document.uri.toString());
    }),
    vscode.languages.registerHoverProvider(rqlFileDocumentSelectors(), {
      provideHover: async (document, position, token) => {
        const currentClient = client;
        if (currentClient?.state !== State.Running) {
          return undefined;
        }
        const request = hoverRequest(document.languageId, document.getText(), {
          line: position.line,
          character: position.character
        });
        if (!request) {
          return undefined;
        }
        try {
          const hover = await currentClient.sendRequest<WireHover | null>(
            request.method,
            request.params,
            token
          );
          return hover ? vscodeHover(hover) : undefined;
        } catch {
          return undefined;
        }
      }
    })
  );

  void startClient(context);
}

async function showRuneIrForEditor(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  const document = editor?.document;
  const currentClient = client;
  const selection = editor?.selection;
  const selectedRange: RuneIrRange | undefined =
    selection && !selection.isEmpty
      ? {
          start: { line: selection.start.line, character: selection.start.character },
          end: { line: selection.end.line, character: selection.end.character }
        }
      : undefined;
  const position = selection
    ? { line: selection.active.line, character: selection.active.character }
    : undefined;
  await showRuneIr(
    document ? { uri: document.uri.toString(), languageId: document.languageId } : undefined,
    selectedRange,
    position,
    {
      isReady: () => currentClient?.state === State.Running,
      sendRequest: (method, params) => currentClient!.sendRequest<RuneIrResponse>(method, params),
      showError: (message) => {
        void vscode.window.showErrorMessage(message);
      },
      showWarning: (message) => {
        void vscode.window.showWarningMessage(message);
      },
      showDocument: async (text, languageId) => {
        const result = await vscode.workspace.openTextDocument({
          content: text,
          language: languageId
        });
        await vscode.window.showTextDocument(result, { preview: true });
      }
    }
  );
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

  if (response.mode !== "results") {
    outputChannel?.appendLine(`\n[CodeQuery ${response.mode}]\n${formatRqlQueryOutput(response)}`);
    outputChannel?.show(true);
  }
  rqlQueryResults.update(response);
  if (response.mode !== "explain") {
    await vscode.commands.executeCommand("bifrost.queryResults.focus");
  }
  if (response.mode === "results" && response.results.length === 0) {
    void vscode.window.showInformationMessage("Bifrost RQL query returned no results.");
  }
}

async function runRqlPolicyForEditor(resource?: vscode.Uri): Promise<void> {
  const document = resource
    ? await vscode.workspace.openTextDocument(resource)
    : vscode.window.activeTextEditor?.document;
  const policyDocument: RqlPolicyDocument | undefined = document
    ? {
        languageId: document.languageId,
        uri: document.uri.toString(),
        text: document.getText(),
        version: document.version
      }
    : undefined;
  const currentClient = client;
  const runSnapshot = policyRunTracker.beginRun();
  activePolicyRunCancellation?.cancel();
  activePolicyRunCancellation?.dispose();
  const cancellation = new vscode.CancellationTokenSource();
  activePolicyRunCancellation = cancellation;
  rqlPolicyResults?.markStale("a new policy run started");
  let response: RqlPolicyResponse | undefined;
  try {
    response = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Running Bifrost RQL policy",
        cancellable: true
      },
      async (_progress, progressCancellation) => {
        const subscription = progressCancellation.onCancellationRequested(() => {
          cancellation.cancel();
        });
        try {
          return await runRqlPolicy(policyDocument, {
            isReady: () => currentClient?.state === State.Running,
            sendRequest: (method, params) =>
              currentClient!.sendRequest<RqlPolicyResponse>(method, params, cancellation.token),
            showError: (message) => {
              if (!cancellation.token.isCancellationRequested) {
                void vscode.window.showErrorMessage(message);
              }
            },
            showWarning: (message) => {
              void vscode.window.showWarningMessage(message);
            }
          });
        } finally {
          subscription.dispose();
        }
      }
    );
  } finally {
    if (activePolicyRunCancellation === cancellation) {
      activePolicyRunCancellation = undefined;
    }
    cancellation.dispose();
  }
  if (!response || !rqlPolicyResults) {
    return;
  }

  const publication = policyRunTracker.publicationFor(runSnapshot);
  if (!publication.publish) {
    return;
  }
  rqlPolicyResults.update(response, policyDocument);
  if (publication.staleReason) {
    rqlPolicyResults.markStale(publication.staleReason);
  }
  await vscode.commands.executeCommand("bifrost.policyResults.focus");
  if (!publication.staleReason && policyReportCompletedWithoutFindings(response.report)) {
    void vscode.window.showInformationMessage("Bifrost RQL policy completed with no findings.");
  }
}

function markPolicyResultsStale(reason: string): void {
  policyRunTracker.markChanged(reason);
  rqlPolicyResults?.markStale(reason);
}

async function openRqlQueryResult(
  result: RqlQueryResultItem | RqlQueryNavigationTarget
): Promise<void> {
  const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(result.uri));
  const editor = await vscode.window.showTextDocument(document, { preview: true });
  const resultRange = "result_type" in result ? queryResultRange(result) : result.range;
  if (resultRange) {
    const startLine = Math.min(Math.max(0, resultRange.start_line - 1), document.lineCount - 1);
    const endLine = Math.min(Math.max(startLine, resultRange.end_line - 1), document.lineCount - 1);
    const startColumn = codePointColumnToUtf16(
      document.lineAt(startLine).text,
      resultRange.start_column
    );
    const endColumn = codePointColumnToUtf16(document.lineAt(endLine).text, resultRange.end_column);
    const start = new vscode.Position(startLine, startColumn);
    const end = new vscode.Position(endLine, endColumn);
    const range = new vscode.Range(start, end);
    editor.selection = new vscode.Selection(start, end);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    return;
  }
  const resultStartLine = 1;
  const resultEndLine = resultStartLine;
  const startLine = Math.min(Math.max(0, resultStartLine - 1), document.lineCount - 1);
  const endLine = Math.min(Math.max(startLine, resultEndLine - 1), document.lineCount - 1);
  const start = new vscode.Position(startLine, 0);
  const end = document.lineAt(endLine).range.end;
  const range = new vscode.Range(start, end);
  editor.selection = new vscode.Selection(start, end);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
}

async function openRqlPolicyFinding(target: PolicyFindingTarget): Promise<void> {
  return openRqlPolicyLocation(target.reportRootUri, target.finding.primary);
}

async function suppressRqlPolicyFinding(
  target: PolicyFindingTarget | PolicyFindingItem
): Promise<void> {
  const normalizedTarget: PolicyFindingTarget =
    target instanceof PolicyFindingItem
      ? {
          reportRootUri: target.reportRootUri,
          finding: target.finding,
          policyDocument: target.policyDocument,
          resultGeneration: target.resultGeneration,
          sourceVersion: target.sourceVersion
        }
      : target;
  if (
    !isPolicyFindingSuppressible(normalizedTarget.finding) ||
    !rqlPolicyResults?.canSuppress(normalizedTarget.finding, normalizedTarget.resultGeneration)
  ) {
    void vscode.window.showWarningMessage(
      "This policy finding is stale, already suppressed, or does not have a strong identity."
    );
    return;
  }
  const sourceVersion = effectivePolicyFindingSourceVersion(
    normalizedTarget.reportRootUri,
    normalizedTarget.finding,
    normalizedTarget.sourceVersion
  );
  if (!client || client.state !== State.Running) {
    void vscode.window.showWarningMessage(
      "Bifrost is not ready. Start the language server before authoring a suppression."
    );
    return;
  }

  const destination = await choosePolicySuppressionDestination();
  if (!destination) {
    return;
  }
  const reasonInput = await vscode.window.showInputBox({
    title: "Suppress Bifrost policy finding",
    prompt: "Reason (optional)",
    placeHolder: 'Leave blank to use "unspecified"',
    ignoreFocusOut: true
  });
  if (reasonInput === undefined) {
    return;
  }
  const workspaceRoot = vscode.Uri.parse(normalizedTarget.reportRootUri);
  const requireReason = vscode.workspace
    .getConfiguration("bifrost", workspaceRoot)
    .get<boolean>("requireSuppressionReason", false);
  const reason = normalizeSuppressionReason(reasonInput, requireReason);
  if (!reason) {
    void vscode.window.showErrorMessage(
      "A suppression reason is required by the bifrost.requireSuppressionReason setting."
    );
    return;
  }

  const policyDocument = normalizedTarget.policyDocument ?? currentPolicyDocument();
  if (!policyDocument) {
    void vscode.window.showWarningMessage(
      "Open the RQL policy document that produced this finding before suppressing it."
    );
    return;
  }
  const params: PolicySuppressionAuthoringParams = {
    reportRootUri: normalizedTarget.reportRootUri,
    policyDocumentUri: policyDocument.uri,
    policyDocumentVersion: policyDocument.version,
    finding: {
      policyId: normalizedTarget.finding.policy_id,
      findingId: normalizedTarget.finding.id,
      path: normalizedTarget.finding.primary.path,
      identityStability: "strong",
      policyHash: normalizedTarget.finding.policy_hash,
      sourceUri: sourceUriForFinding(normalizedTarget.reportRootUri, normalizedTarget.finding),
      sourceVersion
    },
    destination,
    evaluationDate: utcEvaluationDate(),
    reason
  };

  let rawResponse: unknown;
  try {
    rawResponse = await client.sendRequest<unknown>(PREPARE_POLICY_SUPPRESSION_METHOD, params);
  } catch (error) {
    void vscode.window.showErrorMessage(
      `Bifrost could not prepare the suppression: ${formatError(error)}`
    );
    return;
  }
  const response = decodePolicySuppressionAuthoringResponse(rawResponse);
  if (!response) {
    void vscode.window.showErrorMessage("Bifrost returned an invalid suppression edit.");
    return;
  }
  if (!(await applyPreparedPolicySuppression(response))) {
    return;
  }

  const rerunUri = policyDocument.uri ? vscode.Uri.parse(policyDocument.uri) : undefined;
  await runRqlPolicyForEditor(rerunUri);
}

async function choosePolicySuppressionDestination(): Promise<
  PolicySuppressionDestination | undefined
> {
  const choice = await vscode.window.showQuickPick(
    [
      {
        label: "Public (.bifrost/suppressions.json)",
        description: "Share this suppression with the project.",
        destination: "public" as const
      },
      {
        label: "Private (.bifrost/suppressions.private.json)",
        description: "Keep this suppression out of the public project file.",
        destination: "private" as const
      },
      {
        label: "Local (.bifrost/suppressions.local.json)",
        description: "Keep this suppression local to your checkout.",
        destination: "local" as const
      }
    ],
    {
      title: "Choose suppression destination",
      placeHolder: "Public suppression file"
    }
  );
  return choice && isPolicySuppressionDestination(choice.destination)
    ? choice.destination
    : undefined;
}

function currentPolicyDocument(): RqlPolicyDocument | undefined {
  const document = vscode.window.activeTextEditor?.document;
  return document && document.languageId === RQL_POLICY_LANGUAGE_ID
    ? {
        languageId: document.languageId,
        uri: document.uri.toString(),
        text: document.getText(),
        version: document.version
      }
    : undefined;
}

function sourceUriForFinding(
  reportRootUri: string,
  finding: PolicyFindingTarget["finding"]
): string {
  return vscode.Uri.joinPath(vscode.Uri.parse(reportRootUri), finding.primary.path).toString();
}

async function applyPreparedPolicySuppression(
  response: PolicySuppressionAuthoringResponse
): Promise<boolean> {
  const uri = vscode.Uri.parse(response.documentUri);
  let document: vscode.TextDocument | undefined;
  if (response.create) {
    try {
      await vscode.workspace.fs.stat(uri);
      void vscode.window.showWarningMessage(
        "The suppression destination was created after the request. Reload the finding and retry."
      );
      return false;
    } catch (error) {
      if (!(error instanceof vscode.FileSystemError) || error.code !== "FileNotFound") {
        void vscode.window.showErrorMessage(
          `Bifrost could not inspect the suppression destination: ${formatError(error)}`
        );
        return false;
      }
      // A missing destination is expected for a create response.
    }
  } else {
    try {
      document = await vscode.workspace.openTextDocument(uri);
    } catch (error) {
      void vscode.window.showErrorMessage(
        `Bifrost could not open the suppression file: ${formatError(error)}`
      );
      return false;
    }
    if (response.expectedVersion !== null && document.version !== response.expectedVersion) {
      void vscode.window.showWarningMessage(
        "The suppression file changed while the edit was being prepared. Reload the finding and retry."
      );
      return false;
    }
    if (
      response.expectedText !== undefined &&
      response.expectedText !== null &&
      document.getText() !== response.expectedText
    ) {
      void vscode.window.showWarningMessage(
        "The suppression file changed while the edit was being prepared. Reload the finding and retry."
      );
      return false;
    }
  }

  if (!(await verifyPolicySuppressionSourcePreconditions(response))) {
    return false;
  }
  if (response.create) {
    const parent = vscode.Uri.joinPath(uri, "..");
    try {
      await vscode.workspace.fs.stat(parent);
    } catch (error) {
      if (!(error instanceof vscode.FileSystemError) || error.code !== "FileNotFound") {
        void vscode.window.showErrorMessage(
          `Bifrost could not inspect the suppression directory: ${formatError(error)}`
        );
        return false;
      }
      try {
        await vscode.workspace.fs.createDirectory(parent);
      } catch (createError) {
        void vscode.window.showErrorMessage(
          `Bifrost could not create the suppression directory: ${formatError(createError)}`
        );
        return false;
      }
    }
    // Directory creation is the only setup write before the WorkspaceEdit;
    // verify the complete source snapshot again after that setup.
    if (!(await verifyPolicySuppressionSourcePreconditions(response))) {
      return false;
    }
  }

  expectedPolicySuppressionWrite.expect(uri.toString(), response.content);
  const edit = new vscode.WorkspaceEdit();
  if (response.create) {
    edit.createFile(uri, { ignoreIfExists: false });
    edit.insert(uri, new vscode.Position(0, 0), response.content);
  } else {
    if (!document) {
      return false;
    }
    edit.replace(
      uri,
      new vscode.Range(new vscode.Position(0, 0), document.positionAt(document.getText().length)),
      response.content
    );
  }
  if (!(await vscode.workspace.applyEdit(edit))) {
    expectedPolicySuppressionWrite.clear(uri.toString());
    void vscode.window.showErrorMessage("VS Code could not apply the prepared suppression edit.");
    return false;
  }
  const saved = await vscode.workspace.openTextDocument(uri);
  if (!(await saved.save())) {
    expectedPolicySuppressionWrite.clear(uri.toString());
    void vscode.window.showErrorMessage("VS Code could not save the suppression document.");
    return false;
  }
  return true;
}

async function verifyPolicySuppressionSourcePreconditions(
  response: PolicySuppressionAuthoringResponse
): Promise<boolean> {
  for (const source of response.sourcePreconditions) {
    const uri = vscode.Uri.parse(source.uri);
    let exists: boolean;
    try {
      await vscode.workspace.fs.stat(uri);
      exists = true;
    } catch (error) {
      if (error instanceof vscode.FileSystemError && error.code === "FileNotFound") {
        exists = false;
      } else {
        void vscode.window.showErrorMessage(
          `Bifrost could not inspect suppression source ${source.path}: ${formatError(error)}`
        );
        return false;
      }
    }
    if (exists !== source.exists) {
      void vscode.window.showWarningMessage(
        `A suppression source changed after preparation (${source.path} appeared or disappeared). Reload the finding and retry.`
      );
      return false;
    }
    if (!exists) {
      continue;
    }

    let document: vscode.TextDocument;
    try {
      document = await vscode.workspace.openTextDocument(uri);
    } catch (error) {
      void vscode.window.showErrorMessage(
        `Bifrost could not read suppression source ${source.path}: ${formatError(error)}`
      );
      return false;
    }
    if (source.expectedVersion !== null && document.version !== source.expectedVersion) {
      void vscode.window.showWarningMessage(
        `A suppression source changed after preparation (${source.path} has a newer document version). Reload the finding and retry.`
      );
      return false;
    }
    if (
      source.expectedText !== undefined &&
      source.expectedText !== null &&
      document.getText() !== source.expectedText
    ) {
      void vscode.window.showWarningMessage(
        `A suppression source changed after preparation (${source.path} contents differ). Reload the finding and retry.`
      );
      return false;
    }
  }
  return true;
}

async function openRqlPolicyDisplayStep(target: PolicyDisplayStepTarget): Promise<void> {
  return openRqlPolicyLocation(target.reportRootUri, target.step.location);
}

async function openRqlPolicyLocation(
  reportRootUri: string,
  location: PolicySourceLocation
): Promise<void> {
  const root = vscode.Uri.parse(reportRootUri);
  const uri = vscode.Uri.joinPath(root, location.path);
  const document = await vscode.workspace.openTextDocument(uri);
  const editor = await vscode.window.showTextDocument(document, { preview: true });
  const locationRange = policyLocationRange(location);
  if (!locationRange) {
    return;
  }
  const startLine = Math.min(locationRange.start.line, document.lineCount - 1);
  const endLine = Math.min(Math.max(startLine, locationRange.end.line), document.lineCount - 1);
  const startColumn = Math.min(
    locationRange.start.character,
    document.lineAt(startLine).text.length
  );
  const endColumn = Math.min(locationRange.end.character, document.lineAt(endLine).text.length);
  const start = new vscode.Position(startLine, startColumn);
  const end = new vscode.Position(endLine, endColumn);
  const range = new vscode.Range(start, end);
  editor.selection = new vscode.Selection(start, end);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
}

function isGeneratedWorkspacePath(uri: vscode.Uri): boolean {
  return ["/.brokk/", "/.git/", "/node_modules/", "/target/"].some((part) =>
    uri.path.includes(part)
  );
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
  schedulePreparedManagedBinaryActivation(context);
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
  void promptReplaceLegacyBifrostGitignore(context, root);

  const config = vscode.workspace.getConfiguration("bifrost");
  const command = config.get<string>("serverPath") || "bifrost";
  const mode = config.get<LaunchMode>("launchMode") || "auto";
  const debug = config.get<boolean>("debug") ?? false;
  const slowRequestMs = config.get<number>("slowRequestMs") ?? 2000;
  const extraArgs = parseExtraArgs(config.get<string[]>("extraArgs") ?? []);
  const initializationOptions = currentBifrostRuntimeSettings(root, config);

  let launchConfig: BifrostLaunchConfig;
  try {
    const managedBinary = await prepareManagedBinary(context, mode, command);
    const managedBinaryPath = managedBinary?.selected.path ?? null;
    pendingManagedBinaryPreparation = managedBinary?.preferredInstall ? managedBinary : undefined;
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

  const serverOptions: ServerOptions = () => {
    const handle = spawnBifrostServer(launchConfig, log);
    log(`Command: ${handle.commandLine}`);
    return Promise.resolve(handle.process);
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      ...RUNE_IR_SOURCE_LANGUAGE_IDS.map((language) => ({ scheme: "file", language })),
      ...rqlFileDocumentSelectors(),
      { scheme: "file", language: RUNE_IR_LANGUAGE_ID }
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
        cancelActivePolicyRun();
        markPolicyResultsStale("language server stopped");
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
  cancelActivePolicyRun();
  markPolicyResultsStale("language server stopped");
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

function cancelActivePolicyRun(): void {
  activePolicyRunCancellation?.cancel();
  activePolicyRunCancellation?.dispose();
  activePolicyRunCancellation = undefined;
}

function createRqlValidationController(): RqlValidationController<vscode.CancellationToken> {
  return new RqlValidationController<vscode.CancellationToken>({
    validate: async (document, token) => {
      const currentClient = client;
      if (currentClient?.state !== State.Running) {
        throw new Error("Bifrost is not running");
      }
      const request = validationRequest(document);
      if (!request) {
        throw new Error(`Unsupported RQL source language: ${document.languageId}`);
      }
      return currentClient.sendRequest<{ diagnostics: WireDiagnostic[] }>(
        request.method,
        request.params,
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
      return current?.languageId === expected.languageId && current.version === expected.version;
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

async function promptReplaceLegacyBifrostGitignore(
  context: vscode.ExtensionContext,
  workspaceRoot: string
): Promise<void> {
  const declinedKey = `${BIFROST_GITIGNORE_DECLINED_KEY_PREFIX}${workspaceRoot}`;
  if (context.workspaceState.get<boolean>(declinedKey)) {
    return;
  }

  let hasLegacyEntry: boolean;
  try {
    hasLegacyEntry = await workspaceGitignoreIncludesLegacyBifrostEntry(workspaceRoot);
  } catch (error) {
    log(`Failed to inspect .gitignore for legacy Bifrost entry: ${formatError(error)}`);
    return;
  }

  if (!hasLegacyEntry) {
    await context.workspaceState.update(declinedKey, undefined);
    return;
  }

  const choice = await vscode.window.showInformationMessage(
    "Bifrost now tracks project configuration in .bifrost. Replace the legacy .bifrost ignore rule with .bifrost/cache/?",
    "Replace",
    BIFROST_GITIGNORE_ASK_AGAIN_LATER,
    BIFROST_GITIGNORE_DONT_ASK_AGAIN
  );
  const decision = decideBifrostGitignorePrompt(choice);
  if (decision === "defer") {
    log("User deferred replacing the legacy .bifrost ignore.");
    return;
  }
  if (decision === "decline") {
    await context.workspaceState.update(declinedKey, true);
    log("User declined replacing the legacy .bifrost ignore.");
    return;
  }

  try {
    await replaceLegacyBifrostGitignoreEntry(workspaceRoot);
    await context.workspaceState.update(declinedKey, undefined);
    log("Replaced legacy .bifrost ignore with .bifrost/cache/ in .gitignore.");
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
  const managedBinary = await prepareManagedBinary(context, mode, command);
  const managedBinaryPath = managedBinary?.selected.path ?? null;
  return buildMcpConfig(root, context.extensionUri.fsPath, mode, command, managedBinaryPath);
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
): Promise<ManagedBinaryPreparation | null> {
  const configured = configuredPath.trim();
  if (mode === "path" || (mode === "auto" && configured && configured !== "bifrost")) {
    return null;
  }

  const compatibility = requiredBinaryCompatibility(context);
  const binaryVersion = compatibility.binaryVersion;
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

  const managed = await selectManagedBinaryAndPreparePreferred(
    () => findCompatibleManagedBinary(storageDir, compatibility),
    () => installManagedBinaryForContext(context, compatibility, archiveSha256),
    log
  );
  if (!managed) {
    const binaryPath = await promptAndInstallManagedBinary(
      context,
      mode,
      compatibility,
      archiveSha256
    );
    if (!binaryPath && mode === "bundled") {
      throw new Error(
        `Bifrost ${binaryVersion} is not installed for ${process.platform}-${process.arch}.`
      );
    }
    return binaryPath
      ? {
          selected: {
            path: binaryPath,
            version: binaryVersion,
            compatibilityMode: "exact"
          },
          preferredInstall: null
        }
      : null;
  }
  if (managed.selected.compatibilityMode === "compatible") {
    log(
      `Using compatible managed Bifrost ${managed.selected.version}; preferred ${binaryVersion}.`
    );
  }
  return managed;
}

function schedulePreparedManagedBinaryActivation(context: vscode.ExtensionContext): void {
  const preparation = pendingManagedBinaryPreparation;
  pendingManagedBinaryPreparation = undefined;
  if (!preparation) {
    return;
  }

  void activatePreparedManagedBinary(
    preparation,
    (selectedPath) =>
      extensionActive &&
      client?.state === State.Running &&
      lastLaunchConfig?.command === selectedPath,
    async (preferredPath) => {
      log(`Preferred managed Bifrost is ready at ${preferredPath}; restarting language server.`);
      await restartClient(context);
    }
  ).catch((error: unknown) => {
    log(`Preferred managed Bifrost activation failed: ${formatError(error)}`);
  });
}

async function promptAndInstallManagedBinary(
  context: vscode.ExtensionContext,
  mode: LaunchMode,
  compatibility: BinaryCompatibility,
  archiveSha256: string
): Promise<string | null> {
  const binaryVersion = compatibility.binaryVersion;
  const choice = await vscode.window.showInformationMessage(
    `Install Bifrost ${binaryVersion} for ${process.platform}-${process.arch}?`,
    "Install",
    mode === "auto" ? "Use PATH" : "Cancel"
  );
  if (choice !== "Install") {
    log("Managed Bifrost install was skipped.");
    return null;
  }
  return tryInstallManagedBinaryForMode(context, mode, compatibility, archiveSha256);
}

async function tryInstallManagedBinaryForMode(
  context: vscode.ExtensionContext,
  mode: LaunchMode,
  compatibility: BinaryCompatibility,
  archiveSha256: string
): Promise<string | null> {
  try {
    return await installManagedBinaryForContext(context, compatibility, archiveSha256);
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
  compatibility: BinaryCompatibility,
  archiveSha256: string
): Promise<string> {
  const binaryVersion = compatibility.binaryVersion;
  setStatus("$(sync~spin) Bifrost", `Installing Bifrost ${binaryVersion}...`);
  try {
    return await installManagedBinary({
      storageDir: context.globalStorageUri.fsPath,
      version: binaryVersion,
      minimumBinaryVersion: compatibility.minimumBinaryVersion,
      allowPrerelease: compatibility.allowPrerelease,
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

function requiredBinaryCompatibility(context: vscode.ExtensionContext): BinaryCompatibility {
  const packageJson = context.extension.packageJSON as {
    bifrost?: {
      binaryVersion?: string;
      minimumBinaryVersion?: string;
      allowPrerelease?: boolean;
    };
  };
  const binaryVersion = packageJson.bifrost?.binaryVersion?.trim();
  const minimumBinaryVersion = packageJson.bifrost?.minimumBinaryVersion?.trim();
  const allowPrerelease = packageJson.bifrost?.allowPrerelease;
  if (!binaryVersion) {
    throw new Error("Extension package metadata is missing bifrost.binaryVersion.");
  }
  if (!minimumBinaryVersion) {
    throw new Error("Extension package metadata is missing bifrost.minimumBinaryVersion.");
  }
  if (allowPrerelease === undefined) {
    throw new Error("Extension package metadata is missing bifrost.allowPrerelease.");
  }
  return normalizeBinaryCompatibility({ binaryVersion, minimumBinaryVersion, allowPrerelease });
}

function requiredArchiveSha256(context: vscode.ExtensionContext, binaryVersion: string): string {
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
