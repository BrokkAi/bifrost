import * as vscode from "vscode";
import type {
  PolicyFinding,
  PolicyReportDiagnostic,
  PolicyRule,
  PolicyRun,
  RqlPolicyResponse
} from "./rql_policy";
import {
  policyCompletionDetail,
  policyCompletionLabel,
  policyFindingDetail,
  policyFindingTerminalSymbol
} from "./rql_policy";

export interface PolicyFindingTarget {
  workspaceRootUri: string;
  finding: PolicyFinding;
}

type PolicyTreeItem = PolicyStaleItem | PolicyRunItem | PolicyFindingItem | PolicyDiagnosticItem;

export class RqlPolicyResultsProvider implements vscode.TreeDataProvider<PolicyTreeItem> {
  private readonly changeEmitter = new vscode.EventEmitter<PolicyTreeItem | undefined>();
  private response: RqlPolicyResponse | undefined;
  private staleReason: string | undefined;

  readonly onDidChangeTreeData = this.changeEmitter.event;

  update(response: RqlPolicyResponse): void {
    this.response = response;
    this.staleReason = undefined;
    this.changeEmitter.fire(undefined);
  }

  markStale(reason: string): void {
    if (!this.response || this.staleReason === reason) {
      return;
    }
    this.staleReason = reason;
    this.changeEmitter.fire(undefined);
  }

  getTreeItem(element: PolicyTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: PolicyTreeItem): vscode.ProviderResult<PolicyTreeItem[]> {
    if (element instanceof PolicyRunItem) {
      return element.run.findings.map(
        (finding) => new PolicyFindingItem(element.workspaceRootUri, finding)
      );
    }
    if (element) {
      return [];
    }
    if (!this.response) {
      return [];
    }

    const items: PolicyTreeItem[] = [];
    if (this.staleReason) {
      items.push(new PolicyStaleItem(this.staleReason));
    }
    items.push(
      ...this.response.report.diagnostics.map((diagnostic) => new PolicyDiagnosticItem(diagnostic))
    );
    const rules = new Map(
      this.response.report.rules.map((rule) => [rule.policy_id, rule] as const)
    );
    items.push(
      ...this.response.report.runs.map(
        (run) => new PolicyRunItem(this.response!.workspaceRootUri, run, rules.get(run.policy_id))
      )
    );
    return items;
  }

  dispose(): void {
    this.changeEmitter.dispose();
  }
}

class PolicyStaleItem extends vscode.TreeItem {
  constructor(reason: string) {
    super("Results are stale", vscode.TreeItemCollapsibleState.None);
    this.description = reason;
    this.tooltip = `These findings were retained for inspection but no longer describe the current ${reason}.`;
    this.iconPath = new vscode.ThemeIcon("history");
  }
}

class PolicyRunItem extends vscode.TreeItem {
  constructor(
    readonly workspaceRootUri: string,
    readonly run: PolicyRun,
    rule: PolicyRule | undefined
  ) {
    super(
      rule ? `${rule.name} (${run.policy_id})` : run.policy_id,
      run.findings.length > 0
        ? vscode.TreeItemCollapsibleState.Expanded
        : vscode.TreeItemCollapsibleState.None
    );
    const completion = policyCompletionLabel(run.completion);
    const findings = `${run.findings.length} ${run.findings.length === 1 ? "finding" : "findings"}`;
    this.description = `${completion} · ${findings}`;
    this.tooltip = new vscode.MarkdownString(
      `**${rule?.name ?? run.policy_id}**  \nPolicy ID: \`${run.policy_id}\`  \nAnalysis: \`${
        run.analysis_type
      }\`  \n${policyCompletionDetail(run.completion)}`
    );
    this.iconPath = new vscode.ThemeIcon(completionIcon(run));
  }
}

class PolicyFindingItem extends vscode.TreeItem {
  constructor(
    workspaceRootUri: string,
    readonly finding: PolicyFinding
  ) {
    super(compactText(finding.message), vscode.TreeItemCollapsibleState.None);
    const terminal = policyFindingTerminalSymbol(finding);
    const region = finding.primary.region;
    const location = region
      ? `${finding.primary.path}:${region.start_line}:${region.start_column}`
      : finding.primary.path;
    this.description = terminal
      ? `${finding.severity} · ${terminal} · ${location}`
      : `${finding.severity} · ${location}`;
    const tooltip = new vscode.MarkdownString(
      `**${finding.severity.toUpperCase()}** — ${finding.message}  \n\`${location}\``
    );
    tooltip.appendMarkdown("\n\n**Evidence and provenance**\n\n");
    tooltip.appendCodeblock(policyFindingDetail(finding), "json");
    this.tooltip = tooltip;
    this.iconPath = new vscode.ThemeIcon(severityIcon(finding.severity));
    this.command = {
      command: "bifrost.openRqlPolicyFinding",
      title: "Open Bifrost Policy Finding",
      arguments: [{ workspaceRootUri, finding } satisfies PolicyFindingTarget]
    };
  }
}

class PolicyDiagnosticItem extends vscode.TreeItem {
  constructor(diagnostic: PolicyReportDiagnostic) {
    super(compactText(diagnostic.message), vscode.TreeItemCollapsibleState.None);
    this.description = `${diagnostic.severity} · ${diagnostic.code}`;
    this.tooltip = diagnostic.source
      ? `${diagnostic.message}\n\nSource: ${diagnostic.source}`
      : diagnostic.message;
    this.iconPath = new vscode.ThemeIcon(severityIcon(diagnostic.severity));
  }
}

function completionIcon(run: PolicyRun): string {
  switch (run.completion.type) {
    case "complete":
      return run.findings.length > 0 ? "issues" : "pass";
    case "inconclusive":
      return "question";
    case "unsupported":
      return "circle-slash";
    case "failed":
      return "error";
  }
}

function severityIcon(severity: string): string {
  switch (severity) {
    case "error":
      return "error";
    case "warning":
      return "warning";
    default:
      return "info";
  }
}

function compactText(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}
