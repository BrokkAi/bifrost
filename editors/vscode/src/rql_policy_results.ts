import * as vscode from "vscode";
import type {
  PolicyFinding,
  PolicyReportDiagnostic,
  PolicyRule,
  PolicyRun,
  PolicyRunDiagnostic,
  RqlPolicyResponse
} from "./rql_policy";
import {
  policyCompletionDetail,
  policyCompletionLabel,
  policyFindingDetail,
  policyFindingTerminalSymbol,
  policyRunDiagnosticCodeLabel
} from "./rql_policy";

export interface PolicyFindingTarget {
  reportRootUri: string;
  finding: PolicyFinding;
}

type PolicyTreeItem =
  | PolicyStaleItem
  | PolicyRunItem
  | PolicyFindingItem
  | PolicyDiagnosticItem
  | PolicyRunDiagnosticItem
  | PolicyTruncationItem;

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
      const children: PolicyTreeItem[] = element.run.diagnostics.map(
        (diagnostic) => new PolicyRunDiagnosticItem(diagnostic)
      );
      if (element.run.diagnostics_truncated) {
        children.push(new PolicyTruncationItem("Additional run diagnostics were omitted."));
      }
      children.push(
        ...element.run.findings.map(
          (finding) => new PolicyFindingItem(element.reportRootUri, finding)
        )
      );
      return children;
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
    if (this.response.report.diagnostics_truncated) {
      items.push(
        new PolicyTruncationItem(
          `At least ${this.response.report.omitted_diagnostics_lower_bound} additional report diagnostics were omitted.`
        )
      );
    }
    const rules = new Map(
      this.response.report.rules.map((rule) => [rule.policy_id, rule] as const)
    );
    items.push(
      ...this.response.report.runs.map(
        (run) => new PolicyRunItem(this.response!.reportRootUri, run, rules.get(run.policy_id))
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
    readonly reportRootUri: string,
    readonly run: PolicyRun,
    rule: PolicyRule | undefined
  ) {
    super(
      rule ? `${rule.name} (${run.policy_id})` : run.policy_id,
      run.findings.length > 0 || run.diagnostics.length > 0 || run.diagnostics_truncated
        ? vscode.TreeItemCollapsibleState.Expanded
        : vscode.TreeItemCollapsibleState.None
    );
    const completion = policyCompletionLabel(run.completion);
    const findings = `${run.findings.length} ${run.findings.length === 1 ? "finding" : "findings"}`;
    this.description = `${completion} · ${findings}`;
    const tooltip = new vscode.MarkdownString();
    tooltip.appendMarkdown("**Policy:** ");
    tooltip.appendText(rule?.name ?? run.policy_id);
    tooltip.appendMarkdown("  \n**Policy ID:** ");
    tooltip.appendText(run.policy_id);
    tooltip.appendMarkdown("  \n**Analysis:** ");
    tooltip.appendText(run.analysis_type);
    tooltip.appendMarkdown("  \n");
    tooltip.appendText(policyCompletionDetail(run.completion));
    this.tooltip = tooltip;
    this.iconPath = new vscode.ThemeIcon(completionIcon(run));
  }
}

class PolicyFindingItem extends vscode.TreeItem {
  constructor(
    reportRootUri: string,
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
    const tooltip = new vscode.MarkdownString();
    tooltip.appendMarkdown("**Severity:** ");
    tooltip.appendText(finding.severity.toUpperCase());
    tooltip.appendMarkdown("  \n**Message:** ");
    tooltip.appendText(finding.message);
    tooltip.appendMarkdown("  \n**Location:** ");
    tooltip.appendText(location);
    tooltip.appendMarkdown("\n\n**Evidence and provenance**\n\n");
    tooltip.appendCodeblock(policyFindingDetail(finding), "json");
    this.tooltip = tooltip;
    this.iconPath = new vscode.ThemeIcon(severityIcon(finding.severity));
    this.command = {
      command: "bifrost.openRqlPolicyFinding",
      title: "Open Bifrost Policy Finding",
      arguments: [{ reportRootUri, finding } satisfies PolicyFindingTarget]
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

class PolicyRunDiagnosticItem extends vscode.TreeItem {
  constructor(diagnostic: PolicyRunDiagnostic) {
    super(compactText(diagnostic.message), vscode.TreeItemCollapsibleState.None);
    this.description = `${diagnostic.severity} · ${policyRunDiagnosticCodeLabel(
      diagnostic.code
    )} · ${diagnostic.impact}`;
    this.tooltip = diagnostic.message;
    this.iconPath = new vscode.ThemeIcon(severityIcon(diagnostic.severity));
  }
}

class PolicyTruncationItem extends vscode.TreeItem {
  constructor(message: string) {
    super("Diagnostics truncated", vscode.TreeItemCollapsibleState.None);
    this.description = message;
    this.tooltip = message;
    this.iconPath = new vscode.ThemeIcon("ellipsis");
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
