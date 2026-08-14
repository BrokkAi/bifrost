import * as vscode from "vscode";
import type {
  PolicyDisplayStep,
  PolicyFinding,
  PolicyReportDiagnostic,
  PolicyReportEvaluation,
  PolicyRule,
  PolicyRun,
  PolicyRunDiagnostic,
  PolicySuppressionReview,
  RqlPolicyResponse
} from "./rql_policy";
import {
  policyCompletionDetail,
  policyCompletionLabel,
  policyFindingDisplayRows,
  policyFindingDetail,
  policyFindingTerminalSymbol,
  policyRunDiagnosticCodeLabel,
  policySuppressionAuditSummary
} from "./rql_policy";

export interface PolicyFindingTarget {
  reportRootUri: string;
  finding: PolicyFinding;
}

export interface PolicyDisplayStepTarget {
  reportRootUri: string;
  step: PolicyDisplayStep;
}

type PolicyTreeItem =
  | PolicyStaleItem
  | PolicyRunItem
  | PolicyFindingItem
  | PolicyDisplayStepItem
  | PolicySuppressionSummaryItem
  | PolicySuppressionReviewItem
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
        ...activeFindings(element.run).map(
          (finding) => new PolicyFindingItem(element.reportRootUri, finding)
        )
      );
      return children;
    }
    if (element instanceof PolicySuppressionSummaryItem) {
      return element.reviews.map((review) => new PolicySuppressionReviewItem(review));
    }
    if (element instanceof PolicyFindingItem) {
      return policyFindingDisplayRows(element.finding).map(
        (step, index) => new PolicyDisplayStepItem(element.reportRootUri, step, index)
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
    if (this.response.report.diagnostics_truncated) {
      items.push(
        new PolicyTruncationItem(
          `At least ${this.response.report.omitted_diagnostics_lower_bound} additional report diagnostics were omitted.`
        )
      );
    }
    if (this.response.report.suppressions.length > 0) {
      items.push(
        new PolicySuppressionSummaryItem(
          this.response.report.evaluation,
          this.response.report.suppressions
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
      activeFindings(run).length > 0 || run.diagnostics.length > 0 || run.diagnostics_truncated
        ? vscode.TreeItemCollapsibleState.Expanded
        : vscode.TreeItemCollapsibleState.None
    );
    const active = activeFindings(run);
    const completion = policyCompletionLabel(run.completion);
    const findings = `${active.length} active ${active.length === 1 ? "finding" : "findings"}`;
    const suppressed = run.findings.length - active.length;
    this.description =
      suppressed > 0
        ? `${completion} · ${findings} · ${suppressed} suppressed`
        : `${completion} · ${findings}`;
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

class PolicySuppressionSummaryItem extends vscode.TreeItem {
  constructor(
    evaluation: PolicyReportEvaluation,
    readonly reviews: PolicySuppressionReview[]
  ) {
    super("Suppression audit", vscode.TreeItemCollapsibleState.Expanded);
    const omitted = reviews.filter((review) => review.result_omitted).length;
    this.description = policySuppressionAuditSummary(reviews);
    this.tooltip = `Evaluated ${evaluation.suppression_path} on ${evaluation.evaluation_date}; document ${evaluation.suppression_document_state.replaceAll("_", " ")}.`;
    this.iconPath = new vscode.ThemeIcon(omitted > 0 ? "error" : "verified");
  }
}

class PolicySuppressionReviewItem extends vscode.TreeItem {
  constructor(review: PolicySuppressionReview) {
    super(
      `${review.policy_id} · ${review.finding_id.slice(0, 12)}`,
      vscode.TreeItemCollapsibleState.None
    );
    const states = [
      review.applied ? "applied" : review.match_state.replaceAll("_", " "),
      review.temporal_state === "expired" ? "expired" : undefined,
      review.policy_hash_state === "drifted" ? "policy hash drifted" : undefined,
      review.stale ? "stale" : undefined,
      review.result_omitted ? "result omitted" : undefined
    ].filter((state): state is string => state !== undefined);
    this.description = states.join(" · ");
    const tooltip = new vscode.MarkdownString();
    tooltip.appendMarkdown("**Policy:** ");
    tooltip.appendText(review.policy_id);
    tooltip.appendMarkdown("  \n**Finding:** ");
    tooltip.appendText(review.finding_id);
    tooltip.appendMarkdown("  \n**Reason:** ");
    tooltip.appendText(review.reason);
    tooltip.appendMarkdown("  \n**Accepted:** ");
    tooltip.appendText(
      review.accepted_by ? `${review.accepted_at} by ${review.accepted_by}` : review.accepted_at
    );
    tooltip.appendMarkdown("\n\n**Audit state**\n\n");
    tooltip.appendCodeblock(JSON.stringify(review, null, 2), "json");
    this.tooltip = tooltip;
    this.iconPath = new vscode.ThemeIcon(suppressionReviewIcon(review));
  }
}

class PolicyFindingItem extends vscode.TreeItem {
  constructor(
    readonly reportRootUri: string,
    readonly finding: PolicyFinding
  ) {
    super(
      compactText(finding.message),
      policyFindingDisplayRows(finding).length > 0
        ? vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None
    );
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

class PolicyDisplayStepItem extends vscode.TreeItem {
  constructor(
    reportRootUri: string,
    readonly step: PolicyDisplayStep,
    index: number
  ) {
    super(`${index + 1}. ${compactText(step.label)}`, vscode.TreeItemCollapsibleState.None);
    const region = step.location.region;
    const location = region
      ? `${step.location.path}:${region.start_line}:${region.start_column}`
      : step.location.path;
    this.description = `${step.kind} · ${location}`;
    this.tooltip = `${step.kind.toUpperCase()}\n${step.label}\n\n${location}`;
    this.iconPath = new vscode.ThemeIcon(displayStepIcon(step));
    this.command = {
      command: "bifrost.openRqlPolicyDisplayStep",
      title: "Open Bifrost Policy Display Step",
      arguments: [{ reportRootUri, step } satisfies PolicyDisplayStepTarget]
    };
  }
}

function displayStepIcon(step: PolicyDisplayStep): string {
  switch (step.kind) {
    case "source":
      return "debug-start";
    case "call":
      return "call-outgoing";
    case "return":
      return "call-incoming";
    case "sink":
      return "target";
    case "propagation":
      return "arrow-right";
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
      return activeFindings(run).length > 0 ? "issues" : "pass";
    case "proven_subset":
      return "warning";
    case "inconclusive":
      return "question";
    case "unsupported":
      return "circle-slash";
    case "failed":
      return "error";
  }
}

function activeFindings(run: PolicyRun): PolicyFinding[] {
  return run.findings.filter((finding) => finding.suppression === null);
}

function suppressionReviewIcon(review: PolicySuppressionReview): string {
  if (review.result_omitted) {
    return "error";
  }
  if (review.stale) {
    return "history";
  }
  if (review.temporal_state === "expired") {
    return "watch";
  }
  if (review.policy_hash_state === "drifted") {
    return "warning";
  }
  if (review.applied) {
    return "verified";
  }
  return "question";
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
