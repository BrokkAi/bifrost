import { RQL_POLICY_LANGUAGE_ID } from "./rql_validation";

export const RUN_RQL_POLICY_METHOD = "bifrost/runPolicy";

export interface RqlPolicyDocument {
  languageId: string;
  uri: string;
  text: string;
}

export interface PolicyDisplayRegion {
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
}

export interface PolicySourceLocation {
  path: string;
  region?: PolicyDisplayRegion | null;
  byte_span?: { start: number; end: number } | null;
}

export type PolicyRunCompletion =
  | { type: "complete" }
  | { type: "proven_subset"; codes: readonly unknown[] }
  | { type: "inconclusive"; reasons: readonly unknown[] }
  | { type: "unsupported"; capability: unknown }
  | { type: "failed"; reasons: readonly unknown[] };

export interface PolicyFinding {
  id: string;
  policy_id: string;
  severity: string;
  message: string;
  primary: PolicySourceLocation;
  suppression: PolicyFindingSuppression | null;
  evidence?: unknown;
  proof?: unknown;
  related?: unknown[];
  witnesses?: unknown[];
  [key: string]: unknown;
}

export interface PolicySuppressionDecision {
  identity_stability: "strong";
  status: "accepted";
  reason: string;
  policy_hash_at_acceptance?: string | null;
  accepted_by?: string | null;
  accepted_at: string;
  expires_at?: string | null;
  [key: string]: unknown;
}

export interface PolicyFindingSuppression extends PolicySuppressionDecision {
  policy_hash_state: "matching" | "drifted" | "unknown";
}

export interface PolicySuppressionReview extends PolicySuppressionDecision {
  policy_id: string;
  finding_id: string;
  match_state:
    | "strong_finding"
    | "current_finding_not_strong"
    | "finding_absent"
    | "policy_not_evaluated"
    | "policy_incomplete";
  temporal_state: "current" | "expired";
  policy_hash_state: "matching" | "drifted" | "unknown";
  applied: boolean;
  stale: boolean;
  result_omitted: boolean;
}

export interface PolicyReportEvaluation {
  evaluation_date: string;
  suppression_path: string;
  suppression_document_state: "not_found" | "loaded" | "invalid";
}

export interface PolicyRun {
  policy_id: string;
  analysis_type: string;
  completion: PolicyRunCompletion;
  findings: PolicyFinding[];
  diagnostics: PolicyRunDiagnostic[];
  diagnostics_truncated: boolean;
  [key: string]: unknown;
}

export interface PolicyRunDiagnostic {
  code: PolicyRunDiagnosticCode;
  severity: string;
  impact: string;
  message: string;
  primary?: PolicySourceLocation | null;
  related?: unknown[];
}

export interface PolicyRunDiagnosticCode {
  type: string;
  code?: string;
}

export interface PolicyRule {
  policy_id: string;
  name: string;
  analysis_type: string;
  message: unknown;
  severity: unknown;
  [key: string]: unknown;
}

export interface PolicyReportDiagnostic {
  code: string;
  severity: string;
  message: string;
  source?: string | null;
  byte_range?: { start: number; end: number } | null;
  related?: unknown[];
}

export interface PolicyReport {
  schema_version: 2;
  evaluation: PolicyReportEvaluation;
  rules: PolicyRule[];
  runs: PolicyRun[];
  suppressions: PolicySuppressionReview[];
  diagnostics: PolicyReportDiagnostic[];
  diagnostics_truncated: boolean;
  omitted_diagnostics_lower_bound: number;
  worst_omitted_diagnostic_severity?: string | null;
}

export interface RqlPolicyResponse {
  policyRootUri: string;
  reportRootUri: string;
  report: PolicyReport;
}

export interface PolicyEditorRange {
  start: { line: number; character: number };
  end: { line: number; character: number };
}

export interface RqlPolicyRunner {
  isReady(): boolean;
  sendRequest(
    method: string,
    params: {
      documentUri: string;
      source: string;
      evaluationDate: string;
      suppressionFile?: string;
    }
  ): Promise<unknown>;
  showError(message: string): void;
  showWarning(message: string): void;
}

export async function runRqlPolicy(
  document: RqlPolicyDocument | undefined,
  runner: RqlPolicyRunner
): Promise<RqlPolicyResponse | undefined> {
  if (!document || document.languageId !== RQL_POLICY_LANGUAGE_ID) {
    runner.showWarning("Open a Bifrost RQL policy file to run a policy.");
    return undefined;
  }
  if (!runner.isReady()) {
    runner.showWarning(
      "Bifrost is not ready. Start the language server and wait for indexing to finish."
    );
    return undefined;
  }
  try {
    const response = await runner.sendRequest(RUN_RQL_POLICY_METHOD, {
      documentUri: document.uri,
      source: document.text,
      evaluationDate: utcEvaluationDate()
    });
    if (!isRqlPolicyResponse(response)) {
      runner.showError(
        "Bifrost policy results require an updated language server. Rebuild and restart Bifrost, then run the policy again."
      );
      return undefined;
    }
    return response;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    runner.showError(`Bifrost RQL policy failed: ${message}`);
    return undefined;
  }
}

export function utcEvaluationDate(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

export interface PolicyRunSnapshot {
  runId: number;
  contentRevision: number;
}

export interface PolicyRunPublication {
  publish: boolean;
  staleReason?: string;
}

export class PolicyRunTracker {
  private latestRunId = 0;
  private contentRevision = 0;
  private staleReason: string | undefined;

  beginRun(): PolicyRunSnapshot {
    return {
      runId: ++this.latestRunId,
      contentRevision: this.contentRevision
    };
  }

  markChanged(reason: string): void {
    this.contentRevision += 1;
    this.staleReason = reason;
  }

  publicationFor(snapshot: PolicyRunSnapshot): PolicyRunPublication {
    if (snapshot.runId !== this.latestRunId) {
      return { publish: false };
    }
    return {
      publish: true,
      staleReason: snapshot.contentRevision === this.contentRevision ? undefined : this.staleReason
    };
  }
}

export function isRqlPolicyResponse(value: unknown): value is RqlPolicyResponse {
  if (
    !isRecord(value) ||
    typeof value.policyRootUri !== "string" ||
    typeof value.reportRootUri !== "string"
  ) {
    return false;
  }
  const report = value.report;
  if (
    !isRecord(report) ||
    report.schema_version !== 2 ||
    !isPolicyReportEvaluation(report.evaluation) ||
    !Array.isArray(report.rules) ||
    !Array.isArray(report.runs) ||
    !Array.isArray(report.suppressions) ||
    !Array.isArray(report.diagnostics) ||
    typeof report.diagnostics_truncated !== "boolean" ||
    typeof report.omitted_diagnostics_lower_bound !== "number"
  ) {
    return false;
  }
  return (
    report.rules.every(isPolicyRule) &&
    report.runs.every(isPolicyRun) &&
    report.suppressions.every(isPolicySuppressionReview) &&
    report.diagnostics.every(isPolicyDiagnostic)
  );
}

export function policyCompletionLabel(completion: PolicyRunCompletion): string {
  switch (completion.type) {
    case "complete":
      return "complete";
    case "proven_subset":
      return "proven subset";
    case "inconclusive":
      return "inconclusive";
    case "unsupported":
      return "unsupported";
    case "failed":
      return "failed";
  }
}

export function policyCompletionDetail(completion: PolicyRunCompletion): string {
  switch (completion.type) {
    case "complete":
      return "The policy run is complete.";
    case "proven_subset":
      return `The policy run reports only a proven subset, not all callers: ${formatUnknown(
        completion.codes
      )}.`;
    case "inconclusive":
      return `The policy run was inconclusive: ${formatUnknown(completion.reasons)}.`;
    case "unsupported":
      return `The policy requires an unsupported capability: ${formatUnknown(
        completion.capability
      )}.`;
    case "failed":
      return `The policy run failed: ${formatUnknown(completion.reasons)}.`;
  }
}

export function policyReportCompletedWithoutFindings(report: PolicyReport): boolean {
  return (
    report.runs.length > 0 &&
    report.diagnostics.length === 0 &&
    !report.diagnostics_truncated &&
    report.runs.every(
      (run) =>
        run.completion.type === "complete" &&
        run.findings.every((finding) => finding.suppression !== null) &&
        run.diagnostics.length === 0 &&
        !run.diagnostics_truncated
    )
  );
}

export function policySuppressionAuditSummary(reviews: readonly PolicySuppressionReview[]): string {
  const applied = reviews.filter((review) => review.applied).length;
  const stale = reviews.filter((review) => review.stale).length;
  const expired = reviews.filter((review) => review.temporal_state === "expired").length;
  const drifted = reviews.filter((review) => review.policy_hash_state === "drifted").length;
  const unproven = reviews.filter((review) =>
    ["current_finding_not_strong", "policy_not_evaluated", "policy_incomplete"].includes(
      review.match_state
    )
  ).length;
  const omitted = reviews.filter((review) => review.result_omitted).length;
  return [
    `${applied} applied`,
    stale > 0 ? `${stale} stale` : undefined,
    expired > 0 ? `${expired} expired` : undefined,
    drifted > 0 ? `${drifted} drifted` : undefined,
    unproven > 0 ? `${unproven} unproven` : undefined,
    omitted > 0 ? `${omitted} result omitted` : undefined
  ]
    .filter((part): part is string => part !== undefined)
    .join(" · ");
}

export function policyRunDiagnosticCodeLabel(code: PolicyRunDiagnosticCode): string {
  return code.type === "code_query" && code.code ? `${code.type}:${code.code}` : code.type;
}

export function policyFindingTerminalSymbol(finding: PolicyFinding): string | undefined {
  if (!isRecord(finding.evidence) || !isRecord(finding.evidence.evidence)) {
    return undefined;
  }
  const terminal = finding.evidence.evidence.terminal;
  if (!isRecord(terminal)) {
    return undefined;
  }
  for (const field of ["fq_name", "callee_fq_name", "target_fq_name", "caller_fq_name"]) {
    if (typeof terminal[field] === "string" && terminal[field].length > 0) {
      return terminal[field];
    }
  }
  if (typeof terminal.kind === "string" && terminal.kind.length > 0) {
    return terminal.kind;
  }
  return typeof terminal.type === "string" ? terminal.type : undefined;
}

export function policyFindingDetail(finding: PolicyFinding): string {
  return JSON.stringify(
    {
      severity: finding.severity,
      message: finding.message,
      location: finding.primary,
      suppression: finding.suppression,
      terminal: policyFindingTerminalSymbol(finding),
      evidence: finding.evidence,
      proof: finding.proof,
      related: finding.related,
      witnesses: finding.witnesses
    },
    null,
    2
  );
}

export function policyLocationRange(location: PolicySourceLocation): PolicyEditorRange | undefined {
  const region = location.region;
  if (!region) {
    return undefined;
  }
  return {
    start: {
      line: Math.max(0, region.start_line - 1),
      character: Math.max(0, region.start_column - 1)
    },
    end: {
      line: Math.max(0, region.end_line - 1),
      character: Math.max(0, region.end_column - 1)
    }
  };
}

function isPolicyRule(value: unknown): value is PolicyRule {
  return (
    isRecord(value) &&
    typeof value.policy_id === "string" &&
    typeof value.name === "string" &&
    typeof value.analysis_type === "string"
  );
}

function isPolicyRun(value: unknown): value is PolicyRun {
  return (
    isRecord(value) &&
    typeof value.policy_id === "string" &&
    typeof value.analysis_type === "string" &&
    isPolicyCompletion(value.completion) &&
    Array.isArray(value.findings) &&
    value.findings.every(isPolicyFinding) &&
    Array.isArray(value.diagnostics) &&
    value.diagnostics.every(isPolicyRunDiagnostic) &&
    typeof value.diagnostics_truncated === "boolean"
  );
}

function isPolicyRunDiagnostic(value: unknown): value is PolicyRunDiagnostic {
  return (
    isRecord(value) &&
    isRecord(value.code) &&
    typeof value.code.type === "string" &&
    (value.code.code === undefined || typeof value.code.code === "string") &&
    typeof value.severity === "string" &&
    typeof value.impact === "string" &&
    typeof value.message === "string"
  );
}

function isPolicyCompletion(value: unknown): value is PolicyRunCompletion {
  if (!isRecord(value) || typeof value.type !== "string") {
    return false;
  }
  switch (value.type) {
    case "complete":
      return true;
    case "proven_subset":
      return Array.isArray(value.codes);
    case "inconclusive":
    case "failed":
      return Array.isArray(value.reasons);
    case "unsupported":
      return "capability" in value;
    default:
      return false;
  }
}

function isPolicyFinding(value: unknown): value is PolicyFinding {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.policy_id === "string" &&
    typeof value.severity === "string" &&
    typeof value.message === "string" &&
    (value.suppression === null || isPolicyFindingSuppression(value.suppression)) &&
    isPolicyLocation(value.primary)
  );
}

function isPolicyReportEvaluation(value: unknown): value is PolicyReportEvaluation {
  return (
    isRecord(value) &&
    isPolicyDate(value.evaluation_date) &&
    typeof value.suppression_path === "string" &&
    (value.suppression_document_state === "not_found" ||
      value.suppression_document_state === "loaded" ||
      value.suppression_document_state === "invalid")
  );
}

function isPolicySuppressionDecision(value: unknown): value is PolicySuppressionDecision {
  return (
    isRecord(value) &&
    value.identity_stability === "strong" &&
    value.status === "accepted" &&
    typeof value.reason === "string" &&
    isPolicyDate(value.accepted_at) &&
    (value.policy_hash_at_acceptance === undefined ||
      value.policy_hash_at_acceptance === null ||
      typeof value.policy_hash_at_acceptance === "string") &&
    (value.accepted_by === undefined ||
      value.accepted_by === null ||
      typeof value.accepted_by === "string") &&
    (value.expires_at === undefined || value.expires_at === null || isPolicyDate(value.expires_at))
  );
}

function isPolicyFindingSuppression(value: unknown): value is PolicyFindingSuppression {
  return (
    isPolicySuppressionDecision(value) &&
    (value.policy_hash_state === "matching" ||
      value.policy_hash_state === "drifted" ||
      value.policy_hash_state === "unknown")
  );
}

function isPolicySuppressionReview(value: unknown): value is PolicySuppressionReview {
  return (
    isPolicySuppressionDecision(value) &&
    typeof value.policy_id === "string" &&
    typeof value.finding_id === "string" &&
    (value.match_state === "strong_finding" ||
      value.match_state === "current_finding_not_strong" ||
      value.match_state === "finding_absent" ||
      value.match_state === "policy_not_evaluated" ||
      value.match_state === "policy_incomplete") &&
    (value.temporal_state === "current" || value.temporal_state === "expired") &&
    (value.policy_hash_state === "matching" ||
      value.policy_hash_state === "drifted" ||
      value.policy_hash_state === "unknown") &&
    typeof value.applied === "boolean" &&
    typeof value.stale === "boolean" &&
    typeof value.result_omitted === "boolean"
  );
}

function isPolicyLocation(value: unknown): value is PolicySourceLocation {
  return isRecord(value) && typeof value.path === "string";
}

function isPolicyDiagnostic(value: unknown): value is PolicyReportDiagnostic {
  return (
    isRecord(value) &&
    typeof value.code === "string" &&
    typeof value.severity === "string" &&
    typeof value.message === "string"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isPolicyDate(value: unknown): value is string {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value);
}

function formatUnknown(value: unknown): string {
  return (JSON.stringify(value) ?? String(value)).replace(/[_"]/g, " ").replace(/\s+/g, " ").trim();
}
