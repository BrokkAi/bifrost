import { RQL_POLICY_LANGUAGE_ID } from "./rql_validation";

export const RUN_RQL_POLICY_METHOD = "bifrost/runPolicy";

export interface RqlPolicyDocument {
  languageId: string;
  uri: string;
  workspaceRootUri: string;
  sourceIdentity: string;
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
  | { type: "inconclusive"; reasons: readonly unknown[] }
  | { type: "unsupported"; capability: unknown }
  | { type: "failed"; reasons: readonly unknown[] };

export interface PolicyFinding {
  id: string;
  policy_id: string;
  severity: string;
  message: string;
  primary: PolicySourceLocation;
  evidence?: unknown;
  proof?: unknown;
  related?: unknown[];
  witnesses?: unknown[];
  [key: string]: unknown;
}

export interface PolicyRun {
  policy_id: string;
  analysis_type: string;
  completion: PolicyRunCompletion;
  findings: PolicyFinding[];
  diagnostics: unknown[];
  [key: string]: unknown;
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
  schema_version: 1;
  rules: PolicyRule[];
  runs: PolicyRun[];
  diagnostics: PolicyReportDiagnostic[];
  diagnostics_truncated: boolean;
  omitted_diagnostics_lower_bound: number;
  worst_omitted_diagnostic_severity?: string | null;
}

export interface RqlPolicyResponse {
  workspaceRootUri: string;
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
    params: { documentUri: string; sourceIdentity: string; source: string }
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
  if (!document.sourceIdentity || !document.workspaceRootUri) {
    runner.showWarning("Save the RQL policy inside an active workspace before running it.");
    return undefined;
  }

  try {
    const response = await runner.sendRequest(RUN_RQL_POLICY_METHOD, {
      documentUri: document.uri,
      sourceIdentity: document.sourceIdentity,
      source: document.text
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

export function isRqlPolicyResponse(value: unknown): value is RqlPolicyResponse {
  if (!isRecord(value) || typeof value.workspaceRootUri !== "string") {
    return false;
  }
  const report = value.report;
  if (
    !isRecord(report) ||
    report.schema_version !== 1 ||
    !Array.isArray(report.rules) ||
    !Array.isArray(report.runs) ||
    !Array.isArray(report.diagnostics) ||
    typeof report.diagnostics_truncated !== "boolean" ||
    typeof report.omitted_diagnostics_lower_bound !== "number"
  ) {
    return false;
  }
  return (
    report.rules.every(isPolicyRule) &&
    report.runs.every(isPolicyRun) &&
    report.diagnostics.every(isPolicyDiagnostic)
  );
}

export function policyCompletionLabel(completion: PolicyRunCompletion): string {
  switch (completion.type) {
    case "complete":
      return "complete";
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
    Array.isArray(value.diagnostics)
  );
}

function isPolicyCompletion(value: unknown): value is PolicyRunCompletion {
  if (!isRecord(value) || typeof value.type !== "string") {
    return false;
  }
  switch (value.type) {
    case "complete":
      return true;
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
    isPolicyLocation(value.primary)
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

function formatUnknown(value: unknown): string {
  return (JSON.stringify(value) ?? String(value)).replace(/[_"]/g, " ").replace(/\s+/g, " ").trim();
}
