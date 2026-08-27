import { RQL_POLICY_LANGUAGE_ID } from "./rql_validation";

export const RUN_RQL_POLICY_METHOD = "bifrost/runPolicy";
export const PREPARE_POLICY_SUPPRESSION_METHOD = "bifrost/preparePolicySuppression";
export const SUPPORTED_POLICY_REPORT_SCHEMA_VERSION = 5;
export const SUPPORTED_POLICY_DISPLAY_PATH_SCHEMA_VERSION = 1;

export interface RqlPolicyDocument {
  languageId: string;
  uri: string;
  text: string;
  version?: number;
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

export type PolicyDisplayStepKind = "source" | "propagation" | "call" | "return" | "sink";

export interface PolicyDisplayStep {
  kind: PolicyDisplayStepKind;
  location: PolicySourceLocation;
  label: string;
}

export interface PolicyDisplayPath {
  schema_version: 1;
  representative_witness_id: string;
  witness_ids: string[];
  steps: PolicyDisplayStep[];
  canonical_incomplete: boolean;
  omitted_meaningful_steps: number;
  alternatives_truncated: boolean;
  omitted_alternative_paths_lower_bound: number;
  omitted_witnesses_lower_bound: number;
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
  identity_stability: "strong" | "weak";
  policy_hash: string;
  severity: string;
  message: string;
  primary: PolicySourceLocation;
  display_path?: PolicyDisplayPath;
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
  orphan_state: "resolved" | "orphaned" | "path_not_analyzed" | "path_unrecorded";
  applied: boolean;
  result_omitted: boolean;
  rekey_candidates?: string[];
}

export interface PolicyReportEvaluation {
  evaluation_date: string;
  suppression_sources: PolicySuppressionSourceState[];
  scope_path: string;
  scope_document_state: PolicyDocumentState;
}

export type PolicyDocumentState = "not_evaluated" | "not_found" | "loaded" | "invalid";

export interface PolicySuppressionSourceState {
  path: string;
  state: PolicyDocumentState;
}

export type PolicySuppressionDestination = "public" | "private" | "local";

export interface PolicySuppressionAuthoringParams {
  reportRootUri: string;
  policyDocumentUri: string;
  policyDocumentVersion?: number | null;
  finding: {
    policyId: string;
    findingId: string;
    path: string;
    identityStability: "strong";
    policyHash: string;
    sourceUri?: string;
    sourceVersion?: number | null;
  };
  destination: PolicySuppressionDestination;
  evaluationDate: string;
  reason?: string;
  acceptedBy?: string;
  expiresAt?: string;
}

export interface PolicySuppressionAuthoringResponse {
  documentUri: string;
  expectedVersion: number | null;
  expectedText?: string | null;
  content: string;
  create: boolean;
  sourcePreconditions: PolicySuppressionSourcePrecondition[];
}

export interface PolicySuppressionSourcePrecondition {
  path: string;
  uri: string;
  exists: boolean;
  expectedVersion: number | null;
  expectedText?: string | null;
}

const POLICY_SUPPRESSION_SOURCE_PATHS = new Set([
  ".bifrost/suppressions.json",
  ".bifrost/suppressions.private.json",
  ".bifrost/suppressions.local.json"
]);

export interface PolicyExecutionMetadata {
  total_elapsed_ms: number;
  stage_timings: Array<{ stage: string; elapsed_ms: number }>;
  termination: string | null;
  terminal_stage: string | null;
  active_policy_id: string | null;
  completed_policy_ids: string[];
  pending_policy_ids: string[];
}

export interface PolicyScopeReview {
  path: string;
  reason: string;
  matched_findings: number;
  applied: boolean;
  result_omitted: boolean;
  [key: string]: unknown;
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
  schema_version: 5;
  evaluation: PolicyReportEvaluation;
  execution: PolicyExecutionMetadata;
  rules: PolicyRule[];
  runs: PolicyRun[];
  suppressions: PolicySuppressionReview[];
  scope: PolicyScopeReview[];
  diff?: unknown;
  packs?: unknown;
  baseline?: unknown;
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
      const observed = policyReportSchemaVersion(response);
      if (observed !== undefined && observed !== SUPPORTED_POLICY_REPORT_SCHEMA_VERSION) {
        runner.showError(
          `Bifrost policy report schema ${observed} is not supported. This extension supports schema ${SUPPORTED_POLICY_REPORT_SCHEMA_VERSION}.`
        );
        return undefined;
      }
      runner.showError(
        `Bifrost returned an invalid policy report for supported schema ${SUPPORTED_POLICY_REPORT_SCHEMA_VERSION}.`
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

export class ExpectedPolicySuppressionWrite {
  private expected: { uri: string; content: string } | undefined;

  expect(uri: string, content: string): void {
    this.expected = { uri, content: normalizePolicySuppressionContent(content) };
  }

  isPending(uri: string): boolean {
    return this.expected?.uri === uri;
  }

  observe(uri: string, content: string): boolean {
    if (this.expected?.uri !== uri) {
      return false;
    }
    if (this.expected.content === normalizePolicySuppressionContent(content)) {
      return true;
    }
    this.expected = undefined;
    return false;
  }

  clear(uri: string): void {
    if (this.expected?.uri === uri) {
      this.expected = undefined;
    }
  }
}

function normalizePolicySuppressionContent(content: string): string {
  return content.replace(/\r\n?/g, "\n");
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
    report.schema_version !== SUPPORTED_POLICY_REPORT_SCHEMA_VERSION ||
    !isPolicyReportEvaluation(report.evaluation) ||
    !isPolicyExecutionMetadata(report.execution) ||
    !Array.isArray(report.rules) ||
    !Array.isArray(report.runs) ||
    !Array.isArray(report.suppressions) ||
    !Array.isArray(report.scope) ||
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
    report.scope.every(isPolicyScopeReview) &&
    report.diagnostics.every(isPolicyDiagnostic)
  );
}

function policyReportSchemaVersion(value: unknown): number | undefined {
  if (!isRecord(value) || !isRecord(value.report)) {
    return undefined;
  }
  return typeof value.report.schema_version === "number" ? value.report.schema_version : undefined;
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
  const orphaned = reviews.filter((review) => review.orphan_state === "orphaned").length;
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
    orphaned > 0 ? `${orphaned} orphaned` : undefined,
    expired > 0 ? `${expired} expired` : undefined,
    drifted > 0 ? `${drifted} drifted` : undefined,
    unproven > 0 ? `${unproven} unproven` : undefined,
    omitted > 0 ? `${omitted} result omitted` : undefined
  ]
    .filter((part): part is string => part !== undefined)
    .join(" · ");
}

/** Return the ordered suppression source union from the current report. */
export function policySuppressionSources(
  evaluation: PolicyReportEvaluation
): readonly PolicySuppressionSourceState[] {
  return evaluation.suppression_sources;
}

/**
 * Policy reports are authoring inputs only while their identity is strong and
 * the retained result has not been made stale by a newer run or workspace
 * change. The server repeats these checks before creating the edit.
 */
export function isPolicyFindingSuppressible(finding: PolicyFinding, stale = false): boolean {
  return (
    !stale &&
    finding.suppression === null &&
    finding.identity_stability === "strong" &&
    finding.id.length > 0 &&
    finding.policy_id.length > 0 &&
    typeof finding.policy_hash === "string" &&
    finding.policy_hash.length > 0 &&
    finding.primary.path.length > 0
  );
}

/**
 * Check that a suppression target still belongs to the live published run.
 * The generation and object identity prevent cached tree items or command
 * arguments from authoring against a later policy/source revision.
 */
export function isCurrentPolicyFinding(
  finding: PolicyFinding,
  findingGeneration: number | undefined,
  currentGeneration: number,
  liveStale: boolean,
  currentFinding: PolicyFinding | undefined
): boolean {
  return (
    !liveStale &&
    findingGeneration !== undefined &&
    findingGeneration === currentGeneration &&
    currentFinding === finding &&
    isPolicyFindingSuppressible(finding)
  );
}

/** Normalize the optional reason prompt according to project policy. */
export function normalizeSuppressionReason(
  value: string | undefined,
  requireReason: boolean
): string | undefined {
  const trimmed = value?.trim() ?? "";
  if (trimmed.length > 0) {
    return trimmed;
  }
  return requireReason ? undefined : "unspecified";
}

export function isPolicySuppressionDestination(
  value: unknown
): value is PolicySuppressionDestination {
  return value === "public" || value === "private" || value === "local";
}

export function decodePolicySuppressionAuthoringResponse(
  value: unknown
): PolicySuppressionAuthoringResponse | undefined {
  if (
    !isRecord(value) ||
    typeof value.documentUri !== "string" ||
    (value.expectedVersion !== null && !isNonNegativeInteger(value.expectedVersion)) ||
    (value.expectedText !== undefined &&
      value.expectedText !== null &&
      typeof value.expectedText !== "string") ||
    typeof value.content !== "string" ||
    typeof value.create !== "boolean" ||
    !hasCompletePolicySuppressionSourcePreconditions(value.sourcePreconditions)
  ) {
    return undefined;
  }
  return {
    documentUri: value.documentUri,
    expectedVersion: value.expectedVersion,
    expectedText: value.expectedText,
    content: value.content,
    create: value.create,
    sourcePreconditions: value.sourcePreconditions
  };
}

export function hasCompletePolicySuppressionSourcePreconditions(
  value: unknown
): value is PolicySuppressionSourcePrecondition[] {
  if (
    !Array.isArray(value) ||
    value.length !== 3 ||
    !value.every(isPolicySuppressionSourcePrecondition)
  ) {
    return false;
  }
  const paths = new Set(value.map((source) => source.path));
  const uris = new Set(value.map((source) => source.uri));
  return (
    paths.size === value.length &&
    uris.size === value.length &&
    value.every((source) => POLICY_SUPPRESSION_SOURCE_PATHS.has(source.path))
  );
}

export function isPolicySuppressionSourcePrecondition(
  value: unknown
): value is PolicySuppressionSourcePrecondition {
  if (
    !isRecord(value) ||
    typeof value.path !== "string" ||
    value.path.length === 0 ||
    typeof value.uri !== "string" ||
    value.uri.length === 0 ||
    typeof value.exists !== "boolean" ||
    (value.expectedVersion !== null && !isNonNegativeInteger(value.expectedVersion)) ||
    (value.expectedText !== undefined &&
      value.expectedText !== null &&
      typeof value.expectedText !== "string")
  ) {
    return false;
  }
  return value.exists
    ? typeof value.expectedText === "string"
    : value.expectedVersion === null &&
        (value.expectedText === undefined || value.expectedText === null);
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
      display_path: finding.display_path,
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

export function policyFindingDisplayRows(finding: PolicyFinding): readonly PolicyDisplayStep[] {
  return finding.display_path?.steps ?? [];
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
    (value.identity_stability === "strong" || value.identity_stability === "weak") &&
    typeof value.policy_hash === "string" &&
    typeof value.severity === "string" &&
    typeof value.message === "string" &&
    (value.display_path === undefined || isPolicyDisplayPath(value.display_path)) &&
    (value.suppression === null || isPolicyFindingSuppression(value.suppression)) &&
    isPolicyLocation(value.primary)
  );
}

function isPolicyDisplayPath(value: unknown): value is PolicyDisplayPath {
  return (
    isRecord(value) &&
    value.schema_version === SUPPORTED_POLICY_DISPLAY_PATH_SCHEMA_VERSION &&
    typeof value.representative_witness_id === "string" &&
    value.representative_witness_id.length > 0 &&
    Array.isArray(value.witness_ids) &&
    value.witness_ids.length > 0 &&
    value.witness_ids.every((id) => typeof id === "string" && id.length > 0) &&
    value.witness_ids.includes(value.representative_witness_id) &&
    Array.isArray(value.steps) &&
    value.steps.length > 0 &&
    value.steps.every(isPolicyDisplayStep) &&
    typeof value.canonical_incomplete === "boolean" &&
    isNonNegativeInteger(value.omitted_meaningful_steps) &&
    typeof value.alternatives_truncated === "boolean" &&
    isNonNegativeInteger(value.omitted_alternative_paths_lower_bound) &&
    isNonNegativeInteger(value.omitted_witnesses_lower_bound) &&
    value.alternatives_truncated === value.omitted_witnesses_lower_bound > 0
  );
}

function isPolicyDisplayStep(value: unknown): value is PolicyDisplayStep {
  return (
    isRecord(value) &&
    isPolicyDisplayStepKind(value.kind) &&
    isPrecisePolicyLocation(value.location) &&
    typeof value.label === "string" &&
    value.label.length > 0
  );
}

function isPrecisePolicyLocation(value: unknown): value is PolicySourceLocation {
  if (!isPolicyLocation(value) || !isRecord(value.region)) {
    return false;
  }
  const { start_line, start_column, end_line, end_column } = value.region;
  return (
    isPositiveInteger(start_line) &&
    isPositiveInteger(start_column) &&
    isPositiveInteger(end_line) &&
    isPositiveInteger(end_column) &&
    (start_line < end_line || (start_line === end_line && start_column <= end_column))
  );
}

function isPolicyDisplayStepKind(value: unknown): value is PolicyDisplayStepKind {
  return (
    value === "source" ||
    value === "propagation" ||
    value === "call" ||
    value === "return" ||
    value === "sink"
  );
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return isNonNegativeInteger(value) && value > 0;
}

function isPolicyReportEvaluation(value: unknown): value is PolicyReportEvaluation {
  return (
    isRecord(value) &&
    isPolicyDate(value.evaluation_date) &&
    Array.isArray(value.suppression_sources) &&
    value.suppression_sources.every(isPolicySuppressionSourceState) &&
    typeof value.scope_path === "string" &&
    isPolicyDocumentState(value.scope_document_state)
  );
}

function isPolicySuppressionSourceState(value: unknown): value is PolicySuppressionSourceState {
  return isRecord(value) && typeof value.path === "string" && isPolicyDocumentState(value.state);
}

function isPolicyDocumentState(value: unknown): value is PolicyDocumentState {
  return (
    value === "not_evaluated" || value === "not_found" || value === "loaded" || value === "invalid"
  );
}

function isPolicyExecutionMetadata(value: unknown): value is PolicyExecutionMetadata {
  return (
    isRecord(value) &&
    typeof value.total_elapsed_ms === "number" &&
    Array.isArray(value.stage_timings) &&
    value.stage_timings.every(
      (timing) =>
        isRecord(timing) &&
        typeof timing.stage === "string" &&
        typeof timing.elapsed_ms === "number"
    ) &&
    (value.termination === null || typeof value.termination === "string") &&
    (value.terminal_stage === null || typeof value.terminal_stage === "string") &&
    (value.active_policy_id === null || typeof value.active_policy_id === "string") &&
    Array.isArray(value.completed_policy_ids) &&
    value.completed_policy_ids.every((id) => typeof id === "string") &&
    Array.isArray(value.pending_policy_ids) &&
    value.pending_policy_ids.every((id) => typeof id === "string")
  );
}

function isPolicyScopeReview(value: unknown): value is PolicyScopeReview {
  return (
    isRecord(value) &&
    typeof value.path === "string" &&
    typeof value.reason === "string" &&
    typeof value.matched_findings === "number" &&
    typeof value.applied === "boolean" &&
    typeof value.result_omitted === "boolean"
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
    (value.orphan_state === "resolved" ||
      value.orphan_state === "orphaned" ||
      value.orphan_state === "path_not_analyzed" ||
      value.orphan_state === "path_unrecorded") &&
    typeof value.applied === "boolean" &&
    typeof value.result_omitted === "boolean" &&
    (value.rekey_candidates === undefined ||
      (Array.isArray(value.rekey_candidates) &&
        value.rekey_candidates.every((candidate) => typeof candidate === "string")))
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
