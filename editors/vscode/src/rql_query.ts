export const RQL_LANGUAGE_ID = "bifrost-rql";
export const RUN_RQL_QUERY_METHOD = "bifrost/queryCode";

export interface RqlQueryDocument {
  languageId: string;
  text: string;
}

interface RqlQueryResultBase {
  uri: string;
  path: string;
  witnessStepUris?: string[];
  provenance?: RqlQueryProvenance[];
  provenance_truncated?: boolean;
}

export interface RqlQueryProvenance {
  branch?: number[];
  seed: unknown;
  steps: unknown[];
}

export interface RqlResultRange {
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
}

/** Convert Bifrost's one-based Unicode code-point column to VS Code UTF-16. */
export function codePointColumnToUtf16(line: string, column: number): number {
  const codePointOffset = Math.max(0, column - 1);
  return Array.from(line).slice(0, codePointOffset).join("").length;
}

export interface RqlStructuralMatchResult extends RqlQueryResultBase {
  result_type: "structural_match";
  kind: string;
  language: string;
  start_line: number;
  end_line: number;
  text: string;
  enclosing_symbol?: string;
}

export interface RqlDeclarationResult extends RqlQueryResultBase {
  result_type: "declaration";
  kind: string;
  language: string;
  fq_name: string;
  start_line: number;
  end_line: number;
  signature?: string;
}

export interface RqlSemanticEvidence {
  proof: "proven" | "unproven";
  proof_reason?: string;
  completeness: "complete" | "partial";
  completeness_reason?: string;
}

export type RqlProgramPointBoundary = "entry" | "normal_exit" | "exceptional_exit";

export interface RqlProgramPointRef {
  id: string;
  procedure_id: string;
  path: string;
  range: RqlResultRange;
  boundary?: RqlProgramPointBoundary;
}

export interface RqlProcedureResult extends RqlQueryResultBase {
  result_type: "procedure";
  id: string;
  artifact_id: string;
  language: string;
  procedure_kind: string;
  range: RqlResultRange;
  evidence: RqlSemanticEvidence;
}

export interface RqlProgramPointResult extends RqlQueryResultBase {
  result_type: "program_point";
  id: string;
  procedure_id: string;
  language: string;
  range: RqlResultRange;
  boundary?: RqlProgramPointBoundary;
  event_count: number;
  evidence: RqlSemanticEvidence;
}

export interface RqlControlEdgeResult extends RqlQueryResultBase {
  result_type: "control_edge";
  id: string;
  procedure_id: string;
  language: string;
  range: RqlResultRange;
  edge_kind: string;
  source: RqlProgramPointRef;
  target: RqlProgramPointRef;
  evidence: RqlSemanticEvidence;
}

export interface RqlTypestateSubject {
  class: string;
  identity: string;
}

export type RqlTypestateFindingKind =
  | {
      type: "error_transition";
      event: string;
      from_state: string;
      to_state: string;
    }
  | {
      type: "terminal_expectation";
      expectation: string;
      actual_states: string[];
    };

export type RqlTypestateCertainty = "may" | "must" | "inconclusive";
export type RqlTypestateUncertainty =
  | "ambiguous_dispatch"
  | "unknown_call"
  | "external_call"
  | "escape"
  | "incomplete_analysis"
  | "unmatched_event";

export interface RqlTypestateFindingResult extends RqlQueryResultBase {
  result_type: "typestate_finding";
  id: string;
  protocol_ref: string;
  protocol_hash: string;
  binding_plan_hash: string;
  subject: RqlTypestateSubject;
  finding_kind: RqlTypestateFindingKind;
  certainty: RqlTypestateCertainty;
  language: string;
  range: RqlResultRange;
  path_proven: boolean;
  path_complete: boolean;
  analysis_complete: boolean;
  uncertainty?: RqlTypestateUncertainty[];
  abstained?: boolean;
  retained_witnesses: number;
  omitted_witnesses: number;
}

export type RqlTypestateWitnessStepKind =
  | { type: "seed" }
  | { type: "edge"; edge_kind: string }
  | { type: "end_summary_gap"; return_kind: string };

export interface RqlSourceSite {
  path: string;
  range: RqlResultRange;
}

export interface RqlTypestateWitnessStep {
  kind: RqlTypestateWitnessStepKind;
  source: RqlSourceSite;
  target?: RqlSourceSite;
  origin?: RqlSourceSite;
  evidence: RqlSemanticEvidence;
}

export interface RqlTypestateWitnessResult extends RqlQueryResultBase {
  result_type: "typestate_witness";
  id: string;
  finding_id: string;
  protocol_ref: string;
  protocol_hash: string;
  binding_plan_hash: string;
  subject: RqlTypestateSubject;
  witness_index: number;
  observed_state?: string;
  language: string;
  range: RqlResultRange;
  quality: RqlSemanticEvidence;
  uncertainty?: RqlTypestateUncertainty[];
  abstained?: boolean;
  steps: RqlTypestateWitnessStep[];
  retained_bytes: number;
  truncated?: boolean;
  omitted_steps_lower_bound: number;
  alternatives_truncated?: boolean;
  retention_truncated?: boolean;
}

export type RqlFlowReachability = "reached" | "not_reached" | "inconclusive";
export type RqlFlowCertainty = "exact" | "may";
export type RqlFlowCompletion =
  "complete" | "incomplete" | "budget_exhausted" | "cancelled" | "unsupported";

export interface RqlFlowEvent {
  id: string;
  site: RqlFlowSymbolSite;
  path: string;
  range: RqlResultRange;
  phase: string;
  ordinal: number;
  carrier: RqlFlowCarrierSymbol;
}

export interface RqlFlowDeclarationSegment {
  kind: string;
  name?: string;
  start_byte: number;
  end_byte: number;
  occurrence: number;
  sibling_ordinal: number;
}

export interface RqlFlowSymbolSite {
  id: string;
  path: string;
  language: string;
  declaration: RqlFlowDeclarationSegment[];
  role: string;
  start_byte: number;
  end_byte: number;
  occurrence: number;
  range: RqlResultRange;
}

export type RqlFlowPortSymbol =
  | { kind: "receiver" }
  | { kind: "parameter"; ordinal: number }
  | { kind: "normal_return" }
  | { kind: "exceptional_return" }
  | { kind: "capture"; slot: number };

export type RqlFlowSelectorSymbol =
  | { kind: "field"; field: RqlFlowSymbolSite }
  | { kind: "exact_index"; index: RqlFlowCarrierSymbol }
  | { kind: "any_index" };

export type RqlFlowCarrierSymbol =
  | {
      kind: "value";
      id: string;
      site: RqlFlowSymbolSite;
      role: string;
      ordinal?: number;
    }
  | {
      kind: "port";
      id: string;
      procedure: RqlFlowSymbolSite;
      port: RqlFlowPortSymbol;
    }
  | { kind: "allocation"; id: string; site: RqlFlowSymbolSite }
  | {
      kind: "call_result";
      id: string;
      call: RqlFlowSymbolSite;
      result: RqlFlowCarrierSymbol;
      callee: RqlFlowSymbolSite;
    }
  | {
      kind: "scoped_root";
      id: string;
      root_kind: string;
      site: RqlFlowSymbolSite;
    }
  | {
      kind: "location";
      id: string;
      root: RqlFlowCarrierSymbol;
      selectors: RqlFlowSelectorSymbol[];
      exact: boolean;
    };

export type RqlFlowFactSymbol =
  | { kind: "zero" }
  | {
      kind: "carrier";
      source: RqlFlowEvent;
      carrier: RqlFlowCarrierSymbol;
      uncertain?: boolean;
    }
  | {
      kind: "meeting";
      source: RqlFlowEvent;
      sink: RqlFlowEvent;
      uncertain?: boolean;
    };

export interface RqlFlowEndpointResult extends RqlQueryResultBase {
  result_type: "flow_endpoint";
  id: string;
  plan_ref: string;
  source?: RqlFlowEvent;
  sink: RqlFlowEvent;
  reachability: RqlFlowReachability;
  certainty?: RqlFlowCertainty;
  must: "not_established";
  ambiguous?: boolean;
  completion: RqlFlowCompletion;
  semantic_status: string;
  solver_termination: "fixed_point" | "budget_exhausted" | "cancelled";
  language: string;
  range: RqlResultRange;
  path_qualities?: RqlSemanticEvidence[];
  retained_witnesses: number;
  omitted_witnesses: number;
}

export interface RqlFlowWitnessStep extends RqlTypestateWitnessStep {
  boundary?: string;
  source_symbol?: RqlFlowSymbolSite;
  target_symbol?: RqlFlowSymbolSite;
  origin_symbol?: RqlFlowSymbolSite;
  input?: RqlFlowFactSymbol;
  output?: RqlFlowFactSymbol;
}

export interface RqlFlowWitnessResult extends RqlQueryResultBase {
  result_type: "flow_witness";
  id: string;
  endpoint_id: string;
  plan_ref: string;
  witness_index: number;
  language: string;
  range: RqlResultRange;
  quality: RqlSemanticEvidence;
  steps: RqlFlowWitnessStep[];
  retained_bytes: number;
  truncated?: boolean;
  omitted_steps_lower_bound: number;
  alternatives_truncated?: boolean;
  retention_truncated?: boolean;
}

export interface RqlTaintOrigin {
  id: string;
  event_id: string;
  labels: string[];
  site: RqlSourceSite;
}

export interface RqlTaintWitness {
  id: string;
  finding_id: string;
  witness_index: number;
  path: string;
  language: string;
  range: RqlResultRange;
  quality: RqlSemanticEvidence;
  steps: RqlFlowWitnessStep[];
  retained_bytes: number;
  truncated?: boolean;
  omitted_steps_lower_bound: number;
  alternatives_truncated?: boolean;
  retention_truncated?: boolean;
}

export interface RqlTaintFindingResult extends RqlQueryResultBase {
  result_type: "taint_finding";
  id: string;
  language: string;
  range: RqlResultRange;
  sink_event_id: string;
  sink: RqlSourceSite;
  reached_labels: string[];
  origins: RqlTaintOrigin[];
  origins_truncated?: boolean;
  witnesses: RqlTaintWitness[];
  witnesses_truncated?: boolean;
  evidence: RqlSemanticEvidence;
  ambiguous?: boolean;
}

export interface RqlReferenceSiteResult extends RqlQueryResultBase {
  result_type: "reference_site";
  language: string;
  range: RqlResultRange;
  target: Omit<RqlDeclarationResult, "result_type" | "uri" | "provenance" | "provenance_truncated">;
  enclosing_declaration?: Omit<
    RqlDeclarationResult,
    "result_type" | "uri" | "provenance" | "provenance_truncated"
  >;
  usage_kind: string;
  proof: string;
  reference_kind?: string;
}

export interface RqlFileResult extends RqlQueryResultBase {
  result_type: "file";
  language: string;
  /**
   * The package or module this file belongs to. Present together with
   * `package_syntactic`; both absent means no package could be named at all,
   * which is not the same as "the file is in the root package".
   */
  package_fq?: string;
  /** True when the language spells the package in the source. */
  package_syntactic?: boolean;
}

type RqlDeclarationValue = Omit<
  RqlDeclarationResult,
  "result_type" | "uri" | "provenance" | "provenance_truncated"
>;

export interface RqlCallSiteResult extends RqlQueryResultBase {
  result_type: "call_site";
  language: string;
  range: RqlResultRange;
  caller: RqlDeclarationValue;
  callee: RqlDeclarationValue;
  call_kind: string;
  proof: string;
}

export interface RqlExpressionSiteResult extends RqlQueryResultBase {
  result_type: "expression_site";
  language: string;
  range: RqlResultRange;
  text: string;
  input_kind: string;
  caller_fq_name: string;
  callee_fq_name: string;
}

export interface RqlReceiverValue {
  receiver_value_kind: string;
  declaration?: RqlDeclarationValue;
  type_declaration?: RqlDeclarationValue;
  allocation_site?: { path: string; range: RqlResultRange };
  factory?: RqlDeclarationValue;
  returned_value?: RqlReceiverValue;
}

function receiverValueLabel(value: RqlReceiverValue): string {
  switch (value.receiver_value_kind) {
    case "allocation_site":
      return `allocation ${value.type_declaration?.fq_name ?? "unknown"}`;
    case "instance_type":
      return `instance ${value.declaration?.fq_name ?? "unknown"}`;
    case "class_or_static_object":
      return `class/static ${value.declaration?.fq_name ?? "unknown"}`;
    case "module_or_export_object":
      return `module/export ${value.declaration?.fq_name ?? "unknown"}`;
    case "current_receiver":
      return `current receiver ${value.declaration?.fq_name ?? "unknown"}`;
    case "factory_return":
      return `factory ${value.factory?.fq_name ?? "unknown"} → ${
        value.returned_value ? receiverValueLabel(value.returned_value) : "unknown"
      }`;
    default:
      return value.receiver_value_kind;
  }
}

export interface RqlReceiverAnalysisResult extends RqlQueryResultBase {
  result_type: "receiver_analysis";
  analysis_kind: string;
  language: string;
  range: RqlResultRange;
  text: string;
  input_kind: string;
  capture?: string;
  outcome: string;
  values?: RqlReceiverValue[];
  member_targets?: RqlDeclarationValue[];
  reason?: string;
  limit?: string;
}

export interface RqlOccurrenceTarget {
  target_kind: "none" | "resolved" | "lexical" | "unresolved";
  units?: RqlDeclarationValue[];
  name?: string;
  kind?: string;
  range?: RqlResultRange;
  status?: string;
}

export interface RqlOccurrenceResult extends RqlQueryResultBase {
  result_type: "occurrence";
  id: string;
  /**
   * Content-scoped identity of the underlying AST node, equal to the `ast_id`
   * a structural capture over the same node reports. This is the correlation
   * join; never compare ranges or spellings instead.
   */
  ast_id: string;
  language: string;
  class: string;
  role: string;
  namespace: string;
  range: RqlResultRange;
  start_byte: number;
  end_byte: number;
  enclosing_symbol?: string;
  raw_spelling: string;
  decoded_spelling?: string;
  target: RqlOccurrenceTarget;
}

export interface RqlLexicalScopeResult extends RqlQueryResultBase {
  result_type: "lexical_scope";
  id: string;
  /**
   * Absent for exactly one scope per file: the synthesized whole-file scope,
   * which no grammar gives an AST node. Every other scope joins with a
   * structural capture over the same node by `ast_id` equality.
   */
  ast_id?: string;
  language: string;
  index: number;
  kind?: string;
  range: RqlResultRange;
  start_byte: number;
  end_byte: number;
  parent_index?: number;
}

export interface RqlImportBinder {
  local_name: string;
  alias?: string;
  /** Empty when the adapter records no parser-derived import path. */
  target_segments: string[];
  wildcard: boolean;
  wildcard_ambiguous?: boolean;
  boundary: string;
}

export interface RqlBindingResult extends RqlQueryResultBase {
  result_type: "binding";
  id: string;
  /** Absent when the binder's local name is not spelled by a classified token. */
  ast_id?: string;
  language: string;
  name: string;
  kind: string;
  hoisting: string;
  namespace: string;
  range: RqlResultRange;
  start_byte: number;
  end_byte: number;
  activation_start_byte: number;
  activation_end_byte: number;
  declaring_scope_index: number;
  source_order: number;
  visibility: string;
  import?: RqlImportBinder;
  /** True only for rows a `reaching-binding :include-shadowed` emitted as losers. */
  shadowed?: boolean;
}

export interface RqlCandidateRef {
  candidate_kind: "unit" | "lexical" | "binding" | "import_binder" | "external_route";
  unit?: RqlDeclarationValue;
  name?: string;
  kind?: string;
  range?: RqlResultRange;
  path?: string;
  ast_id?: string;
}

export interface RqlResolutionCandidateResult extends RqlQueryResultBase {
  result_type: "resolution_candidate";
  id: string;
  /** The AST identity of the *reference*, which a capture over it joins on. */
  ast_id: string;
  language: string;
  range: RqlResultRange;
  start_byte: number;
  end_byte: number;
  ordinal: number;
  /**
   * Absent when the recording seam could not name a precedence tier. That is
   * *unattributed*, never "the weakest tier".
   */
  tier?: string;
  outcome: string;
  rejection_reason?: string;
  boundary: string;
  visibility: string;
  /** `selection_only` means an absent rejection row says nothing. */
  trace_completeness: string;
  candidate: RqlCandidateRef;
  external_target?: string;
}

/**
 * One canonical reference edge, in the same row shape whichever producer
 * derived it.
 *
 * The producer label is serialized as `edge_provenance` so the branch trace
 * every result item carries keeps the `provenance` key to itself.
 */
export interface RqlReferenceEdgeResult extends RqlQueryResultBase {
  result_type: "reference_edge";
  id: string;
  /**
   * The site token's AST identity, absent when the producer cannot address
   * the site as a facts-arena node. Where present it is the join with a
   * capture's or an occurrence's `ast_id`.
   */
  ast_id?: string;
  language: string;
  range: RqlResultRange;
  start_byte: number;
  end_byte: number;
  target: RqlDeclarationValue;
  enclosing_declaration?: RqlDeclarationValue;
  /** Absent when the producer classified no structured reference kind. */
  reference_kind?: string;
  proof: string;
  usage_kind: string;
  /** A declaration site is editor-visible navigation, not a runtime usage. */
  site_class: string;
  /** `unknown` is inconclusive; it is never silently equal to `external`. */
  owner_relation: string;
  /** Which producer derived the row: `forward` (resolver) or `inverse` (usage index). */
  edge_provenance: string;
  /** A comparison must refuse to relate rows from two generations. */
  generation: number;
}

/**
 * The mandatory terminal row for one receiver or value analysis site.
 *
 * Evidence rows can be empty. This row always states why, and whether that
 * absence is exhaustive. Do not read an empty evidence relation as "no
 * values"; read `coverage` instead.
 */
export interface RqlReceiverOutcomeResult extends RqlQueryResultBase {
  result_type: "receiver_outcome";
  id: string;
  /** Joins the outcome row to its evidence rows and to the analysis site. */
  site_id: string;
  /** Absent when the producer cannot address the site as a facts-arena node. */
  site_ast_id?: string;
  language: string;
  range: RqlResultRange;
  analysis_kind: string;
  outcome: string;
  /** `exhaustive` proves the candidate set; any other value leaves it open. */
  coverage: string;
  candidate_count: number;
  /** True when the retained candidates are a prefix, not the whole set. */
  candidates_truncated: boolean;
  reason?: string;
  limit?: string;
  /** Present when the language records no semantic support for the analysis. */
  semantic_unsupported?: string;
  setup_nodes: number;
  summary_expansions: number;
  scope_nodes: number;
}

/**
 * One typed receiver value retained for a site.
 *
 * Nested factory returns are flattened into a parent-linked chain, so follow
 * `parent_evidence_id` and `chain_hop` instead of nesting. The row carries no
 * range and no language: it is evidence about a site, not a second location.
 */
export interface RqlReceiverEvidenceResult extends RqlQueryResultBase {
  result_type: "receiver_evidence";
  id: string;
  site_id: string;
  site_ast_id?: string;
  /** Absent for a first-hop row; set for each further hop of a chain. */
  parent_evidence_id?: string;
  ordinal: number;
  chain_hop: number;
  evidence_kind: string;
  declaration_id?: string;
  declaration_fq_name?: string;
  declaration_kind?: string;
  /** Set when the value came from a factory return. */
  factory_id?: string;
  proof: string;
  completeness: string;
}

/**
 * The mandatory member-selection summary row for one reference occurrence,
 * projected from the production resolver's own candidate trace.
 *
 * The row exists even when the file records no trace, so an empty candidate
 * relation can never masquerade as a proven-empty selection. `coverage` is
 * `exhaustive` only for a full trace, `open` for a selection-only trace, and
 * `unsupported` when the language records no trace at all. Under
 * `selection_only` or `absent`, an absent rejection row says nothing.
 */
export interface RqlMemberSelectionResult extends RqlQueryResultBase {
  result_type: "member_selection";
  id: string;
  /** The occurrence's AST identity; the join with occurrence and receiver rows. */
  site_ast_id: string;
  language: string;
  range: RqlResultRange;
  /** The decoded member spelling at the occurrence. */
  member: string;
  role: string;
  /** `selected`, `unresolved`, or `untraced`. */
  outcome: string;
  selected_count: number;
  candidate_count: number;
  /** `full`, `selection_only`, or `absent`. */
  trace_completeness: string;
  /** `exhaustive`, `open`, or `unsupported`. */
  coverage: string;
}

export type RqlQueryResultItem =
  | RqlStructuralMatchResult
  | RqlDeclarationResult
  | RqlProcedureResult
  | RqlProgramPointResult
  | RqlControlEdgeResult
  | RqlTypestateFindingResult
  | RqlTypestateWitnessResult
  | RqlFlowEndpointResult
  | RqlFlowWitnessResult
  | RqlTaintFindingResult
  | RqlFileResult
  | RqlReferenceSiteResult
  | RqlCallSiteResult
  | RqlExpressionSiteResult
  | RqlReceiverAnalysisResult
  | RqlOccurrenceResult
  | RqlLexicalScopeResult
  | RqlBindingResult
  | RqlResolutionCandidateResult
  | RqlReferenceEdgeResult
  | RqlReceiverOutcomeResult
  | RqlReceiverEvidenceResult
  | RqlMemberSelectionResult;

export interface RqlQueryResponse {
  text: string;
  mode?: "results" | "explain" | "profile";
  report?: unknown;
  results?: RqlQueryResultItem[];
}

export interface RqlQueryResult {
  text: string;
  mode: "results" | "explain" | "profile";
  report?: unknown;
  results: RqlQueryResultItem[];
}

export function formatRqlQueryOutput(response: RqlQueryResult): string {
  if (response.mode !== "profile" || response.report === undefined) {
    return response.text;
  }

  return `${response.text.trimEnd()}\n\nCodeQuery profile report:\n${JSON.stringify(response.report, null, 2)}\n`;
}

export interface RqlQueryFileGroup {
  path: string;
  results: RqlQueryResultItem[];
}

export interface RqlQueryRunner {
  isReady(): boolean;
  sendRequest(method: string, params: { query: string }): Promise<RqlQueryResponse>;
  showError(message: string): void;
  showWarning(message: string): void;
}

export async function runRqlQuery(
  document: RqlQueryDocument | undefined,
  runner: RqlQueryRunner
): Promise<RqlQueryResult | undefined> {
  if (!document || document.languageId !== RQL_LANGUAGE_ID) {
    runner.showWarning("Open a Bifrost RQL file to run a query.");
    return undefined;
  }
  if (!runner.isReady()) {
    runner.showWarning(
      "Bifrost is not ready. Start the language server and wait for indexing to finish."
    );
    return undefined;
  }

  try {
    const response = await runner.sendRequest(RUN_RQL_QUERY_METHOD, { query: document.text });
    if (!Array.isArray(response.results)) {
      runner.showError(
        "Bifrost RQL results require an updated language server. Rebuild and restart Bifrost, then run the query again."
      );
      return undefined;
    }
    return {
      text: response.text,
      mode: response.mode ?? "results",
      report: response.report,
      results: response.results
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    runner.showError(`Bifrost RQL query failed: ${message}`);
    return undefined;
  }
}

export function groupRqlQueryResults(results: readonly RqlQueryResultItem[]): RqlQueryFileGroup[] {
  const files = new Map<string, RqlQueryFileGroup>();
  for (const result of results) {
    const existing = files.get(result.path);
    if (existing) {
      existing.results.push(result);
    } else {
      files.set(result.path, { path: result.path, results: [result] });
    }
  }
  return [...files.values()];
}

export function queryResultLabel(result: RqlQueryResultItem): string {
  switch (result.result_type) {
    case "structural_match":
      return result.text;
    case "declaration":
      return result.fq_name;
    case "procedure":
      return result.procedure_kind;
    case "program_point":
      return result.boundary ?? "program point";
    case "control_edge":
      return `${result.edge_kind}: ${result.source.id} → ${result.target.id}`;
    case "typestate_finding":
      return typestateFindingKindLabel(result.finding_kind);
    case "typestate_witness":
      return `witness ${result.witness_index + 1}: ${result.steps.length} step${result.steps.length === 1 ? "" : "s"}`;
    case "flow_endpoint":
      return `${result.reachability}: ${result.sink.id}`;
    case "flow_witness":
      return `flow witness ${result.witness_index + 1}: ${result.steps.length} step${result.steps.length === 1 ? "" : "s"}`;
    case "taint_finding":
      return `taint: ${result.reached_labels.join(", ")}`;
    case "file":
      return result.path;
    case "reference_site":
      return result.target.fq_name;
    case "call_site":
      return `${result.caller.fq_name} → ${result.callee.fq_name}`;
    case "expression_site":
      return result.text;
    case "receiver_analysis":
      return `${result.analysis_kind}: ${result.text}`;
    case "occurrence":
      return result.decoded_spelling ?? result.raw_spelling;
    case "lexical_scope":
      return `scope #${result.index}`;
    case "binding":
      return result.name;
    case "resolution_candidate":
      return candidateName(result.candidate);
    case "reference_edge":
      return result.target.fq_name;
    case "receiver_outcome":
      return `${result.analysis_kind}: ${result.outcome}`;
    case "receiver_evidence":
      return result.declaration_fq_name ?? result.evidence_kind;
    case "member_selection":
      return result.member;
  }
}

/** The display name of a candidate, whatever shape it took. */
function candidateName(candidate: RqlCandidateRef): string {
  return candidate.unit?.fq_name ?? candidate.name ?? candidate.candidate_kind;
}

export function queryResultDescription(result: RqlQueryResultItem): string {
  switch (result.result_type) {
    case "procedure":
      return `${result.evidence.proof}/${result.evidence.completeness} · ${result.range.start_line}:${result.range.start_column}`;
    case "program_point":
      return `${result.event_count} events · ${result.evidence.proof}/${result.evidence.completeness}`;
    case "control_edge":
      return `${result.evidence.proof}/${result.evidence.completeness} · ${result.range.start_line}:${result.range.start_column}`;
    case "typestate_finding":
      return `${result.certainty} · ${result.protocol_ref} · ${result.range.start_line}:${result.range.start_column}`;
    case "typestate_witness":
      return `${semanticEvidenceLabel(result.quality)} · ${result.truncated ? "truncated" : "complete"}`;
    case "flow_endpoint":
      return `${result.certainty ?? "n/a"} · ${result.completion} · ${result.plan_ref}`;
    case "flow_witness":
      return `${semanticEvidenceLabel(result.quality)} · ${result.truncated ? "truncated" : "complete"}`;
    case "taint_finding":
      return `${semanticEvidenceLabel(result.evidence)} · ${result.origins.length} origin${result.origins.length === 1 ? "" : "s"}`;
    case "file":
      return `file · ${result.language}`;
    case "reference_site":
      return `${result.reference_kind ?? "reference"} · ${result.range.start_line}:${result.range.start_column}`;
    case "call_site":
      return `${result.call_kind} · ${result.proof}`;
    case "expression_site":
      return `call input · ${result.input_kind}`;
    case "receiver_analysis":
      return `${result.outcome} · ${result.range.start_line}:${result.range.start_column}`;
    case "occurrence":
      return `${result.class}/${result.role} · ${result.namespace} · ${result.range.start_line}:${result.range.start_column}`;
    case "lexical_scope":
      return `${result.kind ?? "file"} · ${result.range.start_line}:${result.range.start_column}`;
    case "binding":
      return `${result.kind} · ${result.hoisting} · scope #${result.declaring_scope_index}${result.shadowed ? " · shadowed" : ""}`;
    case "resolution_candidate":
      return `${result.tier ?? "unattributed"} · ${result.outcome}${result.rejection_reason ? ` (${result.rejection_reason})` : ""} · ${result.boundary}`;
    case "reference_edge":
      return `${result.edge_provenance} · ${result.reference_kind ?? "unclassified"} · ${result.usage_kind} · ${result.site_class}`;
    case "receiver_outcome":
      return (
        `${result.coverage} · ${result.candidate_count} candidate${result.candidate_count === 1 ? "" : "s"}` +
        (result.candidates_truncated ? " (truncated)" : "") +
        ` · ${result.range.start_line}:${result.range.start_column}`
      );
    case "receiver_evidence":
      return `${result.evidence_kind} · hop ${result.chain_hop} · ${result.proof}/${result.completeness}`;
    case "member_selection":
      return `${result.outcome} · ${result.selected_count}/${result.candidate_count} · ${result.coverage}`;
    case "structural_match":
    case "declaration":
      return `${result.kind} · ${result.start_line}-${result.end_line}`;
  }
}

export function queryResultTooltip(result: RqlQueryResultItem): string {
  switch (result.result_type) {
    case "structural_match":
      return (
        `**${result.kind}** at ${result.path}:${result.start_line}-${result.end_line}` +
        (result.enclosing_symbol ? `\n\nInside \`${result.enclosing_symbol}\`` : "")
      );
    case "declaration":
      return (
        `**${result.kind}** at ${result.path}:${result.start_line}-${result.end_line}` +
        (result.signature ? `\n\n\`${result.signature}\`` : "")
      );
    case "procedure":
      return (
        `**${result.procedure_kind} procedure** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\nArtifact: \`${result.artifact_id}\`` +
        `\n\nEvidence: ${semanticEvidenceLabel(result.evidence)}`
      );
    case "program_point":
      return (
        `**${result.boundary ?? "program point"}** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\nProcedure: \`${result.procedure_id}\`` +
        `\n\nEvents: ${result.event_count}` +
        `\n\nEvidence: ${semanticEvidenceLabel(result.evidence)}`
      );
    case "control_edge":
      return (
        `**${result.edge_kind} control edge** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\nSource: \`${programPointRefLabel(result.source)}\`` +
        `\n\nTarget: \`${programPointRefLabel(result.target)}\`` +
        `\n\nEvidence: ${semanticEvidenceLabel(result.evidence)}`
      );
    case "typestate_finding":
      return (
        `**Typestate finding (${result.certainty})** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\n${typestateFindingKindLabel(result.finding_kind)}` +
        `\n\nProtocol: \`${result.protocol_ref}\` (${result.protocol_hash.slice(0, 12)})` +
        `\n\nSubject: \`${result.subject.class}\` · \`${result.subject.identity}\`` +
        `\n\nEvidence: ${result.path_proven ? "proven" : "unproven"}/${result.path_complete && result.analysis_complete ? "complete" : "partial"}` +
        typestateUncertaintyLabel(result.uncertainty) +
        `\n\nWitnesses: ${result.retained_witnesses} retained, ${result.omitted_witnesses} omitted`
      );
    case "typestate_witness":
      return (
        `**Typestate witness ${result.witness_index + 1}** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\nProtocol: \`${result.protocol_ref}\` (${result.protocol_hash.slice(0, 12)})` +
        `\n\nEvidence: ${semanticEvidenceLabel(result.quality)}` +
        `\n\nSteps: ${result.steps.length}; retained bytes: ${result.retained_bytes}` +
        (result.truncated
          ? `\n\nTruncated; at least ${result.omitted_steps_lower_bound} step(s) omitted.`
          : "") +
        (result.alternatives_truncated ? "\n\nAlternative witnesses were omitted." : "") +
        (result.retention_truncated ? "\n\nWitness retention hit its request bound." : "") +
        typestateUncertaintyLabel(result.uncertainty)
      );
    case "flow_endpoint":
      return (
        `**Value-flow endpoint (${result.reachability})** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\nPlan: \`${result.plan_ref}\`` +
        `\n\nCertainty: ${result.certainty ?? "not applicable"}; ambiguous: ${result.ambiguous ? "yes" : "no"}` +
        `\n\nCompletion: ${result.completion}; must: ${result.must}` +
        `\n\nWitnesses: ${result.retained_witnesses} retained, ${result.omitted_witnesses} omitted`
      );
    case "flow_witness":
      return (
        `**Value-flow witness ${result.witness_index + 1}** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\nPlan: \`${result.plan_ref}\`` +
        `\n\nEvidence: ${semanticEvidenceLabel(result.quality)}` +
        `\n\nSteps: ${result.steps.length}; retained bytes: ${result.retained_bytes}` +
        (result.truncated
          ? `\n\nTruncated; at least ${result.omitted_steps_lower_bound} step(s) omitted.`
          : "") +
        (result.alternatives_truncated ? "\n\nAlternative witnesses were omitted." : "") +
        (result.retention_truncated ? "\n\nWitness retention hit its request bound." : "")
      );
    case "taint_finding":
      return (
        `**Taint finding** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\nLabels: ${result.reached_labels.map((label) => `\`${label}\``).join(", ")}` +
        `\n\nOrigins: ${result.origins.length}; witnesses: ${result.witnesses.length}` +
        `\n\nEvidence: ${semanticEvidenceLabel(result.evidence)}` +
        (result.origins_truncated ? "\n\nOrigins were truncated." : "") +
        (result.witnesses_truncated ? "\n\nWitnesses were truncated." : "")
      );
    case "file":
      return `**file** at ${result.path}\n\nLanguage: ${result.language}`;
    case "reference_site":
      return (
        `**${result.reference_kind ?? "reference"}** to \`${result.target.fq_name}\` at ` +
        `${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\n${result.usage_kind} · ${result.proof}`
      );
    case "call_site":
      return (
        `**${result.call_kind} call** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\n\`${result.caller.fq_name}\` → \`${result.callee.fq_name}\` · ${result.proof}`
      );
    case "expression_site":
      return (
        `**${result.input_kind} call input** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\n\`${result.text}\``
      );
    case "receiver_analysis":
      return (
        `**${result.analysis_kind}** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\n${result.outcome} · \`${result.text}\`` +
        (result.values?.length
          ? `\n\n${result.values.map((value) => `Value: \`${receiverValueLabel(value)}\``).join("\n\n")}`
          : "") +
        (result.member_targets?.length
          ? `\n\n${result.member_targets.map((target) => `Member: \`${target.fq_name}\``).join("\n\n")}`
          : "") +
        (result.reason ? `\n\n${result.reason}` : "") +
        (result.limit ? `\n\nLimit: ${result.limit}` : "")
      );
    case "occurrence":
      return (
        `**${result.role}** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\n\`${result.raw_spelling}\`` +
        (result.decoded_spelling ? ` (decodes to \`${result.decoded_spelling}\`)` : "") +
        `\n\n${result.class} · ${result.namespace} · target ${result.target.target_kind}` +
        (result.enclosing_symbol ? `\n\nIn \`${result.enclosing_symbol}\`` : "")
      );
    case "lexical_scope":
      return (
        `**lexical scope #${result.index}** (${result.kind ?? "file"}) at ${result.path}:${result.range.start_line}` +
        (result.parent_index !== undefined ? `\n\nInside scope #${result.parent_index}` : "") +
        (result.ast_id === undefined ? "\n\nSynthesized whole-file scope: no AST node" : "")
      );
    case "binding":
      return (
        `**${result.kind}** \`${result.name}\` at ${result.path}:${result.range.start_line}` +
        `\n\n${result.hoisting} · declared in scope #${result.declaring_scope_index}` +
        `\n\nIn effect over bytes ${result.activation_start_byte}..${result.activation_end_byte}` +
        (result.shadowed ? "\n\nShadowed by a nearer binding" : "")
      );
    case "resolution_candidate":
      return (
        `**${result.tier ?? "unattributed tier"}** · ${result.outcome} at ${result.path}:${result.range.start_line}` +
        `\n\n${result.candidate.candidate_kind} \`${candidateName(result.candidate)}\`` +
        (result.rejection_reason ? `\n\nRejected: ${result.rejection_reason}` : "") +
        `\n\nBoundary ${result.boundary} · trace ${result.trace_completeness}` +
        (result.trace_completeness === "selection_only"
          ? "\n\nThis resolver reports only its selections, so an absent rejection row says nothing."
          : "")
      );
    case "reference_edge":
      return (
        `**${result.reference_kind ?? "unclassified"} edge** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\n→ \`${result.target.fq_name}\` (${result.target.kind})` +
        (result.enclosing_declaration
          ? `\n\nFrom \`${result.enclosing_declaration.fq_name}\``
          : "") +
        `\n\n${result.edge_provenance} · ${result.proof} · ${result.usage_kind} · ${result.site_class}` +
        `\n\nOwner relation ${result.owner_relation}` +
        (result.owner_relation === "unknown"
          ? " -- the classifier could not relate the owners, which is inconclusive rather than external."
          : "") +
        `\n\nGeneration ${result.generation}` +
        (result.site_class === "declaration_site"
          ? "\n\nA declaration site is editor-visible navigation, not a runtime usage."
          : "")
      );
    case "receiver_outcome":
      return (
        `**${result.analysis_kind} outcome** at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\n${result.outcome} · coverage ${result.coverage}` +
        `\n\nCandidates: ${result.candidate_count}` +
        (result.candidates_truncated ? " (truncated)" : "") +
        `\n\nSetup nodes ${result.setup_nodes} · summary expansions ${result.summary_expansions} · scope nodes ${result.scope_nodes}` +
        (result.reason ? `\n\n${result.reason}` : "") +
        (result.limit ? `\n\nLimit: ${result.limit}` : "") +
        (result.semantic_unsupported
          ? `\n\nSemantic support absent: ${result.semantic_unsupported}`
          : "") +
        (result.coverage === "exhaustive"
          ? ""
          : "\n\nCoverage is not exhaustive, so an absent candidate says nothing.")
      );
    case "receiver_evidence":
      return (
        `**${result.evidence_kind}** for site \`${result.site_id}\` in ${result.path}` +
        (result.declaration_fq_name ? `\n\n\`${result.declaration_fq_name}\`` : "") +
        (result.declaration_kind ? ` (${result.declaration_kind})` : "") +
        `\n\nOrdinal ${result.ordinal} · chain hop ${result.chain_hop} · ${result.proof}/${result.completeness}` +
        (result.parent_evidence_id
          ? `\n\nChained from evidence \`${result.parent_evidence_id}\``
          : "\n\nFirst hop of its chain") +
        (result.factory_id ? `\n\nFactory: \`${result.factory_id}\`` : "")
      );
    case "member_selection":
      return (
        `**${result.member}** (${result.role}) at ${result.path}:${result.range.start_line}:${result.range.start_column}` +
        `\n\n${result.outcome} · ${result.selected_count} selected of ${result.candidate_count} candidate${result.candidate_count === 1 ? "" : "s"}` +
        `\n\nTrace ${result.trace_completeness} · coverage ${result.coverage}` +
        (result.trace_completeness === "selection_only"
          ? "\n\nThis resolver reports only its selections, so an absent rejection row says nothing."
          : "") +
        (result.trace_completeness === "absent"
          ? "\n\nThis language records no candidate trace, so an absent rejection row says nothing."
          : "")
      );
  }
}

export function queryResultIcon(result: RqlQueryResultItem): string {
  switch (result.result_type) {
    case "structural_match":
      return "symbol-method";
    case "declaration":
      return "symbol-class";
    case "procedure":
      return "symbol-method";
    case "program_point":
      return "debug-breakpoint";
    case "control_edge":
      return "arrow-right";
    case "typestate_finding":
      return "symbol-event";
    case "typestate_witness":
      return "debug-alt";
    case "flow_endpoint":
      return "target";
    case "flow_witness":
      return "debug-alt";
    case "taint_finding":
      return "warning";
    case "file":
      return "file-code";
    case "reference_site":
      return "references";
    case "call_site":
      return "call-outgoing";
    case "expression_site":
      return "symbol-variable";
    case "receiver_analysis":
      return "type-hierarchy";
    case "occurrence":
      return "symbol-key";
    case "lexical_scope":
      return "bracket";
    case "binding":
      return "symbol-variable";
    case "resolution_candidate":
      return "list-selection";
    case "reference_edge":
      return "arrow-both";
    case "receiver_outcome":
      return "pulse";
    case "receiver_evidence":
      return "symbol-field";
    case "member_selection":
      return "checklist";
  }
}

export function queryResultRange(result: RqlQueryResultItem): RqlResultRange | undefined {
  switch (result.result_type) {
    // A receiver-evidence row is evidence about a site, not a second location.
    case "file":
    case "receiver_evidence":
      return undefined;
    case "receiver_outcome":
    case "member_selection":
    case "reference_site":
    case "call_site":
    case "expression_site":
    case "receiver_analysis":
    case "occurrence":
    case "lexical_scope":
    case "binding":
    case "resolution_candidate":
    case "reference_edge":
    case "procedure":
    case "program_point":
    case "control_edge":
    case "typestate_finding":
    case "typestate_witness":
    case "flow_endpoint":
    case "flow_witness":
    case "taint_finding":
      return result.range;
    case "structural_match":
    case "declaration":
      return {
        start_line: result.start_line,
        start_column: 1,
        end_line: result.end_line,
        end_column: 1
      };
  }
}

export interface RqlQueryNavigationTarget {
  uri: string;
  path: string;
  range?: RqlResultRange;
}

export interface RqlTypestateWitnessStepTarget extends RqlQueryNavigationTarget {
  index: number;
  label: string;
  description: string;
  tooltip: string;
}

export function typestateWitnessStepTargets(
  result: RqlTypestateWitnessResult
): RqlTypestateWitnessStepTarget[] {
  return result.steps.map((step, index) => ({
    index,
    uri: result.witnessStepUris?.[index] ?? result.uri,
    path: step.source.path,
    range: step.source.range,
    label: `${index + 1}. ${typestateWitnessStepKindLabel(step.kind)}`,
    description: `${step.source.path}:${step.source.range.start_line}:${step.source.range.start_column}`,
    tooltip:
      `**${typestateWitnessStepKindLabel(step.kind)}** at ` +
      `${step.source.path}:${step.source.range.start_line}:${step.source.range.start_column}` +
      `\n\nEvidence: ${semanticEvidenceLabel(step.evidence)}`
  }));
}

export function flowWitnessStepTargets(
  result: RqlFlowWitnessResult
): RqlTypestateWitnessStepTarget[] {
  return result.steps.map((step, index) => ({
    index,
    uri: result.witnessStepUris?.[index] ?? result.uri,
    path: step.source.path,
    range: step.source.range,
    label: `${index + 1}. ${typestateWitnessStepKindLabel(step.kind)}`,
    description: `${step.source.path}:${step.source.range.start_line}:${step.source.range.start_column}`,
    tooltip:
      `**${typestateWitnessStepKindLabel(step.kind)}** at ` +
      `${step.source.path}:${step.source.range.start_line}:${step.source.range.start_column}` +
      `\n\nEvidence: ${semanticEvidenceLabel(step.evidence)}` +
      (step.boundary ? `\n\nBoundary: ${step.boundary}` : "") +
      (step.input && step.output
        ? `\n\nFacts: ${flowFactLabel(step.input)} -> ${flowFactLabel(step.output)}`
        : "")
  }));
}

function flowFactLabel(fact: RqlFlowFactSymbol): string {
  switch (fact.kind) {
    case "zero":
      return "zero";
    case "carrier":
      return `${fact.source.id} on ${fact.carrier.kind}:${fact.carrier.id}`;
    case "meeting":
      return `${fact.source.id} meets ${fact.sink.id}`;
  }
}

function semanticEvidenceLabel(evidence: RqlSemanticEvidence): string {
  const status = `${evidence.proof}/${evidence.completeness}`;
  const reasons = [evidence.proof_reason, evidence.completeness_reason].filter(
    (reason): reason is string => reason !== undefined
  );
  return reasons.length > 0 ? `${status} — ${reasons.join("; ")}` : status;
}

function programPointRefLabel(point: RqlProgramPointRef): string {
  const boundary = point.boundary ? ` ${point.boundary}` : "";
  return `${point.id}${boundary} at ${point.path}:${point.range.start_line}:${point.range.start_column}`;
}

function typestateFindingKindLabel(kind: RqlTypestateFindingKind): string {
  if (kind.type === "error_transition") {
    return `${kind.event}: ${kind.from_state} → ${kind.to_state}`;
  }
  return `${kind.expectation}: actual ${kind.actual_states.join(", ")}`;
}

function typestateWitnessStepKindLabel(kind: RqlTypestateWitnessStepKind): string {
  switch (kind.type) {
    case "seed":
      return "seed";
    case "edge":
      return `${kind.edge_kind} edge`;
    case "end_summary_gap":
      return `${kind.return_kind} summary gap`;
  }
}

function typestateUncertaintyLabel(
  uncertainty: readonly RqlTypestateUncertainty[] | undefined
): string {
  return uncertainty?.length ? `\n\nUncertainty: ${uncertainty.join(", ")}` : "";
}
