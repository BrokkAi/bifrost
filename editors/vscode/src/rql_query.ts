export const RQL_LANGUAGE_ID = "bifrost-rql";
export const RUN_RQL_QUERY_METHOD = "bifrost/queryCode";

export interface RqlQueryDocument {
  languageId: string;
  text: string;
}

interface RqlQueryResultBase {
  uri: string;
  path: string;
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

export type RqlQueryResultItem =
  | RqlStructuralMatchResult
  | RqlDeclarationResult
  | RqlFileResult
  | RqlReferenceSiteResult
  | RqlCallSiteResult
  | RqlExpressionSiteResult
  | RqlReceiverAnalysisResult;

export interface RqlQueryResponse {
  text: string;
  results?: RqlQueryResultItem[];
}

export interface RqlQueryResult {
  text: string;
  results: RqlQueryResultItem[];
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
    return { text: response.text, results: response.results };
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
  }
}

export function queryResultDescription(result: RqlQueryResultItem): string {
  switch (result.result_type) {
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
  }
}

export function queryResultIcon(result: RqlQueryResultItem): string {
  switch (result.result_type) {
    case "structural_match":
      return "symbol-method";
    case "declaration":
      return "symbol-class";
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
  }
}

export function queryResultRange(result: RqlQueryResultItem): RqlResultRange | undefined {
  switch (result.result_type) {
    case "file":
      return undefined;
    case "reference_site":
    case "call_site":
    case "expression_site":
    case "receiver_analysis":
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
