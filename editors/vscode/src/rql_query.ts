export const RQL_LANGUAGE_ID = "bifrost-rql";
export const RUN_RQL_QUERY_METHOD = "bifrost/queryCode";

export interface RqlQueryDocument {
  languageId: string;
  text: string;
}

interface RqlQueryResultBase {
  uri: string;
  path: string;
  provenance?: unknown[];
  provenance_truncated?: boolean;
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

export type RqlQueryResultItem =
  | RqlStructuralMatchResult
  | RqlDeclarationResult
  | RqlFileResult
  | RqlReferenceSiteResult;

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
    runner.showWarning("Bifrost is not ready. Start the language server and wait for indexing to finish.");
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
  }
}

export function queryResultDescription(result: RqlQueryResultItem): string {
  switch (result.result_type) {
    case "file":
      return `file · ${result.language}`;
    case "reference_site":
      return `${result.reference_kind ?? "reference"} · ${result.range.start_line}:${result.range.start_column}`;
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
  }
}

export function queryResultRange(result: RqlQueryResultItem): RqlResultRange | undefined {
  switch (result.result_type) {
    case "file":
      return undefined;
    case "reference_site":
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
