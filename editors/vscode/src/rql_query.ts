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

export interface RqlFileResult extends RqlQueryResultBase {
  result_type: "file";
  language: string;
}

export type RqlQueryResultItem =
  | RqlStructuralMatchResult
  | RqlDeclarationResult
  | RqlFileResult;

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
