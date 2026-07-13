export const RQL_LANGUAGE_ID = "bifrost-rql";
export const RUN_RQL_QUERY_METHOD = "bifrost/queryCode";

export interface RqlQueryDocument {
  languageId: string;
  text: string;
}

export interface RqlQueryMatch {
  uri: string;
  path: string;
  kind: string;
  startLine: number;
  endLine: number;
  text: string;
  enclosingSymbol?: string;
}

export interface RqlQueryResponse {
  text: string;
  matches?: RqlQueryMatch[];
}

export interface RqlQueryResult {
  text: string;
  matches: RqlQueryMatch[];
}

export interface RqlQueryFileGroup {
  path: string;
  matches: RqlQueryMatch[];
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
    if (!Array.isArray(response.matches)) {
      runner.showError(
        "Bifrost RQL results require an updated language server. Rebuild and restart Bifrost, then run the query again."
      );
      return undefined;
    }
    return { text: response.text, matches: response.matches };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    runner.showError(`Bifrost RQL query failed: ${message}`);
    return undefined;
  }
}

export function groupRqlQueryMatches(matches: readonly RqlQueryMatch[]): RqlQueryFileGroup[] {
  const files = new Map<string, RqlQueryFileGroup>();
  for (const match of matches) {
    const existing = files.get(match.path);
    if (existing) {
      existing.matches.push(match);
    } else {
      files.set(match.path, { path: match.path, matches: [match] });
    }
  }
  return [...files.values()];
}
