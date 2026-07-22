import assert from "node:assert/strict";
import { test } from "node:test";
import {
  RQL_LANGUAGE_ID,
  RUN_RQL_QUERY_METHOD,
  formatRqlQueryOutput,
  groupRqlQueryResults,
  queryResultDescription,
  queryResultIcon,
  queryResultLabel,
  queryResultRange,
  queryResultTooltip,
  runRqlQuery,
  type RqlQueryRunner,
  type RqlReceiverAnalysisResult,
  type RqlReferenceSiteResult
} from "../src/rql_query";
import { RQL_POLICY_LANGUAGE_ID } from "../src/rql_validation";

function runner(overrides: Partial<RqlQueryRunner> = {}): RqlQueryRunner {
  return {
    isReady: () => true,
    sendRequest: () => Promise.resolve({ text: "1 result\n", results: [] }),
    showError: () => {},
    showWarning: () => {},
    ...overrides
  };
}

void test("runs unsaved RQL editor text and returns typed results", async () => {
  const requests: Array<[string, { query: string }]> = [];
  const response = await runRqlQuery(
    {
      languageId: RQL_LANGUAGE_ID,
      text: '(class :name "UnsavedClass")'
    },
    runner({
      sendRequest: (method, params) => {
        requests.push([method, params]);
        return Promise.resolve({
          text: "1 match\n\nsrc/app.py:1 [class] `class UnsavedClass`\n",
          results: [
            {
              uri: "file:///workspace/src/app.py",
              path: "src/app.py",
              result_type: "structural_match",
              kind: "class",
              language: "python",
              start_line: 1,
              end_line: 1,
              text: "class UnsavedClass"
            }
          ]
        });
      }
    })
  );

  assert.ok(response);
  assert.deepEqual(requests, [[RUN_RQL_QUERY_METHOD, { query: '(class :name "UnsavedClass")' }]]);
  assert.equal(response.results[0].path, "src/app.py");
  assert.equal(response.mode, "results");
});

void test("accepts planning-only explain responses without result rows", async () => {
  const response = await runRqlQuery(
    { languageId: RQL_LANGUAGE_ID, text: "(explain (class))" },
    runner({
      sendRequest: () =>
        Promise.resolve({
          text: "CodeQuery explain\n",
          mode: "explain",
          report: { format: "bifrost_code_query_explain/v1" },
          results: []
        })
    })
  );

  assert.ok(response);
  assert.equal(response.mode, "explain");
  assert.deepEqual(response.results, []);
  assert.deepEqual(response.report, { format: "bifrost_code_query_explain/v1" });
});

void test("retains profiled ordinary results for navigation", async () => {
  const response = await runRqlQuery(
    { languageId: RQL_LANGUAGE_ID, text: "(profile (class))" },
    runner({
      sendRequest: () =>
        Promise.resolve({
          text: "1 result\n\nCodeQuery profile\n",
          mode: "profile",
          report: { format: "bifrost_code_query_profile/v1" },
          results: [
            {
              uri: "file:///workspace/src/app.py",
              path: "src/app.py",
              result_type: "file",
              language: "python"
            }
          ]
        })
    })
  );

  assert.ok(response);
  assert.equal(response.mode, "profile");
  assert.equal(response.results.length, 1);
  assert.match(formatRqlQueryOutput(response), /CodeQuery profile report:/);
  assert.match(formatRqlQueryOutput(response), /bifrost_code_query_profile\/v1/);
});

void test("warns without issuing a request when Bifrost is not ready", async () => {
  const warnings: string[] = [];
  const response = await runRqlQuery(
    { languageId: RQL_LANGUAGE_ID, text: "(class)" },
    runner({
      isReady: () => false,
      showWarning: (message) => warnings.push(message)
    })
  );

  assert.equal(response, undefined);
  assert.deepEqual(warnings, [
    "Bifrost is not ready. Start the language server and wait for indexing to finish."
  ]);
});

void test("does not expose query execution to RQL policy documents", async () => {
  const warnings: string[] = [];
  let requests = 0;
  const response = await runRqlQuery(
    { languageId: RQL_POLICY_LANGUAGE_ID, text: "(policy)" },
    runner({
      sendRequest: () => {
        requests += 1;
        return Promise.resolve({ text: "unexpected", results: [] });
      },
      showWarning: (message) => warnings.push(message)
    })
  );

  assert.equal(response, undefined);
  assert.equal(requests, 0);
  assert.deepEqual(warnings, ["Open a Bifrost RQL file to run a query."]);
});

void test("reports request failures through the error UI", async () => {
  const errors: string[] = [];
  const response = await runRqlQuery(
    { languageId: RQL_LANGUAGE_ID, text: "(class" },
    runner({
      sendRequest: () =>
        Promise.reject(new Error("Failed to parse query source: unexpected end of input")),
      showError: (message) => errors.push(message)
    })
  );

  assert.equal(response, undefined);
  assert.deepEqual(errors, [
    "Bifrost RQL query failed: Failed to parse query source: unexpected end of input"
  ]);
});

void test("reports an outdated server response without attempting to render it", async () => {
  const errors: string[] = [];
  const response = await runRqlQuery(
    { languageId: RQL_LANGUAGE_ID, text: "(class)" },
    runner({
      sendRequest: () => Promise.resolve({ text: "1 match\n" }),
      showError: (message) => errors.push(message)
    })
  );

  assert.equal(response, undefined);
  assert.deepEqual(errors, [
    "Bifrost RQL results require an updated language server. Rebuild and restart Bifrost, then run the query again."
  ]);
});

void test("groups mixed typed results by path while preserving result order", () => {
  const grouped = groupRqlQueryResults([
    {
      uri: "file:///a.rs",
      path: "a.rs",
      result_type: "structural_match",
      kind: "function",
      language: "rust",
      start_line: 1,
      end_line: 2,
      text: "a"
    },
    {
      uri: "file:///b.rs",
      path: "b.rs",
      result_type: "file",
      language: "rust"
    },
    {
      uri: "file:///a.rs",
      path: "a.rs",
      result_type: "declaration",
      kind: "class",
      language: "rust",
      fq_name: "crate::C",
      start_line: 5,
      end_line: 6
    }
  ]);

  assert.deepEqual(
    grouped.map((group) => [group.path, group.results.map((result) => result.result_type)]),
    [
      ["a.rs", ["structural_match", "declaration"]],
      ["b.rs", ["file"]]
    ]
  );
});

void test("renders and navigates an exact reference-site result", () => {
  const reference: RqlReferenceSiteResult = {
    uri: "file:///workspace/src/user.ts",
    path: "src/user.ts",
    result_type: "reference_site",
    language: "typescript",
    range: {
      start_line: 7,
      start_column: 14,
      end_line: 7,
      end_column: 20
    },
    target: {
      path: "src/target.ts",
      language: "typescript",
      kind: "function",
      fq_name: "Target.status",
      start_line: 2,
      end_line: 2
    },
    usage_kind: "reference",
    proof: "proven",
    reference_kind: "field_read"
  };

  assert.equal(queryResultLabel(reference), "Target.status");
  assert.equal(queryResultDescription(reference), "field_read · 7:14");
  assert.equal(queryResultIcon(reference), "references");
  assert.match(queryResultTooltip(reference), /Target\.status/);
  assert.deepEqual(queryResultRange(reference), reference.range);
});

void test("renders and navigates a receiver-analysis result", () => {
  const analysis: RqlReceiverAnalysisResult = {
    uri: "file:///workspace/src/app.ts",
    path: "src/app.ts",
    result_type: "receiver_analysis",
    analysis_kind: "points_to",
    language: "typescript",
    range: {
      start_line: 9,
      start_column: 15,
      end_line: 9,
      end_column: 22
    },
    text: "service",
    input_kind: "identifier",
    outcome: "precise",
    values: [
      {
        receiver_value_kind: "factory_return",
        factory: {
          path: "src/app.ts",
          language: "typescript",
          kind: "function",
          fq_name: "makeService",
          start_line: 2,
          end_line: 4
        },
        returned_value: {
          receiver_value_kind: "allocation_site",
          type_declaration: {
            path: "src/app.ts",
            language: "typescript",
            kind: "class",
            fq_name: "Service",
            start_line: 1,
            end_line: 1
          },
          allocation_site: {
            path: "src/app.ts",
            range: {
              start_line: 3,
              start_column: 10,
              end_line: 3,
              end_column: 23
            }
          }
        }
      }
    ]
  };

  assert.equal(queryResultLabel(analysis), "points_to: service");
  assert.equal(queryResultDescription(analysis), "precise · 9:15");
  assert.equal(queryResultIcon(analysis), "type-hierarchy");
  const tooltip = queryResultTooltip(analysis);
  assert.match(tooltip, /points_to/);
  assert.match(tooltip, /factory makeService/);
  assert.match(tooltip, /allocation Service/);
  assert.deepEqual(queryResultRange(analysis), analysis.range);
});
