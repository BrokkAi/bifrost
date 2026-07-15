import assert from "node:assert/strict";
import { test } from "node:test";
import {
  RQL_LANGUAGE_ID,
  RUN_RQL_QUERY_METHOD,
  groupRqlQueryResults,
  queryResultDescription,
  queryResultIcon,
  queryResultLabel,
  queryResultRange,
  queryResultTooltip,
  runRqlQuery,
  type RqlQueryRunner,
  type RqlReferenceSiteResult
} from "../src/rql_query";

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
