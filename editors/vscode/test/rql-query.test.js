const assert = require("node:assert/strict");
const test = require("node:test");

const {
  RQL_LANGUAGE_ID,
  RUN_RQL_QUERY_METHOD,
  groupRqlQueryResults,
  runRqlQuery
} = require("../out-test/rql_query.js");

function runner(overrides = {}) {
  return {
    isReady: () => true,
    sendRequest: async () => ({ text: "1 result\n", results: [] }),
    showError: () => {},
    showWarning: () => {},
    ...overrides
  };
}

test("runs unsaved RQL editor text and returns typed results", async () => {
  const requests = [];
  const response = await runRqlQuery(
    {
      languageId: RQL_LANGUAGE_ID,
      text: '(class :name "UnsavedClass")'
    },
    runner({
      sendRequest: async (method, params) => {
        requests.push([method, params]);
        return {
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
        };
      }
    })
  );

  assert.deepEqual(requests, [
    [RUN_RQL_QUERY_METHOD, { query: '(class :name "UnsavedClass")' }]
  ]);
  assert.equal(response.results[0].path, "src/app.py");
});

test("warns without issuing a request when Bifrost is not ready", async () => {
  const warnings = [];
  const response = await runRqlQuery(
    { languageId: RQL_LANGUAGE_ID, text: "(class)" },
    runner({
      isReady: () => false,
      showWarning: (message) => warnings.push(message)
    })
  );

  assert.equal(response, undefined);
  assert.deepEqual(warnings, ["Bifrost is not ready. Start the language server and wait for indexing to finish."]);
});

test("reports request failures through the error UI", async () => {
  const errors = [];
  const response = await runRqlQuery(
    { languageId: RQL_LANGUAGE_ID, text: "(class" },
    runner({
      sendRequest: async () => {
        throw new Error("Failed to parse query source: unexpected end of input");
      },
      showError: (message) => errors.push(message)
    })
  );

  assert.equal(response, undefined);
  assert.deepEqual(errors, [
    "Bifrost RQL query failed: Failed to parse query source: unexpected end of input"
  ]);
});

test("reports an outdated server response without attempting to render it", async () => {
  const errors = [];
  const response = await runRqlQuery(
    { languageId: RQL_LANGUAGE_ID, text: "(class)" },
    runner({
      sendRequest: async () => ({ text: "1 match\n" }),
      showError: (message) => errors.push(message)
    })
  );

  assert.equal(response, undefined);
  assert.deepEqual(errors, [
    "Bifrost RQL results require an updated language server. Rebuild and restart Bifrost, then run the query again."
  ]);
});

test("groups mixed typed results by path while preserving result order", () => {
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
