const assert = require("node:assert/strict");
const test = require("node:test");

const {
  RQL_LANGUAGE_ID,
  RUN_RQL_QUERY_METHOD,
  groupRqlQueryMatches,
  runRqlQuery
} = require("../out-test/rql_query.js");

function runner(overrides = {}) {
  return {
    isReady: () => true,
    sendRequest: async () => ({ text: "1 match\n", matches: [] }),
    showError: () => {},
    showWarning: () => {},
    ...overrides
  };
}

test("runs unsaved RQL editor text and returns structured matches", async () => {
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
          matches: [
            {
              uri: "file:///workspace/src/app.py",
              path: "src/app.py",
              kind: "class",
              startLine: 1,
              endLine: 1,
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
  assert.equal(response.matches[0].path, "src/app.py");
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
        throw new Error("Failed to parse RQL query: unexpected end of input");
      },
      showError: (message) => errors.push(message)
    })
  );

  assert.equal(response, undefined);
  assert.deepEqual(errors, [
    "Bifrost RQL query failed: Failed to parse RQL query: unexpected end of input"
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

test("groups query matches by path while preserving result order", () => {
  const grouped = groupRqlQueryMatches([
    { uri: "file:///a.rs", path: "a.rs", kind: "function", startLine: 1, endLine: 2, text: "a" },
    { uri: "file:///b.rs", path: "b.rs", kind: "function", startLine: 3, endLine: 4, text: "b" },
    { uri: "file:///a.rs", path: "a.rs", kind: "class", startLine: 5, endLine: 6, text: "c" }
  ]);

  assert.deepEqual(grouped.map((group) => [group.path, group.matches.map((match) => match.text)]), [
    ["a.rs", ["a", "c"]],
    ["b.rs", ["b"]]
  ]);
});
