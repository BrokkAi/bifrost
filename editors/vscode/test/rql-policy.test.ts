import assert from "node:assert/strict";
import { test } from "node:test";
import {
  RUN_RQL_POLICY_METHOD,
  policyCompletionDetail,
  policyCompletionLabel,
  policyFindingTerminalSymbol,
  policyLocationRange,
  runRqlPolicy,
  type PolicyFinding,
  type RqlPolicyRunner
} from "../src/rql_policy";
import { RQL_POLICY_LANGUAGE_ID } from "../src/rql_validation";

function response(completion: unknown = { type: "complete" }): unknown {
  return {
    workspaceRootUri: "file:///workspace",
    report: {
      schema_version: 1,
      rules: [
        {
          policy_id: "test.policy",
          name: "Test policy",
          analysis_type: "match",
          message: { type: "static", text: "Avoid target" },
          severity: { type: "fixed", level: "warning" }
        }
      ],
      runs: [
        {
          policy_id: "test.policy",
          analysis_type: "match",
          completion,
          findings: [],
          diagnostics: []
        }
      ],
      diagnostics: [],
      diagnostics_truncated: false,
      omitted_diagnostics_lower_bound: 0,
      worst_omitted_diagnostic_severity: null
    }
  };
}

function runner(overrides: Partial<RqlPolicyRunner> = {}): RqlPolicyRunner {
  return {
    isReady: () => true,
    sendRequest: () => Promise.resolve(response()),
    showError: () => {},
    showWarning: () => {},
    ...overrides
  };
}

void test("runs unsaved policy text with URI and workspace-relative identity", async () => {
  const requests: Array<[string, unknown]> = [];
  const result = await runRqlPolicy(
    {
      languageId: RQL_POLICY_LANGUAGE_ID,
      uri: "file:///workspace/policies/live.rqlp",
      workspaceRootUri: "file:///workspace",
      sourceIdentity: "policies/live.rqlp",
      text: '(policy :id "test.unsaved")'
    },
    runner({
      sendRequest: (method, params) => {
        requests.push([method, params]);
        return Promise.resolve(response());
      }
    })
  );

  assert.ok(result);
  assert.deepEqual(requests, [
    [
      RUN_RQL_POLICY_METHOD,
      {
        documentUri: "file:///workspace/policies/live.rqlp",
        sourceIdentity: "policies/live.rqlp",
        source: '(policy :id "test.unsaved")'
      }
    ]
  ]);
});

void test("keeps every policy completion state explicit", async () => {
  for (const completion of [
    { type: "complete" },
    { type: "inconclusive", reasons: [{ type: "partial_discovery" }] },
    { type: "unsupported", capability: { type: "taint_evaluation" } },
    { type: "failed", reasons: ["internal_invariant"] }
  ] as const) {
    const result = await runRqlPolicy(
      {
        languageId: RQL_POLICY_LANGUAGE_ID,
        uri: "file:///workspace/p.rqlp",
        workspaceRootUri: "file:///workspace",
        sourceIdentity: "p.rqlp",
        text: "(policy)"
      },
      runner({ sendRequest: () => Promise.resolve(response(completion)) })
    );
    assert.equal(result?.report.runs[0].completion.type, completion.type);
    assert.equal(policyCompletionLabel(completion), completion.type);
    assert.ok(policyCompletionDetail(completion).includes(completion.type));
  }
});

void test("extracts terminal symbols while keeping evidence structured", () => {
  const finding = {
    id: "finding",
    policy_id: "test.policy",
    severity: "warning",
    message: "Avoid target",
    primary: { path: "app.ts", region: null },
    evidence: {
      type: "match",
      evidence: {
        terminal: {
          type: "declaration",
          kind: "function",
          fq_name: "app.target"
        }
      }
    }
  } satisfies PolicyFinding;

  assert.equal(policyFindingTerminalSymbol(finding), "app.target");
  assert.deepEqual(
    policyLocationRange({
      path: "app.ts",
      region: { start_line: 7, start_column: 4, end_line: 8, end_column: 9 }
    }),
    {
      start: { line: 6, character: 3 },
      end: { line: 7, character: 8 }
    }
  );
});

void test("rejects wrong documents, missing workspaces, and outdated report shapes", async () => {
  const warnings: string[] = [];
  const errors: string[] = [];
  let requests = 0;
  const base = {
    languageId: RQL_POLICY_LANGUAGE_ID,
    uri: "file:///workspace/p.rqlp",
    workspaceRootUri: "file:///workspace",
    sourceIdentity: "p.rqlp",
    text: "(policy)"
  };
  const testRunner = runner({
    sendRequest: () => {
      requests += 1;
      return Promise.resolve({ report: { schema_version: 2 } });
    },
    showWarning: (message) => warnings.push(message),
    showError: (message) => errors.push(message)
  });

  assert.equal(await runRqlPolicy({ ...base, languageId: "bifrost-rql" }, testRunner), undefined);
  assert.equal(
    await runRqlPolicy({ ...base, workspaceRootUri: "", sourceIdentity: "" }, testRunner),
    undefined
  );
  assert.equal(await runRqlPolicy(base, testRunner), undefined);
  assert.equal(requests, 1);
  assert.equal(warnings.length, 2);
  assert.match(errors[0], /updated language server/);
});
