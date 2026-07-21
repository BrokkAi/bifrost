import assert from "node:assert/strict";
import { test } from "node:test";
import {
  RUN_RQL_POLICY_METHOD,
  PolicyRunTracker,
  policyCompletionDetail,
  policyCompletionLabel,
  policyFindingTerminalSymbol,
  policyLocationRange,
  policyReportCompletedWithoutFindings,
  policyRunDiagnosticCodeLabel,
  runRqlPolicy,
  type PolicyFinding,
  type RqlPolicyRunner
} from "../src/rql_policy";
import { RQL_POLICY_LANGUAGE_ID } from "../src/rql_validation";

function response(completion: unknown = { type: "complete" }): unknown {
  return {
    policyRootUri: "file:///workspace/service-a",
    reportRootUri: "file:///workspace",
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
          diagnostics: [],
          diagnostics_truncated: false
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

void test("runs unsaved policy text and lets the server derive workspace identity", async () => {
  const requests: Array<[string, unknown]> = [];
  const result = await runRqlPolicy(
    {
      languageId: RQL_POLICY_LANGUAGE_ID,
      uri: "file:///workspace/policies/live.rqlp",
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
        text: "(policy)"
      },
      runner({ sendRequest: () => Promise.resolve(response(completion)) })
    );
    assert.equal(result?.report.runs[0].completion.type, completion.type);
    assert.equal(policyCompletionLabel(completion), completion.type);
    assert.ok(policyCompletionDetail(completion).includes(completion.type));
  }
});

void test("accepts and labels canonical tagged run diagnostics", async () => {
  const unsupported = response({
    type: "unsupported",
    capability: { type: "taint_evaluation" }
  }) as {
    report: { runs: Array<{ diagnostics: unknown[] }> };
  };
  unsupported.report.runs[0].diagnostics = [
    {
      code: { type: "unsupported_analysis" },
      severity: "warning",
      impact: "run_unsupported",
      message: "Taint evaluation is not supported.",
      primary: null,
      related: []
    },
    {
      code: { type: "code_query", code: "execution_budget_exhausted" },
      severity: "warning",
      impact: "run_incomplete",
      message: "The query budget was exhausted.",
      primary: null,
      related: []
    }
  ];

  const result = await runRqlPolicy(
    {
      languageId: RQL_POLICY_LANGUAGE_ID,
      uri: "file:///external/p.rqlp",
      text: "(policy)"
    },
    runner({ sendRequest: () => Promise.resolve(unsupported) })
  );

  assert.equal(result?.report.runs[0].diagnostics.length, 2);
  assert.equal(
    policyRunDiagnosticCodeLabel(result.report.runs[0].diagnostics[0].code),
    "unsupported_analysis"
  );
  assert.equal(
    policyRunDiagnosticCodeLabel(result.report.runs[0].diagnostics[1].code),
    "code_query:execution_budget_exhausted"
  );
});

void test("treats only complete diagnostic-free zero-finding reports as clean", () => {
  const complete = response() as {
    report: Parameters<typeof policyReportCompletedWithoutFindings>[0];
  };
  const unsupported = response({
    type: "unsupported",
    capability: { type: "taint_evaluation" }
  }) as typeof complete;

  assert.equal(policyReportCompletedWithoutFindings(complete.report), true);
  assert.equal(policyReportCompletedWithoutFindings(unsupported.report), false);
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

void test("rejects wrong documents and outdated report shapes", async () => {
  const warnings: string[] = [];
  const errors: string[] = [];
  let requests = 0;
  const base = {
    languageId: RQL_POLICY_LANGUAGE_ID,
    uri: "file:///workspace/p.rqlp",
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
  assert.equal(await runRqlPolicy(base, testRunner), undefined);
  assert.equal(requests, 1);
  assert.equal(warnings.length, 1);
  assert.match(errors[0], /updated language server/);
});

void test("publishes only the newest run and preserves changes during execution", () => {
  const tracker = new PolicyRunTracker();
  const first = tracker.beginRun();
  const second = tracker.beginRun();

  assert.deepEqual(tracker.publicationFor(first), { publish: false });
  assert.deepEqual(tracker.publicationFor(second), { publish: true, staleReason: undefined });

  const third = tracker.beginRun();
  tracker.markChanged("policy changed");
  assert.deepEqual(tracker.publicationFor(third), {
    publish: true,
    staleReason: "policy changed"
  });
});
