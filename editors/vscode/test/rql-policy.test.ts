import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { resolve } from "node:path";
import {
  RUN_RQL_POLICY_METHOD,
  PolicyRunTracker,
  policyCompletionDetail,
  policyCompletionLabel,
  policyFindingTerminalSymbol,
  policyLocationRange,
  policyReportCompletedWithoutFindings,
  policyRunDiagnosticCodeLabel,
  policySuppressionAuditSummary,
  isRqlPolicyResponse,
  runRqlPolicy,
  utcEvaluationDate,
  type PolicyFinding,
  type RqlPolicyRunner
} from "../src/rql_policy";
import { RQL_POLICY_LANGUAGE_ID } from "../src/rql_validation";

function response(completion: unknown = { type: "complete" }): unknown {
  return {
    policyRootUri: "file:///workspace/service-a",
    reportRootUri: "file:///workspace",
    report: {
      schema_version: 3,
      evaluation: {
        evaluation_date: "2026-07-27",
        suppression_path: ".bifrost/suppressions.json",
        suppression_document_state: "not_found",
        scope_path: ".bifrost/scopes.json",
        scope_document_state: "not_found"
      },
      execution: {
        total_elapsed_ms: 1,
        stage_timings: [],
        termination: null,
        terminal_stage: null,
        active_policy_id: null,
        completed_policy_ids: ["test.policy"],
        pending_policy_ids: []
      },
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
      suppressions: [],
      scope: [],
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

void test("accepts the canonical Rust schema-3 one-finding contract artifact", () => {
  const fixture = JSON.parse(
    readFileSync(
      resolve(__dirname, "../../../../tests/fixtures/policy-report/v3-one-finding.json"),
      "utf8"
    )
  ) as unknown;

  assert.equal(isRqlPolicyResponse(fixture), true);
  if (!isRqlPolicyResponse(fixture)) {
    return;
  }
  assert.equal(fixture.report.schema_version, 3);
  assert.equal(fixture.report.runs[0].findings.length, 1);
  assert.equal(fixture.report.runs[0].findings[0].primary.path, "app.ts");
});

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
  assert.equal(requests.length, 1);
  assert.equal(requests[0][0], RUN_RQL_POLICY_METHOD);
  assert.deepEqual(
    {
      ...(requests[0][1] as Record<string, unknown>),
      evaluationDate: "<date>"
    },
    {
      documentUri: "file:///workspace/policies/live.rqlp",
      source: '(policy :id "test.unsaved")',
      evaluationDate: "<date>"
    }
  );
  assert.match(
    (requests[0][1] as { evaluationDate: string }).evaluationDate,
    /^\d{4}-\d{2}-\d{2}$/
  );
  assert.equal(utcEvaluationDate(new Date("2026-07-27T23:59:59.000Z")), "2026-07-27");
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

  complete.report.runs[0].findings.push({
    id: "1".repeat(64),
    policy_id: "test.policy",
    severity: "warning",
    message: "Accepted result",
    primary: { path: "app.ts", region: null },
    suppression: {
      identity_stability: "strong",
      status: "accepted",
      reason: "Reviewed",
      accepted_at: "2026-07-01",
      policy_hash_state: "matching"
    }
  });
  assert.equal(policyReportCompletedWithoutFindings(complete.report), true);
});

void test("summarizes orthogonal suppression audit states without hiding overlap", () => {
  const decision = {
    identity_stability: "strong" as const,
    status: "accepted" as const,
    reason: "Reviewed",
    accepted_at: "2026-07-01",
    policy_hash_state: "matching" as const,
    policy_id: "test.policy",
    finding_id: "1".repeat(64),
    match_state: "strong_finding" as const,
    temporal_state: "current" as const,
    applied: true,
    stale: false,
    result_omitted: false
  };
  assert.equal(
    policySuppressionAuditSummary([
      decision,
      {
        ...decision,
        finding_id: "2".repeat(64),
        match_state: "finding_absent",
        temporal_state: "expired",
        policy_hash_state: "drifted",
        applied: false,
        stale: true,
        result_omitted: true
      },
      {
        ...decision,
        finding_id: "3".repeat(64),
        match_state: "policy_incomplete",
        applied: false
      }
    ]),
    "1 applied · 1 stale · 1 expired · 1 drifted · 1 unproven · 1 result omitted"
  );
});

void test("extracts terminal symbols while keeping evidence structured", () => {
  const finding = {
    id: "finding",
    policy_id: "test.policy",
    severity: "warning",
    message: "Avoid target",
    primary: { path: "app.ts", region: null },
    suppression: null,
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

void test("rejects wrong documents and reports observed and supported schemas", async () => {
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
      return Promise.resolve({
        policyRootUri: "file:///workspace",
        reportRootUri: "file:///workspace",
        report: { schema_version: 99 }
      });
    },
    showWarning: (message) => warnings.push(message),
    showError: (message) => errors.push(message)
  });

  assert.equal(await runRqlPolicy({ ...base, languageId: "bifrost-rql" }, testRunner), undefined);
  assert.equal(await runRqlPolicy(base, testRunner), undefined);
  assert.equal(requests, 1);
  assert.equal(warnings.length, 1);
  assert.match(errors[0], /schema 99/);
  assert.match(errors[0], /schema 3/);
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
