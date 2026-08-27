import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { resolve } from "node:path";
import {
  RUN_RQL_POLICY_METHOD,
  decodePolicySuppressionAuthoringResponse,
  ExpectedPolicySuppressionWrite,
  hasCompletePolicySuppressionSourcePreconditions,
  isPolicySuppressionSourcePrecondition,
  isCurrentPolicyFinding,
  isPolicyFindingSuppressible,
  normalizeSuppressionReason,
  PolicyRunTracker,
  policyCompletionDetail,
  policyCompletionLabel,
  policyFindingDisplayRows,
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
      schema_version: 5,
      evaluation: {
        evaluation_date: "2026-07-27",
        suppression_sources: [
          { path: ".bifrost/suppressions.json", state: "not_found" },
          { path: ".bifrost/suppressions.private.json", state: "not_found" },
          { path: ".bifrost/suppressions.local.json", state: "not_found" }
        ],
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

void test("accepts the canonical Rust schema-5 one-finding contract artifact", () => {
  const fixture = JSON.parse(
    readFileSync(
      resolve(__dirname, "../../../../scripts/fixtures/policy-report/v5-one-finding.json"),
      "utf8"
    )
  ) as unknown;

  assert.equal(isRqlPolicyResponse(fixture), true);
  if (!isRqlPolicyResponse(fixture)) {
    return;
  }
  assert.equal(fixture.report.schema_version, 5);
  assert.equal(fixture.report.runs[0].findings.length, 1);
  assert.equal(fixture.report.runs[0].findings[0].primary.path, "app.ts");
});

void test("accepts a canonical schema-5 report with an applied suppression review", () => {
  const fixture = JSON.parse(
    readFileSync(
      resolve(__dirname, "../../../../scripts/fixtures/policy-report/v5-suppressed-finding.json"),
      "utf8"
    )
  ) as unknown;

  assert.equal(isRqlPolicyResponse(fixture), true);
  if (!isRqlPolicyResponse(fixture)) {
    return;
  }
  assert.equal(fixture.report.suppressions.length, 1);
  assert.equal(fixture.report.suppressions[0].orphan_state, "resolved");
  assert.equal(fixture.report.suppressions[0].applied, true);
  assert.equal(fixture.report.runs[0].findings[0].suppression?.policy_hash_state, "matching");
});

void test("rejects the removed singular suppression evaluation fields", () => {
  const legacy = response() as {
    report: { evaluation: Record<string, unknown> };
  };
  delete legacy.report.evaluation.suppression_sources;
  legacy.report.evaluation.suppression_path = ".bifrost/suppressions.json";
  legacy.report.evaluation.suppression_document_state = "not_found";
  assert.equal(isRqlPolicyResponse(legacy), false);
});

void test("decodes current suppression sources and prepared destination content", () => {
  const decoded = decodePolicySuppressionAuthoringResponse({
    documentUri: "file:///workspace/.bifrost/suppressions.json",
    expectedVersion: 7,
    expectedText: '{\n  "schema_version": 1\n}\n',
    content: '{\n  "schema_version": 1,\n  "suppressions": []\n}\n',
    create: false,
    sourcePreconditions: [
      {
        path: ".bifrost/suppressions.json",
        uri: "file:///workspace/.bifrost/suppressions.json",
        exists: true,
        expectedVersion: 7,
        expectedText: '{\n  "schema_version": 1\n}\n'
      },
      {
        path: ".bifrost/suppressions.private.json",
        uri: "file:///workspace/.bifrost/suppressions.private.json",
        exists: false,
        expectedVersion: null
      },
      {
        path: ".bifrost/suppressions.local.json",
        uri: "file:///workspace/.bifrost/suppressions.local.json",
        exists: false,
        expectedVersion: null
      }
    ]
  });
  assert.ok(decoded);
  assert.equal(decoded.documentUri, "file:///workspace/.bifrost/suppressions.json");
  assert.equal(decoded.expectedVersion, 7);
  assert.equal(decoded.create, false);
  assert.equal(decoded.sourcePreconditions.length, 3);
  assert.equal(decodePolicySuppressionAuthoringResponse({ content: "bad" }), undefined);
  assert.equal(hasCompletePolicySuppressionSourcePreconditions(decoded.sourcePreconditions), true);
  assert.equal(
    isPolicySuppressionSourcePrecondition({
      path: ".bifrost/suppressions.json",
      uri: "file:///workspace/.bifrost/suppressions.json",
      exists: false,
      expectedVersion: null,
      expectedText: "unexpected"
    }),
    false
  );
  assert.equal(
    hasCompletePolicySuppressionSourcePreconditions([
      ...decoded.sourcePreconditions.slice(0, 2),
      decoded.sourcePreconditions[0]
    ]),
    false
  );
  assert.equal(
    hasCompletePolicySuppressionSourcePreconditions(
      decoded.sourcePreconditions.map((source, index) =>
        index === 0 ? { ...source, path: ".bifrost/suppressions.other.json" } : source
      )
    ),
    false
  );
});

void test("eligibility and optional reason normalization fail closed", () => {
  const finding = {
    id: "1".repeat(64),
    identity_stability: "strong",
    policy_id: "test.policy",
    policy_hash: "a".repeat(64),
    severity: "warning",
    message: "Avoid target",
    primary: { path: "app.ts" },
    suppression: null
  } as PolicyFinding;
  assert.equal(isPolicyFindingSuppressible(finding), true);
  assert.equal(isPolicyFindingSuppressible(finding, true), false);
  assert.equal(isPolicyFindingSuppressible({ ...finding, identity_stability: "weak" }), false);
  assert.equal(
    isPolicyFindingSuppressible({
      ...finding,
      suppression: {
        identity_stability: "strong",
        status: "accepted",
        reason: "reviewed",
        accepted_at: "2026-07-27",
        policy_hash_state: "matching"
      }
    }),
    false
  );
  assert.equal(normalizeSuppressionReason("  reviewed  ", false), "reviewed");
  assert.equal(normalizeSuppressionReason("", false), "unspecified");
  assert.equal(normalizeSuppressionReason("   ", true), undefined);
  assert.equal(isCurrentPolicyFinding(finding, 4, 4, false, finding), true);
  assert.equal(isCurrentPolicyFinding(finding, 4, 5, false, finding), false);
  assert.equal(isCurrentPolicyFinding(finding, 4, 4, true, finding), false);
  assert.equal(isCurrentPolicyFinding(finding, 4, 4, false, { ...finding }), false);
});

void test("rejects a cached finding after policy or source state changes", () => {
  const finding = {
    id: "2".repeat(64),
    identity_stability: "strong",
    policy_id: "test.policy",
    policy_hash: "b".repeat(64),
    severity: "warning",
    message: "Avoid target",
    primary: { path: "app.ts" },
    suppression: null
  } as PolicyFinding;

  // A new policy publication invalidates command arguments from the prior run.
  assert.equal(isCurrentPolicyFinding(finding, 8, 9, false, finding), false);
  // A source edit marks the retained run stale before the replacement run is published.
  assert.equal(isCurrentPolicyFinding(finding, 8, 8, true, finding), false);
});

void test("keeps the Java relay display rows in server order for the policy tree", () => {
  const fixture = JSON.parse(
    readFileSync(
      resolve(__dirname, "../../../../scripts/fixtures/policy-report/v5-java-display-path.json"),
      "utf8"
    )
  ) as unknown;

  assert.equal(isRqlPolicyResponse(fixture), true);
  if (!isRqlPolicyResponse(fixture)) {
    return;
  }
  const finding = fixture.report.runs[0].findings[0];
  assert.deepEqual(
    policyFindingDisplayRows(finding).map((step) => ({
      kind: step.kind,
      path: step.location.path,
      line: step.location.region?.start_line,
      column: step.location.region?.start_column,
      label: step.label
    })),
    [
      { kind: "source", path: "Foo.java", line: 14, column: 20, label: "userInput()" },
      {
        kind: "call",
        path: "Foo.java",
        line: 14,
        column: 14,
        label: "relay(userInput())"
      },
      {
        kind: "propagation",
        path: "Foo.java",
        line: 8,
        column: 9,
        label: "return value;"
      },
      {
        kind: "return",
        path: "Foo.java",
        line: 14,
        column: 14,
        label: "return from relay(userInput())"
      },
      {
        kind: "sink",
        path: "Foo.java",
        line: 14,
        column: 9,
        label: "eval(relay(userInput()))"
      }
    ]
  );

  const unsupportedProjection = JSON.parse(JSON.stringify(fixture)) as {
    report: { runs: Array<{ findings: Array<{ display_path: { schema_version: number } }> }> };
  };
  unsupportedProjection.report.runs[0].findings[0].display_path.schema_version = 2;
  assert.equal(isRqlPolicyResponse(unsupportedProjection), false);
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
    identity_stability: "strong",
    policy_id: "test.policy",
    policy_hash: "a".repeat(64),
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
    orphan_state: "resolved" as const,
    applied: true,
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
        orphan_state: "orphaned",
        result_omitted: true
      },
      {
        ...decision,
        finding_id: "3".repeat(64),
        match_state: "policy_incomplete",
        applied: false
      }
    ]),
    "1 applied · 1 orphaned · 1 expired · 1 drifted · 1 unproven · 1 result omitted"
  );
});

void test("extracts terminal symbols while keeping evidence structured", () => {
  const finding = {
    id: "finding",
    identity_stability: "strong",
    policy_id: "test.policy",
    policy_hash: "a".repeat(64),
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
  assert.match(errors[0], /schema 5/);
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

void test("ignores repeated watcher events only while an authored suppression matches", () => {
  const tracker = new ExpectedPolicySuppressionWrite();
  const uri = "file:///workspace/.bifrost/suppressions.json";
  const expected = '{"suppressions":[]}\r\n';

  tracker.expect(uri, expected);
  assert.equal(tracker.observe(uri, '{"suppressions":[]}\n'), true);
  assert.equal(tracker.observe(uri, expected), true);
  assert.equal(tracker.observe(uri, '{"suppressions":["external"]}\r\n'), false);
  assert.equal(tracker.isPending(uri), false);
  assert.equal(tracker.observe(uri, expected), false);
});

void test("does not consume an authored suppression expectation for another path", () => {
  const tracker = new ExpectedPolicySuppressionWrite();
  const uri = "file:///workspace/.bifrost/suppressions.json";
  const otherUri = "file:///workspace/src/app.ts";
  const expected = '{"suppressions":[]}\n';

  tracker.expect(uri, expected);
  assert.equal(tracker.observe(otherUri, "changed"), false);
  assert.equal(tracker.isPending(uri), true);
  assert.equal(tracker.observe(uri, expected), true);
});
