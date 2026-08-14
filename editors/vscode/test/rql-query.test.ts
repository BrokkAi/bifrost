import assert from "node:assert/strict";
import { test } from "node:test";
import {
  RQL_LANGUAGE_ID,
  RUN_RQL_QUERY_METHOD,
  codePointColumnToUtf16,
  flowWitnessStepTargets,
  formatRqlQueryOutput,
  groupRqlQueryResults,
  queryResultDescription,
  queryResultIcon,
  queryResultLabel,
  queryResultRange,
  queryResultTooltip,
  runRqlQuery,
  typestateWitnessStepTargets,
  type RqlCandidateHopResult,
  type RqlControlEdgeResult,
  type RqlDispatchOutcomeResult,
  type RqlDispatchTargetResult,
  type RqlFlowEndpointResult,
  type RqlFlowWitnessResult,
  type RqlProcedureResult,
  type RqlMemberFamilyEdgeResult,
  type RqlMemberFamilyResult,
  type RqlMemberSelectionResult,
  type RqlProgramPointResult,
  type RqlQueryRunner,
  type RqlReceiverAnalysisResult,
  type RqlReceiverEvidenceResult,
  type RqlReceiverOutcomeResult,
  type RqlReferenceSiteResult,
  type RqlTypestateFindingResult,
  type RqlTypestateWitnessResult
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

void test("converts CodeQuery code-point columns to VS Code UTF-16 offsets", () => {
  const line = "a😀finding";
  assert.equal(codePointColumnToUtf16(line, 1), 0);
  assert.equal(codePointColumnToUtf16(line, 2), 1);
  assert.equal(codePointColumnToUtf16(line, 3), 3);
  assert.equal(codePointColumnToUtf16(line, 999), line.length);
});

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
          report: { format: "bifrost_code_query_profile/v2" },
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
  assert.match(formatRqlQueryOutput(response), /bifrost_code_query_profile\/v2/);
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

void test("renders and navigates procedure-local CFG results", () => {
  const range = {
    start_line: 7,
    start_column: 4,
    end_line: 7,
    end_column: 12
  };
  const evidence = { proof: "proven" as const, completeness: "complete" as const };
  const procedure: RqlProcedureResult = {
    uri: "file:///workspace/src/run.ts",
    path: "src/run.ts",
    result_type: "procedure",
    id: "procedure-a",
    artifact_id: "artifact-a",
    language: "typescript",
    procedure_kind: "function",
    range,
    evidence
  };
  const point: RqlProgramPointResult = {
    uri: procedure.uri,
    path: procedure.path,
    result_type: "program_point",
    id: "point-a",
    procedure_id: procedure.id,
    language: procedure.language,
    range,
    boundary: "entry",
    event_count: 2,
    evidence
  };
  const edge: RqlControlEdgeResult = {
    uri: procedure.uri,
    path: procedure.path,
    result_type: "control_edge",
    id: "edge-a",
    procedure_id: procedure.id,
    language: procedure.language,
    range,
    edge_kind: "normal",
    source: {
      id: point.id,
      procedure_id: procedure.id,
      path: procedure.path,
      range,
      boundary: "entry"
    },
    target: {
      id: "point-b",
      procedure_id: procedure.id,
      path: procedure.path,
      range: { ...range, start_line: 8, end_line: 8 },
      boundary: "normal_exit"
    },
    evidence
  };

  assert.equal(queryResultLabel(procedure), "function");
  assert.equal(queryResultIcon(procedure), "symbol-method");
  assert.match(queryResultTooltip(procedure), /artifact-a/);
  assert.deepEqual(queryResultRange(procedure), range);
  assert.equal(queryResultLabel(point), "entry");
  assert.equal(queryResultDescription(point), "2 events · proven/complete");
  assert.equal(queryResultIcon(point), "debug-breakpoint");
  assert.match(queryResultTooltip(point), /procedure-a/);
  assert.deepEqual(queryResultRange(point), range);
  assert.match(queryResultLabel(edge), /point-a → point-b/);
  assert.equal(queryResultIcon(edge), "arrow-right");
  assert.match(queryResultTooltip(edge), /Source: `point-a entry at src\/run\.ts:7:4`/);
  assert.match(queryResultTooltip(edge), /Target: `point-b normal_exit at src\/run\.ts:8:4`/);
  assert.deepEqual(queryResultRange(edge), range);
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

void test("renders and navigates a receiver-outcome result", () => {
  const outcome: RqlReceiverOutcomeResult = {
    uri: "file:///workspace/src/app.ts",
    path: "src/app.ts",
    result_type: "receiver_outcome",
    id: "outcome-a",
    site_id: "site-a",
    site_ast_id: "ast-a",
    language: "typescript",
    range: {
      start_line: 9,
      start_column: 15,
      end_line: 9,
      end_column: 22
    },
    analysis_kind: "points_to",
    outcome: "precise",
    coverage: "open",
    candidate_count: 2,
    candidates_truncated: true,
    reason: "budget exhausted",
    limit: "candidate_limit",
    semantic_unsupported: "typescript records no summary",
    setup_nodes: 4,
    summary_expansions: 1,
    scope_nodes: 3
  };

  assert.equal(queryResultLabel(outcome), "points_to: precise");
  assert.equal(queryResultDescription(outcome), "open · 2 candidates (truncated) · 9:15");
  assert.equal(queryResultIcon(outcome), "pulse");
  const tooltip = queryResultTooltip(outcome);
  assert.match(tooltip, /precise · coverage open/);
  assert.match(tooltip, /Candidates: 2 \(truncated\)/);
  assert.match(tooltip, /budget exhausted/);
  assert.match(tooltip, /Limit: candidate_limit/);
  assert.match(tooltip, /Semantic support absent: typescript records no summary/);
  assert.match(tooltip, /Coverage is not exhaustive/);
  assert.deepEqual(queryResultRange(outcome), outcome.range);
});

void test("renders a receiver-evidence result without a range", () => {
  const evidence: RqlReceiverEvidenceResult = {
    uri: "file:///workspace/src/app.ts",
    path: "src/app.ts",
    result_type: "receiver_evidence",
    id: "evidence-b",
    site_id: "site-a",
    site_ast_id: "ast-a",
    parent_evidence_id: "evidence-a",
    ordinal: 1,
    chain_hop: 2,
    evidence_kind: "factory_return",
    declaration_id: "decl-a",
    declaration_fq_name: "Service",
    declaration_kind: "class",
    factory_id: "makeService",
    proof: "proven",
    completeness: "complete"
  };

  assert.equal(queryResultLabel(evidence), "Service");
  assert.equal(queryResultDescription(evidence), "factory_return · hop 2 · proven/complete");
  assert.equal(queryResultIcon(evidence), "symbol-field");
  const tooltip = queryResultTooltip(evidence);
  assert.match(tooltip, /site `site-a`/);
  assert.match(tooltip, /Chained from evidence `evidence-a`/);
  assert.match(tooltip, /Factory: `makeService`/);
  assert.equal(queryResultRange(evidence), undefined);
});

void test("renders a member-selection result and states an absent trace", () => {
  const selection: RqlMemberSelectionResult = {
    uri: "file:///workspace/src/app.ts",
    path: "src/app.ts",
    result_type: "member_selection",
    id: "selection-a",
    site_ast_id: "ast-a",
    language: "typescript",
    range: {
      start_line: 11,
      start_column: 5,
      end_line: 11,
      end_column: 12
    },
    member: "connect",
    role: "call_target",
    outcome: "untraced",
    selected_count: 0,
    candidate_count: 0,
    trace_completeness: "absent",
    coverage: "unsupported"
  };

  assert.equal(queryResultLabel(selection), "connect");
  assert.equal(queryResultDescription(selection), "untraced · 0/0 · unsupported");
  assert.equal(queryResultIcon(selection), "checklist");
  const tooltip = queryResultTooltip(selection);
  assert.match(tooltip, /call_target/);
  assert.match(tooltip, /Trace absent · coverage unsupported/);
  assert.match(
    tooltip,
    /This language records no candidate trace, so an absent rejection row says nothing\./
  );
  assert.deepEqual(queryResultRange(selection), selection.range);

  const traced: RqlMemberSelectionResult = {
    ...selection,
    outcome: "selected",
    selected_count: 1,
    candidate_count: 1,
    trace_completeness: "selection_only",
    coverage: "open"
  };
  assert.match(
    queryResultTooltip(traced),
    /This resolver reports only its selections, so an absent rejection row says nothing\./
  );
});

void test("renders a candidate-hop result and states a rendering gap", () => {
  const hop: RqlCandidateHopResult = {
    uri: "file:///workspace/src/app.ts",
    path: "src/app.ts",
    result_type: "candidate_hop",
    id: "hop-a",
    candidate_id: "candidate-a",
    ast_id: "ast-a",
    language: "typescript",
    range: {
      start_line: 12,
      start_column: 7,
      end_line: 12,
      end_column: 14
    },
    start_byte: 120,
    end_byte: 127,
    hop: 1,
    relation: "extends",
    from: {
      path: "src/app.ts",
      language: "typescript",
      kind: "class",
      fq_name: "Derived",
      start_line: 1,
      end_line: 3
    },
    to: {
      path: "src/app.ts",
      language: "typescript",
      kind: "class",
      fq_name: "Base",
      start_line: 5,
      end_line: 8
    }
  };

  assert.equal(queryResultLabel(hop), "extends: Derived → Base");
  assert.equal(queryResultDescription(hop), "hop 1 · extends · 12:7");
  assert.equal(queryResultIcon(hop), "arrow-up");
  const tooltip = queryResultTooltip(hop);
  assert.match(tooltip, /\*\*extends hop 1\*\*/);
  assert.match(tooltip, /`Derived` → `Base`/);
  assert.match(tooltip, /Candidate `candidate-a`/);
  assert.doesNotMatch(tooltip, /rendering gap/);
  assert.deepEqual(queryResultRange(hop), hop.range);

  const unrenderable: RqlCandidateHopResult = { ...hop, to: undefined };
  assert.equal(queryResultLabel(unrenderable), "extends: Derived → unknown");
  assert.match(queryResultTooltip(unrenderable), /rendering gap, not an absent hop/);
});

void test("renders a dispatch-outcome result and refuses to prove an empty target set", () => {
  const outcome: RqlDispatchOutcomeResult = {
    uri: "file:///workspace/src/app.ts",
    path: "src/app.ts",
    result_type: "dispatch_outcome",
    id: "dispatch-a",
    site_id: "site-a",
    site_ast_id: "ast-a",
    language: "typescript",
    range: {
      start_line: 14,
      start_column: 3,
      end_line: 14,
      end_column: 19
    },
    outcome: "unknown",
    coverage: "open",
    call_site_count: 0,
    target_count: 0,
    targets_truncated: false
  };

  assert.equal(queryResultLabel(outcome), "dispatch: unknown");
  assert.equal(queryResultDescription(outcome), "open · 0 targets · 0 call sites");
  assert.equal(queryResultIcon(outcome), "git-merge");
  const tooltip = queryResultTooltip(outcome);
  assert.match(tooltip, /unknown · coverage open/);
  assert.match(tooltip, /unknown, not proven-empty/);
  assert.match(tooltip, /Coverage is not exhaustive, so an absent target says nothing\./);
  assert.deepEqual(queryResultRange(outcome), outcome.range);

  const unsupported: RqlDispatchOutcomeResult = {
    ...outcome,
    outcome: "unsupported",
    call_site_count: 2,
    target_count: 3,
    targets_truncated: true,
    semantic_unsupported: "typescript records no dispatch oracle",
    exceeded_limit: "call_depth"
  };
  assert.equal(queryResultDescription(unsupported), "open · 3 targets (truncated) · 2 call sites");
  const unsupportedTooltip = queryResultTooltip(unsupported);
  assert.match(
    unsupportedTooltip,
    /Semantic support absent: typescript records no dispatch oracle/
  );
  assert.match(unsupportedTooltip, /Exceeded budget: call_depth/);
  assert.doesNotMatch(unsupportedTooltip, /not proven-empty/);
});

void test("renders a may-dispatch target without claiming it is proven", () => {
  const target: RqlDispatchTargetResult = {
    uri: "file:///workspace/src/app.ts",
    path: "src/app.ts",
    result_type: "dispatch_target",
    id: "target-a",
    site_id: "site-a",
    site_ast_id: "ast-a",
    ordinal: 0,
    target_id: "digest-a",
    target_path: "src/service.ts",
    target_declaration: {
      path: "src/service.ts",
      language: "typescript",
      kind: "method",
      fq_name: "Service.connect",
      start_line: 4,
      end_line: 6
    },
    proof: "unproven",
    completeness: "partial",
    coverage: "open",
    dispatch: "may_dispatch"
  };

  assert.equal(queryResultLabel(target), "Service.connect");
  assert.equal(queryResultDescription(target), "may_dispatch · unproven/partial · open");
  assert.equal(queryResultIcon(target), "call-incoming");
  const tooltip = queryResultTooltip(target);
  assert.match(tooltip, /\*\*may_dispatch\*\* to `Service\.connect`/);
  assert.match(tooltip, /This arm may dispatch; it is not proven\./);
  assert.doesNotMatch(tooltip, /proven_dispatch/);
  // The arm is one arm of a site, not a second location.
  assert.equal(queryResultRange(target), undefined);

  const boundary: RqlDispatchTargetResult = {
    ...target,
    target_declaration: undefined,
    boundary_kind: "external_call"
  };
  assert.equal(queryResultLabel(boundary), "src/service.ts");
  assert.equal(
    queryResultDescription(boundary),
    "may_dispatch · unproven/partial · open · external_call"
  );
  const boundaryTooltip = queryResultTooltip(boundary);
  assert.match(boundaryTooltip, /Boundary arm \(external_call\)/);
  assert.match(boundaryTooltip, /The workspace located no declaration for this target\./);

  const proven: RqlDispatchTargetResult = {
    ...target,
    proof: "proven",
    completeness: "complete",
    coverage: "exhaustive",
    dispatch: "proven_dispatch"
  };
  assert.doesNotMatch(queryResultTooltip(proven), /may dispatch; it is not proven/);
});

void test("renders an incomplete member family without showing a family id", () => {
  const family: RqlMemberFamilyResult = {
    uri: "file:///workspace/src/app.ts",
    path: "src/app.ts",
    result_type: "member_family",
    id: "family-a",
    member_id: "member-digest-a",
    language: "typescript",
    range: {
      start_line: 20,
      start_column: 3,
      end_line: 22,
      end_column: 4
    },
    member: {
      path: "src/app.ts",
      language: "typescript",
      kind: "method",
      fq_name: "Service.connect",
      start_line: 20,
      end_line: 22
    },
    outcome: "incomplete",
    reason: "hierarchy walk hit its bound",
    capability: "partial",
    coverage: "open",
    overrides_count: 0,
    implements_count: 0,
    overridden_by_count: 0,
    implemented_by_count: 0,
    edge_count: 0,
    root_count: 0
  };

  assert.equal(queryResultLabel(family), "Service.connect");
  assert.equal(queryResultDescription(family), "incomplete · open · 0 edges");
  assert.equal(queryResultIcon(family), "type-hierarchy-sub");
  const tooltip = queryResultTooltip(family);
  assert.match(tooltip, /\*\*member family \(incomplete\)\*\*/);
  assert.match(tooltip, /hierarchy walk hit its bound/);
  // An incomplete outcome proves no family, so no family id may be shown.
  assert.doesNotMatch(tooltip, /Family: `/);
  assert.match(tooltip, /No family id: this outcome does not prove a family\./);
  assert.match(tooltip, /Coverage is not exhaustive, so an absent edge says nothing\./);
  assert.deepEqual(queryResultRange(family), family.range);

  const proven: RqlMemberFamilyResult = {
    ...family,
    outcome: "proven",
    reason: undefined,
    coverage: "exhaustive",
    family_id: "family-digest-a",
    overrides_count: 1,
    edge_count: 1,
    root_count: 2
  };
  const provenTooltip = queryResultTooltip(proven);
  assert.match(provenTooltip, /Family: `family-digest-a` over 2 roots/);
  assert.doesNotMatch(provenTooltip, /No family id/);
  assert.doesNotMatch(provenTooltip, /Coverage is not exhaustive/);
});

void test("renders a member-family edge and names an inverse row as an inversion", () => {
  const edge: RqlMemberFamilyEdgeResult = {
    uri: "file:///workspace/src/app.ts",
    path: "src/app.ts",
    result_type: "member_family_edge",
    id: "edge-a",
    member_id: "member-digest-a",
    range: {
      start_line: 20,
      start_column: 3,
      end_line: 22,
      end_column: 4
    },
    ordinal: 0,
    source: {
      path: "src/app.ts",
      language: "typescript",
      kind: "method",
      fq_name: "Derived.connect",
      start_line: 20,
      end_line: 22
    },
    target_id: "member-digest-b",
    target: {
      path: "src/base.ts",
      language: "typescript",
      kind: "method",
      fq_name: "Base.connect",
      start_line: 4,
      end_line: 6
    },
    relation: "overrides",
    family_id: "family-digest-a",
    hierarchy_depth: 1,
    proof: "proven",
    completeness: "complete",
    coverage: "exhaustive"
  };

  assert.equal(queryResultLabel(edge), "overrides: Base.connect");
  assert.equal(queryResultDescription(edge), "overrides · depth 1 · proven/complete");
  assert.equal(queryResultIcon(edge), "git-compare");
  const tooltip = queryResultTooltip(edge);
  assert.match(tooltip, /\*\*overrides\*\* `Derived\.connect` → `Base\.connect`/);
  assert.match(tooltip, /Family: `family-digest-a`/);
  assert.doesNotMatch(tooltip, /Unproven/);
  assert.doesNotMatch(tooltip, /bounded inversion/);
  assert.deepEqual(queryResultRange(edge), edge.range);

  const inverse: RqlMemberFamilyEdgeResult = {
    ...edge,
    relation: "overridden_by",
    proof: "unproven"
  };
  const inverseTooltip = queryResultTooltip(inverse);
  assert.match(inverseTooltip, /a spelling is not a resolved type/);
  assert.match(inverseTooltip, /never an independent resolution/);
});

void test("renders typestate findings and exposes navigable witness steps", () => {
  const range = {
    start_line: 8,
    start_column: 3,
    end_line: 8,
    end_column: 16
  };
  const finding: RqlTypestateFindingResult = {
    uri: "file:///workspace/src/run.ts",
    path: "src/run.ts",
    result_type: "typestate_finding",
    id: "finding-a",
    protocol_ref: "embedding:resource-lifecycle",
    protocol_hash: "a".repeat(64),
    binding_plan_hash: "b".repeat(64),
    subject: { class: "resource", identity: '{"kind":"object"}' },
    finding_kind: {
      type: "error_transition",
      event: "use",
      from_state: "closed",
      to_state: "error"
    },
    certainty: "must",
    language: "typescript",
    range,
    path_proven: true,
    path_complete: true,
    analysis_complete: true,
    retained_witnesses: 1,
    omitted_witnesses: 0
  };
  const witness: RqlTypestateWitnessResult = {
    uri: finding.uri,
    path: finding.path,
    witnessStepUris: ["file:///workspace/src/run.ts"],
    result_type: "typestate_witness",
    id: "witness-a",
    finding_id: finding.id,
    protocol_ref: finding.protocol_ref,
    protocol_hash: finding.protocol_hash,
    binding_plan_hash: finding.binding_plan_hash,
    subject: finding.subject,
    witness_index: 0,
    observed_state: "closed",
    language: finding.language,
    range,
    quality: { proof: "proven", completeness: "complete" },
    steps: [
      {
        kind: { type: "edge", edge_kind: "normal" },
        source: { path: finding.path, range },
        target: { path: finding.path, range: { ...range, start_line: 9, end_line: 9 } },
        evidence: { proof: "proven", completeness: "complete" }
      }
    ],
    retained_bytes: 128,
    omitted_steps_lower_bound: 0
  };

  assert.equal(queryResultLabel(finding), "use: closed → error");
  assert.equal(queryResultDescription(finding), "must · embedding:resource-lifecycle · 8:3");
  assert.equal(queryResultIcon(finding), "symbol-event");
  assert.match(queryResultTooltip(finding), /aaaaaaaaaaaa/);
  assert.deepEqual(queryResultRange(finding), range);

  assert.equal(queryResultIcon(witness), "debug-alt");
  assert.match(queryResultTooltip(witness), /retained bytes: 128/);
  const steps = typestateWitnessStepTargets(witness);
  assert.equal(steps[0].label, "1. normal edge");
  assert.equal(steps[0].uri, "file:///workspace/src/run.ts");
  assert.deepEqual(steps[0].range, range);
});

void test("renders diagnostic-neutral flow endpoints and navigable witnesses", () => {
  const range = {
    start_line: 12,
    start_column: 5,
    end_line: 12,
    end_column: 16
  };
  const procedureSite = {
    id: "site-run",
    path: "src/run.ts",
    language: "typescript",
    declaration: [
      {
        kind: "function",
        name: "run",
        start_byte: 12,
        end_byte: 96,
        occurrence: 0,
        sibling_ordinal: 0
      }
    ],
    role: "procedure",
    start_byte: 12,
    end_byte: 96,
    occurrence: 0,
    range
  };
  const parameterCarrier = {
    kind: "port" as const,
    id: "carrier-parameter",
    procedure: procedureSite,
    port: { kind: "parameter" as const, ordinal: 0 }
  };
  const endpoint: RqlFlowEndpointResult = {
    uri: "file:///workspace/src/run.ts",
    path: "src/run.ts",
    result_type: "flow_endpoint",
    id: "endpoint-a",
    plan_ref: "embedding:request-to-sink",
    source: {
      id: "source-a",
      site: procedureSite,
      path: "src/run.ts",
      range,
      phase: "before_effects",
      ordinal: 0,
      carrier: parameterCarrier
    },
    sink: {
      id: "sink-a",
      site: procedureSite,
      path: "src/run.ts",
      range,
      phase: "after_effects",
      ordinal: 0,
      carrier: parameterCarrier
    },
    reachability: "reached",
    certainty: "may",
    must: "not_established",
    ambiguous: true,
    completion: "budget_exhausted",
    semantic_status: "ambiguous",
    solver_termination: "budget_exhausted",
    language: "typescript",
    range,
    retained_witnesses: 1,
    omitted_witnesses: 0
  };
  const witness: RqlFlowWitnessResult = {
    uri: endpoint.uri,
    path: endpoint.path,
    witnessStepUris: [endpoint.uri],
    result_type: "flow_witness",
    id: "witness-a",
    endpoint_id: endpoint.id,
    plan_ref: endpoint.plan_ref,
    witness_index: 0,
    language: endpoint.language,
    range,
    quality: { proof: "unproven", completeness: "partial" },
    steps: [
      {
        kind: { type: "end_summary_gap", return_kind: "normal" },
        source: { path: endpoint.path, range },
        source_symbol: procedureSite,
        evidence: { proof: "unproven", completeness: "partial" },
        boundary: "unmaterialized",
        input: {
          kind: "carrier",
          source: endpoint.source!,
          carrier: parameterCarrier
        },
        output: {
          kind: "meeting",
          source: endpoint.source!,
          sink: endpoint.sink,
          uncertain: true
        }
      }
    ],
    retained_bytes: 96,
    truncated: true,
    omitted_steps_lower_bound: 1
  };

  assert.equal(queryResultLabel(endpoint), "reached: sink-a");
  assert.equal(
    queryResultDescription(endpoint),
    "may · budget_exhausted · embedding:request-to-sink"
  );
  assert.equal(queryResultIcon(endpoint), "target");
  assert.match(queryResultTooltip(endpoint), /ambiguous: yes/);
  assert.match(queryResultTooltip(endpoint), /must: not_established/);
  assert.deepEqual(queryResultRange(endpoint), range);

  assert.equal(queryResultIcon(witness), "debug-alt");
  assert.match(queryResultTooltip(witness), /at least 1 step/);
  const steps = flowWitnessStepTargets(witness);
  assert.equal(steps[0].label, "1. normal summary gap");
  assert.match(steps[0].tooltip, /Boundary: unmaterialized/);
  assert.match(
    steps[0].tooltip,
    /Facts: source-a on port:carrier-parameter -> source-a meets sink-a/
  );
  assert.equal(steps[0].uri, endpoint.uri);
  assert.deepEqual(steps[0].range, range);
});
