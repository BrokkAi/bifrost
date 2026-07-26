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
  typestateWitnessStepTargets,
  type RqlControlEdgeResult,
  type RqlProcedureResult,
  type RqlProgramPointResult,
  type RqlQueryRunner,
  type RqlReceiverAnalysisResult,
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
  assert.equal(queryResultIcon(finding), "warning");
  assert.match(queryResultTooltip(finding), /aaaaaaaaaaaa/);
  assert.deepEqual(queryResultRange(finding), range);

  assert.equal(queryResultIcon(witness), "debug-alt");
  assert.match(queryResultTooltip(witness), /retained bytes: 128/);
  const steps = typestateWitnessStepTargets(witness);
  assert.equal(steps[0].label, "1. normal edge");
  assert.equal(steps[0].uri, "file:///workspace/src/run.ts");
  assert.deepEqual(steps[0].range, range);
});
