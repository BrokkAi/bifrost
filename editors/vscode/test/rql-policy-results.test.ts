import assert from "node:assert/strict";
import Module from "node:module";
import { test } from "node:test";
import type { PolicyFinding, RqlPolicyResponse } from "../src/rql_policy";

type ModuleLoader = {
  _load: (request: string, parent: unknown, isMain: boolean) => unknown;
};

void test("selects an effective source version without upgrading a stale snapshot", async () => {
  const textDocuments: Array<{ uri: { toString(): string }; version: number }> = [];
  const fakeVscode = {
    TreeItem: class {
      constructor(
        readonly label?: string,
        readonly collapsibleState?: number
      ) {}
    },
    EventEmitter: class {
      readonly event = () => {};
      fire(): void {}
      dispose(): void {}
    },
    ThemeIcon: class {},
    MarkdownString: class {
      appendMarkdown(): void {}
      appendText(): void {}
      appendCodeblock(): void {}
    },
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    Uri: {
      parse(value: string): { toString(): string } {
        return { toString: () => value };
      },
      joinPath(base: { toString(): string }, path: string): { toString(): string } {
        return { toString: () => `${base.toString().replace(/\/$/, "")}/${path}` };
      }
    },
    workspace: { textDocuments }
  };
  const moduleLoader = Module as unknown as ModuleLoader;
  const originalLoad = moduleLoader._load;
  moduleLoader._load = (request, parent, isMain) =>
    request === "vscode" ? fakeVscode : originalLoad(request, parent, isMain);

  try {
    const { effectivePolicyFindingSourceVersion, RqlPolicyResultsProvider } =
      await import("../src/rql_policy_results.js");
    const finding = {
      id: "1".repeat(64),
      policy_id: "test.policy",
      identity_stability: "strong",
      policy_hash: "a".repeat(64),
      severity: "warning",
      message: "Avoid target",
      primary: { path: "app.ts" },
      suppression: null
    } satisfies PolicyFinding;

    assert.equal(
      effectivePolicyFindingSourceVersion("file:///workspace", finding, undefined),
      undefined,
      "the report can be published before the source is opened"
    );
    textDocuments.push({
      uri: { toString: () => "file:///workspace/app.ts" },
      version: 1
    });
    assert.equal(effectivePolicyFindingSourceVersion("file:///workspace", finding, undefined), 1);
    textDocuments[0].version = 2;
    assert.equal(
      effectivePolicyFindingSourceVersion("file:///workspace", finding, 1),
      1,
      "the report snapshot must not be upgraded after the source changes"
    );

    const provider = new RqlPolicyResultsProvider();
    provider.update({
      policyRootUri: "file:///workspace",
      reportRootUri: "file:///workspace",
      report: {
        schema_version: 5,
        evaluation: {
          evaluation_date: "2026-08-25",
          suppression_sources: [],
          scope_path: ".",
          scope_document_state: "loaded"
        },
        execution: {
          started_at: "2026-08-25T00:00:00Z",
          finished_at: "2026-08-25T00:00:01Z",
          duration_ms: 100,
          cancellation_requested: false
        },
        rules: [],
        runs: [],
        suppressions: [
          {
            policy_id: "test.policy",
            finding_id: "1".repeat(64),
            identity_stability: "strong",
            status: "accepted",
            reason: "reviewed",
            accepted_at: "2026-08-25",
            match_state: "strong_finding",
            temporal_state: "current",
            policy_hash_state: "matching",
            orphan_state: "resolved",
            applied: true,
            result_omitted: false
          }
        ],
        scope: [],
        diagnostics: [],
        diagnostics_truncated: false,
        omitted_diagnostics_lower_bound: 0
      }
    } as unknown as RqlPolicyResponse);
    const children = provider.getChildren() as Array<{ collapsibleState?: number }>;
    assert.equal(children.length, 1);
    assert.equal(children[0].collapsibleState, 1, "suppression audit starts collapsed");
    provider.clear();
    assert.equal(
      (provider.getChildren() as unknown[]).length,
      0,
      "clearing policy results removes the retained response"
    );
    provider.dispose();
  } finally {
    moduleLoader._load = originalLoad;
  }
});
