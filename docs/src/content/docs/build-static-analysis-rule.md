---
title: Build a Static-Analysis Rule
description: Take a query from RQL exploration to a native RQLP policy or tested CLI, MCP, Python, or Rust integration.
---

A Bifrost rule begins as a versioned `CodeQuery`. It can remain an application-owned query integration, or it can become a native `.rqlp` policy with stable rule identity, severity, completeness, and human/JSON/SARIF reporting. This guide builds a small “direct calls to Python `eval`” query, then shows both production paths.

> **Warning — only code matching is implemented:** Bifrost currently executes
> only `.rqlp` policies whose analysis has `:type match`. Taint-analysis and
> typestate-analysis policy syntax is available for authoring and validation,
> but those analyzers are not implemented yet. Running either type reports
> `unsupported` and exits with status 2.

This example becomes a structural policy: it finds parsed call expressions whose callee is named `eval`. It does not prove runtime dispatch, taint, reachability, or data flow. Choose a graph step and proof filter when declaration identity matters, and choose another analysis engine when the policy requires an unsupported guarantee.

## 1. Explore In RQL

Start the interactive prompt from the target repository:

```bash
bifrost --root /path/to/project --repl
```

Enter the narrowest structural query that expresses the policy:

<!-- code-query-test:rql:rule-eval -->
```lisp
(result-detail full
  (limit 1000
    (language python
      (call :callee (name "eval")))))
```

Run `:validate`, then `:run`. Inspect positive matches and nearby non-matches before treating the shape as a policy. Use `:ir python` with representative source when you need to see the normalized syntax Bifrost actually matches.

## 2. Inspect And Pin Canonical JSON

Run `:json` in the RQL prompt. Save the resulting canonical model under the analyzed workspace, for example as `queries/no-direct-eval.json`, and include the schema version explicitly:

<!-- code-query-test:json:rule-eval -->
```json
{
  "schema_version": 2,
  "languages": ["python"],
  "match": {
    "kind": "call",
    "callee": {"name": "eval"}
  },
  "limit": 1000,
  "result_detail": "full"
}
```

RQL and JSON are peer frontends to the same query model. Pinning `schema_version` makes an incompatible future engine reject the rule instead of quietly interpreting a changed shape. Keep language and path scope in the saved query so every execution surface analyzes the same policy.

## 3. Promote A Diagnostic To RQLP

When the query represents a durable diagnostic, wrap the native RQL selector in
one policy document instead of writing a reporting adapter:

```lisp
(policy
  :schema-version 1
  :id "example.security.no-direct-eval"
  :name "No direct dynamic evaluation"
  :message "Dynamic evaluation is forbidden"
  :severity warning
  :analysis
    (analysis
      :type match
      :selector
        (rql :schema-version 2
          (language python
            (call :callee (name "eval"))))))
```

Save it as one `.rqlp` file and run it with `bifrost --policy-file`. The policy
owns finding identity and presentation while the nested RQL remains the same
typed selector explored above. See [Static-Analysis
Policies](/static-analysis-policies/) for endpoint libraries, taint and
typestate syntax, schema inference, composition, report parity, and the current
execution boundary.

If an application needs the raw query result or custom domain logic rather than
a Bifrost policy report, keep the checked-in CodeQuery and use one of the
integration surfaces below.

## 4. Execute A CodeQuery Through One Supported Surface

Use one integration as the production owner of the rule. The other forms are useful for local debugging and parity checks.

### CLI

```bash
bifrost --root /path/to/project --query-file queries/no-direct-eval.json
```

The CLI prints an envelope whose `structuredContent` is the `CodeQueryResult`. Check `isError` before reading it.

### Agent MCP

Expose `query_code` with `symbol|extended` or `searchtools`, then call it with exactly:

```json
{"query_file":"queries/no-direct-eval.json"}
```

The path is relative to the active workspace. Do not send raw inline RQL or combine `query_file` with other fields.

### Python

```python
from bifrost_searchtools import SearchToolsClient

with SearchToolsClient("/path/to/project") as client:
    result = client.query_code(
        {"kind": "call", "callee": {"name": "eval"}},
        languages=["python"],
        limit=1000,
        result_detail="full",
        schema_version=2,
    )
```

The Python method accepts the canonical query fields as typed arguments; it does not currently accept `query_file`. Keep the checked-in JSON as the source of truth and test that the arguments constructed by the integration remain equivalent when the rule changes.

### Rust

```rust
use brokk_bifrost::analyzer::structural::CodeQueryResult;
use brokk_bifrost::SearchToolsService;
use serde_json::json;
use std::path::PathBuf;

fn run_rule(root: PathBuf) -> Result<CodeQueryResult, String> {
    let service = SearchToolsService::new_without_semantic_index(root)?;
    let result = service.query_code_result(json!({
        "schema_version": 2,
        "languages": ["python"],
        "match": {"kind": "call", "callee": {"name": "eval"}},
        "limit": 1000,
        "result_detail": "full"
    })).map_err(|error| error.to_string())?;
    Ok(result)
}
```

`query_code_result` returns the Rust `CodeQueryResult` directly. Constructing `SearchToolsService` owns workspace indexing and file watching for a long-lived integration. Use `new_without_semantic_index` when this rule does not need the optional embedding service.

## 5. Consume Every Result Variant

Dispatch on `result_type` in JSON, the corresponding Python dataclass, or `CodeQueryResultValue` in Rust. Do not assume a pipeline will always end in a structural match: changing or appending a typed step changes the terminal value.

| `result_type` | Produced by | Consume as |
| --- | --- | --- |
| `structural_match` | A query with no steps | Parsed shape, source snippet, captures, enclosing symbol, and optional full ranges/ID. |
| `declaration` | Enclosing, semantic-user, caller/callee, hierarchy, member, or owner steps | Exact indexed declaration identity and source range. |
| `reference_site` | `references_of` | Exact source site, target declaration, optional enclosing declaration, reference kind, and proof. |
| `call_site` | `call_sites_to` or `call_sites_from` | Caller, callee, call/callee ranges, receiver, arguments, call kind, and proof. |
| `expression_site` | `call_input` | Direct receiver or formal-parameter expression at a resolved call site. |
| `receiver_analysis` | `receiver_targets`, `points_to`, or `member_targets` | Explicit analysis outcome plus bounded receiver values or exact member declarations. |
| `file` | `file_of`, `imports_of`, or `importers_of` | Exact project file reached by the pipeline. |

In Python, the seven classes are `CodeQueryMatch`, `CodeQueryDeclaration`, `CodeQueryReferenceSite`, `CodeQueryCallSite`, `CodeQueryExpressionSite`, `CodeQueryReceiverAnalysis`, and `CodeQueryFile`. In Rust, match all variants of `brokk_bifrost::analyzer::structural::CodeQueryResultValue` without a wildcard so a future result type becomes a compile-time integration decision.

Request `result_detail: "full"` when a report needs stable IDs, byte/line/column ranges, capture ranges, or decorator ranges. Compact mode is designed for agent context, not durable finding identity.

## 6. Gate On Safety Metadata

Before a rule passes, fails, or claims completeness:

1. Treat a transport or validation error as a rule execution failure, not as zero findings.
2. Inspect every capability and execution diagnostic. A diagnostic can mean part of the requested language or role was not searched.
3. Require `truncated == false` for a complete rule result. Raising only `limit` may not remove a scan or pipeline-work budget diagnostic; narrow the query or split the scope when necessary.
4. Decide whether `unproven` graph edges are findings, warnings, or excluded evidence. Never present them as proven.
5. Check `provenance_truncated` on every derived result before claiming that all paths to that result are represented.
6. For `receiver_analysis`, branch on every `outcome`. Do not treat `unknown`, `unsupported`, or `exceeded_budget` as an empty candidate set, and do not flatten an `ambiguous` set into several independently precise findings.

Use [Agent Result Safety](/agent-result-safety/) for the exact claim vocabulary and zero-result rules.

## 7. Add Fixture Regression Tests

Keep the smallest source project that demonstrates a true positive, a nearby false positive, and any important language diagnostic. Assert the canonical query, complete tagged result, proof fields, and `truncated: false`; do not assert only a match count.

For Bifrost's own documentation, the executable marker harness in `tests/code_query_tutorials.rs` builds inline projects from `code-query-fixture` blocks and executes paired RQL/JSON cases. External integrations can use their normal test framework, but should preserve the same properties:

- RQL and canonical JSON lower to the same query while RQL is part of authoring.
- Every expected finding includes a stable project-relative path and exact range.
- Unsupported language features retain their diagnostic instead of becoming a zero-match assertion.
- Dynamic candidates test their `proven` or `unproven` contract explicitly.
- A negative fixture is structurally similar enough to catch an over-broad rule.

## 8. Integrate With CI And Reports

Run the saved query against the exact revision being reviewed. Record the Bifrost version or commit, `schema_version`, query file hash or revision, workspace root, source revision, and whether the run was cold or warm when timing matters.

For a raw CodeQuery CI gate, fail closed on execution errors, diagnostics that affect the intended scope, or truncation. Then apply the application's rule to the typed results. For a custom report, map each result from its tagged variant rather than guessing a location: structural matches use `node_range` in full mode, declarations use their declaration range, reference/call/expression sites carry explicit ranges, and receiver analyses cite the analyzed input range while retaining the enclosing outcome around their candidates.

For a native `.rqlp` policy, use `--format human|json|sarif` instead. All three renderers consume the same canonical policy report and preserve the same finding IDs, policy/semantic hashes, locations, completion, classifications, evidence, and CVSS variants. Status 2 takes precedence whenever loading, validation, evaluation, or report completeness is unreliable; an empty incomplete report is never a passing zero-result.

## Production Checklist

- The saved query JSON pins `schema_version` and contains all query scope, or the `.rqlp` policy records whether independently resolved policy and nested RQL versions were explicit or compatible inferences.
- The integration handles all seven terminal result variants and every receiver-analysis outcome.
- Errors, diagnostics, result truncation, proof tiers, and provenance truncation have explicit policy.
- Fixture tests cover a true positive, a convincing negative, and relevant diagnostics.
- CI records the engine, query, workspace, and source revisions.
- Reports cite exact returned locations and do not claim unsupported control or data flow; endpoint matches and source/sink co-presence are not reachability.
