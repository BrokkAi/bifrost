---
title: Library Integration
description: Run one canonical query_code query from Rust and Python and read its completeness signals.
---

The other cookbook pages teach the query vocabulary. This page teaches the call
itself: one fixture, one canonical query, executed twice through Bifrost's
public libraries. The [Rust library](/rust-library/) runs it with
`SearchToolsService::query_code_result(...)` and the
[Python client](/python-client/) runs it with `SearchToolsClient.query_code(...)`.
Both receive the same typed rows, and both must read the same completeness
signals before turning those rows into a claim.

The query is deliberately answerable only in part. Its row set is complete, but
one row is `ambiguous`, so an embedder that reads only the values and ignores
`outcome` reaches a confident wrong conclusion.

> Last verified end to end: 2026-09-02 (`query_code` schema version 1).

## Fixture

Both examples execute against this file. It is checked in at
`docs/fixtures/library-integration/src/ledger.ts`, and the executable test
asserts that the published file and the block below stay identical.

<!-- code-query-fixture:src/ledger.ts -->
```typescript
class LedgerStore {
  commit(entry: string) {}
}

class AuditStore {
  commit(entry: string) {}
}

function openLedger() {
  return new LedgerStore();
}

export function record(useAudit: boolean) {
  const either = useAudit ? new AuditStore() : new LedgerStore();
  either.commit("either");

  const ledger = new LedgerStore();
  ledger.commit("direct");

  const opened = openLedger();
  opened.commit("factory");
}
```

`record` calls `commit` three times on three different receivers: a
conditionally allocated value, a directly allocated one, and a factory result.

## The Canonical Query

Match every `commit` call and run bounded receiver analysis on each receiver.
The two forms below are the same query; the canonical JSON is what both library
calls send.

<!-- code-query-case:receivers:rql -->
```lisp
(receiver-targets
  (language typescript (call :callee "commit")))
```

<!-- code-query-case:receivers:json -->
```json
{"languages":["typescript"],"match":{"kind":"call","callee":{"name":"commit"}},"steps":[{"op":"receiver_targets"}]}
```

<!-- code-query-case:receivers:expected -->
```json
{
  "results": [
    {
      "analysis_kind": "receiver_targets",
      "input_kind": "identifier",
      "language": "typescript",
      "outcome": "ambiguous",
      "path": "src/ledger.ts",
      "provenance": [
        {
          "seed": {
            "end_line": 15,
            "kind": "call",
            "path": "src/ledger.ts",
            "result_type": "structural_match",
            "start_line": 15
          },
          "steps": [
            {
              "op": "receiver_targets",
              "result": {
                "analysis_kind": "receiver_targets",
                "outcome": "ambiguous",
                "path": "src/ledger.ts",
                "range": {
                  "end_column": 9,
                  "end_line": 15,
                  "start_column": 3,
                  "start_line": 15
                },
                "result_type": "receiver_analysis"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 9,
        "end_line": 15,
        "start_column": 3,
        "start_line": 15
      },
      "result_type": "receiver_analysis",
      "site_ast_id": "3c04ee141705b6d11edbc89decf5128bb6218834ab478495d69c25b454e33096",
      "site_id": "3a2bf395bc56b5abc415e0496f4372b17ad58c964f88192674ad04cec56d3621",
      "text": "either",
      "values": [
        {
          "allocation_site": {
            "path": "src/ledger.ts",
            "range": {
              "end_column": 45,
              "end_line": 14,
              "start_column": 29,
              "start_line": 14
            }
          },
          "receiver_value_kind": "allocation_site",
          "type_declaration": {
            "end_line": 7,
            "fq_name": "AuditStore",
            "kind": "class",
            "language": "typescript",
            "path": "src/ledger.ts",
            "signature": "class AuditStore {",
            "start_line": 5
          }
        },
        {
          "allocation_site": {
            "path": "src/ledger.ts",
            "range": {
              "end_column": 65,
              "end_line": 14,
              "start_column": 48,
              "start_line": 14
            }
          },
          "receiver_value_kind": "allocation_site",
          "type_declaration": {
            "end_line": 3,
            "fq_name": "LedgerStore",
            "kind": "class",
            "language": "typescript",
            "path": "src/ledger.ts",
            "signature": "class LedgerStore {",
            "start_line": 1
          }
        }
      ]
    },
    {
      "analysis_kind": "receiver_targets",
      "input_kind": "identifier",
      "language": "typescript",
      "outcome": "precise",
      "path": "src/ledger.ts",
      "provenance": [
        {
          "seed": {
            "end_line": 18,
            "kind": "call",
            "path": "src/ledger.ts",
            "result_type": "structural_match",
            "start_line": 18
          },
          "steps": [
            {
              "op": "receiver_targets",
              "result": {
                "analysis_kind": "receiver_targets",
                "outcome": "precise",
                "path": "src/ledger.ts",
                "range": {
                  "end_column": 9,
                  "end_line": 18,
                  "start_column": 3,
                  "start_line": 18
                },
                "result_type": "receiver_analysis"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 9,
        "end_line": 18,
        "start_column": 3,
        "start_line": 18
      },
      "result_type": "receiver_analysis",
      "site_ast_id": "652f2ee8b3fdfd78aba3eb44d70bf405b4ea2492aae390f591d035f3c50559cd",
      "site_id": "e56308e03d40498625641ff3c8108e1c878073a3aa11a9951c8e5ab0c80ee6b8",
      "text": "ledger",
      "values": [
        {
          "allocation_site": {
            "path": "src/ledger.ts",
            "range": {
              "end_column": 35,
              "end_line": 17,
              "start_column": 18,
              "start_line": 17
            }
          },
          "receiver_value_kind": "allocation_site",
          "type_declaration": {
            "end_line": 3,
            "fq_name": "LedgerStore",
            "kind": "class",
            "language": "typescript",
            "path": "src/ledger.ts",
            "signature": "class LedgerStore {",
            "start_line": 1
          }
        }
      ]
    },
    {
      "analysis_kind": "receiver_targets",
      "input_kind": "identifier",
      "language": "typescript",
      "outcome": "precise",
      "path": "src/ledger.ts",
      "provenance": [
        {
          "seed": {
            "end_line": 21,
            "kind": "call",
            "path": "src/ledger.ts",
            "result_type": "structural_match",
            "start_line": 21
          },
          "steps": [
            {
              "op": "receiver_targets",
              "result": {
                "analysis_kind": "receiver_targets",
                "outcome": "precise",
                "path": "src/ledger.ts",
                "range": {
                  "end_column": 9,
                  "end_line": 21,
                  "start_column": 3,
                  "start_line": 21
                },
                "result_type": "receiver_analysis"
              }
            }
          ]
        }
      ],
      "range": {
        "end_column": 9,
        "end_line": 21,
        "start_column": 3,
        "start_line": 21
      },
      "result_type": "receiver_analysis",
      "site_ast_id": "f566680bb6e76b4504ca2bf4b272f9bd0bb055506d5564373e89a94b0946efb6",
      "site_id": "c2979064a9c7aa2de5086f9e22e1a418d2a8d282ae5b90a88cb2391030aa7db1",
      "text": "opened",
      "values": [
        {
          "declaration": {
            "end_line": 3,
            "fq_name": "LedgerStore",
            "kind": "class",
            "language": "typescript",
            "path": "src/ledger.ts",
            "signature": "class LedgerStore {",
            "start_line": 1
          },
          "receiver_value_kind": "instance_type"
        }
      ]
    }
  ],
  "truncated": false
}
```

Three sites, three rows, `truncated: false`, and no diagnostics. That row set is
complete, and it still does not prove that every `commit` call reaches
`LedgerStore`:

| Receiver | Line | `outcome` | Values |
| --- | --- | --- | --- |
| `either` | 15 | `ambiguous` | two allocation sites: `AuditStore` and `LedgerStore` |
| `ledger` | 18 | `precise` | one allocation site: `LedgerStore` |
| `opened` | 21 | `precise` | one instance type: `LedgerStore` |

The `ambiguous` row is the interesting one. It carries candidates, so a caller
that reads `values` and skips `outcome` sees `LedgerStore` in the list and
concludes the wrong thing. `ambiguous` means the analysis proved a bounded
candidate set, not a single value. The other uncertain outcomes are
`unknown`, `unsupported`, and `exceeded_budget`; treat all four as "not
proven", never as an empty result. See
[Receiver Traversal](../receiver-traversal/) for what each one means.

The same query through the CLI returns the same structured content:

```bash
bifrost --root ./library-integration --tool query_code \
  --args '{"languages":["typescript"],"match":{"kind":"call","callee":{"name":"commit"}},"steps":[{"op":"receiver_targets"}]}'
```

`site_id` and `site_ast_id` are content-scoped join keys, not stable names.
They are derived from the exact bytes of the analyzed file, so the published
fixture, which ends with a newline, reports different values from the block
above, which does not. Join on them within one result; never compare them
across two revisions of a file.

## When The Limit Trips

`limit` caps the row set. The same query with `"limit": 2` returns two of the
three `commit` calls, and it says so twice: `truncated` is `true`, and a
`result_limit_reached` diagnostic with `incomplete` impact names the cap.

<!-- code-query-case:limited:rql -->
```lisp
(limit 2
  (language typescript (call :callee "commit")))
```

<!-- code-query-case:limited:json -->
```json
{"languages":["typescript"],"match":{"kind":"call","callee":{"name":"commit"}},"limit":2}
```

<!-- code-query-case:limited:expected -->
```json
{
  "diagnostics": [
    {
      "code": "result_limit_reached",
      "impact": "incomplete",
      "language": "workspace",
      "message": "query_code reached the query limit of 2 and returned the first 2 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
    }
  ],
  "results": [
    {
      "enclosing_symbol": "record",
      "end_line": 15,
      "kind": "call",
      "language": "typescript",
      "path": "src/ledger.ts",
      "result_type": "structural_match",
      "start_line": 15,
      "text": "either.commit(\"either\")"
    },
    {
      "enclosing_symbol": "record",
      "end_line": 18,
      "kind": "call",
      "language": "typescript",
      "path": "src/ledger.ts",
      "result_type": "structural_match",
      "start_line": 18,
      "text": "ledger.commit(\"direct\")"
    }
  ],
  "truncated": true
}
```

Two rows out of three, in project-relative path order. Neither signal says how
many rows the query would have returned without the cap, so a truncated result
never supports a "there are no other targets" claim. Raise `limit`, or narrow
the query with `where`, `languages`, or a more exact name, until the result
comes back untruncated.

The message states the cap and the row count and nothing else. Work counters
such as scanned files and fact nodes depend on scheduling and on how far the
scan got before the cap, so two runs of one query over unchanged files disagree
about them; keeping them out of the text is what makes a truncated result
reproducible enough to document and to diff. Set `BIFROST_TIMING=1` when you
want those counters for one run.

## Rust

`SearchToolsService` is the in-process form of the same tool surface MCP and the
Python client use, so the argument object is the canonical query's JSON, without
the `limit` the section above added.

```rust
use brokk_bifrost::rql::{CodeQueryDiagnosticImpact, CodeQueryResultValue};
use brokk_bifrost::SearchToolsService;
use serde_json::json;
use std::path::PathBuf;

/// Split the `commit` receivers into proven single targets and unproven sites.
fn commit_receivers(root: PathBuf) -> Result<(Vec<String>, Vec<String>), String> {
    let service = SearchToolsService::new(root)?;
    let response = service
        .query_code_result(json!({
            "languages": ["typescript"],
            "match": { "kind": "call", "callee": { "name": "commit" } },
            "steps": [{ "op": "receiver_targets" }]
        }))
        .map_err(|error| error.to_string())?;
    let result = response
        .result()
        .expect("the default results mode returns ordinary rows");

    // 1. Is the row set itself complete?
    if result.truncated {
        return Err("bounded row set: raise the limit or narrow the query".to_string());
    }
    for diagnostic in &result.diagnostics {
        match diagnostic.impact {
            CodeQueryDiagnosticImpact::Invalid | CodeQueryDiagnosticImpact::Incomplete => {
                return Err(format!(
                    "{}: {}",
                    diagnostic.code.as_str(),
                    diagnostic.message
                ));
            }
            CodeQueryDiagnosticImpact::DeclaredNonExhaustive
            | CodeQueryDiagnosticImpact::Advisory => {}
        }
    }

    // 2. Is each row's own evidence complete, and what did the analysis prove?
    let mut proven = Vec::new();
    let mut unproven = Vec::new();
    for item in &result.results {
        let CodeQueryResultValue::ReceiverAnalysis { value } = &item.value else {
            return Err(format!("unexpected row: {:?}", item.value));
        };
        if item.provenance_truncated {
            unproven.push(value.text.clone());
            continue;
        }
        match value.outcome {
            "precise" => proven.push(value.text.clone()),
            "ambiguous" | "unknown" | "unsupported" | "exceeded_budget" => {
                unproven.push(value.text.clone())
            }
            other => return Err(format!("unhandled receiver outcome {other}")),
        }
    }
    Ok((proven, unproven))
}
```

Against the fixture this returns `["ledger", "opened"]` as proven and
`["either"]` as unproven.

`result.completion()` is the typed one-call summary of that first check. It
returns `CodeQueryCompletion::Complete` only when nothing was truncated and no
diagnostic reported `invalid`, `incomplete`, or `declared_non_exhaustive`
impact; the other variants name the codes that blocked it. It says nothing
about per-row receiver outcomes, so the second loop is still required.

### Service Or Lower-Level Execution

Use `SearchToolsService` when you want the deployed behavior: it owns the
workspace, keeps the analyzer warm across calls, normalizes tool arguments
against the project root, accepts `query_file`, and returns exactly what MCP
and the Python client return. Reach for the lower-level API instead when you
already own an `IAnalyzer` and want no workspace machinery around it: parse the
query once with `CodeQuery::from_json(...)` or `CodeQuery::from_sexp(...)`, keep
the parsed value, and call `brokk_bifrost::execute_request(analyzer, &query)`
per analyzer. That is the right shape for a batch tool that sweeps many
revisions or repositories with one compiled query, and for a host that supplies
its own cancellation through `execute_request_with_cancellation`. The result
contract is identical, so the completeness reading above does not change.

## Python

The Python client speaks to the same Rust service through a native extension
module, so it sends the same canonical JSON and parses the same rows into typed
dataclasses.

```python
from pathlib import Path

from bifrost_searchtools import (
    CodeQueryDiagnosticImpact,
    CodeQueryReceiverAnalysis,
    SearchToolsClient,
)


def commit_receivers(root: Path) -> tuple[list[str], list[str]]:
    """Split the commit receivers into proven single targets and unproven sites."""
    with SearchToolsClient(root) as client:
        result = client.query_code(
            {"kind": "call", "callee": {"name": "commit"}},
            languages=["typescript"],
            steps=[{"op": "receiver_targets"}],
            schema_version=1,
        )

    # 1. Is the row set itself complete?
    if result.truncated:
        raise RuntimeError("bounded row set: raise the limit or narrow the query")
    blocking = [
        diagnostic
        for diagnostic in result.diagnostics
        if diagnostic.impact
        in (CodeQueryDiagnosticImpact.INCOMPLETE, CodeQueryDiagnosticImpact.INVALID)
    ]
    if blocking:
        raise RuntimeError(f"incomplete answer: {blocking}")

    # 2. Is each row's own evidence complete, and what did the analysis prove?
    proven: list[str] = []
    unproven: list[str] = []
    for row in result.results:
        if not isinstance(row, CodeQueryReceiverAnalysis):
            raise RuntimeError(f"unexpected row: {row}")
        if row.provenance_truncated:
            unproven.append(row.text)
        elif row.outcome == "precise":
            proven.append(row.text)
        elif row.outcome in ("ambiguous", "unknown", "unsupported", "exceeded_budget"):
            unproven.append(row.text)
        else:
            raise RuntimeError(f"unhandled receiver outcome {row.outcome!r}")
    return proven, unproven
```

Against the fixture this returns `(["ledger", "opened"], ["either"])`, the same
split the Rust example produces.

`schema_version=1` is optional here; version 1 is the only supported version, so
omitting it selects the same vocabulary. Pin it when you want a future
vocabulary change to fail loudly instead of silently altering a saved query.

## Completeness Checklist

Both examples read the same four signals in the same order. Anything that
claims "there are no other targets" has to clear all four:

1. `truncated` on the result. `true` means the row set is bounded output, not
   the whole answer.
2. `diagnostics`. Reject or account for every entry whose `impact` is
   `incomplete` or `invalid`; `advisory` and `declared_non_exhaustive` do not
   block a claim but do describe the frame it holds in.
3. `provenance_truncated` on each row. The row is real, but the path that
   derived it is not completely reported.
4. The domain's own outcome field, here the receiver `outcome`. A complete row
   set can still contain rows the analysis did not resolve to one value.

[Agent Result Safety](/agent-result-safety/) states the same rule for every
result domain, not only receivers.
