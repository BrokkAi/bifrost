---
title: Evaluate Bifrost in Ten Minutes
description: Run one reproducible query and match policy through the CLI, agent MCP, and VS Code.
---

> Last verified end to end: 2026-07-20 (`query_code` schema version 2).
> Match-policy path verified the same day (policy schema version 1).

This evaluation uses one checked-in Python fixture, one saved RQL query, and one
match-only policy. The query journeys and policy should all find the same call
at `src/app.py:5`, so differences come from the interface rather than the
analysis question.

The exercise proves that Bifrost can index a small project, match a normalized call shape, execute equivalent RQL and JSON, and preserve the source location across CLI, MCP, and VS Code. It does not measure large-repository performance, prove that every possible Python call resolves, or exercise control flow or data flow.

## Get The Fixture

Install Bifrost by following [Install Bifrost](/install/), or build the current checkout with `cargo build --bin bifrost`. From a Bifrost checkout, enter the published fixture:

```bash
cd docs/fixtures/ten-minute-evaluation
```

If you are reading the published site without a checkout, clone the repository first:

```bash
git clone https://github.com/BrokkAi/bifrost.git
cd bifrost/docs/fixtures/ten-minute-evaluation
```

The fixture contains these two source files:

<!-- code-query-fixture:src/app.py -->
```python
from service import audit


def handle(value):
    return audit(value)
```

<!-- code-query-fixture:src/service.py -->
```python
def audit(value):
    return value.strip()
```

The reusable query is checked in as `queries/find-audit.rql`:

<!-- code-query-case:find-audit:rql -->
```lisp
(language python
  (call :callee (name "audit")))
```

Its canonical JSON form is:

<!-- code-query-case:find-audit:json -->
```json
{"languages":["python"],"match":{"kind":"call","callee":{"name":"audit"}}}
```

The fixture and both query forms are executed by the documentation test suite. Their complete expected engine result is:

<!-- code-query-case:find-audit:expected -->
```json
{
  "results": [
    {
      "enclosing_symbol": "src.app.handle",
      "end_line": 5,
      "kind": "call",
      "language": "python",
      "path": "src/app.py",
      "result_type": "structural_match",
      "start_line": 5,
      "text": "audit(value)"
    }
  ],
  "truncated": false
}
```

## Journey 1: Direct CLI

From the fixture root, run the saved RQL file:

```bash
bifrost --root . --query-file queries/find-audit.rql
```

The result should contain one `structural_match` at `src/app.py`, starting and ending on line 5, with text `audit(value)`, and `truncated` should be `false`.

Run the equivalent canonical JSON through one-shot tool mode:

```bash
bifrost --root . --tool query_code --args '{"languages":["python"],"match":{"kind":"call","callee":{"name":"audit"}}}'
```

It should return the same path, line, text, and truncation state. This parity is useful when exploring in RQL before checking a stable JSON query into an integration.

## Journey 2: Run A Match Policy

The published fixture also contains `policies/review-audit-call.rqlp`. It wraps
the same RQL selector in stable finding metadata:

<!-- policy-doc-test:rqlp:docs/fixtures/ten-minute-evaluation/policies/review-audit-call.rqlp -->
```lisp
(policy
  :schema-version 1
  :id "bifrost.example.review-audit-call"
  :name "Review direct audit calls"
  :message "Review this direct audit call"
  :severity warning
  :analysis
    (analysis
      :type match
      :selector
        (rql-file
          :schema-version 2
          :path "queries/find-audit.rql")))
```

Run the exact checked-in policy from the fixture root:

```bash
bifrost --root . \
  --policy-file policies/review-audit-call.rqlp \
  --format human \
  --fail-on never
```

`--fail-on never` keeps this demonstration command at status 0 without hiding
the finding. The documentation test runs that exact command through the current
`bifrost` binary and checks this complete human output. The report identifies
the `audit(...)` call at `src/app.py:5:12` and ends with one complete policy run.

<details>
<summary>Checked current output</summary>

<!-- policy-doc-test:human:ten-minute-audit -->
```text
[warning]  src/app.py:5:12
    Review this direct audit call

summary: 1 finding; 1 complete policy run
```

</details>

Run the same command with `--fail-on warning` to use the policy as a gate. The
report is identical, but the process exits 1 because the finding is a warning.

## Journey 3: Agent MCP

Configure the agent's Bifrost server with the fixture directory as its explicit root and the query-capable toolset:

```bash
bifrost --root /absolute/path/to/bifrost/docs/fixtures/ten-minute-evaluation --mcp "symbol|extended"
```

Start a fresh agent session and confirm that `query_code` appears in its Bifrost tools. First call it with these inline JSON fields:

```json
{"languages":["python"],"match":{"kind":"call","callee":{"name":"audit"}}}
```

Then call the same tool with exactly one saved-query field:

```json
{"query_file":"queries/find-audit.rql"}
```

Both calls should return the same `src/app.py:5` match as the CLI. The saved file path is relative to the configured workspace root. Do not combine `query_file` with inline filters or send the RQL expression as raw inline text.

If the first call is impossible because `query_code` is missing, the agent has not loaded a query-capable MCP configuration. If only the second fails, verify the active workspace root and relative file path. A successful symbol-tool call alone does not prove query access.

## Journey 4: VS Code

Install the [Bifrost VS Code extension](/vscode/), then open the fixture directory as the workspace:

```bash
code docs/fixtures/ten-minute-evaluation
```

Open `queries/find-audit.rql`. Wait for the Bifrost language server to finish indexing, then use the Play button in the RQL editor title. The **Bifrost Query Results** Explorer view should show one result under `src/app.py`; selecting it should open and highlight `audit(value)` on line 5.

To prove that this is the editor/LSP path rather than saved-file execution, change `"audit"` to `"strip"` without saving and press Play again. The result should move to `src/service.py:2`. Undo the edit to restore the checked-in fixture.

This unsaved-buffer behavior is specific to the VS Code language-server request. It does not expose `query_code` to an agent and is not available through MCP `query_file`.

## Interpret The Result

All query runs and the match policy should agree on one structural call shape.
The policy adds diagnostic identity and presentation; it does not strengthen the
underlying fact into a claim about every runtime target or caller. For
declaration identity and proof tiers, continue with [Reference
Traversal](/code-query-tutorials/reference-traversal/). For language-specific
boundaries, use the [capability matrix](/capabilities/).

Before treating any larger query as complete, inspect `truncated` and all returned diagnostics. When graph steps are present, also distinguish `proven` from `unproven` edges and check `provenance_truncated`. Continue with [Agent Result Safety](/agent-result-safety/) before using these results in automated claims, or [Build a Static-Analysis Rule](/build-static-analysis-rule/) to productize a query.
