# Issue #328 / PR #451: search_ast review remediation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md` from the repository root.

Upstream context: GitHub issue `BrokkAi/bifrost#328` introduced the normalized `search_ast` tool. Pull request `BrokkAi/bifrost#451` adds the first implementation. A PR comment by `jbellis` on 2026-07-03 identified six review findings around result precision, span policy, capability caveats, query extension/versioning, result ordering/truncation, and broad-query performance UX.


## Purpose / Big Picture

`search_ast` is intended to be a first-class structural query language for agents and, later, human REPL users and refactoring/rules layers. The initial PR deliberately kept output compact, but the review correctly points out that downstream tools need precise ranges, stable IDs, explicit capability caveats, defined duplicate-capture behavior, predictable ordering, and better guidance for broad expensive queries. After this plan is complete, existing compact `search_ast` results remain small by default, while callers that need precise follow-up locations can opt into full detail without changing the matcher’s normalized language model.


## Progress

- [x] (2026-07-03T12:27Z) Created this review-remediation ExecPlan from the accepted implementation plan. No runtime behavior has changed yet.
- [ ] Milestone 1: add opt-in full result detail without changing compact output.
- [ ] Milestone 2: define and expose decorator/annotation span ranges in full detail.
- [ ] Milestone 3: document capability and precision caveats for humans and LLMs.
- [ ] Milestone 4: add schema versioning and exact-text duplicate capture equality.
- [ ] Milestone 5: switch to global project-relative ordering and add truncation diagnostics.
- [ ] Milestone 6: add compact broad-query performance guidance.


## Surprises & Discoveries

- None yet.


## Decision Log

- Decision: Keep compact `search_ast` output as the default and add `result_detail: "full"` for precise metadata.
  Rationale: Agents often operate under tight context budgets, but rules/refactoring/follow-up tools need byte ranges, columns, capture ranges, and stable match IDs.
  Date/Author: 2026-07-03 / dave + Codex.

- Decision: Use exact source-text equality for duplicate capture labels.
  Rationale: This gives repeated captures a useful Semgrep-like meaning without adding a deeper AST-equivalence model before the rules layer exists.
  Date/Author: 2026-07-03 / dave + Codex.

- Decision: Add a new review-remediation ExecPlan instead of appending the original issue #328 plan.
  Rationale: The original plan records the feature implementation history; this plan is specifically about PR review remediation and should remain easier to review milestone by milestone.
  Date/Author: 2026-07-03 / dave + Codex.


## Outcomes & Retrospective

- Not started.


## Context and Orientation

The structural search implementation lives under `src/analyzer/structural/`. The canonical query type is `AstQuery` in `src/analyzer/structural/query/ir.rs`; JSON decoding is in `src/analyzer/structural/query/decode.rs`; canonical JSON rendering is in `src/analyzer/structural/query/json.rs`. Matching happens in `src/analyzer/structural/matcher.rs`, which evaluates one `Pattern` against normalized per-file facts. Workspace execution and result rendering happen in `src/analyzer/structural/search.rs`.

A normalized fact is one tree-sitter node mapped to a language-independent kind such as `call`, `function`, or `assignment`. Facts are stored in `FileFacts` in `src/analyzer/structural/facts.rs`, which already has byte spans, line starts, role edges, and a private source string. A role is an edge such as `callee`, `args`, `decorators`, or `right`. A capture is a user-supplied label on a pattern; currently captures only report name, snippet text, and start line.

The tool is exposed through MCP in `src/mcp_extended.rs`, Rust service dispatch in `src/searchtools_service.rs`, and Python client models in `bifrost_searchtools/models.py` plus `bifrost_searchtools/client.py`. The most relevant tests are `tests/structural_search_python.rs`, `tests/structural_search_cross_language.rs`, `tests/structural_search_planner.rs`, `python_tests/test_searchtools_client.py`, and structural unit tests under `src/analyzer/structural/`.


## Plan of Work

Milestone 1 adds `result_detail` to `AstQuery`, defaulting to compact. Define a public result-detail enum and a serializable range struct. In compact mode, serialized output must remain unchanged except for any fields already present today. In full mode, matches include a deterministic `id` and `node_range`, while captures include `range` and optional normalized `kind`. Add Python model fields that are optional so existing callers keep working.

Milestone 2 keeps match semantics unchanged but exposes decorator span policy in full detail. `node_range` remains the matched normalized fact’s current parser-backed span. `decorator_ranges` are the spans of decorator/annotation role targets on that fact. `decorated_range` is the union of `node_range` and `decorator_ranges`. Add tests over Python, Java, JavaScript, and TypeScript decorated callables/classes.

Milestone 3 adds a concise capability and precision matrix to `bifrost_searchtools/README.md` and tightens MCP descriptor wording. It must cover constructor calls, kwargs, aliases/import bindings, syntactic receiver/callee extraction, decorator span policy, argument-subsequence semantics, and unsupported-role diagnostics. Do not emit this full matrix in every result.

Milestone 4 adds `schema_version: 1` to the query surface. Omitted means v1; any other version is rejected with a path-specific error; canonical JSON emits `schema_version: 1`. Implement duplicate-capture equality in the matcher: the first capture label binds exact source text, later captures with the same label must match the same text, and all successful capture occurrences remain in output order.

Milestone 5 changes candidate traversal from language-grouped order to global project-relative path order, with language as a deterministic tiebreaker. Keep the `limit + 1` bounded execution rule. When truncation occurs, add a compact workspace diagnostic with scanned file/source/fact counts and guidance to refine with `where`, `languages`, or exact-name anchors.

Milestone 6 adds compact diagnostics for broad unanchored queries only when useful: no source anchors, no `where`, no `languages`, and either truncation, budget exhaustion, or a meaningful scanned-file threshold. Do not add a richer index in this PR.


## Concrete Steps

Work from `/Users/dave/.codex/worktrees/3114/bifrost`. After each milestone, update this plan’s `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` as needed, run the focused tests for that milestone, stage only touched files, and commit with a message describing the milestone outcome and rationale.

For every Rust-internal milestone, run:

    cargo fmt -- --check
    cargo test structural --lib
    cargo test --test structural_search_cross_language --test structural_search_planner --test structural_search_python

For Python model/client changes, run:

    uv run --python 3.12 --with maturin python -m unittest python_tests.test_searchtools_client.SearchToolsClientTest.test_search_ast_returns_typed_matches

Before final push, run:

    cargo fmt -- --check
    cargo clippy-no-cuda
    cargo test --test structural_search_cross_language --test structural_search_planner --test structural_search_python


## Validation and Acceptance

Milestone 1 is accepted when compact `search_ast` JSON and rendered text are unchanged for existing tests, and a full-detail query returns match/capture byte ranges, 1-based character columns, capture end lines, deterministic match IDs, and capture kinds where available.

Milestone 2 is accepted when full-detail decorated-function/class results show `node_range`, `decorator_ranges`, and `decorated_range` consistently across Python, Java, JavaScript, and TypeScript, without changing which nodes match.

Milestone 3 is accepted when README and MCP wording clearly state the current precision limits and recommended use. No test should start failing because of changed runtime output.

Milestone 4 is accepted when `schema_version` parsing/canonicalization is tested, invalid versions fail at `schema_version`, duplicate captures with equal text match, and duplicate captures with different text do not match.

Milestone 5 is accepted when broad cross-language results are ordered by global project-relative path rather than language buckets, bounded truncation behavior remains intact, and truncated outputs include compact scan-count guidance.

Milestone 6 is accepted when focused anchored/scoped queries stay quiet, while broad unanchored truncated or budget-exhausted queries include actionable compact guidance.


## Idempotence and Recovery

All edits are ordinary source and documentation changes. If a milestone fails tests, do not continue to the next milestone; fix the failing milestone in place, update this plan with the discovery, and rerun the focused tests. Avoid `git add -A`; stage only files changed for the milestone. The worktree may be detached, so pushes should use `git push origin HEAD:dave/elastic-moser-237638`.


## Interfaces and Dependencies

At the end of the plan, `AstQuery` has `schema_version` and `result_detail` fields. `SearchAstResultDetail` is the internal enum for compact versus full output. `SearchAstMatch` and `SearchAstCapture` keep their compact fields and add optional full-detail fields that are skipped during serialization when absent. `FactMatch` captures must carry enough metadata to render optional capture kind as well as range. No new third-party dependency is required.


## Artifacts and Notes

Review source: `https://github.com/BrokkAi/bifrost/pull/451#issuecomment-4875987392`.

Revision note 2026-07-03T12:27Z: Initial review-remediation ExecPlan created before implementation so the six PR review findings can be addressed as isolated, testable, committed milestones.
