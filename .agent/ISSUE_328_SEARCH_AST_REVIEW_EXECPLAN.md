# Issue #328 / PR #451: search_ast review remediation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md` from the repository root.

Upstream context: GitHub issue `BrokkAi/bifrost#328` introduced the normalized `search_ast` tool. Pull request `BrokkAi/bifrost#451` adds the first implementation. A PR comment by `jbellis` on 2026-07-03 identified six review findings around result precision, span policy, capability caveats, query extension/versioning, result ordering/truncation, and broad-query performance UX.


## Purpose / Big Picture

`search_ast` is intended to be a first-class structural query language for agents and, later, human REPL users and refactoring/rules layers. The initial PR deliberately kept output compact, but the review correctly points out that downstream tools need precise ranges, stable IDs, explicit capability caveats, defined duplicate-capture behavior, predictable ordering, and better guidance for broad expensive queries. After this plan is complete, existing compact `search_ast` results remain small by default, while callers that need precise follow-up locations can opt into full detail without changing the matcher’s normalized language model.


## Progress

- [x] (2026-07-03T12:27Z) Created this review-remediation ExecPlan from the accepted implementation plan. No runtime behavior has changed yet.
- [x] (2026-07-03T12:34Z) Milestone 1: added opt-in full result detail without changing compact output. `result_detail` now defaults to compact, full detail adds deterministic match IDs, byte/line/column ranges, capture ranges, and optional capture kinds. Python models parse the optional fields. Validation passed with `cargo fmt -- --check`, `cargo test structural --lib`, `cargo test --test structural_search_cross_language --test structural_search_planner --test structural_search_python`, and the targeted Python client unittest through `uv run --python 3.12 --with maturin`.
- [x] (2026-07-03T12:37Z) Milestone 2: defined the full-detail decorator/annotation span policy in README docs and added cross-language tests for decorated callables and decorated classes. `node_range` remains the matched normalized fact range, `decorator_ranges` report extracted decorator/annotation role spans, and `decorated_range` is their union. Validation passed with `cargo fmt -- --check`, `cargo test structural --lib`, and `cargo test --test structural_search_cross_language --test structural_search_planner --test structural_search_python`.
- [x] (2026-07-03T12:38Z) Milestone 3: documented capability and precision caveats in `bifrost_searchtools/README.md` and tightened the MCP descriptor text. The docs cover constructor-as-call behavior, kwargs support, aliases/import caveats, syntactic receiver/callee extraction, decorator span policy, argument-subsequence semantics, and unsupported-role diagnostics. Validation passed with `cargo fmt -- --check` and `cargo test structural --lib`.
- [x] (2026-07-03T12:42Z) Milestone 4: added `schema_version: 1` validation/canonicalization and exact-text duplicate capture equality. Python client docs now call `search_ast` experimental v1 and can pass `schema_version=1`. Validation passed with `cargo fmt -- --check`, `cargo test structural --lib`, `cargo test --test structural_search_cross_language --test structural_search_planner --test structural_search_python`, and the targeted Python client unittest through `uv run --python 3.12 --with maturin`.
- [x] (2026-07-03T12:46Z) Milestone 5: switched candidate traversal to global project-relative path order with language as the deterministic tiebreaker, while preserving the `limit + 1` truncation proof. Truncated result sets now include a compact workspace diagnostic with scanned file/source/fact counts and refinement guidance. Validation passed with `cargo fmt -- --check` and `cargo test --test structural_search_cross_language --test structural_search_planner`.
- [x] (2026-07-03T12:49Z) Milestone 6: added compact broad-query performance guidance for unanchored, unscoped searches when they truncate, exhaust a budget, or scan at least 100 files. Anchored and scoped queries stay quiet apart from existing focused diagnostics. Validation passed with `cargo fmt -- --check`, `cargo test structural --lib`, and `cargo test --test structural_search_planner`.


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

- Decision: Make full-detail fields optional on the existing result structs instead of introducing parallel compact/full result types.
  Rationale: This preserves the current compact JSON shape via serde skip rules and lets Python callers use one model with optional fields.
  Date/Author: 2026-07-03 / Codex.

- Decision: Expose decorator span policy in full-detail output without changing fact extraction or match semantics.
  Rationale: The PR review asked for explicit span policy. Reporting `node_range`, `decorator_ranges`, and `decorated_range` makes the behavior inspectable while avoiding adapter-risky semantic rewrites in this milestone.
  Date/Author: 2026-07-03 / Codex.

- Decision: Keep capability caveats in docs and descriptor prose, not every `search_ast` result.
  Rationale: The review asked for discoverability, but always emitting the full matrix would inflate LLM context for common queries. Runtime diagnostics remain focused on unsupported features and later broad/truncated query guidance.
  Date/Author: 2026-07-03 / Codex.

- Decision: Treat omitted `schema_version` as v1 and reject any explicit non-v1 version.
  Rationale: Existing callers remain compatible, while explicit callers get a clear failure instead of silently running an incompatible query shape.
  Date/Author: 2026-07-03 / Codex.

- Decision: Enforce duplicate capture equality by exact source text during matching.
  Rationale: This gives repeated labels meaningful rule-like semantics while preserving all successful capture occurrences for full-detail callers.
  Date/Author: 2026-07-03 / Codex.

- Decision: Order workspace candidates globally by project-relative path, with language only as a tiebreaker.
  Rationale: Global path order is easier to explain and reproduce than language buckets, and it keeps `limit` behavior predictable for mixed-language workspaces.
  Date/Author: 2026-07-03 / Codex.

- Decision: Emit truncation guidance only when the match set is actually truncated by `limit`.
  Rationale: Compact outputs should stay quiet when complete; when incomplete, callers need scan counts and concrete refinement knobs to make the next query narrower.
  Date/Author: 2026-07-03 / Codex.

- Decision: Gate broad-query guidance on no source anchors, no `where`, no `languages`, and either truncation, budget exhaustion, or 100 scanned files.
  Rationale: This catches expensive context-heavy searches without warning on small complete queries or deliberately scoped language/path searches.
  Date/Author: 2026-07-03 / Codex.


## Outcomes & Retrospective

- 2026-07-03T12:34Z: Milestone 1 completed. Existing compact output remains the default and existing structural tests continue to pass. Callers that request `result_detail: "full"` now get match IDs and precise match/capture ranges suitable for follow-up tooling.
- 2026-07-03T12:37Z: Milestone 2 completed. Full-detail results now have documented decorator/annotation range semantics and cross-language coverage for decorated callables and classes.
- 2026-07-03T12:38Z: Milestone 3 completed. The Python README and MCP descriptor now make the normalization precision limits explicit without adding per-result verbosity.
- 2026-07-03T12:42Z: Milestone 4 completed. The query surface now has an explicit v1 compatibility marker, and repeated capture labels are real equality constraints instead of independent labels.
- 2026-07-03T12:46Z: Milestone 5 completed. Mixed-language result order is now path-first across the workspace, and truncated outputs explain how much work was scanned before returning the bounded result set.
- 2026-07-03T12:49Z: Milestone 6 completed. Broad unanchored queries now receive concise performance guidance only when they are likely to cost meaningful context or compute.


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
